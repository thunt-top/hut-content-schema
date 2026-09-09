//! Builds a synthetic manifest fixture (`tests/fixtures/manifest`, committed
//! here so this test is fully self-contained — never the real, git-ignored
//! `../manifest` the `hut_content` binary publishes) with a `MockVersionRegistry`
//! (no network, no `.env`), then round-trips every resulting resource back
//! through decrypt/gunzip to confirm the crypto and grant
//! (inherit/independent/purchase) logic all agree with each other.

use std::{collections::HashSet, path::Path};

use content_parser::content_gzip::ungzip;
use content_parser::scope::puzzle_scope::PuzzleScope;
use content_parser::version_registry::MockVersionRegistry;
use content_crypto::{decrypt, derive_key, derive_url};

/// A fixed key, not read from `.env` or generated — keeps this test hermetic
/// and reproducible regardless of the local environment.
const TEST_BASE_KEY: [u8; 32] = *b"content_parser test fixture key!";

/// Replays the same chain of `derive_key` calls that produced `derive_path`,
/// starting back over from the base key.
fn rederive_key(base: [u8; 32], path: &[(&'static str, i32)]) -> [u8; 32] {
    path.iter()
        .fold(base, |key, (tag, id)| derive_key(&key, tag, *id))
}

#[tokio::test]
async fn builds_and_round_trips_synthetic_manifest() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/manifest/puzzle/test_puzzle/content.toml");
    let puzzle_scope = PuzzleScope::from_toml_file(&manifest_path);

    assert_eq!(puzzle_scope.contents.len(), 2);
    assert_eq!(puzzle_scope.data.len(), 3);
    assert_eq!(puzzle_scope.hints.len(), 2);
    assert_eq!(
        puzzle_scope.base_manifest.content,
        vec![("content-a".to_string(), 901.try_into().unwrap())]
    );
    assert_eq!(
        puzzle_scope.base_manifest.data,
        vec![("data-hint".to_string(), 903.try_into().unwrap())]
    );
    assert_eq!(
        puzzle_scope.base_manifest.hint,
        vec![("hint-a".to_string(), 906.try_into().unwrap())]
    );

    let base_resource = puzzle_scope.base_resource;
    let mut registry = MockVersionRegistry::new();
    let mut seen = HashSet::new();
    let built = puzzle_scope
        .build(TEST_BASE_KEY, &mut registry, &mut seen)
        .await
        .expect("synthetic fixture manifest should build against a mock registry");

    // One `Encrypted` entry per independently-keyed resource: `extra.md`
    // (902), the two independent `data` entries (904, 905), both hint
    // answers (907, 909, both `purchase`), the second hint itself (908,
    // `independent`), and the scope's own base resource (900). The two
    // `inherit` entries (901, 903) and the first hint (906, also `inherit`)
    // fold into their ancestor's payload instead of appearing here.
    assert_eq!(built.len(), 7);

    let mut base_resource_json = None;
    for (registration, encrypted) in built {
        let key = rederive_key(TEST_BASE_KEY, &encrypted.derive_path);
        let gz = decrypt(&key, &encrypted.encrypted).expect("decrypt with re-derived key");
        let raw = ungzip(&gz).expect("gunzip decrypted content");

        assert_eq!(
            blake3::hash(&raw),
            *registration.digest(),
            "round-tripped content should match its recorded hash"
        );

        let expected_url_prefix = derive_url(&key, i32::from(*registration.resource_id()));
        assert_eq!(expected_url_prefix, encrypted.url_prefix);

        if *registration.resource_id() == base_resource {
            base_resource_json = Some(
                serde_json::from_slice::<serde_json::Value>(&raw)
                    .expect("scope base resource content should be valid JSON"),
            );
        }
    }

    // The scope's own base resource carries `base_manifest` straight through
    // as initial state for `behavior_parser`'s patch ops to mutate at
    // runtime — never interpreted here, just round-tripped.
    let base_resource_json = base_resource_json.expect("scope base resource should have built");
    assert_eq!(
        base_resource_json["base_manifest"],
        serde_json::json!({
            "content": [["content-a", 901]],
            "data": [["data-hint", 903]],
            "hint": [["hint-a", 906]],
        })
    );
}
