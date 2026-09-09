//! Builds a JSON file of test vectors from the same synthetic fixture
//! manifest and `MockVersionRegistry` that `tests/build.rs` builds and
//! round-trips, so frontend code can exercise its decrypt path (fetch by
//! URL, AES-256-GCM decrypt, gunzip, compare against the known-good
//! plaintext/digest) against real ciphertext without a running backend or
//! bucket.
//!
//! Run with: `cargo run -p content_parser --example build_test_vectors`
//!
//! Writes `tests/fixtures/test_vectors.json`, a JSON object with three maps:
//! - `urls`: `<url_prefix>_<version>` (the object key a client fetches from
//!   the bucket/CDN) -> base64-encoded ciphertext blob (as served, i.e. the
//!   `"HU&T"` magic + nonce + gzip'd-and-AES-256-GCM-sealed content).
//! - `keys`: `resource_id` (as a string) -> `{"version": <i64>,
//!   "key": <base64 AES-256 key>}`.
//! - `contents`: `resource_id` (as a string) -> `{"raw_content": <string>,
//!   "blake3": <64-char lowercase hex>}`, the plaintext (and its digest) a
//!   correct decrypt + gunzip of that resource's ciphertext should produce.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::json;

use content_parser::content_gzip::ungzip;
use content_parser::scope::puzzle_scope::PuzzleScope;
use content_parser::version_registry::MockVersionRegistry;
use content_crypto::{decrypt, derive_key};

/// Matches `TEST_BASE_KEY` in `tests/build.rs`. Not required for
/// correctness (any fixed key works here) -- kept identical so both files
/// describe the exact same synthetic keys/URLs/ciphertext.
const TEST_BASE_KEY: [u8; 32] = *b"content_parser test fixture key!";
const OUTPUT_PATH: &str = "tests/fixtures/test_vectors.json";

/// Replays the same chain of `derive_key` calls that produced `derive_path`,
/// starting back over from the base key (see `tests/build.rs`).
fn rederive_key(base: [u8; 32], path: &[(&'static str, i32)]) -> [u8; 32] {
    path.iter()
        .fold(base, |key, (tag, id)| derive_key(&key, tag, *id))
}

#[tokio::main]
async fn main() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/manifest/puzzle/test_puzzle/content.toml");
    let puzzle_scope = PuzzleScope::from_toml_file(&manifest_path);

    let mut registry = MockVersionRegistry::new();
    let mut seen = HashSet::new();
    let built = puzzle_scope
        .build(TEST_BASE_KEY, &mut registry, &mut seen)
        .await
        .expect("synthetic fixture manifest should build against a mock registry");

    let mut urls = BTreeMap::new();
    let mut keys = BTreeMap::new();
    let mut contents = BTreeMap::new();

    for (registration, encrypted) in built {
        let key = rederive_key(TEST_BASE_KEY, &encrypted.derive_path);
        let gz = decrypt(&key, &encrypted.encrypted).expect("decrypt with re-derived key");
        let raw = ungzip(&gz).expect("gunzip decrypted content");
        let raw_content = String::from_utf8(raw).expect("fixture content is valid UTF-8");

        let resource_id = i32::from(*registration.resource_id()).to_string();
        let url = format!("{}_{}", encrypted.url_prefix, registration.version());

        urls.insert(url, BASE64.encode(&encrypted.encrypted));
        keys.insert(
            resource_id.clone(),
            json!({
                "version": registration.version(),
                "key": BASE64.encode(key),
            }),
        );
        contents.insert(
            resource_id,
            json!({
                "raw_content": raw_content,
                "blake3": registration.digest().to_hex().to_string(),
            }),
        );
    }

    let resource_count = urls.len();
    let vectors = json!({
        "urls": urls,
        "keys": keys,
        "contents": contents,
    });
    let output = serde_json::to_string_pretty(&vectors).expect("serialize test vectors");

    let output_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(OUTPUT_PATH);
    std::fs::write(&output_path, output).expect("write test vectors file");
    println!(
        "wrote {resource_count} resource(s) to {}",
        output_path.display()
    );
}
