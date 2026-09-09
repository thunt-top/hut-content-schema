//! CI grammar-check tool: walks a manifest root (`--base`) for
//! `content.toml` files and builds each into a `PuzzleScope` against a
//! `MockVersionRegistry` and a throwaway key -- the same "does this parse
//! and do its grants resolve" check `hut-content`'s dry-run mode runs
//! against the real manifest before ever touching the network, but usable
//! here with no `.env` and no `hut-content` checked out at all.
//!
//! Run with: `cargo run -p content_parser -- --base <manifest-root>`

use std::collections::HashSet;
use std::path::PathBuf;

use content_parser::collect::walk_content_tomls;
use content_parser::scope::puzzle_scope::PuzzleScope;
use content_parser::version_registry::MockVersionRegistry;

/// A throwaway key: this is a syntax/grant-resolution check, not a real
/// publish, so the actual key material never needs to be stable or secret.
fn random_key() -> [u8; 32] {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos()
        .to_le_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&std::process::id().to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[tokio::main]
async fn main() {
    let mut base: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base" => {
                let value = args.next().expect("--base requires a path");
                base = Some(PathBuf::from(value));
            }
            other => panic!("unrecognized argument {other:?} (expected --base <dir>)"),
        }
    }
    let base = base.expect("--base <manifest-root> is required");

    let scopes: Vec<PuzzleScope> = walk_content_tomls(&base)
        .into_iter()
        .map(|path| PuzzleScope::from_toml_file(&path))
        .collect();
    let puzzle_count = scopes.len();

    let base_key = random_key();
    let mut registry = MockVersionRegistry::new();
    let mut seen = HashSet::new();
    let mut resource_count = 0;
    for scope in scopes {
        let resources = scope
            .build(base_key, &mut registry, &mut seen)
            .await
            .unwrap_or_else(|e| panic!("manifest failed to build: {e}"));
        resource_count += resources.len();
    }

    println!("manifest OK: {puzzle_count} puzzle(s), {resource_count} resource(s) parsed and built");
}
