//! Walks a manifest root looking for `content.toml` files and parses each
//! into a [`crate::PuzzleBehavior`], ignoring every field that isn't
//! `id`/`title`/`patch`/`answer` (`content_parser`'s fields, e.g.
//! `base_resource`/`contents`/`data`/`hints`/`base_manifest`, are silently
//! skipped the same way `toml::from_str` always ignores unknown fields).
//!
//! This is the shared logic behind the crate's CLI (`src/main.rs`), which
//! runs it during CI to produce the single `behavior.toml` `hut-core` reads
//! at startup — kept as a library function so it's directly testable without
//! spawning the binary.

use std::path::Path;

use crate::PuzzleBehavior;

/// Recursively finds every `content.toml` under `base`, parses each into a
/// `PuzzleBehavior`, and returns them sorted by `id` — sorted so the output
/// is deterministic regardless of filesystem iteration order, since this
/// feeds a generated file that's diffed/reviewed in CI.
pub fn walk_puzzle_behaviors(base: &Path) -> Vec<PuzzleBehavior> {
    let mut out = Vec::new();
    walk(base, &mut out);
    out.sort_by_key(|behavior| behavior.id);
    out
}

fn walk(dir: &Path, out: &mut Vec<PuzzleBehavior>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("failed to read dir entry under {dir:?}: {e}"))
            .path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.file_name().and_then(|f| f.to_str()) == Some("content.toml") {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
            let behavior: PuzzleBehavior =
                toml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"));
            out.push(behavior);
        }
    }
}
