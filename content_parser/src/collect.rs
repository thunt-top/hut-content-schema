//! Walks a manifest root looking for `content.toml` files -- the same tree
//! `behavior_parser` walks -- so both parsers agree on which files make up
//! a manifest.

use std::path::{Path, PathBuf};

/// Recursively finds every `content.toml` under `base` and returns their
/// paths sorted for deterministic ordering, regardless of filesystem
/// iteration order.
pub fn walk_content_tomls(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(base, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("failed to read dir entry under {dir:?}: {e}"))
            .path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.file_name().and_then(|f| f.to_str()) == Some("content.toml") {
            out.push(path);
        }
    }
}
