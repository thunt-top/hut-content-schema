//! CI build-stage tool: walks a manifest root (`--base`, not a fixed path —
//! CI decides where the manifest tree lives) for `content.toml` files and
//! writes their collected `PuzzleBehavior`s out as a single `behavior.toml`
//! (`--out`, defaulting to `behavior.toml` in the current directory).
//!
//! `hut-core` reads that single generated file at startup (its path given
//! via an env var, since a deployed SCF function has no CLI arguments),
//! rather than re-walking a directory tree itself.
//!
//! Run with: `cargo run -p behavior_parser -- --base <manifest-root> [--out <file>]`

use std::path::PathBuf;

use behavior_parser::BehaviorManifest;
use behavior_parser::collect::walk_puzzle_behaviors;

fn main() {
    let mut base: Option<PathBuf> = None;
    let mut out = PathBuf::from("behavior.toml");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base" => {
                let value = args.next().expect("--base requires a path");
                base = Some(PathBuf::from(value));
            }
            "--out" => {
                let value = args.next().expect("--out requires a path");
                out = PathBuf::from(value);
            }
            other => {
                panic!("unrecognized argument {other:?} (expected --base <dir> [--out <file>])")
            }
        }
    }
    let base = base.expect("--base <manifest-root> is required");

    let puzzle = walk_puzzle_behaviors(&base);
    println!(
        "collected {} puzzle behavior(s) from {}",
        puzzle.len(),
        base.display()
    );

    let manifest = BehaviorManifest { puzzle };
    let rendered = toml::to_string_pretty(&manifest).expect("serialize behavior manifest");
    std::fs::write(&out, rendered).unwrap_or_else(|e| panic!("failed to write {out:?}: {e}"));

    println!("wrote {}", out.display());
}
