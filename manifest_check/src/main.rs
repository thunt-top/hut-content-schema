//! CI grammar-check tool: walks a manifest root (`--base`) for
//! `content.toml` files -- the same tree both parsers walk -- and runs
//! [`manifest_check::check`] over all of them, printing every problem
//! found and exiting non-zero if there were any.
//!
//! Run with: `cargo run -p manifest_check -- --base <manifest-root>`

use std::path::PathBuf;
use std::process::ExitCode;

use content_parser::collect::walk_content_tomls;
use manifest_check::check;

fn main() -> ExitCode {
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

    let files: Vec<(PathBuf, String)> = walk_content_tomls(&base)
        .into_iter()
        .map(|path| {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
            (path, raw)
        })
        .collect();

    let problems = check(&files);
    if problems.is_empty() {
        println!("manifest OK: {} file(s) checked", files.len());
        return ExitCode::SUCCESS;
    }

    for problem in &problems {
        eprintln!("{problem}");
    }
    eprintln!("{} problem(s) in {} file(s)", problems.len(), files.len());
    ExitCode::FAILURE
}
