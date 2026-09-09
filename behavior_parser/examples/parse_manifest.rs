//! Confirms `behavior_parser` parses exactly the fields documented in
//! `src/lib.rs` (`id`, `title`, `patch`, `answer`) out of a full
//! `content.toml`-shaped manifest, silently ignoring the fields that belong
//! to `content_parser` instead (`base_resource`, `contents`, `data`,
//! `hints`, `base_manifest`).
//!
//! Run with: `cargo run -p behavior_parser --example parse_manifest`

use std::path::Path;

use behavior_parser::PuzzleBehavior;
use behavior_parser::patch::{PatchDomain, PatchOp};

fn main() {
    let manifest_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/content.toml");
    let raw = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {manifest_path:?}: {e}"));
    let behavior: PuzzleBehavior =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {manifest_path:?}: {e}"));

    assert_eq!(behavior.id, 1);
    assert_eq!(behavior.title, "Synthetic Test Puzzle");
    assert_eq!(behavior.patch.len(), 3);
    assert_eq!(behavior.answer.len(), 2);

    assert_eq!(behavior.patch[0].patch_id, 902);
    assert!(!behavior.patch[0].cross_version);
    assert!(!behavior.patch[0].do_not_grant);
    assert!(matches!(
        &behavior.patch[0].op[..],
        [PatchOp::Insert(PatchDomain::Content,name, id)] if name == "content-b" && *id == 902
    ));

    assert_eq!(behavior.patch[1].patch_id, 908);
    assert!(behavior.patch[1].do_not_grant);

    assert_eq!(behavior.patch[2].patch_id, 902);
    assert!(behavior.patch[2].cross_version);
    assert!(
        matches!(&behavior.patch[2].op[0], PatchOp::Hide(PatchDomain::Content,name) if name == "content-a")
    );
    assert!(matches!(
        &behavior.patch[2].op[1],
        PatchOp::Replace(PatchDomain::Content,name, from, to) if name == "hint-a" && *from == 906 && *to == 908
    ));

    assert_eq!(behavior.answer[0].answer, "more-content");
    assert_eq!(behavior.answer[0].patch, vec![902]);

    assert_eq!(behavior.answer[1].answer, "more-test");
    assert_eq!(behavior.answer[1].patch, vec![908]);
    assert_eq!(
        behavior.answer[1].normalization.as_deref(),
        Some("trim_lowercase")
    );
    assert_eq!(behavior.answer[1].solves, Some(1));
    assert_eq!(behavior.answer[1].unlockes, vec![910]);
    assert_eq!(behavior.answer[1].grants, vec![902]);

    println!(
        "parsed PuzzleBehavior from {}, ignoring every content_parser-only field:\n{behavior:#?}",
        manifest_path.display()
    );
}
