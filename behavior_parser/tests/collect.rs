//! Exercises the exact path CI runs at build time: walk a manifest root for
//! `content.toml` files, collect them into a `BehaviorManifest`, render it as
//! TOML, then confirm `hut-core` (or anything else) could read that
//! generated file back and get the same data.

use std::path::Path;

use behavior_parser::BehaviorManifest;
use behavior_parser::collect::walk_puzzle_behaviors;
use behavior_parser::patch::{PatchDomain, PatchOp};

#[test]
fn walks_multiple_puzzles_and_round_trips_generated_behavior_toml() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifest");
    let puzzle = walk_puzzle_behaviors(&base);

    // Sorted by id regardless of directory iteration order.
    assert_eq!(puzzle.len(), 2);
    assert_eq!(puzzle[0].id, 1);
    assert_eq!(puzzle[0].title, "Puzzle A");
    assert_eq!(puzzle[1].id, 2);
    assert_eq!(puzzle[1].title, "Puzzle B");

    let manifest = BehaviorManifest { puzzle };
    let rendered = toml::to_string_pretty(&manifest).expect("serialize behavior manifest");

    let reparsed: BehaviorManifest =
        toml::from_str(&rendered).expect("reparse generated behavior.toml");

    assert_eq!(reparsed.puzzle.len(), 2);

    let puzzle_a = &reparsed.puzzle[0];
    assert_eq!(puzzle_a.patch[0].patch_id, 102);
    assert!(matches!(
        &puzzle_a.patch[0].op[..],
        [PatchOp::Insert(PatchDomain::Content,name, id)] if name == "content-b" && *id == 102
    ));
    assert_eq!(puzzle_a.answer[0].answer, "more-content");
    assert_eq!(puzzle_a.answer[0].patch, vec![102]);

    let puzzle_b = &reparsed.puzzle[1];
    assert_eq!(puzzle_b.patch[0].patch_id, 202);
    assert!(puzzle_b.patch[0].do_not_grant);
    assert!(
        matches!(&puzzle_b.patch[0].op[0], PatchOp::Hide(PatchDomain::Content, name) if name == "content-a")
    );
    assert_eq!(puzzle_b.answer[0].answer, "more-test");
    assert_eq!(puzzle_b.answer[0].patch, vec![202]);
}
