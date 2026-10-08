//! Whole-manifest checks that neither parser can make on its own, because
//! each one only ever sees its own half of a `content.toml`:
//!
//! - **Top-level keys.** `behavior_parser` and `content_parser` read
//!   different keys from the same top-level table, so neither can reject a
//!   key it doesn't know -- it might be the other's. This checks the top
//!   level against both. (Every nested table belongs to just one parser,
//!   which rejects unknown keys there itself.)
//! - **Cross-references**, between the two halves and across files: an
//!   answer's `patch` names a patch of its puzzle; every resource id a
//!   patch, an answer or `base_manifest` mentions is one some puzzle's
//!   content actually defines; `unlocks`/`solves` name real puzzles; no two
//!   files claim the same puzzle id.
//!
//! [`check`] takes file contents rather than paths, so it's testable
//! without a manifest on disk; the `--base` CLI (`src/main.rs`) walks a
//! manifest tree and feeds it in.
//!
//! Problems name an answer by its position (`answer #2`), never by its
//! text: the output ends up in CI logs, and answers are spoilers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use behavior_parser::PuzzleBehavior;
use behavior_parser::patch::PatchOp;
use content_parser::scope::config::GrantConfig;
use content_parser::scope::puzzle_scope::PuzzleScopeConfig;

/// Every key a `content.toml` may have at its top level, and which parser
/// reads it. Must list every top-level field of `PuzzleBehavior` and
/// `PuzzleScopeConfig`: a field missing here makes every manifest using it
/// fail this check, so drift shows up loudly rather than silently.
const TOP_LEVEL_KEYS: &[(&str, &str)] = &[
    ("id", "both"),
    ("title", "both"),
    ("base_resource", "both"),
    ("init_grant", "behavior_parser"),
    ("patch", "behavior_parser"),
    ("answer", "behavior_parser"),
    ("contents", "content_parser"),
    ("data", "content_parser"),
    ("hints", "content_parser"),
    ("base_manifest", "content_parser"),
];

/// One thing wrong with one file of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: PathBuf,
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file.display(), self.message)
    }
}

/// Both parsers' view of one file -- only for files both could parse.
struct Parsed<'a> {
    file: &'a Path,
    behavior: PuzzleBehavior,
    content: PuzzleScopeConfig,
}

/// Checks a whole manifest, given as `(path, contents)` of each of its
/// `content.toml` files. Returns every problem found, not just the first;
/// empty means the manifest is fine.
pub fn check(files: &[(PathBuf, String)]) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut report = |file: &Path, message: String| {
        problems.push(Problem {
            file: file.to_path_buf(),
            message,
        })
    };

    let mut parsed = Vec::new();
    for (file, raw) in files {
        let table: toml::Table = match toml::from_str(raw) {
            Ok(table) => table,
            Err(e) => {
                report(file, format!("not valid TOML: {e}"));
                continue;
            }
        };
        for key in table.keys() {
            if !TOP_LEVEL_KEYS.iter().any(|(known, _)| known == key) {
                let known: Vec<_> = TOP_LEVEL_KEYS.iter().map(|(k, _)| *k).collect();
                report(
                    file,
                    format!("unknown top-level key `{key}` (expected one of {known:?})"),
                );
            }
        }

        let behavior = toml::from_str::<PuzzleBehavior>(raw)
            .map_err(|e| report(file, format!("behavior_parser can't read it: {e}")));
        let content = toml::from_str::<PuzzleScopeConfig>(raw)
            .map_err(|e| report(file, format!("content_parser can't read it: {e}")));
        if let (Ok(behavior), Ok(content)) = (behavior, content) {
            parsed.push(Parsed {
                file,
                behavior,
                content,
            });
        }
    }

    // What the whole manifest defines, for the references below.
    let mut puzzles: BTreeMap<i32, &Path> = BTreeMap::new();
    let mut resources: BTreeSet<i32> = BTreeSet::new();
    for p in &parsed {
        if let Some(first) = puzzles.insert(p.behavior.id, p.file) {
            report(
                p.file,
                format!(
                    "puzzle id {} is already used by {}",
                    p.behavior.id,
                    first.display()
                ),
            );
        }
        resources.extend(content_resource_ids(&p.content));
    }

    for p in &parsed {
        let puzzle = p.behavior.id;
        let patches: BTreeSet<i32> = p
            .behavior
            .patch
            .iter()
            .map(|patch| patch.patch_id)
            .collect();

        for patch in &p.behavior.patch {
            for op in &patch.op {
                for resource in op_resource_ids(op) {
                    if !resources.contains(&resource) {
                        report(
                            p.file,
                            format!(
                                "patch {} refers to resource {resource}, which no puzzle's content defines",
                                patch.patch_id
                            ),
                        );
                    }
                }
            }
        }

        for (index, answer) in p.behavior.answer.iter().enumerate() {
            let answer_no = index + 1;
            for patch in &answer.patches {
                if !patches.contains(patch) {
                    report(
                        p.file,
                        format!(
                            "answer #{answer_no} applies patch {patch}, which puzzle {puzzle} doesn't define"
                        ),
                    );
                }
            }
            for resource in &answer.grants {
                if !resources.contains(resource) {
                    report(
                        p.file,
                        format!(
                            "answer #{answer_no} grants resource {resource}, which no puzzle's content defines"
                        ),
                    );
                }
            }
            for target in answer.unlocks.iter().chain(&answer.solve) {
                if !puzzles.contains_key(target) {
                    report(
                        p.file,
                        format!(
                            "answer #{answer_no} refers to puzzle {target}, which doesn't exist"
                        ),
                    );
                }
            }
        }

        let base_manifest = &p.content.base_manifest;
        for (name, resource) in base_manifest
            .content
            .iter()
            .chain(&base_manifest.data)
            .chain(&base_manifest.hint)
        {
            if !resources.contains(resource) {
                report(
                    p.file,
                    format!(
                        "base_manifest entry `{name}` refers to resource {resource}, which no puzzle's content defines"
                    ),
                );
            }
        }
    }

    problems
}

/// Every resource id a puzzle's content defines: its base resource, and
/// each `contents`/`data`/`hints` entry's (and hint answer's) grant.
fn content_resource_ids(content: &PuzzleScopeConfig) -> Vec<i32> {
    let grants = content
        .contents
        .iter()
        .map(|c| &c.grant)
        .chain(content.data.iter().map(|d| &d.grant))
        .chain(
            content
                .hints
                .iter()
                .flat_map(|h| [&h.grant, &h.answer.grant]),
        );
    std::iter::once(content.base_resource)
        .chain(grants.map(|grant| match grant {
            GrantConfig::Inherit(id) | GrantConfig::Independent(id) | GrantConfig::Purchase(id) => {
                *id
            }
        }))
        .collect()
}

/// The resource ids a patch op mentions -- for `Replace`, both the old and
/// the new one.
fn op_resource_ids(op: &PatchOp) -> Vec<i32> {
    match op {
        PatchOp::Hide(_, _) => vec![],
        PatchOp::Insert(_, _, resource) => vec![*resource],
        PatchOp::Replace(_, _, old, new) => vec![*old, *new],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUZZLE_1: &str = r#"
id = 1
base_resource = 100
title = "One"
init_grant = true

[[contents]]
grant = { independent = 101 }
content = "body"

[[hints]]
grant = { independent = 102 }
title = "Hint"
[hints.answer]
grant = { purchase = 103 }
content = "secret hint answer"

[base_manifest]
content = [["body", 101]]

[[patch]]
patch_id = 7
[[patch.op]]
Replace = ["content", "body", 101, 102]

[[answer]]
answer = "SECRET-ANSWER"
patch = [7]
grants = [103]
unlocks = [2]
solves = 1
"#;

    const PUZZLE_2: &str = r#"
id = 2
base_resource = 200
title = "Two"
"#;

    fn files(contents: &[&str]) -> Vec<(PathBuf, String)> {
        contents
            .iter()
            .enumerate()
            .map(|(i, raw)| (PathBuf::from(format!("p{i}/content.toml")), raw.to_string()))
            .collect()
    }

    fn messages(contents: &[&str]) -> Vec<String> {
        check(&files(contents))
            .into_iter()
            .map(|p| p.message)
            .collect()
    }

    #[test]
    fn a_consistent_manifest_passes() {
        assert_eq!(messages(&[PUZZLE_1, PUZZLE_2]), Vec::<String>::new());
    }

    #[test]
    fn rejects_unknown_top_level_keys() {
        let typo = format!("{PUZZLE_2}\ninit_grnat = true\n");
        let problems = messages(&[PUZZLE_1, &typo]);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("unknown top-level key `init_grnat`"));
    }

    #[test]
    fn rejects_unknown_nested_keys_through_the_parsers() {
        let typo = PUZZLE_1.replace("solves = 1", "solve = 1");
        let problems = messages(&[&typo, PUZZLE_2]);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("unknown field `solve`"),
            "{problems:?}"
        );
    }

    #[test]
    fn reports_every_dangling_reference() {
        let broken = PUZZLE_1
            .replace("patch = [7]", "patch = [8]")
            .replace("grants = [103]", "grants = [104]")
            .replace("unlocks = [2]", "unlocks = [3]")
            .replace(
                r#"content = [["body", 101]]"#,
                r#"content = [["body", 105]]"#,
            )
            .replace("101, 102]", "101, 106]");
        let problems = messages(&[&broken, PUZZLE_2]);
        assert_eq!(
            problems,
            [
                "patch 7 refers to resource 106, which no puzzle's content defines",
                "answer #1 applies patch 8, which puzzle 1 doesn't define",
                "answer #1 grants resource 104, which no puzzle's content defines",
                "answer #1 refers to puzzle 3, which doesn't exist",
                "base_manifest entry `body` refers to resource 105, which no puzzle's content defines",
            ]
        );
        assert!(problems.iter().all(|p| !p.contains("SECRET-ANSWER")));
    }

    #[test]
    fn rejects_duplicate_puzzle_ids() {
        let clash = PUZZLE_2.replace("base_resource = 200", "base_resource = 300");
        let problems = check(&files(&[PUZZLE_1, PUZZLE_2, &clash]));
        assert_eq!(
            problems,
            [Problem {
                file: "p2/content.toml".into(),
                message: "puzzle id 2 is already used by p1/content.toml".into(),
            }]
        );
    }
}
