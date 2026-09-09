//! Shared TOML building blocks for `Scope` config files.
//!
//! Every `Scope` kind (currently just [`crate::scope::puzzle_scope::PuzzleScope`],
//! more to come) is authored as a `.toml` file and turned into its runtime
//! struct through a `*Config` type here plus a per-scope `*EntryConfig`. The
//! pieces below (`GrantConfig`, `resolve_content`, `resolve_json`) are the
//! parts that don't change from one scope kind to the next.
//!
//! Resource ids in the TOML are plain `i32`s (`ResourceId` itself isn't
//! `Deserialize`); [`to_resource_id`] converts them once the whole file has
//! parsed successfully.
//!
//! A "content" entry is either an inline literal or a file loaded relative to
//! the config file, one of `.html` (used verbatim) or `.md`/`.markdown`
//! (rendered with `comrak`):
//!
//! ```toml
//! content = "literal text"
//! # or
//! content_file = "body.md"
//! ```
//!
//! A "json" entry is either an inline TOML value (table, array, or literal)
//! or a `.json` file loaded relative to the config file:
//!
//! ```toml
//! json = { foo = "bar" }
//! # or
//! json_file = "data.json"
//! ```
//!
//! Exactly one of the pair must be set; building panics otherwise.

use std::path::{Path, PathBuf};

use comrak::Options;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::resource::{Grant, ResourceId};

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantConfig {
    Inherit(i32),
    Independent(i32),
    Purchase(i32),
}

impl GrantConfig {
    pub fn resolve(&self) -> Grant {
        match self {
            GrantConfig::Inherit(id) => Grant::Inherit(to_resource_id(*id)),
            GrantConfig::Independent(id) => Grant::Independent(to_resource_id(*id)),
            GrantConfig::Purchase(id) => Grant::Purchase(to_resource_id(*id)),
        }
    }
}

pub fn to_resource_id(id: i32) -> ResourceId {
    ResourceId::try_from(id).unwrap_or_else(|_| panic!("resource id must be positive, got {id}"))
}

pub fn resolve_content(
    content: &Option<String>,
    content_file: &Option<PathBuf>,
    base_dir: &Path,
) -> String {
    match (content, content_file) {
        (Some(literal), None) => literal.clone(),
        (None, Some(rel_path)) => {
            let path = base_dir.join(rel_path);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read content file {path:?}: {e}"));
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("md") | Some("markdown") => {
                    comrak::markdown_to_html(&raw, &Options::default())
                }
                Some("html") | Some("htm") => raw,
                ext => panic!("unsupported content file extension {ext:?} for {path:?}"),
            }
        }
        (None, None) => panic!("content entry must set either `content` or `content_file`"),
        (Some(_), Some(_)) => {
            panic!("content entry must not set both `content` and `content_file`")
        }
    }
}

pub fn resolve_json(
    json: &Option<toml::Value>,
    json_file: &Option<PathBuf>,
    base_dir: &Path,
) -> JsonValue {
    match (json, json_file) {
        (Some(inline), None) => toml_value_to_json(inline),
        (None, Some(rel_path)) => {
            let path = base_dir.join(rel_path);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read json file {path:?}: {e}"));
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid json in {path:?}: {e}"))
        }
        (None, None) => panic!("json entry must set either `json` or `json_file`"),
        (Some(_), Some(_)) => panic!("json entry must not set both `json` and `json_file`"),
    }
}

fn toml_value_to_json(value: &toml::Value) -> JsonValue {
    match value {
        toml::Value::String(s) => JsonValue::String(s.clone()),
        toml::Value::Integer(i) => JsonValue::from(*i),
        toml::Value::Float(f) => JsonValue::from(*f),
        toml::Value::Boolean(b) => JsonValue::Bool(*b),
        toml::Value::Datetime(dt) => JsonValue::String(dt.to_string()),
        toml::Value::Array(arr) => JsonValue::Array(arr.iter().map(toml_value_to_json).collect()),
        toml::Value::Table(t) => JsonValue::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_value_to_json(v)))
                .collect(),
        ),
    }
}
