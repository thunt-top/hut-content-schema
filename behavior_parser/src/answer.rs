use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Answer {
    pub answer: String,
    // (String) => (String)
    #[serde(default)]
    pub normalization: Option<String>,
    // (&str, &str, game_version) => bool,
    #[serde(default)]
    pub special_judge: Option<String>,
    #[serde(default)]
    pub idempotency: Option<i32>,
    #[serde(default)]
    pub solves: Option<i32>,
    #[serde(default)]
    pub unlockes: Vec<i32>,
    #[serde(default)]
    // Grant for access to resources. In most cases, try to use the `auto_grant` in an patch instead.
    pub grants: Vec<i32>,
    #[serde(default)]
    pub patch: Vec<i32>,

    #[serde(default)]
    pub message: Option<String>,
}
