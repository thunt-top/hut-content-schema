use serde::{Deserialize, Serialize};

/// One `[[answer]]` entry. Unknown keys are rejected, so a typo'd key
/// fails the grammar check instead of silently reading as its default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    // `unlockes` is the original (misspelled) key, still accepted.
    #[serde(default, alias = "unlockes")]
    pub unlocks: Vec<i32>,
    #[serde(default)]
    // Grant for access to resources. In most cases, try to use the `auto_grant` in an patch instead.
    pub grants: Vec<i32>,
    #[serde(default)]
    pub patch: Vec<i32>,

    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_old_unlockes_spelling() {
        let answer: Answer = toml::from_str("answer = \"x\"\nunlockes = [3]").unwrap();
        assert_eq!(answer.unlocks, vec![3]);
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = toml::from_str::<Answer>("answer = \"x\"\nsolve = 1").unwrap_err();
        assert!(err.to_string().contains("unknown field `solve`"), "{err}");
    }
}
