use serde::{Deserialize, Serialize};

/// One `[[answer]]` entry. Unknown keys are rejected, so a typo'd key
/// fails the grammar check instead of silently reading as its default.
/// 
/// Field naming convention: single for `T` or `Option<T>`, plural for `Vec<T>`
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
    pub solve: Option<i32>,
    #[serde(default)]
    pub unlocks: Vec<i32>,
    #[serde(default)]
    // Grant for access to resources. In most cases, try to use the `auto_grant` in an patch instead.
    pub grants: Vec<i32>,
    #[serde(default)]
    pub patches: Vec<i32>,
    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_keys() {
        let err = toml::from_str::<Answer>("answer = \"x\"\nsolve = 1").unwrap_err();
        assert!(err.to_string().contains("unknown field `solve`"), "{err}");      
        let err = toml::from_str::<Answer>("answer = \"x\"\nunlockes = [3,5]").unwrap_err();
        assert!(err.to_string().contains("unknown field `unlockes`"), "{err}");
    }
}
