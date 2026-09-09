use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchDomain {
    Content,
    Data,
    Hint,
}

impl PatchDomain {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Data => "data",
            Self::Hint => "hint",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchOp {
    Hide(PatchDomain, String),
    Insert(PatchDomain, String, i32),
    Replace(PatchDomain, String, i32, i32),
}

impl PatchOp {
    pub fn get_resource_id(&self) -> Option<i64> {
        match self {
            Self::Hide(_, _) => None,
            Self::Insert(_, _, res) => Some(*res as i64),
            Self::Replace(_, _, _, new_res) => Some(*new_res as i64),
        }
    }

    pub fn build_with_version(
        &self,
        version: Option<i64>,
    ) -> Option<(&'static str, String, String)> {
        match (self, version) {
            (Self::Hide(domain, location), _) => (domain.as_str(), location.clone(), "hide".into()),
            (Self::Insert(domain, location, resource), Some(version)) => (
                domain.as_str(),
                location.clone(),
                format!("insert_{resource}v{version}"),
            ),
            (Self::Replace(domain, location, old, new), Some(version)) => (
                domain.as_str(),
                location.clone(),
                format!("replace_{old}_{new}v{version}"),
            ),
            _ => return None,
        }
        .into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub patch_id: i32,

    #[serde(default)]
    // Default to be `false`, which means that any change (applying patch and granting resource will be reset by a `GAME_START`)
    pub cross_version: bool,
    #[serde(default)]
    // Defualt to be `false`, which means that the access to resource refered in `Insert` or `Replace` will be granted automatically.
    // Note that, for a resrouce with child resources, the access to the resource is granted for the base resource only, which is the
    // expected behaviour for a Hint, where the title and metadata will be automatically granted, yet the answer to the hint is not.
    pub do_not_grant: bool,
    #[serde(default)]
    pub op: Vec<PatchOp>,
}
