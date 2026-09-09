use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::patch::PatchOp;

pub mod answer;
pub mod collect;
pub mod patch;

#[derive(Debug, Serialize, Deserialize)]
pub struct PuzzleBehavior {
    pub id: i32,
    pub title: String,
    pub base_resource: i32,
    #[serde(default)]
    pub init_grant: bool,
    #[serde(default)]
    pub patch: Vec<patch::Patch>,
    #[serde(default)]
    pub answer: Vec<answer::Answer>,
}

impl PuzzleBehavior {
    pub fn get_scope_id<T: From<i32>>(&self) -> T {
        T::from(self.id)
    }

    pub fn get_puzzle_id<T: From<i32>>(&self) -> T {
        T::from(self.id)
    }

    pub fn get_base_resource<T: From<i32>>(&self) -> T {
        T::from(self.base_resource)
    }

    pub fn load_patches(&self, patches: &BTreeSet<i32>) -> Vec<&PatchOp> {
        let mut result = vec![];
        for patch in self
            .patch
            .iter()
            .filter(|&patch| patches.contains(&patch.patch_id))
        {
            result.extend(patch.op.iter());
        }
        result
    }
}

/// The single file `behavior_parser`'s CLI generates during CI (one
/// `PuzzleBehavior` per `content.toml` found under the manifest root it's
/// pointed at) and the shape `hut-core` reads back at startup. Kept here
/// rather than duplicated on the `hut-core` side so generator and consumer
/// can never disagree about the schema.
#[derive(Debug, Serialize, Deserialize)]
pub struct BehaviorManifest {
    pub puzzle: Vec<PuzzleBehavior>,
}
