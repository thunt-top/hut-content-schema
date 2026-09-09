use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    resource::{
        BuiltArtifact, BuiltResource, ContentResource, EncryptContext, Encrypted, Grant, Hint,
        HintResource, JsonResource, ResourceEncrypt, ResourceId,
    },
    scope::{
        ScopeId,
        config::{GrantConfig, resolve_content, resolve_json, to_resource_id},
    },
    version_registry::{ResourceRegistration, VersionRegistry, VersionRegistryError},
};

pub struct PuzzleScope {
    pub id: ScopeId,
    pub base_resource: ResourceId,
    pub title: String,
    pub contents: Vec<ContentResource>,
    pub data: Vec<JsonResource>,
    pub hints: Vec<HintResource>,
    pub base_manifest: BaseManifest,
}

/// TOML shape:
///
/// ```toml
/// id = 1
/// base_resource = 100
/// title = "Puzzle Title"
///
/// [[contents]]
/// grant = { independent = 101 }
/// content_file = "body.md"
///
/// [[data]]
/// grant = { inherit = 100 }
/// json = { hint_count = 2 }
///
/// [[hints]]
/// grant = { purchase = 102 }
/// title = "First hint"
/// [hints.answer]
/// grant = { independent = 103 }
/// content = "Look under the rug."
/// ```
///
/// See [`crate::scope::config`] for how `content`/`content_file` and
/// `json`/`json_file` are resolved.
#[derive(Deserialize)]
pub struct PuzzleScopeConfig {
    pub id: i32,
    pub base_resource: i32,
    pub title: String,
    #[serde(default)]
    pub contents: Vec<ContentEntryConfig>,
    #[serde(default)]
    pub data: Vec<JsonEntryConfig>,
    #[serde(default)]
    pub hints: Vec<HintEntryConfig>,
    #[serde(default)]
    pub base_manifest: BaseManifestConfig,
}

/// The named, ordered view of a scope's resources that `behavior_parser`'s
/// `patch`/`patchOp` mutate at runtime (`Insert`/`Hide`/`Replace` a named
/// entry) — `content_parser` only carries it through into the scope's base
/// resource JSON as initial state, it never interprets it.
///
/// TOML shape (one list of `[name, resource_id]` pairs per field, matching
/// the `contents`/`data`/`hints` fields above):
///
/// ```toml
/// [base_manifest]
/// content = [["content-a", 101]]
/// data = [["data-hint", 103]]
/// hint = [["hint-a", 105]]
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct BaseManifestConfig {
    #[serde(default)]
    pub content: Vec<(String, i32)>,
    #[serde(default)]
    pub data: Vec<(String, i32)>,
    #[serde(default)]
    pub hint: Vec<(String, i32)>,
}

impl BaseManifestConfig {
    fn resolve(&self) -> BaseManifest {
        BaseManifest {
            content: resolve_named_ids(&self.content),
            data: resolve_named_ids(&self.data),
            hint: resolve_named_ids(&self.hint),
        }
    }
}

fn resolve_named_ids(entries: &[(String, i32)]) -> Vec<(String, ResourceId)> {
    entries
        .iter()
        .map(|(name, id)| (name.clone(), to_resource_id(*id)))
        .collect()
}

#[derive(Debug, Default)]
pub struct BaseManifest {
    pub content: Vec<(String, ResourceId)>,
    pub data: Vec<(String, ResourceId)>,
    pub hint: Vec<(String, ResourceId)>,
}

#[derive(Deserialize)]
pub struct ContentEntryConfig {
    pub grant: GrantConfig,
    pub content: Option<String>,
    pub content_file: Option<PathBuf>,
}

impl ContentEntryConfig {
    fn resolve(&self, base_dir: &Path) -> ContentResource {
        ContentResource {
            grant: self.grant.resolve(),
            inner: resolve_content(&self.content, &self.content_file, base_dir),
        }
    }
}

#[derive(Deserialize)]
pub struct JsonEntryConfig {
    pub grant: GrantConfig,
    pub json: Option<toml::Value>,
    pub json_file: Option<PathBuf>,
}

impl JsonEntryConfig {
    fn resolve(&self, base_dir: &Path) -> JsonResource {
        JsonResource {
            grant: self.grant.resolve(),
            inner: resolve_json(&self.json, &self.json_file, base_dir),
        }
    }
}

#[derive(Deserialize)]
pub struct HintEntryConfig {
    pub grant: GrantConfig,
    pub title: String,
    pub answer: ContentEntryConfig,
}

impl HintEntryConfig {
    fn resolve(&self, base_dir: &Path) -> HintResource {
        HintResource {
            grant: self.grant.resolve(),
            inner: Hint {
                title: self.title.clone(),
                answer: self.answer.resolve(base_dir),
            },
        }
    }
}

impl PuzzleScopeConfig {
    /// Resolves file references and inline values against `base_dir`
    /// (typically the directory the config file lives in).
    pub fn resolve(&self, base_dir: &Path) -> PuzzleScope {
        PuzzleScope {
            id: to_resource_id(self.id),
            base_resource: to_resource_id(self.base_resource),
            title: self.title.clone(),
            contents: self.contents.iter().map(|c| c.resolve(base_dir)).collect(),
            data: self.data.iter().map(|d| d.resolve(base_dir)).collect(),
            hints: self.hints.iter().map(|h| h.resolve(base_dir)).collect(),
            base_manifest: self.base_manifest.resolve(),
        }
    }
}

impl PuzzleScope {
    pub fn from_toml_file(path: &Path) -> PuzzleScope {
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read scope config {path:?}: {e}"));
        let config: PuzzleScopeConfig = toml::from_str(&raw)
            .unwrap_or_else(|e| panic!("failed to parse scope config {path:?}: {e}"));
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        config.resolve(base_dir)
    }
}

/// Records `res_id` as seen, panicking if it was already claimed by an
/// earlier resource. Resource ids share one namespace across every grant
/// type (`independent`/`purchase`/`inherit`) and every field
/// (`contents`/`data`/`hints`, including hint answers) — the same numeric id
/// must never name two different pieces of content, since the backend's
/// admin API and this crate's key derivation both key purely off of it with
/// no other disambiguator.
/// Renders a `base_manifest` field's `(name, resource_id)` list as JSON
/// `[name, resource_id]` pairs, preserving declaration order since that
/// order is what `patchOp::Insert`/`Hide`/`Replace` operate against.
fn named_ids_json(entries: &[(String, ResourceId)]) -> Value {
    json!(
        entries
            .iter()
            .map(|(name, id)| json!([name, i32::from(*id)]))
            .collect::<Vec<_>>()
    )
}

fn claim_id(res_id: ResourceId, seen: &mut HashSet<ResourceId>) {
    if !seen.insert(res_id) {
        panic!(
            "duplicate resource id {res_id}: resource ids must be unique across the whole \
             manifest, regardless of grant type"
        );
    }
}

fn add(
    field: &'static str,
    built_resource: BuiltResource,
    inherit: &mut HashMap<&'static str, Vec<(ResourceId, Value)>>,
    built: &mut Vec<(ResourceRegistration, Encrypted)>,
    seen: &mut HashSet<ResourceId>,
) {
    let res_id = built_resource.resource_id();
    claim_id(res_id, seen);
    match built_resource.artifact {
        BuiltArtifact::Encrypted { reg, enc } => built.push((reg, enc)),
        BuiltArtifact::PlainText {
            resource_id: _,
            scope_id: _,
            content,
        } => inherit.entry(field).or_default().push((res_id, content)),
    }
    for child in built_resource.children {
        add(field, child, inherit, built, seen);
    }
}

pub async fn build<T: ResourceEncrypt, R: VersionRegistry + Send>(
    field: &'static str,
    resource: Vec<T>,
    ctx: &EncryptContext,
    registry: &mut R,
    inherit: &mut HashMap<&'static str, Vec<(ResourceId, Value)>>,
    built: &mut Vec<(ResourceRegistration, Encrypted)>,
    seen: &mut HashSet<ResourceId>,
) -> Result<(), VersionRegistryError> {
    for res in resource {
        let built_resource = res.build(ctx, registry).await?;
        add(field, built_resource, inherit, built, seen);
    }
    Ok(())
}

impl PuzzleScope {
    /// `base_key` is the root secret every resource key/path in this scope is
    /// derived from — the caller decides where it comes from (the real
    /// `BASE_KEY` env var via [`content_crypto::base_key`], a fixed
    /// constant for tests, or a random one for an offline syntax check),
    /// keeping this crate itself oblivious to *how* it was obtained.
    pub async fn build<R: VersionRegistry + Send>(
        self,
        base_key: [u8; 32],
        registry: &mut R,
        seen: &mut HashSet<ResourceId>,
    ) -> Result<Vec<(ResourceRegistration, Encrypted)>, VersionRegistryError> {
        let scope_ctx = EncryptContext::base(base_key, self.id).derive_ctx("Scope", self.id);

        let ctx = scope_ctx.derive_ctx("ScopeDerive", self.id);

        let mut inherit: HashMap<&'static str, Vec<(ResourceId, Value)>> = HashMap::new();
        let mut built: Vec<(ResourceRegistration, Encrypted)> = Vec::new();

        build(
            "context",
            self.contents,
            &ctx,
            registry,
            &mut inherit,
            &mut built,
            seen,
        )
        .await?;
        build(
            "data",
            self.data,
            &ctx,
            registry,
            &mut inherit,
            &mut built,
            seen,
        )
        .await?;
        build(
            "hint",
            self.hints,
            &ctx,
            registry,
            &mut inherit,
            &mut built,
            seen,
        )
        .await?;

        let mut inherit_json = serde_json::Map::new();
        for (field, inherited) in inherit {
            let inherited = inherited
                .into_iter()
                .map(|(id, value)| (id.to_string(), value));
            let field_json = serde_json::Map::from_iter(inherited);
            inherit_json.insert(field.to_string(), json!(field_json));
        }

        let scope_resource = JsonResource {
            grant: Grant::Independent(self.base_resource),
            inner: json!({
                "title": &self.title,
                "inherit": inherit_json,
                "base_manifest": {
                    "content": named_ids_json(&self.base_manifest.content),
                    "data": named_ids_json(&self.base_manifest.data),
                    "hint": named_ids_json(&self.base_manifest.hint),
                }
            }),
        };

        let ctx = scope_ctx.derive_ctx("ScopeInherit", self.id);
        let scope_base_resource = scope_resource.build(&ctx, registry).await?;

        let BuiltArtifact::Encrypted { reg, enc } = scope_base_resource.artifact else {
            unreachable!("Scope artifact should be encrypted")
        };
        claim_id(*reg.resource_id(), seen);
        built.push((reg, enc));

        Ok(built)
    }
}
