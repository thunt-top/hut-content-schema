//! Looks up the backend-assigned `version` for a resource's content.
//!
//! A resource's `version` is allocated by the backend the first time
//! `(resource_id, scope_id, digest)` is submitted (see
//! `API_doc/Admin/resource_metadata.md` § Update) — this crate never invents
//! one locally. [`VersionRegistry`] is the seam a resource's `build()` calls
//! through to get that number, so the crypto/manifest code here never has to
//! know whether it's actually talking to the backend (see
//! `AdminVersionRegistry` in the `hut_content` binary crate) or to a
//! [`MockVersionRegistry`] (e.g. `content_parser`'s own no-network demo).

use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;

use derive_getters::Getters;

use crate::resource::ResourceId;
use crate::scope::ScopeId;

#[derive(Debug)]
pub struct VersionRegistryError(pub String);

impl std::fmt::Display for VersionRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "version registry error: {}", self.0)
    }
}

impl std::error::Error for VersionRegistryError {}

/// An idempotent `(resource_id, scope_id, digest) -> version` map, backed by
/// whatever actually assigns versions (the real backend, or a fake for
/// tests/demos). Idempotent: looking up the same `(resource_id, scope_id,
/// digest)` twice must return the same `version` both times.
pub trait VersionRegistry {
    fn version_for(
        &mut self,
        resource_id: ResourceId,
        scope_id: ScopeId,
        digest: blake3::Hash,
    ) -> impl Future<Output = Result<ResourceRegistration, VersionRegistryError>> + Send;
}

#[derive(Getters)]
pub struct ResourceRegistration {
    resource_id: ResourceId,
    scope_id: ScopeId,
    digest: blake3::Hash,
    version: i64,
    confirmed: bool,
}

impl ResourceRegistration {
    pub fn new(
        resource_id: ResourceId,
        scope_id: ScopeId,
        digest: blake3::Hash,
        version: i64,
        confirmed: bool,
    ) -> Self {
        Self {
            resource_id,
            scope_id,
            digest,
            version,
            confirmed,
        }
    }
}

impl Display for ResourceRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digest_text = self.digest.to_hex();
        let (prefix, _) = digest_text.split_at(16);
        f.write_fmt(format_args!(
            "{:03}/{:05}_{:05} {} confirmed=[{}]",
            self.scope_id(),
            self.resource_id(),
            self.version(),
            prefix,
            self.confirmed()
        ))
    }
}

/// An in-memory [`VersionRegistry`] that never touches the network: the first
/// time a `(resource_id, digest)` pair is seen it's handed the next
/// never-reused version number, matching the real backend's "globally
/// unique, strictly increasing in allocation order" contract closely enough
/// for local dry runs and tests.
#[derive(Default)]
pub struct MockVersionRegistry {
    versions: HashMap<(i32, blake3::Hash), i64>,
    next_version: i64,
}

impl MockVersionRegistry {
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
            next_version: 1,
        }
    }
}

impl VersionRegistry for MockVersionRegistry {
    async fn version_for(
        &mut self,
        resource_id: ResourceId,
        scope_id: ScopeId,
        digest: blake3::Hash,
    ) -> Result<ResourceRegistration, VersionRegistryError> {
        let key = (i32::from(resource_id), digest);
        let version = self.versions.get(&key).cloned().unwrap_or_else(|| {
            let version = self.next_version;
            self.next_version += 1;
            version
        });
        self.versions.insert(key, version);
        Ok(ResourceRegistration {
            resource_id,
            scope_id,
            digest,
            version,
            confirmed: false,
        })
    }
}
