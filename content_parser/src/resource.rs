use std::borrow::Cow;

use serde_json::{Value, json};
use sign_bound::PositiveI32;

use content_crypto::{derive_key, derive_url, encrypt};

use crate::{
    content_gzip::PrepareToEncrypt,
    resource::Grant::{Independent, Inherit, Purchase},
    scope::ScopeId,
    version_registry::{ResourceRegistration, VersionRegistry, VersionRegistryError},
};

pub type ResourceId = sign_bound::PositiveI32;

pub struct Encrypted {
    pub encrypted: Vec<u8>,
    pub derive_path: Vec<(&'static str, i32)>,
    pub url_prefix: String,
}

pub enum BuiltArtifact {
    Encrypted {
        reg: ResourceRegistration,
        enc: Encrypted,
    },
    PlainText {
        resource_id: ResourceId,
        scope_id: ScopeId,
        content: Value,
    },
}

impl BuiltArtifact {
    pub fn resource_id(&self) -> ResourceId {
        match self {
            Self::Encrypted { reg, enc: _ } => *reg.resource_id(),
            Self::PlainText {
                resource_id,
                scope_id: _,
                content: _,
            } => *resource_id,
        }
    }

    pub fn scope_id(&self) -> ScopeId {
        match self {
            Self::Encrypted { reg, enc: _ } => *reg.scope_id(),
            Self::PlainText {
                resource_id: _,
                scope_id,
                content: _,
            } => *scope_id,
        }
    }
}

pub struct BuiltResource {
    pub artifact: BuiltArtifact,
    pub children: Vec<BuiltResource>,
}

impl BuiltResource {
    pub fn resource_id(&self) -> ResourceId {
        self.artifact.resource_id()
    }
    pub fn scope_id(&self) -> ScopeId {
        self.artifact.scope_id()
    }
}

pub struct EncryptContext {
    derive_root: DerivedKey,
    pub scope_id: ScopeId,
}

impl EncryptContext {
    pub fn base(base: [u8; 32], scope_id: ScopeId) -> Self {
        Self {
            derive_root: DerivedKey::as_base(base),
            scope_id,
        }
    }

    pub fn derive(&self, tag: &'static str, resource_id: impl Into<i32>) -> DerivedKey {
        self.derive_root.derive(tag, resource_id.into())
    }

    pub fn derive_ctx(&self, tag: &'static str, resource_id: impl Into<i32>) -> Self {
        let new_root = self.derive(tag, resource_id);
        EncryptContext {
            derive_root: new_root,
            scope_id: self.scope_id,
        }
    }
}

pub struct Hint {
    pub title: String,
    pub answer: ContentResource,
}

#[derive(Clone, Debug)]
pub enum Grant {
    Inherit(ResourceId),
    Independent(ResourceId),
    Purchase(ResourceId),
}

pub struct DerivedKey {
    path: Vec<(&'static str, i32)>,
    key: [u8; 32],
}

impl DerivedKey {
    pub fn as_base(key: [u8; 32]) -> DerivedKey {
        DerivedKey { path: vec![], key }
    }
    pub fn derive(&self, tag: &'static str, id: i32) -> DerivedKey {
        let key = derive_key(&self.key, tag, id);
        let mut path = self.path.clone();
        path.push((tag, id));
        DerivedKey { path, key }
    }
    pub fn encrypt(&self, plaintext: impl AsRef<[u8]>) -> (Vec<u8>, Vec<(&'static str, i32)>) {
        (encrypt(&self.key, plaintext.as_ref()), self.path.clone())
    }
    pub fn url_prefix(&self, resource_id: impl Into<i32>) -> String {
        derive_url(&self.key, resource_id.into())
    }
}

impl Grant {
    fn derive_key(&self, ctx: &EncryptContext) -> Option<DerivedKey> {
        match self {
            Inherit(_) => return None,
            Independent(x) => ctx.derive("Indep", *x),
            Purchase(x) => ctx.derive("Purchase", *x),
        }
        .into()
    }

    pub fn get_resource_id(&self) -> PositiveI32 {
        match self {
            Independent(x) => *x,
            Inherit(x) => *x,
            Purchase(x) => *x,
        }
    }
}

pub struct Resource<T> {
    pub grant: Grant,
    pub inner: T,
}

pub type ContentResource = Resource<String>;
pub type JsonResource = Resource<Value>;
pub type HintResource = Resource<Hint>;

pub trait PlainResource {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
    fn to_json(self) -> Value;
}

impl PlainResource for String {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
    fn to_json(self) -> Value {
        json!(self)
    }
}

impl PlainResource for Value {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::Owned(self.to_string().into_bytes())
    }
    fn to_json(self) -> Value {
        self
    }
}

pub trait ResourceEncrypt {
    fn build<R: VersionRegistry + Send>(
        self,
        ctx: &EncryptContext,
        registry: &mut R,
    ) -> impl std::future::Future<Output = Result<BuiltResource, VersionRegistryError>> + Send;
}

/// Either encrypts `raw` under `grant`'s own key, or — for an `Inherit`
/// grant, which has none — wraps `inherited` as plaintext to fold into an
/// ancestor's payload instead. `raw` and `inherited` are independent views of
/// the same content (e.g. a `ContentResource`'s `raw` is plain HTML/text
/// while `inherited` is that text wrapped as a JSON string), so both are
/// taken as plain values rather than one being derived from the other; this
/// is the single place every [`ResourceEncrypt`] impl should go through
/// rather than re-deriving the encrypt-or-inherit branch itself.
async fn build_artifact<R: VersionRegistry + Send>(
    grant: &Grant,
    ctx: &EncryptContext,
    registry: &mut R,
    raw: &[u8],
    inherited: Value,
) -> Result<BuiltArtifact, VersionRegistryError> {
    let resource_id = grant.get_resource_id();
    Ok(match grant.derive_key(ctx) {
        Some(key) => {
            let content = PrepareToEncrypt::new(resource_id, raw);
            let reg = registry
                .version_for(resource_id, ctx.scope_id, content.digest)
                .await?;
            let enc = content.encrypt(&key);
            BuiltArtifact::Encrypted { reg, enc }
        }
        None => BuiltArtifact::PlainText {
            resource_id,
            scope_id: ctx.scope_id,
            content: inherited,
        },
    })
}

impl<T: PlainResource + Send> ResourceEncrypt for Resource<T> {
    async fn build<R: VersionRegistry + Send>(
        self,
        ctx: &EncryptContext,
        registry: &mut R,
    ) -> Result<BuiltResource, VersionRegistryError> {
        let raw = self.inner.as_bytes().into_owned();
        let artifact =
            build_artifact(&self.grant, ctx, registry, &raw, self.inner.to_json()).await?;
        Ok(BuiltResource {
            artifact,
            children: vec![],
        })
    }
}

impl ResourceEncrypt for HintResource {
    async fn build<R: VersionRegistry + Send>(
        self,
        ctx: &EncryptContext,
        registry: &mut R,
    ) -> Result<BuiltResource, VersionRegistryError> {
        let built_answer = self.inner.answer.build(ctx, registry).await?;

        let mut children = vec![];

        let answer = match built_answer.artifact {
            BuiltArtifact::Encrypted { enc: _, ref reg } => {
                let value = json!({
                    "resource_id": i32::from(*reg.resource_id()),
                    "version": reg.version()
                });
                children.push(built_answer);
                value
            }
            BuiltArtifact::PlainText {
                resource_id: _,
                scope_id: _,
                content,
            } => {
                assert_eq!(
                    built_answer.children.len(),
                    0,
                    "Answer for a resource should not have children"
                );
                content
            }
        };

        let meta_value = json!({
            "title": &self.inner.title,
            "answer": answer,
        });

        let raw = meta_value.to_string().into_bytes();
        let artifact = build_artifact(&self.grant, ctx, registry, &raw, meta_value).await?;

        Ok(BuiltResource { artifact, children })
    }
}
