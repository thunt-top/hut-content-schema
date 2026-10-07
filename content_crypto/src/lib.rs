//!
//! The object path and the content key are both derived from the same
//! per-resource `secret`, via BLAKE3's keyed `derive_key` mode
//! (<https://github.com/BLAKE3-team/BLAKE3#derive_key-mode>), each under its
//! own hardcoded `CTX_*` context string below. BLAKE3 hashes a context under
//! a dedicated internal domain *before* it ever touches `secret`, so distinct
//! contexts can never collide into the same output the way two ad hoc HKDF
//! `info` labels could — as long as no two `CTX_*` constants below are ever
//! made equal, a public object path can never coincide with a key.
//!
//! Blob layout, as served by the CDN (`application/octet-stream`):
//!
//! ```text
//! "HU&T"       4 bytes   magic
//! nonce       12 bytes   random, fresh per encryption
//! ciphertext   N bytes
//! tag         16 bytes   AES-GCM tag, appended
//! ```
//!
//! This module has no opinion on *where* a caller's root secret material
//! comes from -- a `BASE_KEY` env var, this workspace's `THUNT_KEY_*`
//! keyring, or anything else. That's deliberate: it lets both the
//! `hut-content` publish CLI (which reads `BASE_KEY` directly) and
//! `hut-core`'s `/resource/get` (which reads it via
//! `hut_util::auth::get("PAGE")`) share this exact derivation without either
//! depending on how the other obtains its secret.

use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};

/// BLAKE3 `derive_key` contexts. Per upstream guidance these must be
/// hardcoded, globally unique, and never reused for a different purpose —
/// see the module docs.
const CTX_BASE: &str = "thunt.top 4724-07-18 resource base_key v1";
const CTX_KEY: &str = "thunt.top 4724-07-18 resource content_key v1";
const CTX_PATH: &str = "thunt.top 4724-07-18 resource url path v1";
const MAGIC: &[u8; 4] = b"HU&T";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PATH_BYTES: usize = 16; // 128 bits -> 26 base32 chars
/// RFC 4648 base32 alphabet, lowercased: object stores are often
/// case-insensitive about keys, so don't hand them base64.
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    TooShort {
        len: usize,
        min: usize,
    },
    BadMagic,
    /// Wrong secret, wrong version, or a corrupt blob — GCM can't tell you which.
    Decrypt,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len, min } => write!(f, "blob too short: {len} < {min}"),
            Self::BadMagic => write!(f, "bad magic: not a content blob"),
            Self::Decrypt => {
                write!(
                    f,
                    "decryption failed: wrong secret, wrong version, or corrupt blob"
                )
            }
        }
    }
}

impl std::error::Error for DecryptError {}

fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Length-prefixes `field` before appending it to `out`. Plain concatenation
/// of variable-length fields is ambiguous (`"ab"+"c"` vs `"a"+"bc"`); a
/// length prefix makes the split unambiguous even if `field` itself later
/// contains whatever byte a bare separator would have used.
fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Note that this is the prefix for the path. if this returns `<PREFIX>`, the url should be `<PREFIX>_<VERSION>`.
pub fn derive_url(secret: &[u8; 32], resource_id: i32) -> String {
    let mut material = Vec::with_capacity(secret.len() + 4);
    material.extend_from_slice(secret);
    material.extend_from_slice(&resource_id.to_be_bytes());

    let digest = blake3::derive_key(CTX_PATH, &material);
    base32(&digest[..PATH_BYTES])
}

pub fn derive_key(secret: &[u8; 32], tag: &str, id: i32) -> [u8; 32] {
    let mut material = Vec::with_capacity(secret.len() + 4 + tag.len() + 4);
    material.extend_from_slice(secret);
    push_len_prefixed(&mut material, tag.as_bytes());
    material.extend_from_slice(&id.to_be_bytes());

    blake3::derive_key(CTX_KEY, &material)
}

/// Domain-separates arbitrary caller-supplied `secret` material into this
/// module's root key. `secret`'s origin is entirely up to the caller (an env
/// var, a keyring lookup, ...) -- this function never reads one itself.
pub fn base_key(secret: impl AsRef<[u8]>) -> [u8; 32] {
    blake3::derive_key(CTX_BASE, secret.as_ref())
}

// ── The per-resource key chain ──────────────────────────────────────
//
// Every encrypted resource's key is derived from the root key in exactly
// three steps:
//
//   base_key --"Scope"(scope_id)--> --"ScopeDerive"/"ScopeInherit"(scope_id)-->
//     ScopeKey --"Indep"/"Purchase"(resource_id)--> resource key
//
// The publisher (`content_parser`) encrypts with it and `hut-core`
// re-derives it to hand out decipher keys, so both go through
// [`scope_key`] + [`resource_key`] rather than spelling the chain out
// themselves. The tags are part of every published blob's key: changing
// one (or the order) makes all existing content undecryptable.

const TAG_SCOPE: &str = "Scope";

/// Which of a scope's two key branches a resource hangs off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeBranch {
    /// The scope's own base resource.
    Inherit,
    /// Every other (content/data/hint) resource in the scope.
    Derive,
}

impl ScopeBranch {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Inherit => "ScopeInherit",
            Self::Derive => "ScopeDerive",
        }
    }
}

/// How a resource's own key is labelled -- one per kind of grant that has
/// a key of its own (an inherited resource has none; it's folded into its
/// parent's plaintext instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKeyKind {
    /// Granted on its own (e.g. unlocked by a patch or an answer).
    Independent,
    /// Granted by purchasing it.
    Purchase,
}

impl ResourceKeyKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Independent => "Indep",
            Self::Purchase => "Purchase",
        }
    }
}

/// A scope branch's key -- the first two steps of the chain. Only
/// [`scope_key`] makes one, and only [`resource_key`] takes one, so the
/// steps can't be skipped or reordered.
#[derive(Clone, Copy)]
pub struct ScopeKey([u8; 32]);

/// Steps 1-2 of the chain: `base_key` (see [`base_key`]) down to
/// `scope_id`'s `branch`. Returns the `(tag, id)` steps taken alongside
/// the key, for callers that record a resource's derivation path.
pub fn scope_key(
    base_key: &[u8; 32],
    scope_id: i32,
    branch: ScopeBranch,
) -> (ScopeKey, [(&'static str, i32); 2]) {
    let path = [(TAG_SCOPE, scope_id), (branch.tag(), scope_id)];
    let key = path
        .iter()
        .fold(*base_key, |key, (tag, id)| derive_key(&key, tag, *id));
    (ScopeKey(key), path)
}

/// Step 3 of the chain: the AES key of `resource_id`, under `scope_key`.
pub fn resource_key(scope_key: &ScopeKey, kind: ResourceKeyKind, resource_id: i32) -> [u8; 32] {
    derive_key(&scope_key.0, kind.tag(), resource_id)
}

/// Encrypt one version's plaintext. Gzip *before* calling this — ciphertext is
/// incompressible, so the CDN's own compression will do nothing for you.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::generate();

    let sealed = cipher
        .encrypt(&nonce, plaintext)
        .expect("GCM encryption failed");

    let mut blob = Vec::with_capacity(MAGIC.len() + NONCE_LEN + sealed.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed); // RustCrypto already appended the tag
    blob
}

/// Decrypt a blob fetched from the CDN.
///
/// A wrong key fails as loudly as a corrupt blob — that is the point of using
/// an AEAD here. Version skew surfaces as an error you can log, not as a
/// mangled puzzle page.
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, DecryptError> {
    const MIN: usize = MAGIC.len() + NONCE_LEN + TAG_LEN;
    if blob.len() < MIN {
        return Err(DecryptError::TooShort {
            len: blob.len(),
            min: MIN,
        });
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(DecryptError::BadMagic);
    }

    let nonce =
        Nonce::try_from(&blob[MAGIC.len()..MAGIC.len() + NONCE_LEN]).expect("nonce is 12 bytes");
    let sealed = &blob[MAGIC.len() + NONCE_LEN..]; // ciphertext || tag

    let cipher =
        Aes256Gcm::new(&Key::<Aes256Gcm>::try_from(key.as_slice()).expect("key is 32 bytes"));
    cipher
        .decrypt(&nonce, sealed)
        .map_err(|_| DecryptError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the chain's tags and order against plain `derive_key` calls:
    /// if this fails, every already-published blob just became
    /// undecryptable.
    #[test]
    fn key_chain_is_stable() {
        let base = base_key(b"key chain test secret");

        for (branch, branch_tag) in [
            (ScopeBranch::Derive, "ScopeDerive"),
            (ScopeBranch::Inherit, "ScopeInherit"),
        ] {
            for (kind, kind_tag) in [
                (ResourceKeyKind::Independent, "Indep"),
                (ResourceKeyKind::Purchase, "Purchase"),
            ] {
                let manual = derive_key(
                    &derive_key(&derive_key(&base, "Scope", 7), branch_tag, 7),
                    kind_tag,
                    42,
                );
                let (scope, path) = scope_key(&base, 7, branch);
                assert_eq!(resource_key(&scope, kind, 42), manual);
                assert_eq!(path, [("Scope", 7), (branch_tag, 7)]);
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Known-answer vectors: fixed inputs, outputs hard-coded. Unlike
    /// [`key_chain_is_stable`], which compares the chain against
    /// `derive_key` itself, this also pins `derive_key`, `base_key` and
    /// `derive_url` -- their `CTX_*` contexts and how their input bytes are
    /// laid out. If this fails, every already-published blob just became
    /// undecryptable (or unreachable, for a URL); fix the code, not the
    /// vectors.
    ///
    /// The values were cross-checked when added by deriving them by hand
    /// from the documented layout (`key || u32_be(tag.len) || tag ||
    /// i32_be(id)` under `CTX_KEY`, `key || i32_be(id)` under `CTX_PATH`)
    /// with the `blake3` crate directly.
    #[test]
    fn known_answers() {
        const SECRET: &[u8] = b"known-answer test secret";
        const SCOPE: i32 = 3;
        const RESOURCE: i32 = 1205;

        let base = base_key(SECRET);
        assert_eq!(
            hex(&base),
            "2909fd2aed65fbb8923023303b814d11cbb9784e0e9a4afd574a585c94418ed5"
        );

        let cases = [
            (
                ScopeBranch::Derive,
                ResourceKeyKind::Independent,
                "5785d9c97dfe19db90d55965c3fee36a189a57ab1f713e7488400ae8f19d2cdd",
                "r47ddeqblgyv7o423bvfjbrrpu",
            ),
            (
                ScopeBranch::Derive,
                ResourceKeyKind::Purchase,
                "303db7060cebd6278150218289e5bb9ecd65911c8cd40485d349d3cbd8ea8496",
                "jcqa5t4zziavwq2amwucgseula",
            ),
            (
                ScopeBranch::Inherit,
                ResourceKeyKind::Independent,
                "f2b18481bde1c852812fa6f0f9da7ee846e5f57acdef0147aacdd7309f046b92",
                "qojty53pzdlbmbyeqf7mndouei",
            ),
            (
                ScopeBranch::Inherit,
                ResourceKeyKind::Purchase,
                "a79a6306c722bff483424f87aaa5001f3f37e3c115ba70fcce7bbb0c54db1306",
                "mu2sgxydi4vzyxyh26jhymovqi",
            ),
        ];

        for (branch, kind, expected_key, expected_url) in cases {
            let (scope, _) = scope_key(&base, SCOPE, branch);
            let key = resource_key(&scope, kind, RESOURCE);
            assert_eq!(hex(&key), expected_key, "{branch:?} {kind:?}");
            assert_eq!(
                derive_url(&key, RESOURCE),
                expected_url,
                "{branch:?} {kind:?}"
            );
        }
    }
}
