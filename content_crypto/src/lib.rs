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
