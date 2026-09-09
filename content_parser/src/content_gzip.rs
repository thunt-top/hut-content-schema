use std::io::{Read, Write};

use blake3::{Hash, hash};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use sign_bound::PositiveI32;

use crate::resource::{DerivedKey, Encrypted};

pub fn gzip(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(input)
        .expect("Write to vec should not fail");
    encoder.finish().expect("Write to vec should not fail")
}

pub fn ungzip(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(input);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

pub struct PrepareToEncrypt {
    pub resource_id: PositiveI32,
    pub gz: Vec<u8>,
    pub digest: Hash,
}

impl PrepareToEncrypt {
    pub fn new(resource_id: PositiveI32, raw: &[u8]) -> Self {
        let gz = gzip(raw);
        Self {
            resource_id,
            gz,
            digest: hash(raw),
        }
    }

    pub fn encrypt(self, key: &DerivedKey) -> Encrypted {
        let (encrypted, derive_path) = key.encrypt(self.gz);
        let url_prefix = key.url_prefix(self.resource_id);
        Encrypted {
            encrypted,
            derive_path,
            url_prefix,
        }
    }
}
