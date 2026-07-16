use crate::model::Certificate;
use crate::{Error, Result};
use md5::Md5;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{DigestSigner, DigestVerifier, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

include!("key_generated.rs");

/// RSA signing key hidden behind a stable KindleTool-owned API.
#[derive(Clone)]
pub struct SigningKey {
    inner: RsaPrivateKey,
}

/// RSA public key used to verify Kindle SP01 signatures.
#[derive(Clone)]
pub struct VerificationKey {
    inner: RsaPublicKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKey")
            .field("bits", &self.inner.n().bits())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Load a PKCS#1 or PKCS#8 PEM private key.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
            .map_err(|error| Error::InvalidKey {
                message: error.to_string(),
            })?;
        Self::validated(key)
    }

    /// Load a private key from a PEM file.
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        let pem = fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    /// Return the public jailbreak signing key embedded by the original `KindleTool`.
    pub fn default_jailbreak() -> Result<Self> {
        let key = RsaPrivateKey::from_components(
            parse_hex_biguint(RSA_N)?,
            parse_hex_biguint(RSA_E)?,
            parse_hex_biguint(RSA_D)?,
            vec![parse_hex_biguint(RSA_P)?, parse_hex_biguint(RSA_Q)?],
        )
        .map_err(|error| Error::InvalidKey {
            message: error.to_string(),
        })?;
        Self::validated(key)
    }

    /// RSA modulus length in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.inner.size()
    }

    /// Return the public half of this signing key.
    #[must_use]
    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey {
            inner: RsaPublicKey::from(&self.inner),
        }
    }

    /// Ensure that this key matches the selected Kindle certificate slot.
    pub fn validate_certificate(&self, certificate: Certificate) -> Result<()> {
        if self.size() != certificate.signature_len() {
            return Err(Error::InvalidKey {
                message: format!(
                    "{}-byte key does not match certificate {} ({} bytes)",
                    self.size(),
                    certificate.raw(),
                    certificate.signature_len()
                ),
            });
        }
        Ok(())
    }

    /// Sign a seekable stream with RSA PKCS#1 v1.5 and SHA-256.
    pub fn sign<R: Read + Seek>(&self, reader: &mut R) -> Result<Vec<u8>> {
        reader.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        copy_into_digest(reader, &mut digest)?;
        reader.seek(SeekFrom::Start(0))?;
        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(self.inner.clone());
        let signature: pkcs1v15::Signature = signing_key.sign_digest(digest);
        let bytes = signature.to_vec();
        if bytes.len() != self.size() {
            return Err(Error::InvalidKey {
                message: format!(
                    "signature has {} bytes, expected {}",
                    bytes.len(),
                    self.size()
                ),
            });
        }
        Ok(bytes)
    }

    fn validated(mut key: RsaPrivateKey) -> Result<Self> {
        if !matches!(key.size(), 128 | 256) {
            return Err(Error::InvalidKey {
                message: format!(
                    "RSA key is {} bytes; KindleTool supports only 128 or 256",
                    key.size()
                ),
            });
        }
        key.validate().map_err(|error| Error::InvalidKey {
            message: error.to_string(),
        })?;
        key.precompute().map_err(|error| Error::InvalidKey {
            message: error.to_string(),
        })?;
        Ok(Self { inner: key })
    }
}

impl fmt::Debug for VerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationKey")
            .field("bits", &self.inner.n().bits())
            .finish_non_exhaustive()
    }
}

impl VerificationKey {
    /// Load a PKCS#1 or `SubjectPublicKeyInfo` PEM public key.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = RsaPublicKey::from_pkcs1_pem(pem)
            .or_else(|_| RsaPublicKey::from_public_key_pem(pem))
            .map_err(|error| Error::InvalidKey {
                message: error.to_string(),
            })?;
        if !matches!(key.size(), 128 | 256) {
            return Err(Error::InvalidKey {
                message: format!(
                    "RSA key is {} bytes; KindleTool supports only 128 or 256",
                    key.size()
                ),
            });
        }
        Ok(Self { inner: key })
    }

    /// Load a PKCS#1 or `SubjectPublicKeyInfo` PEM public key from a file.
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        let pem = fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    /// RSA modulus length in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub(crate) fn verify_reader<R: Read>(&self, mut reader: R, signature: &[u8]) -> Result<bool> {
        let mut digest = Sha256::new();
        copy_into_digest(&mut reader, &mut digest)?;
        let Ok(signature) = pkcs1v15::Signature::try_from(signature) else {
            return Ok(false);
        };
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(self.inner.clone());
        Ok(verifying_key.verify_digest(digest, &signature).is_ok())
    }
}

/// Calculate lowercase hexadecimal MD5 for a stream and rewind it.
pub fn md5_hex<R: Read + Seek>(reader: &mut R) -> Result<String> {
    reader.seek(SeekFrom::Start(0))?;
    let result = md5_hex_reader(&mut *reader)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(result)
}

pub(crate) fn md5_hex_reader<R: Read>(mut reader: R) -> Result<String> {
    let mut digest = Md5::new();
    copy_into_digest(&mut reader, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

/// Calculate lowercase hexadecimal SHA-256 for a stream and rewind it.
pub fn sha256_hex<R: Read + Seek>(reader: &mut R) -> Result<String> {
    reader.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    copy_into_digest(reader, &mut digest)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn copy_into_digest<R: Read, D: Digest>(reader: &mut R, digest: &mut D) -> Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        digest.update(&buffer[..count]);
    }
}

fn parse_hex_biguint(value: &str) -> Result<BigUint> {
    if value.len() % 2 != 0 {
        return Err(Error::InvalidKey {
            message: "odd-length embedded key component".to_owned(),
        });
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| Error::InvalidKey {
                message: error.to_string(),
            })?;
            u8::from_str_radix(text, 16).map_err(|error| Error::InvalidKey {
                message: error.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BigUint::from_bytes_be(&bytes))
}

#[cfg(test)]
mod tests {
    use super::SigningKey;
    use crate::model::Certificate;
    use rand::thread_rng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use std::io::Cursor;

    #[test]
    fn embedded_key_is_valid_and_deterministic() {
        let key = SigningKey::default_jailbreak().unwrap();
        key.validate_certificate(Certificate::Developer).unwrap();
        let first = key.sign(&mut Cursor::new(b"kindletool".to_vec())).unwrap();
        let second = key.sign(&mut Cursor::new(b"kindletool".to_vec())).unwrap();
        assert_eq!(first.len(), 128);
        assert_eq!(first, second);
    }

    #[test]
    fn external_2048_bit_pem_keys_match_production_certificate() {
        let rsa = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
        let pem = rsa.to_pkcs8_pem(LineEnding::LF).unwrap();
        let key = SigningKey::from_pem(pem.as_str()).unwrap();
        assert_eq!(key.size(), 256);
        key.validate_certificate(Certificate::Production2K).unwrap();
        assert!(key.validate_certificate(Certificate::Developer).is_err());
        let message = b"external key";
        let signature = key.sign(&mut Cursor::new(message)).unwrap();
        assert_eq!(signature.len(), 256);
        assert!(
            key.verification_key()
                .verify_reader(Cursor::new(message), &signature)
                .unwrap()
        );
        let pkcs1 = rsa.to_pkcs1_pem(LineEnding::LF).unwrap();
        assert_eq!(SigningKey::from_pem(pkcs1.as_str()).unwrap().size(), 256);
    }
}
