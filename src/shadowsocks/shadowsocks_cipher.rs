// TODO: investigate using SIV variants for nonce reuse resistance
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305};

use super::aead_util::TAG_LEN;

#[derive(Debug, Clone, Copy)]
pub enum ShadowsocksAeadAlgorithm {
    AwsLc(&'static Algorithm),
    Aes192Gcm,
}

impl ShadowsocksAeadAlgorithm {
    pub fn key_len(&self) -> usize {
        match self {
            Self::AwsLc(algorithm) => algorithm.key_len(),
            Self::Aes192Gcm => 24,
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            Self::AwsLc(algorithm) => algorithm.tag_len(),
            Self::Aes192Gcm => TAG_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ShadowsocksCipher {
    algorithm: ShadowsocksAeadAlgorithm,
    salt_len: usize,
    name: &'static str,
}

impl ShadowsocksCipher {
    fn chacha20_ietf_poly1305() -> Self {
        Self::new(
            ShadowsocksAeadAlgorithm::AwsLc(&CHACHA20_POLY1305),
            32,
            "chacha20-ietf-poly1305",
        )
    }

    fn aes_256_gcm() -> Self {
        Self::new(
            ShadowsocksAeadAlgorithm::AwsLc(&AES_256_GCM),
            32,
            "aes-256-gcm",
        )
    }

    fn aes_192_gcm() -> Self {
        Self::new(ShadowsocksAeadAlgorithm::Aes192Gcm, 24, "aes-192-gcm")
    }

    fn aes_128_gcm() -> Self {
        Self::new(
            ShadowsocksAeadAlgorithm::AwsLc(&AES_128_GCM),
            16,
            "aes-128-gcm",
        )
    }

    fn new(algorithm: ShadowsocksAeadAlgorithm, salt_len: usize, name: &'static str) -> Self {
        if algorithm.tag_len() != TAG_LEN {
            panic!("Unexpected tag length: {}", algorithm.tag_len());
        }
        Self {
            algorithm,
            salt_len,
            name,
        }
    }

    pub fn algorithm(&self) -> ShadowsocksAeadAlgorithm {
        self.algorithm
    }

    pub fn salt_len(&self) -> usize {
        self.salt_len
    }

    pub fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl TryFrom<&str> for ShadowsocksCipher {
    type Error = std::io::Error;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        match name {
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => {
                Ok(ShadowsocksCipher::chacha20_ietf_poly1305())
            }
            "aes-256-gcm" => Ok(ShadowsocksCipher::aes_256_gcm()),
            "aes-192-gcm" => Ok(ShadowsocksCipher::aes_192_gcm()),
            "aes-128-gcm" => Ok(ShadowsocksCipher::aes_128_gcm()),
            _ => Err(std::io::Error::other(format!("Unknown cipher: {name}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2board_admin_legacy_aead_ciphers() {
        let cases = [
            ("aes-128-gcm", 16, 16),
            ("aes-192-gcm", 24, 24),
            ("aes-256-gcm", 32, 32),
            ("chacha20-ietf-poly1305", 32, 32),
        ];

        for (name, key_len, salt_len) in cases {
            let cipher: ShadowsocksCipher = name.try_into().unwrap();

            assert_eq!(cipher.name(), name);
            assert_eq!(cipher.key_len(), key_len);
            assert_eq!(cipher.salt_len(), salt_len);
        }
    }
}
