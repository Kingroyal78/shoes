//! Kcptun packet protection compatible with metacubex/kcp-go.
//!
//! The legacy algorithms are provided strictly for wire compatibility.  They
//! do not turn Kcptun into an authenticated protocol; Shadowsocks remains the
//! authenticated inner protocol.

use std::io;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use blowfish::Blowfish;
use cast5::Cast5;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};
use crc32fast::hash as crc32;
use des::TdesEde3;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use salsa20::Salsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use sha1::Sha1;
use twofish::Twofish;

use super::config::KcptunCrypt;

const NONCE_SIZE: usize = 16;
const CRC_SIZE: usize = 4;
const LEGACY_HEADER_SIZE: usize = NONCE_SIZE + CRC_SIZE;
const XOR_TABLE_SIZE: usize = 1500;
const INITIAL_VECTOR: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];

#[allow(clippy::large_enum_variant)]
pub(crate) enum PacketCrypt {
    Null,
    AesGcm(Aes128Gcm),
    Salsa([u8; 32]),
    Xor(Box<[u8; XOR_TABLE_SIZE]>),
    None,
    Block(BlockCipher),
}

impl PacketCrypt {
    pub fn new(kind: KcptunCrypt, password: &str) -> io::Result<Self> {
        let mut key = [0_u8; 32];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), b"kcp-go", 4096, &mut key);
        match kind {
            KcptunCrypt::Null => Ok(Self::Null),
            KcptunCrypt::Aes128Gcm => Aes128Gcm::new_from_slice(&key[..16])
                .map(Self::AesGcm)
                .map_err(|_| invalid("failed to initialise Kcptun AES-128-GCM")),
            KcptunCrypt::Salsa20 => Ok(Self::Salsa(key)),
            KcptunCrypt::Xor => {
                let mut table = Box::new([0_u8; XOR_TABLE_SIZE]);
                pbkdf2_hmac::<Sha1>(&key, b"sH3CIVoF#rWLtJo6", 32, table.as_mut_slice());
                Ok(Self::Xor(table))
            }
            KcptunCrypt::None => Ok(Self::None),
            KcptunCrypt::Aes => Ok(Self::Block(BlockCipher::Aes256(
                Aes256::new_from_slice(&key)
                    .map_err(|_| invalid("failed to initialise Kcptun AES-256"))?,
            ))),
            KcptunCrypt::Aes128 => Ok(Self::Block(BlockCipher::Aes128(
                Aes128::new_from_slice(&key[..16])
                    .map_err(|_| invalid("failed to initialise Kcptun AES-128"))?,
            ))),
            KcptunCrypt::Aes192 => Ok(Self::Block(BlockCipher::Aes192(
                Aes192::new_from_slice(&key[..24])
                    .map_err(|_| invalid("failed to initialise Kcptun AES-192"))?,
            ))),
            KcptunCrypt::Blowfish => Ok(Self::Block(BlockCipher::Blowfish(
                Blowfish::new_from_slice(&key)
                    .map_err(|_| invalid("failed to initialise Kcptun Blowfish"))?,
            ))),
            KcptunCrypt::Twofish => Ok(Self::Block(BlockCipher::Twofish(
                Twofish::new_from_slice(&key)
                    .map_err(|_| invalid("failed to initialise Kcptun Twofish"))?,
            ))),
            KcptunCrypt::Cast5 => Ok(Self::Block(BlockCipher::Cast5(
                Cast5::new_from_slice(&key[..16])
                    .map_err(|_| invalid("failed to initialise Kcptun CAST5"))?,
            ))),
            KcptunCrypt::TripleDes => Ok(Self::Block(BlockCipher::TripleDes(
                TdesEde3::new_from_slice(&key[..24])
                    .map_err(|_| invalid("failed to initialise Kcptun 3DES"))?,
            ))),
            KcptunCrypt::Tea => Ok(Self::Block(BlockCipher::Tea(Tea::new(&key[..16])?))),
            KcptunCrypt::Xtea => Ok(Self::Block(BlockCipher::Xtea(Xtea::new(&key[..16])?))),
        }
    }

    pub fn overhead(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::AesGcm(_) => 12 + 16,
            _ => LEGACY_HEADER_SIZE,
        }
    }

    pub fn seal(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Null => Ok(payload.to_vec()),
            Self::AesGcm(cipher) => {
                let mut nonce = [0_u8; 12];
                rand::rng().fill_bytes(&mut nonce);
                let nonce = Nonce::try_from(nonce.as_slice())
                    .map_err(|_| invalid("failed to construct Kcptun AES-GCM nonce"))?;
                let encrypted = cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| invalid_data("Kcptun AES-GCM encryption failed"))?;
                let mut packet = Vec::with_capacity(12 + encrypted.len());
                packet.extend_from_slice(nonce.as_slice());
                packet.extend_from_slice(&encrypted);
                Ok(packet)
            }
            _ => {
                let mut nonce = [0_u8; NONCE_SIZE];
                rand::rng().fill_bytes(&mut nonce);
                self.seal_legacy_with_nonce(payload, nonce)
            }
        }
    }

    pub fn open(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Null => Ok(packet.to_vec()),
            Self::AesGcm(cipher) => {
                if packet.len() < self.overhead() {
                    return Err(invalid_data("truncated Kcptun AES-GCM packet"));
                }
                let nonce = Nonce::try_from(&packet[..12])
                    .map_err(|_| invalid_data("invalid Kcptun AES-GCM nonce"))?;
                cipher
                    .decrypt(&nonce, &packet[12..])
                    .map_err(|_| invalid_data("invalid Kcptun AES-GCM packet"))
            }
            _ => {
                if packet.len() < LEGACY_HEADER_SIZE {
                    return Err(invalid_data("truncated Kcptun encrypted packet"));
                }
                let plaintext = match self {
                    Self::Salsa(key) => salsa_xor(key, packet)?,
                    Self::Xor(table) => xor_with_table(packet, table.as_slice()),
                    Self::None => packet.to_vec(),
                    Self::Block(block) => block.cfb_decrypt(packet),
                    Self::Null | Self::AesGcm(_) => unreachable!(),
                };
                let expected = u32::from_le_bytes(
                    plaintext[NONCE_SIZE..LEGACY_HEADER_SIZE]
                        .try_into()
                        .expect("fixed CRC slice"),
                );
                let payload = &plaintext[LEGACY_HEADER_SIZE..];
                if crc32(payload) != expected {
                    return Err(invalid_data("Kcptun packet checksum mismatch"));
                }
                Ok(payload.to_vec())
            }
        }
    }

    fn seal_legacy_with_nonce(
        &self,
        payload: &[u8],
        nonce: [u8; NONCE_SIZE],
    ) -> io::Result<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(LEGACY_HEADER_SIZE + payload.len());
        plaintext.extend_from_slice(&nonce);
        plaintext.extend_from_slice(&crc32(payload).to_le_bytes());
        plaintext.extend_from_slice(payload);
        match self {
            Self::Salsa(key) => salsa_xor(key, &plaintext),
            Self::Xor(table) => Ok(xor_with_table(&plaintext, table.as_slice())),
            Self::None => Ok(plaintext),
            Self::Block(block) => Ok(block.cfb_encrypt(&plaintext)),
            Self::Null | Self::AesGcm(_) => Err(invalid(
                "legacy Kcptun packet path used with a non-legacy crypt",
            )),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum BlockCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
    Blowfish(Blowfish),
    Twofish(Twofish),
    Cast5(Cast5),
    TripleDes(TdesEde3),
    Tea(Tea),
    Xtea(Xtea),
}

impl BlockCipher {
    fn block_size(&self) -> usize {
        match self {
            Self::Aes128(_) | Self::Aes192(_) | Self::Aes256(_) | Self::Twofish(_) => 16,
            Self::Blowfish(_)
            | Self::Cast5(_)
            | Self::TripleDes(_)
            | Self::Tea(_)
            | Self::Xtea(_) => 8,
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        match self {
            Self::Aes128(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::Aes192(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::Aes256(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::Blowfish(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::Twofish(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::Cast5(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::TripleDes(cipher) => {
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }
            Self::Tea(cipher) => cipher.encrypt_block(block),
            Self::Xtea(cipher) => cipher.encrypt_block(block),
        }
    }

    fn initial_feedback(&self) -> Vec<u8> {
        let mut feedback = INITIAL_VECTOR[..self.block_size()].to_vec();
        self.encrypt_block(&mut feedback);
        feedback
    }

    fn cfb_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let block_size = self.block_size();
        let mut feedback = self.initial_feedback();
        let mut output = Vec::with_capacity(plaintext.len());
        for chunk in plaintext.chunks(block_size) {
            let encrypted: Vec<u8> = chunk
                .iter()
                .zip(feedback.iter())
                .map(|(left, right)| left ^ right)
                .collect();
            output.extend_from_slice(&encrypted);
            if encrypted.len() == block_size {
                feedback.copy_from_slice(&encrypted);
                self.encrypt_block(&mut feedback);
            }
        }
        output
    }

    fn cfb_decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let block_size = self.block_size();
        let mut feedback = self.initial_feedback();
        let mut output = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks(block_size) {
            output.extend(
                chunk
                    .iter()
                    .zip(feedback.iter())
                    .map(|(left, right)| left ^ right),
            );
            if chunk.len() == block_size {
                feedback.copy_from_slice(chunk);
                self.encrypt_block(&mut feedback);
            }
        }
        output
    }
}

fn salsa_xor(key: &[u8; 32], input: &[u8]) -> io::Result<Vec<u8>> {
    if input.len() < 8 {
        return Err(invalid_data("truncated Kcptun Salsa20 packet"));
    }
    let mut output = input.to_vec();
    let mut cipher = Salsa20::new_from_slices(key, &input[..8])
        .map_err(|_| invalid("failed to initialise Kcptun Salsa20"))?;
    cipher.apply_keystream(&mut output[8..]);
    Ok(output)
}

fn xor_with_table(input: &[u8], table: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(table.iter().cycle())
        .map(|(left, right)| left ^ right)
        .collect()
}

pub(crate) struct Tea {
    key: [u32; 4],
}

impl Tea {
    fn new(key: &[u8]) -> io::Result<Self> {
        if key.len() != 16 {
            return Err(invalid("TEA key must be 16 bytes"));
        }
        Ok(Self {
            key: [
                u32::from_be_bytes(key[0..4].try_into().unwrap()),
                u32::from_be_bytes(key[4..8].try_into().unwrap()),
                u32::from_be_bytes(key[8..12].try_into().unwrap()),
                u32::from_be_bytes(key[12..16].try_into().unwrap()),
            ],
        })
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let mut v0 = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut v1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
        let mut sum = 0_u32;
        for _ in 0..8 {
            sum = sum.wrapping_add(0x9e37_79b9);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(self.key[0]))
                    ^ v1.wrapping_add(sum)
                    ^ ((v1 >> 5).wrapping_add(self.key[1])),
            );
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(self.key[2]))
                    ^ v0.wrapping_add(sum)
                    ^ ((v0 >> 5).wrapping_add(self.key[3])),
            );
        }
        block[..4].copy_from_slice(&v0.to_be_bytes());
        block[4..8].copy_from_slice(&v1.to_be_bytes());
    }
}

pub(crate) struct Xtea {
    table: [u32; 64],
}

impl Xtea {
    fn new(key: &[u8]) -> io::Result<Self> {
        if key.len() != 16 {
            return Err(invalid("XTEA key must be 16 bytes"));
        }
        let key = [
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        ];
        let mut table = [0_u32; 64];
        let mut sum = 0_u32;
        for round in (0..64).step_by(2) {
            table[round] = sum.wrapping_add(key[(sum & 3) as usize]);
            sum = sum.wrapping_add(0x9e37_79b9);
            table[round + 1] = sum.wrapping_add(key[((sum >> 11) & 3) as usize]);
        }
        Ok(Self { table })
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let mut v0 = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut v1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
        for round in (0..64).step_by(2) {
            v0 = v0.wrapping_add((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ self.table[round]);
            v1 =
                v1.wrapping_add((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ self.table[round + 1]);
        }
        block[..4].copy_from_slice(&v0.to_be_bytes());
        block[4..8].copy_from_slice(&v1.to_be_bytes());
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_panel_crypts_round_trip_and_reject_tampering() {
        let payload = b"kcp packet payload";
        for name in [
            "aes",
            "aes-128",
            "aes-192",
            "aes-128-gcm",
            "salsa20",
            "blowfish",
            "twofish",
            "cast5",
            "3des",
            "tea",
            "xtea",
            "xor",
            "none",
            "null",
        ] {
            let kind = KcptunCrypt::parse(name).unwrap();
            let crypt = PacketCrypt::new(kind, "test password").unwrap();
            let encrypted = crypt.seal(payload).unwrap();
            assert_eq!(crypt.open(&encrypted).unwrap(), payload, "{name}");

            if !matches!(kind, KcptunCrypt::Null) {
                let mut tampered = encrypted;
                let index = tampered.len() - 1;
                tampered[index] ^= 1;
                assert!(crypt.open(&tampered).is_err(), "{name}");
            }
        }
    }

    #[test]
    fn legacy_cipher_is_deterministic_for_fixed_nonce() {
        let crypt = PacketCrypt::new(KcptunCrypt::Aes128, "test password").unwrap();
        let packet = crypt
            .seal_legacy_with_nonce(b"payload", [0x11; NONCE_SIZE])
            .unwrap();
        assert_eq!(
            hex(&packet),
            "c3e347f39112eec99e3eff0e86a883f43f4461581c096824a77b14"
        );
        assert_eq!(crypt.open(&packet).unwrap(), b"payload");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
