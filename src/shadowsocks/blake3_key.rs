use super::shadowsocks_key::ShadowsocksKey;
use crate::util::allocate_vec;

#[derive(Debug, Clone)]
pub struct Blake3Key {
    key_bytes: Box<[u8]>,
    session_key_len: usize,
}

impl Blake3Key {
    pub fn new(key_bytes: Box<[u8]>, session_key_len: usize) -> Self {
        Self {
            key_bytes,
            session_key_len,
        }
    }
}

const SESSION_CONTEXT_STR: &str = "shadowsocks 2022 session subkey";
const IDENTITY_CONTEXT_STR: &str = "shadowsocks 2022 identity subkey";
pub const AEAD2022_USER_HASH_LEN: usize = 16;

pub fn create_shadowsocks_2022_subkey(
    psk: &[u8],
    salt: &[u8],
    output_len: usize,
    context: &str,
) -> std::io::Result<Box<[u8]>> {
    if psk.len() != salt.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "shadowsocks 2022 key/salt length mismatch: key={}, salt={}",
                psk.len(),
                salt.len()
            ),
        ));
    }

    let mut key_material = allocate_vec(psk.len() + salt.len());
    key_material[0..psk.len()].copy_from_slice(psk);
    key_material[psk.len()..].copy_from_slice(salt);

    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&key_material);
    let mut output_reader = hasher.finalize_xof();

    let mut subkey = allocate_vec(output_len);
    output_reader.fill(&mut subkey);

    Ok(subkey.into_boxed_slice())
}

pub fn create_shadowsocks_2022_identity_subkey(
    server_psk: &[u8],
    request_salt: &[u8],
) -> std::io::Result<Box<[u8]>> {
    create_shadowsocks_2022_subkey(
        server_psk,
        request_salt,
        request_salt.len(),
        IDENTITY_CONTEXT_STR,
    )
}

pub fn shadowsocks_2022_user_hash(user_psk: &[u8]) -> [u8; AEAD2022_USER_HASH_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(user_psk);
    let mut output_reader = hasher.finalize_xof();

    let mut hash = [0u8; AEAD2022_USER_HASH_LEN];
    output_reader.fill(&mut hash);
    hash
}

impl ShadowsocksKey for Blake3Key {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        create_shadowsocks_2022_subkey(
            &self.key_bytes,
            salt,
            self.session_key_len,
            SESSION_CONTEXT_STR,
        )
        .unwrap_or_else(|_| allocate_vec(self.session_key_len).into_boxed_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hash_uses_blake3_xof_prefix() {
        let psk = [7u8; 16];
        let hash = shadowsocks_2022_user_hash(&psk);

        let mut expected = [0u8; AEAD2022_USER_HASH_LEN];
        let mut reader = blake3::Hasher::new().update(&psk).finalize_xof();
        reader.fill(&mut expected);

        assert_eq!(hash, expected);
    }

    #[test]
    fn subkey_rejects_key_salt_length_mismatch() {
        let err = create_shadowsocks_2022_identity_subkey(&[1u8; 16], &[2u8; 32]).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
