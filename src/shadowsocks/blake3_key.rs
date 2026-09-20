use super::shadowsocks_key::ShadowsocksKey;
use crate::util::allocate_vec;

#[derive(Debug, Clone)]
pub struct Blake3Key {
    key_bytes: Blake3KeyBytes,
    session_key_len: usize,
}

#[derive(Debug, Clone)]
enum Blake3KeyBytes {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
    Other(Box<[u8]>),
}

impl Blake3Key {
    pub fn new(key_bytes: Box<[u8]>, session_key_len: usize) -> Self {
        let key_bytes = match key_bytes.len() {
            16 => Blake3KeyBytes::Aes128(key_bytes.as_ref().try_into().unwrap()),
            32 => Blake3KeyBytes::Aes256(key_bytes.as_ref().try_into().unwrap()),
            _ => Blake3KeyBytes::Other(key_bytes),
        };
        Self {
            key_bytes,
            session_key_len,
        }
    }

    fn key_bytes(&self) -> &[u8] {
        match &self.key_bytes {
            Blake3KeyBytes::Aes128(key) => key,
            Blake3KeyBytes::Aes256(key) => key,
            Blake3KeyBytes::Other(key) => key,
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
    let mut subkey = allocate_vec(output_len);
    write_shadowsocks_2022_subkey(psk, salt, &mut subkey, context)?;
    Ok(subkey.into_boxed_slice())
}

/// Derive a subkey into caller-provided storage, so hot paths can use the
/// stack.
pub fn write_shadowsocks_2022_subkey(
    psk: &[u8],
    salt: &[u8],
    out: &mut [u8],
    context: &str,
) -> std::io::Result<()> {
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

    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(psk);
    hasher.update(salt);
    hasher.finalize_xof().fill(out);

    Ok(())
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
            self.key_bytes(),
            salt,
            self.session_key_len,
            SESSION_CONTEXT_STR,
        )
        .unwrap_or_else(|_| allocate_vec(self.session_key_len).into_boxed_slice())
    }

    fn write_session_key(&self, salt: &[u8], out: &mut [u8]) -> Option<usize> {
        let out = out.get_mut(..self.session_key_len)?;
        if write_shadowsocks_2022_subkey(self.key_bytes(), salt, out, SESSION_CONTEXT_STR).is_err()
        {
            out.fill(0);
        }
        Some(self.session_key_len)
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
