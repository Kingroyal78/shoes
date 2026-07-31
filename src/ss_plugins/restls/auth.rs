// Restls authentication algorithm derived from 3andne/restls (BSD-3-Clause).

use std::io;

use subtle::ConstantTimeEq;

use super::{
    hello::{ClientHello, ServerHello},
    record::{RECORD_HANDSHAKE, TlsRecord, invalid_data},
};

const HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 16;
const HANDSHAKE_AUTH_LEN: usize = 16;
const TLS12_TICKET_OFFSET: usize = 24;
const TLS12_TICKET_AUTH_LEN: usize = 8;
const TLS12_LAYOUT_WITHOUT_TICKET: &[usize] = &[0, 11, 22, 32];
const TLS12_LAYOUT_WITH_TICKET: &[usize] = &[0, 8, 16, 24, 32];

#[derive(Clone)]
pub struct RestlsKey([u8; 32]);

impl std::fmt::Debug for RestlsKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RestlsKey([REDACTED])")
    }
}

impl RestlsKey {
    pub fn derive(password: impl AsRef<[u8]>) -> io::Result<Self> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restls password must not be empty",
            ));
        }
        Ok(Self(blake3::derive_key("restls-traffic-key", password)))
    }

    pub(crate) fn hasher(&self) -> blake3::Hasher {
        blake3::Hasher::new_keyed(&self.0)
    }

    pub fn verify_tls13_client_hello(&self, hello: &ClientHello) -> io::Result<()> {
        let mut hasher = self.hasher();
        hasher.update(&hello.key_shares);
        hasher.update(&hello.psk_identities);
        let digest = hasher.finalize();
        if bool::from(
            hello.session_id[..HANDSHAKE_AUTH_LEN].ct_eq(&digest.as_bytes()[..HANDSHAKE_AUTH_LEN]),
        ) {
            Ok(())
        } else {
            Err(invalid_data(
                "Restls TLS 1.3 ClientHello authentication failed",
            ))
        }
    }

    pub fn verify_tls12_session_ticket(&self, hello: &ClientHello) -> io::Result<()> {
        if hello.session_ticket.is_empty() {
            return Err(invalid_data(
                "Restls TLS 1.2 resumption has no session ticket",
            ));
        }
        let mut hasher = self.hasher();
        hasher.update(&hello.session_ticket);
        let digest = hasher.finalize();
        if bool::from(
            hello.session_id[TLS12_TICKET_OFFSET..]
                .ct_eq(&digest.as_bytes()[..TLS12_TICKET_AUTH_LEN]),
        ) {
            Ok(())
        } else {
            Err(invalid_data(
                "Restls TLS 1.2 session ticket authentication failed",
            ))
        }
    }

    pub fn verify_tls12_client_key_exchange(
        &self,
        hello: &ClientHello,
        curve_id: u16,
        record: &TlsRecord,
    ) -> io::Result<()> {
        if record.content_type != RECORD_HANDSHAKE {
            return Err(invalid_data(
                "ClientKeyExchange must be in a TLS handshake record",
            ));
        }
        let mut messages = record.handshake_messages()?;
        let message = messages
            .next()
            .ok_or_else(|| invalid_data("empty ClientKeyExchange record"))??;
        if message.handshake_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
            return Err(invalid_data("expected ClientKeyExchange"));
        }
        if messages.next().is_some() {
            return Err(invalid_data(
                "ClientKeyExchange record contains trailing handshake messages",
            ));
        }
        let (&public_key_len, public_key) = message
            .body
            .split_first()
            .ok_or_else(|| invalid_data("empty ECDHE ClientKeyExchange"))?;
        if public_key_len as usize != public_key.len() || public_key.is_empty() {
            return Err(invalid_data("malformed ECDHE ClientKeyExchange public key"));
        }

        let curve_index = match curve_id {
            29 => 0, // X25519
            23 => 1, // secp256r1
            24 => 2, // secp384r1
            _ => return Err(invalid_data("unsupported Restls TLS 1.2 ECDHE curve")),
        };
        let mut hasher = self.hasher();
        hasher.update(public_key);
        let digest = hasher.finalize();
        let layout = if hello.session_ticket.is_empty() {
            TLS12_LAYOUT_WITHOUT_TICKET
        } else {
            TLS12_LAYOUT_WITH_TICKET
        };
        let expected = &digest.as_bytes()[..layout[curve_index + 1] - layout[curve_index]];
        let actual = &hello.session_id[layout[curve_index]..layout[curve_index + 1]];
        if bool::from(actual.ct_eq(expected)) {
            Ok(())
        } else {
            Err(invalid_data(
                "Restls TLS 1.2 ClientKeyExchange authentication failed",
            ))
        }
    }

    /// Applies Restls server authentication to the first encrypted handshake
    /// record after server CCS. Returns whether subsequent server records must
    /// mimic TLS 1.2 AES-GCM explicit nonces.
    pub fn apply_server_auth(
        &self,
        server_hello: &ServerHello,
        record: &mut TlsRecord,
    ) -> io::Result<bool> {
        let mut offset = 0usize;
        let mut parrot_tls12_gcm = false;
        if server_hello.is_tls12_gcm && record.payload.len() >= 8 {
            let nonce = u64::from_be_bytes(
                record.payload[..8]
                    .try_into()
                    .map_err(|_| invalid_data("truncated TLS 1.2 GCM nonce"))?,
            );
            if nonce == 0 {
                offset = 8;
                parrot_tls12_gcm = true;
            }
        }
        if record.payload.len().saturating_sub(offset) < HANDSHAKE_AUTH_LEN {
            return Err(invalid_data(
                "server authentication record is shorter than 16 bytes",
            ));
        }

        let mut hasher = self.hasher();
        hasher.update(&server_hello.server_random);
        let digest = hasher.finalize();
        for (byte, mask) in record.payload[offset..offset + HANDSHAKE_AUTH_LEN]
            .iter_mut()
            .zip(&digest.as_bytes()[..HANDSHAKE_AUTH_LEN])
        {
            *byte ^= *mask;
        }
        Ok(parrot_tls12_gcm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(session_id: [u8; 32], key_shares: Vec<u8>, ticket: Vec<u8>) -> ClientHello {
        ClientHello {
            client_random: [0; 32],
            session_id,
            key_shares,
            psk_identities: Vec::new(),
            session_ticket: ticket,
            supports_tls13: true,
        }
    }

    #[test]
    fn tls13_authentication_detects_tampering() {
        let key = RestlsKey::derive("password").unwrap();
        let shares = vec![0, 29, 1, 2, 3];
        let mut hasher = key.hasher();
        hasher.update(&shares);
        let mut session_id = [7u8; 32];
        session_id[..16].copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        let valid = hello(session_id, shares.clone(), vec![]);
        key.verify_tls13_client_hello(&valid).unwrap();

        let mut tampered = valid;
        tampered.key_shares[2] ^= 1;
        assert!(key.verify_tls13_client_hello(&tampered).is_err());
    }

    #[test]
    fn tls12_cke_authentication_is_curve_layout_aware() {
        let key = RestlsKey::derive("password").unwrap();
        let public_key = [3u8; 32];
        let mut hasher = key.hasher();
        hasher.update(&public_key);
        let mut session_id = [0u8; 32];
        session_id[..11].copy_from_slice(&hasher.finalize().as_bytes()[..11]);
        let hello = hello(session_id, vec![], vec![]);

        let mut payload = vec![HANDSHAKE_CLIENT_KEY_EXCHANGE, 0, 0, 33, 32];
        payload.extend_from_slice(&public_key);
        let record = TlsRecord::new(RECORD_HANDSHAKE, 0x0303, payload).unwrap();
        key.verify_tls12_client_key_exchange(&hello, 29, &record)
            .unwrap();

        let mut tampered = record.clone();
        *tampered.payload.last_mut().unwrap() ^= 1;
        assert!(
            key.verify_tls12_client_key_exchange(&hello, 29, &tampered)
                .is_err()
        );
    }

    #[test]
    fn server_auth_is_reversible_and_rejects_short_records() {
        let key = RestlsKey::derive("password").unwrap();
        let hello = ServerHello {
            server_random: [4; 32],
            cipher_suite: 0x1301,
            is_tls13: true,
            is_tls12_gcm: false,
            key_share: vec![],
            selected_identity: None,
        };
        let mut record = TlsRecord::new(
            super::super::record::RECORD_APPLICATION_DATA,
            0x0303,
            vec![9; 32],
        )
        .unwrap();
        let original = record.clone();
        key.apply_server_auth(&hello, &mut record).unwrap();
        assert_ne!(record, original);
        key.apply_server_auth(&hello, &mut record).unwrap();
        assert_eq!(record, original);

        let mut short = TlsRecord::new(
            super::super::record::RECORD_APPLICATION_DATA,
            0x0303,
            vec![0; 15],
        )
        .unwrap();
        assert!(key.apply_server_auth(&hello, &mut short).is_err());
    }

    #[test]
    fn derived_key_debug_output_is_redacted() {
        let key = RestlsKey::derive("do-not-log-this").unwrap();
        assert_eq!(format!("{key:?}"), "RestlsKey([REDACTED])");
        assert!(!format!("{key:?}").contains("do-not-log-this"));
    }
}
