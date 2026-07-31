// TLS hello parsing adapted from 3andne/restls (BSD-3-Clause), rewritten to
// reject truncation, duplicate security-sensitive extensions and trailing data.

use std::{collections::BTreeSet, io};

use super::record::{RECORD_HANDSHAKE, TlsRecord, invalid_data};

const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const TLS13: u16 = 0x0304;
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub const TLS12_GCM_CIPHER_SUITES: &[u16] = &[0xc02f, 0xc02b, 0xc030, 0xc02c];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    /// Concatenated `NamedGroup || key_exchange` values, matching Restls V1.
    pub key_shares: Vec<u8>,
    /// Concatenated PSK identities (without ticket ages or binders).
    pub psk_identities: Vec<u8>,
    pub session_ticket: Vec<u8>,
    pub supports_tls13: bool,
}

impl ClientHello {
    pub fn parse(record: &TlsRecord) -> io::Result<Self> {
        if record.content_type != RECORD_HANDSHAKE {
            return Err(invalid_data("ClientHello must be in a handshake record"));
        }
        if record.legacy_version != 0x0301 && record.legacy_version != 0x0303 {
            return Err(invalid_data("invalid ClientHello legacy record version"));
        }
        let message = only_handshake_message(record, HANDSHAKE_CLIENT_HELLO)?;
        let mut reader = Reader::new(message);

        let legacy_version = reader.u16()?;
        if legacy_version != 0x0303 {
            return Err(invalid_data("invalid ClientHello legacy_version"));
        }
        let client_random = reader.array_32()?;
        let session_id_bytes = reader.prefixed_u8()?;
        let session_id: [u8; 32] = session_id_bytes
            .try_into()
            .map_err(|_| invalid_data("Restls requires a 32-byte ClientHello session ID"))?;

        let cipher_suites = reader.prefixed_u16()?;
        if cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 {
            return Err(invalid_data("malformed ClientHello cipher suites"));
        }
        let compression = reader.prefixed_u8()?;
        if compression.is_empty() {
            return Err(invalid_data("ClientHello has no compression methods"));
        }
        let extensions = reader.prefixed_u16()?;
        reader.finish("trailing ClientHello bytes")?;

        let mut extension_reader = Reader::new(extensions);
        let mut seen = BTreeSet::new();
        let mut key_shares = Vec::new();
        let mut psk_identities = Vec::new();
        let mut session_ticket = Vec::new();
        let mut supports_tls13 = false;
        let mut saw_psk = false;

        while !extension_reader.is_empty() {
            if saw_psk {
                return Err(invalid_data(
                    "pre_shared_key must be the final ClientHello extension",
                ));
            }
            let extension_type = extension_reader.u16()?;
            let extension = extension_reader.prefixed_u16()?;
            if matches!(
                extension_type,
                EXT_SESSION_TICKET | EXT_PRE_SHARED_KEY | EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE
            ) && !seen.insert(extension_type)
            {
                return Err(invalid_data(
                    "duplicate security-sensitive ClientHello extension",
                ));
            }
            match extension_type {
                EXT_SESSION_TICKET => session_ticket.extend_from_slice(extension),
                EXT_SUPPORTED_VERSIONS => {
                    supports_tls13 = parse_supported_versions(extension)?;
                }
                EXT_KEY_SHARE => key_shares = parse_key_shares(extension)?,
                EXT_PRE_SHARED_KEY => {
                    psk_identities = parse_psk(extension)?;
                    saw_psk = true;
                }
                _ => {}
            }
        }
        if !supports_tls13 {
            return Err(invalid_data(
                "Restls ClientHello must advertise TLS 1.3 support",
            ));
        }

        Ok(Self {
            client_random,
            session_id,
            key_shares,
            psk_identities,
            session_ticket,
            supports_tls13,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    pub server_random: [u8; 32],
    pub cipher_suite: u16,
    pub is_tls13: bool,
    pub is_tls12_gcm: bool,
    pub key_share: Vec<u8>,
    pub selected_identity: Option<u16>,
}

impl ServerHello {
    pub fn parse(record: &TlsRecord) -> io::Result<Self> {
        if record.content_type != RECORD_HANDSHAKE {
            return Err(invalid_data("ServerHello must be in a handshake record"));
        }
        let mut messages = record.handshake_messages()?;
        let message = messages
            .next()
            .ok_or_else(|| invalid_data("empty ServerHello record"))??;
        if message.handshake_type != HANDSHAKE_SERVER_HELLO {
            return Err(invalid_data("first server handshake is not ServerHello"));
        }

        let mut reader = Reader::new(message.body);
        if reader.u16()? != 0x0303 {
            return Err(invalid_data("invalid ServerHello legacy_version"));
        }
        let server_random = reader.array_32()?;
        if server_random == HELLO_RETRY_REQUEST_RANDOM {
            return Err(invalid_data("Restls does not support HelloRetryRequest"));
        }
        let session_id = reader.prefixed_u8()?;
        if session_id.len() > 32 {
            return Err(invalid_data("oversized ServerHello session ID"));
        }
        let cipher_suite = reader.u16()?;
        if reader.u8()? != 0 {
            return Err(invalid_data("ServerHello selected non-null compression"));
        }
        let extensions = reader.prefixed_u16()?;
        reader.finish("trailing ServerHello bytes")?;

        let mut extension_reader = Reader::new(extensions);
        let mut seen = BTreeSet::new();
        let mut is_tls13 = false;
        let mut key_share = Vec::new();
        let mut selected_identity = None;
        while !extension_reader.is_empty() {
            let extension_type = extension_reader.u16()?;
            let extension = extension_reader.prefixed_u16()?;
            if matches!(
                extension_type,
                EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE | EXT_PRE_SHARED_KEY
            ) && !seen.insert(extension_type)
            {
                return Err(invalid_data("duplicate ServerHello extension"));
            }
            match extension_type {
                EXT_SUPPORTED_VERSIONS => {
                    if extension.len() != 2 {
                        return Err(invalid_data("malformed supported_versions extension"));
                    }
                    is_tls13 = u16::from_be_bytes([extension[0], extension[1]]) == TLS13;
                }
                EXT_KEY_SHARE => {
                    let mut share = Reader::new(extension);
                    let group = share.u16()?;
                    let exchange = share.prefixed_u16()?;
                    share.finish("trailing ServerHello key_share bytes")?;
                    key_share.extend_from_slice(&group.to_be_bytes());
                    key_share.extend_from_slice(exchange);
                }
                EXT_PRE_SHARED_KEY => {
                    let bytes: [u8; 2] = extension
                        .try_into()
                        .map_err(|_| invalid_data("malformed selected_identity extension"))?;
                    selected_identity = Some(u16::from_be_bytes(bytes));
                }
                _ => {}
            }
        }
        if selected_identity.is_some() && !is_tls13 {
            return Err(invalid_data(
                "selected_identity is only valid in a TLS 1.3 ServerHello",
            ));
        }

        Ok(Self {
            server_random,
            cipher_suite,
            is_tls13,
            is_tls12_gcm: TLS12_GCM_CIPHER_SUITES.contains(&cipher_suite),
            key_share,
            selected_identity,
        })
    }
}

fn only_handshake_message(record: &TlsRecord, expected: u8) -> io::Result<&[u8]> {
    let mut messages = record.handshake_messages()?;
    let first = messages
        .next()
        .ok_or_else(|| invalid_data("empty TLS handshake record"))??;
    if first.handshake_type != expected {
        return Err(invalid_data("unexpected TLS handshake message type"));
    }
    if messages.next().is_some() {
        return Err(invalid_data(
            "ClientHello record contains additional handshake messages",
        ));
    }
    Ok(first.body)
}

fn parse_supported_versions(extension: &[u8]) -> io::Result<bool> {
    let mut reader = Reader::new(extension);
    let versions = reader.prefixed_u8()?;
    reader.finish("trailing supported_versions bytes")?;
    if versions.is_empty() || versions.len() % 2 != 0 {
        return Err(invalid_data("malformed supported_versions list"));
    }
    Ok(versions
        .chunks_exact(2)
        .any(|version| u16::from_be_bytes([version[0], version[1]]) == TLS13))
}

fn parse_key_shares(extension: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = Reader::new(extension);
    let shares = reader.prefixed_u16()?;
    reader.finish("trailing key_share extension bytes")?;
    let mut shares_reader = Reader::new(shares);
    let mut output = Vec::with_capacity(shares.len());
    while !shares_reader.is_empty() {
        let group = shares_reader.u16()?;
        let exchange = shares_reader.prefixed_u16()?;
        if exchange.is_empty() {
            return Err(invalid_data("empty ClientHello key share"));
        }
        output.extend_from_slice(&group.to_be_bytes());
        output.extend_from_slice(exchange);
    }
    if output.is_empty() {
        return Err(invalid_data("ClientHello has no key shares"));
    }
    Ok(output)
}

fn parse_psk(extension: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = Reader::new(extension);
    let identities = reader.prefixed_u16()?;
    let mut identities_reader = Reader::new(identities);
    let mut output = Vec::new();
    let mut identity_count = 0usize;
    while !identities_reader.is_empty() {
        let identity = identities_reader.prefixed_u16()?;
        if identity.is_empty() {
            return Err(invalid_data("empty PSK identity"));
        }
        output.extend_from_slice(identity);
        identities_reader.take(4)?;
        identity_count += 1;
    }
    if output.is_empty() {
        return Err(invalid_data("pre_shared_key has no identities"));
    }

    let binders = reader.prefixed_u16()?;
    reader.finish("trailing pre_shared_key bytes")?;
    let mut binder_reader = Reader::new(binders);
    let mut binder_count = 0usize;
    while !binder_reader.is_empty() {
        if binder_reader.prefixed_u8()?.is_empty() {
            return Err(invalid_data("empty PSK binder"));
        }
        binder_count += 1;
    }
    if binder_count == 0 {
        return Err(invalid_data("pre_shared_key has no binders"));
    }
    if binder_count != identity_count {
        return Err(invalid_data(
            "pre_shared_key identity and binder counts differ",
        ));
    }
    Ok(output)
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| invalid_data("truncated TLS structure"))?;
        let output = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(output)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn array_32(&mut self) -> io::Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| invalid_data("truncated 32-byte TLS field"))
    }

    fn prefixed_u8(&mut self) -> io::Result<&'a [u8]> {
        let length = self.u8()? as usize;
        self.take(length)
    }

    fn prefixed_u16(&mut self) -> io::Result<&'a [u8]> {
        let length = self.u16()? as usize;
        self.take(length)
    }

    fn finish(&self, message: &'static str) -> io::Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(invalid_data(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(extension_bytes: &[u8], session_id: [u8; 32]) -> TlsRecord {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(extension_bytes);
        let mut payload = vec![1, 0, 0, body.len() as u8];
        payload.extend_from_slice(&body);
        TlsRecord::new(RECORD_HANDSHAKE, 0x0301, payload).unwrap()
    }

    fn extension(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&kind.to_be_bytes());
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
        output
    }

    #[test]
    fn parses_tls13_client_auth_material() {
        let mut extensions = extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]);
        extensions.extend_from_slice(&extension(EXT_KEY_SHARE, &[0, 7, 0, 29, 0, 3, 1, 2, 3]));
        let parsed = ClientHello::parse(&client_hello(&extensions, [9; 32])).unwrap();
        assert_eq!(parsed.key_shares, [0, 29, 1, 2, 3]);
        assert!(parsed.supports_tls13);
    }

    #[test]
    fn duplicate_and_truncated_extensions_are_rejected() {
        let one = extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]);
        let mut duplicate = one.clone();
        duplicate.extend_from_slice(&one);
        assert!(ClientHello::parse(&client_hello(&duplicate, [0; 32])).is_err());

        let malformed = extension(EXT_SUPPORTED_VERSIONS, &[3, 3, 4]);
        assert!(ClientHello::parse(&client_hello(&malformed, [0; 32])).is_err());
    }

    #[test]
    fn fragmented_client_hello_messages_are_rejected_explicitly() {
        let mut record = client_hello(&extension(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]), [0; 32]);
        record.payload[3] = record.payload[3].saturating_add(1);
        assert!(ClientHello::parse(&record).is_err());
    }
}
