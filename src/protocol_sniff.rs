use crate::client_proxy_selector::SniffedProtocol;

pub(crate) fn sniff_tcp_protocol(data: &[u8]) -> Option<SniffedProtocol> {
    if data.starts_with(b"\x13BitTorrent protocol") {
        return Some(SniffedProtocol::Bittorrent);
    }
    if is_tls_client_hello(data) {
        return Some(SniffedProtocol::Tls);
    }
    if is_http_request(data) {
        return Some(SniffedProtocol::Http);
    }
    if data.starts_with(b"SSH-") {
        return Some(SniffedProtocol::Ssh);
    }
    None
}

pub(crate) fn sniff_udp_protocol(data: &[u8]) -> Option<SniffedProtocol> {
    if is_quic_initial(data) {
        return Some(SniffedProtocol::Quic);
    }
    None
}

fn is_http_request(data: &[u8]) -> bool {
    if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return true;
    }

    const METHODS: &[&[u8]] = &[
        b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE",
    ];
    METHODS.iter().any(|method| {
        data.len() > method.len()
            && &data[..method.len()] == *method
            && matches!(data[method.len()], b' ' | b'\t')
    })
}

fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04
}

fn is_quic_initial(data: &[u8]) -> bool {
    data.len() >= 6 && data[0] & 0xc0 == 0xc0 && data[0] & 0x30 == 0 && data[1..5] != [0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_tcp_http_request() {
        assert_eq!(
            sniff_tcp_protocol(b"GET /payload HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Some(SniffedProtocol::Http)
        );
        assert_eq!(
            sniff_tcp_protocol(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Some(SniffedProtocol::Http)
        );
    }

    #[test]
    fn sniff_tcp_tls_client_hello() {
        assert_eq!(
            sniff_tcp_protocol(&[0x16, 0x03, 0x01, 0x00, 0x80]),
            Some(SniffedProtocol::Tls)
        );
    }

    #[test]
    fn sniff_tcp_bittorrent_handshake() {
        assert_eq!(
            sniff_tcp_protocol(b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"),
            Some(SniffedProtocol::Bittorrent)
        );
    }

    #[test]
    fn sniff_tcp_ssh_banner() {
        assert_eq!(
            sniff_tcp_protocol(b"SSH-2.0-OpenSSH_9.8\r\n"),
            Some(SniffedProtocol::Ssh)
        );
    }

    #[test]
    fn sniff_udp_quic_initial() {
        assert_eq!(
            sniff_udp_protocol(&[0xc0, 0x00, 0x00, 0x00, 0x01, 0x08]),
            Some(SniffedProtocol::Quic)
        );
    }

    #[test]
    fn sniff_rejects_unknown_payloads() {
        assert_eq!(sniff_tcp_protocol(b"\x01\x02\x03"), None);
        assert_eq!(sniff_udp_protocol(b"\x40\x00\x00\x00\x01"), None);
    }
}
