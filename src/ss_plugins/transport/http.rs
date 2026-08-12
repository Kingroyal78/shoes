use std::collections::HashMap;
use std::io;

use memchr::memchr;

use tokio::io::AsyncReadExt;

use crate::async_stream::AsyncStream;

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    pub max_header_bytes: usize,
    pub max_line_bytes: usize,
    pub max_headers: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 32 * 1024,
            max_line_bytes: 8 * 1024,
            max_headers: 64,
        }
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub(super) headers: HashMap<String, Vec<String>>,
    pub raw_header: Vec<u8>,
    pub unparsed_data: Vec<u8>,
}

impl HttpRequest {
    pub async fn read(stream: &mut Box<dyn AsyncStream>, limits: HttpLimits) -> io::Result<Self> {
        if limits.max_header_bytes < 4 || limits.max_line_bytes == 0 || limits.max_headers == 0 {
            return invalid("invalid HTTP parser limits");
        }

        let mut data = Vec::with_capacity(limits.max_header_bytes.min(4096));
        let header = loop {
            if let Some(header) = find_header_end(&data) {
                break header;
            }
            if data.len() >= limits.max_header_bytes {
                return invalid("HTTP header exceeds configured byte limit");
            }
            let remaining = limits.max_header_bytes - data.len();
            let mut chunk = [0u8; 2048];
            let read_capacity = remaining.min(chunk.len());
            let read_len = stream.read(&mut chunk[..read_capacity]).await?;
            if read_len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF before complete HTTP header",
                ));
            }
            data.extend_from_slice(&chunk[..read_len]);
        };
        let header_end = header.end;
        let body_start = header.body_start;

        let header = &data[..header_end];
        let header = std::str::from_utf8(header)
            .map_err(|_| invalid_error("HTTP header is not valid UTF-8/ASCII"))?;
        let mut lines = header
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line));
        let request_line = lines
            .next()
            .ok_or_else(|| invalid_error("empty HTTP request"))?;
        if request_line.len() > limits.max_line_bytes {
            return invalid("HTTP request line exceeds configured limit");
        }
        let mut request_parts = request_line.split_ascii_whitespace();
        let method = request_parts.next().unwrap_or_default();
        let target = request_parts.next().unwrap_or_default();
        let version = request_parts.next().unwrap_or_default();
        if request_parts.next().is_some()
            || method.is_empty()
            || target.is_empty()
            || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        {
            return invalid("malformed HTTP request line");
        }
        if !method.as_bytes().iter().all(|byte| is_token(*byte)) {
            return invalid("HTTP method contains an invalid byte");
        }
        if target
            .as_bytes()
            .iter()
            .any(|byte| *byte <= 0x20 || *byte == 0x7f)
        {
            return invalid("HTTP request target contains an invalid byte");
        }

        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        let mut header_count = 0usize;
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.len() > limits.max_line_bytes {
                return invalid("HTTP header line exceeds configured limit");
            }
            if line.starts_with([' ', '\t']) {
                return invalid("obsolete folded HTTP headers are not accepted");
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid_error("malformed HTTP header line"))?;
            if name.is_empty() || !name.as_bytes().iter().all(|byte| is_token(*byte)) {
                return invalid("HTTP header name contains an invalid byte");
            }
            if value
                .as_bytes()
                .iter()
                .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
            {
                return invalid("HTTP header value contains a control byte");
            }
            header_count += 1;
            if header_count > limits.max_headers {
                return invalid("HTTP request has too many headers");
            }
            headers
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }

        Ok(Self {
            method: method.to_string(),
            target: target.to_string(),
            version: version.to_string(),
            headers,
            raw_header: data[..body_start].to_vec(),
            unparsed_data: data[body_start..].to_vec(),
        })
    }

    pub fn header(&self, name: &str) -> io::Result<Option<&str>> {
        let Some(values) = self.headers.get(&name.to_ascii_lowercase()) else {
            return Ok(None);
        };
        if values.len() != 1 {
            return invalid(format!("duplicate `{name}` HTTP header"));
        }
        Ok(values.first().map(String::as_str))
    }

    pub fn header_values(&self, name: &str) -> impl Iterator<Item = &str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .into_iter()
            .flatten()
            .map(String::as_str)
    }

    pub fn header_contains_token(&self, name: &str, expected: &str) -> bool {
        self.header_values(name).any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    }

    pub fn path(&self) -> &str {
        request_target_path(&self.target)
            .split_once('?')
            .map(|(path, _)| path)
            .unwrap_or_else(|| request_target_path(&self.target))
    }
}

pub fn normalize_path(path: impl Into<String>) -> String {
    let path = path.into();
    let path = path.trim();
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

pub(crate) fn host_matches_optional_port(actual: &str, expected: &str) -> bool {
    if actual.eq_ignore_ascii_case(expected) {
        return true;
    }

    // An explicitly configured port must match exactly. Bracketed IPv6
    // literals without a port are the one colon-containing form where an
    // optional port can be appended unambiguously.
    let may_append_port = if expected.starts_with('[') {
        expected.ends_with(']')
    } else {
        !expected.contains(':')
    };
    if !may_append_port {
        return false;
    }

    let Some(prefix) = actual.get(..expected.len()) else {
        return false;
    };
    let Some(port) = actual
        .get(expected.len()..)
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return false;
    };
    prefix.eq_ignore_ascii_case(expected)
        && !port.is_empty()
        && port.as_bytes().iter().all(u8::is_ascii_digit)
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn request_target_path(target: &str) -> &str {
    for prefix in ["http://", "https://"] {
        if let Some(rest) = target.strip_prefix(prefix) {
            return rest.find('/').map(|index| &rest[index..]).unwrap_or("/");
        }
    }
    target
}

/// Where the header block stops and the body begins.
struct HeaderEnd {
    /// Offset one past the last header byte, excluding its line ending.
    end: usize,
    /// Offset of the first body byte, past the blank line.
    body_start: usize,
}

/// Finds the blank line that ends the header block, accepting a bare LF as a
/// line ending as well as CRLF.
///
/// Clients in the field send bare LF, and every mainstream HTTP server accepts
/// it, so rejecting the request only locks those users out. Nothing here is
/// forwarded to another HTTP parser, so tolerating it desynchronizes nothing.
fn find_header_end(data: &[u8]) -> Option<HeaderEnd> {
    let mut search = 0usize;
    while let Some(offset) = memchr(b'\n', &data[search..]) {
        let line_feed = search + offset;
        let end = if line_feed > 0 && data[line_feed - 1] == b'\r' {
            line_feed - 1
        } else {
            line_feed
        };
        match data.get(line_feed + 1) {
            Some(b'\n') => {
                return Some(HeaderEnd {
                    end,
                    body_start: line_feed + 2,
                });
            }
            Some(b'\r') => match data.get(line_feed + 2) {
                Some(b'\n') => {
                    return Some(HeaderEnd {
                        end,
                        body_start: line_feed + 3,
                    });
                }
                // Not a blank line, or not enough bytes to tell yet.
                Some(_) => {}
                None => return None,
            },
            Some(_) => {}
            None => return None,
        }
        search = line_feed + 1;
    }
    None
}

fn is_token(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || byte.is_ascii_alphanumeric()
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;
    use crate::async_stream::{AsyncPing, AsyncStream};

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    async fn parse_fragmented(parts: &[&[u8]], limits: HttpLimits) -> io::Result<HttpRequest> {
        let (request, _) = parse_fragmented_with_stream(parts, limits).await?;
        Ok(request)
    }

    async fn parse_fragmented_with_stream(
        parts: &[&[u8]],
        limits: HttpLimits,
    ) -> io::Result<(HttpRequest, Box<dyn AsyncStream>)> {
        let (mut client, server) = tokio::io::duplex(65_536);
        let owned = parts.iter().map(|part| part.to_vec()).collect::<Vec<_>>();
        tokio::spawn(async move {
            for part in owned {
                client.write_all(&part).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut server: Box<dyn AsyncStream> = Box::new(TestStream(server));
        let request = HttpRequest::read(&mut server, limits).await?;
        Ok((request, server))
    }

    #[tokio::test]
    async fn parses_every_byte_fragmented_and_preserves_payload() {
        let request = b"GET /ws?ed=4 HTTP/1.1\r\nHost: Example.COM\r\nConnection: keep-alive, Upgrade\r\n\r\npayload\nrest";
        let parts = request.iter().map(std::slice::from_ref).collect::<Vec<_>>();
        let (parsed, mut stream) = parse_fragmented_with_stream(&parts, HttpLimits::default())
            .await
            .unwrap();
        assert_eq!(parsed.path(), "/ws");
        assert_eq!(parsed.header("host").unwrap(), Some("Example.COM"));
        assert!(parsed.header_contains_token("connection", "upgrade"));
        let mut payload = parsed.unparsed_data;
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"payload\nrest");
    }

    #[tokio::test]
    async fn does_not_validate_read_ahead_payload_as_http_header() {
        let parsed = parse_fragmented(
            &[b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbinary\npayload"],
            HttpLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(parsed.unparsed_data, b"binary\npayload");
    }

    /// gost accepts a bare LF and so must we: the clients that send one are
    /// the ones the panel already handed a working profile to.
    #[tokio::test]
    async fn accepts_bare_lf_line_endings_and_splits_the_body_exactly() {
        let parsed = parse_fragmented(
            &[b"GET /ws HTTP/1.1\nHost: example.com\nUpgrade: websocket\n\nbody\nrest"],
            HttpLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(parsed.path(), "/ws");
        assert_eq!(parsed.header("host").unwrap(), Some("example.com"));
        assert!(parsed.header_contains_token("upgrade", "websocket"));
        assert_eq!(parsed.unparsed_data, b"body\nrest");
        assert_eq!(
            parsed.raw_header,
            b"GET /ws HTTP/1.1\nHost: example.com\nUpgrade: websocket\n\n"
        );
    }

    /// The header block is replayed verbatim to the inner handler, so every
    /// mixture of line endings has to leave the body boundary where it is.
    #[tokio::test]
    async fn finds_the_body_across_mixed_line_endings() {
        for (request, raw_header) in [
            (
                &b"GET / HTTP/1.1\r\nHost: x\n\r\nbody"[..],
                &b"GET / HTTP/1.1\r\nHost: x\n\r\n"[..],
            ),
            (
                &b"GET / HTTP/1.1\nHost: x\r\n\nbody"[..],
                &b"GET / HTTP/1.1\nHost: x\r\n\n"[..],
            ),
        ] {
            let parsed = parse_fragmented(&[request], HttpLimits::default())
                .await
                .unwrap();
            assert_eq!(parsed.header("host").unwrap(), Some("x"));
            assert_eq!(parsed.unparsed_data, b"body");
            assert_eq!(parsed.raw_header, raw_header);
        }
    }

    #[tokio::test]
    async fn rejects_duplicate_singleton_and_too_many_headers() {
        let parsed = parse_fragmented(
            &[b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"],
            HttpLimits::default(),
        )
        .await
        .unwrap();
        assert!(parsed.header("host").is_err());

        let err = parse_fragmented(
            &[b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n"],
            HttpLimits {
                max_headers: 1,
                ..HttpLimits::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("too many"));
    }

    #[tokio::test]
    async fn rejects_header_at_byte_boundary_without_terminator() {
        let err = parse_fragmented(
            &[b"GET / HTTP/1.1\r\nX: 1234"],
            HttpLimits {
                max_header_bytes: 23,
                ..HttpLimits::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("byte limit"));
    }

    #[test]
    fn host_matching_only_accepts_a_well_formed_optional_port() {
        assert!(host_matches_optional_port("EXAMPLE.com", "example.com"));
        assert!(host_matches_optional_port("example.com:1", "example.com"));
        assert!(host_matches_optional_port(
            "example.com:65535",
            "example.com"
        ));
        assert!(host_matches_optional_port("[::1]:443", "[::1]"));
        assert!(host_matches_optional_port(
            "example.com:443",
            "example.com:443"
        ));

        for invalid in [
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:abc",
            "example.com:443evil",
            "example.com:443:1",
            "example.com.attacker",
        ] {
            assert!(
                !host_matches_optional_port(invalid, "example.com"),
                "{invalid} unexpectedly matched"
            );
        }
        assert!(!host_matches_optional_port(
            "example.com:443:80",
            "example.com:443"
        ));
    }
}
