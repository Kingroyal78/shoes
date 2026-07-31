use std::io;

use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;
use crate::h2mux::PrependStream;
use crate::stream_reader::StreamReader;
use crate::util::write_all;

const MAX_HTTP_OBFS_HEADER_SIZE: usize = 16 * 1024;
const HTTP_OBFS_RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowsocksHttpObfs {
    expected_hosts: Vec<String>,
    expected_path: Option<String>,
}

impl ShadowsocksHttpObfs {
    pub fn new(expected_hosts: Vec<String>, expected_path: Option<String>) -> Self {
        Self {
            expected_hosts: expected_hosts
                .into_iter()
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect(),
            expected_path: expected_path
                .map(|path| path.trim().to_string())
                .filter(|path| !path.is_empty()),
        }
    }

    pub async fn accept(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let mut reader = StreamReader::new_with_buffer_size(MAX_HTTP_OBFS_HEADER_SIZE);
        let request_line = reader.read_line(&mut stream).await?.to_string();
        let (method, target) = parse_request_line(&request_line)?;
        if !method.eq_ignore_ascii_case("GET") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Shadowsocks HTTP obfs method `{method}`"),
            ));
        }
        if let Some(expected_path) = &self.expected_path {
            let path = request_target_path(target);
            if path != expected_path && !path.starts_with(&format!("{expected_path}?")) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Shadowsocks HTTP obfs path `{path}` does not match expected `{expected_path}`"
                    ),
                ));
            }
        }

        let mut host_header = None;
        loop {
            let line = reader.read_line(&mut stream).await?.to_string();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("host")
            {
                host_header = Some(value.trim().to_ascii_lowercase());
            }
        }

        if !self.expected_hosts.is_empty() {
            let Some(host_header) = host_header else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks HTTP obfs request is missing Host header",
                ));
            };
            if !self
                .expected_hosts
                .iter()
                .any(|expected| host_matches(expected, &host_header))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Shadowsocks HTTP obfs host `{host_header}` does not match expected hosts"
                    ),
                ));
            }
        }

        write_all(&mut stream, HTTP_OBFS_RESPONSE).await?;
        stream.flush().await?;

        let stream: Box<dyn AsyncStream> =
            Box::new(PrependStream::new(stream, reader.unparsed_data_owned()));
        Ok(stream)
    }
}

fn parse_request_line(line: &str) -> io::Result<(&str, &str)> {
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Shadowsocks HTTP obfs request line is missing method",
        )
    })?;
    let target = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Shadowsocks HTTP obfs request line is missing target",
        )
    })?;
    let version = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Shadowsocks HTTP obfs request line is missing HTTP version",
        )
    })?;
    if !version.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Shadowsocks HTTP obfs version `{version}`"),
        ));
    }
    Ok((method, target))
}

fn request_target_path(target: &str) -> &str {
    let Some(rest) = target.strip_prefix("http://") else {
        return target;
    };
    match rest.find('/') {
        Some(index) => &rest[index..],
        None => "/",
    }
}

fn host_matches(expected: &str, actual: &str) -> bool {
    actual == expected || actual.starts_with(&format!("{expected}:"))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use crate::async_stream::AsyncPing;

    use super::*;

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

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[test]
    fn request_target_path_supports_origin_and_absolute_form() {
        assert_eq!(request_target_path("/"), "/");
        assert_eq!(request_target_path("/obfs?x=1"), "/obfs?x=1");
        assert_eq!(request_target_path("http://example.com/obfs"), "/obfs");
        assert_eq!(request_target_path("http://example.com"), "/");
    }

    #[test]
    fn host_match_accepts_optional_port() {
        assert!(host_matches("example.com", "example.com"));
        assert!(host_matches("example.com", "example.com:443"));
        assert!(!host_matches("example.com", "other.example.com"));
    }

    #[tokio::test]
    async fn accept_http_obfs_returns_remaining_payload_after_headers() {
        let (mut client, server) = tokio::io::duplex(4096);
        let obfs =
            ShadowsocksHttpObfs::new(vec!["example.com".to_string()], Some("/obfs".to_string()));
        let accept =
            tokio::spawn(async move { obfs.accept(Box::new(TestStream(server))).await.unwrap() });
        client
            .write_all(
                b"GET /obfs HTTP/1.1\r\nHost: example.com:443\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nss-payload",
            )
            .await
            .unwrap();

        let mut response = [0u8; HTTP_OBFS_RESPONSE.len()];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            std::str::from_utf8(&response)
                .unwrap()
                .starts_with("HTTP/1.1 101")
        );

        let mut accepted = accept.await.unwrap();
        let mut payload = [0u8; 10];
        accepted.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ss-payload");
    }
}
