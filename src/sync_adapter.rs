/// Sync adapters for bridging async I/O with rustls's synchronous API
///
/// These adapters allow rustls's synchronous `read_tls()` and `write_tls()` methods
/// to work with Tokio's async I/O primitives.
///
/// Adapted from tokio-rustls:
/// https://github.com/rustls/tokio-rustls/blob/ba767aeb51611107e7cb6aa756f10a2f49e70926/src/common/mod.rs#L403
use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Adapter to bridge async read to synchronous read for rustls
///
/// This allows rustls's `read_tls()` method to read from async TCP sockets.
/// When the async socket would block (Poll::Pending), this returns WouldBlock error.
pub struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> std::io::Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Adapter to bridge async write to synchronous write for rustls
///
/// This allows rustls's `write_tls()` method to write to async TCP sockets.
/// When the async socket would block (Poll::Pending), this returns WouldBlock error.
pub struct SyncWriteAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// rustls hands every sealed record it has queued to one `write_vectored`
    /// call. The default implementation writes only the first of them, so a
    /// plaintext write spanning several records went out as one send per
    /// record; forwarding the whole set lets a vectored transport take them in
    /// a single writev.
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{IoSlice, Write};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::SyncWriteAdapter;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use crate::crypto::{CryptoConnection, CryptoTlsStream};
    use crate::rustls_config_util::{create_client_config, create_server_config};

    /// A transport that records the slices each write call carried.
    #[derive(Default)]
    struct RecordingTransport {
        writes: Vec<Vec<usize>>,
        written: Vec<u8>,
    }

    impl AsyncRead for RecordingTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for RecordingTransport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.push(vec![buf.len()]);
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.push(bufs.iter().map(|buf| buf.len()).collect());
            let mut total = 0;
            for buf in bufs {
                self.written.extend_from_slice(buf);
                total += buf.len();
            }
            Poll::Ready(Ok(total))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for RecordingTransport {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for RecordingTransport {}

    #[test]
    fn write_vectored_reaches_the_transport_as_one_call() {
        let mut transport = RecordingTransport::default();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut adapter = SyncWriteAdapter {
            io: &mut transport,
            cx: &mut cx,
        };

        let written = adapter
            .write_vectored(&[IoSlice::new(b"first"), IoSlice::new(b"second")])
            .unwrap();

        assert_eq!(written, 11);
        assert_eq!(transport.writes, vec![vec![5, 6]]);
        assert_eq!(transport.written, b"firstsecond");
    }

    /// Completes a TLS 1.3 handshake in memory and returns the server side.
    fn established_server_connection() -> rustls::ServerConnection {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_config = create_server_config(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
            Vec::new(),
            &[],
            &[],
        );
        let client_config = create_client_config(false, Vec::new(), Vec::new(), true, None, true);
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
                .unwrap();

        while server.is_handshaking() || client.is_handshaking() {
            let mut flight = Vec::new();
            client.write_tls(&mut flight).unwrap();
            server.read_tls(&mut flight.as_slice()).unwrap();
            server.process_new_packets().unwrap();
            flight.clear();
            server.write_tls(&mut flight).unwrap();
            client.read_tls(&mut flight.as_slice()).unwrap();
            client.process_new_packets().unwrap();
        }
        // Session tickets and anything else the handshake left queued.
        while server.wants_write() {
            server.write_tls(&mut std::io::sink()).unwrap();
        }
        server
    }

    /// A plaintext write larger than one TLS record is sealed into several
    /// records at once. Each used to leave in a transport write of its own --
    /// on a WSS listener, two send syscalls for every 16 KiB of download.
    #[test]
    fn records_sealed_together_leave_in_one_transport_write() {
        let session = CryptoConnection::new_rustls_server(established_server_connection());
        let mut stream = CryptoTlsStream::new(RecordingTransport::default(), session);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let payload = vec![0x5a_u8; 20_000];

        let written = match Pin::new(&mut stream).poll_write(&mut cx, &payload) {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => panic!("an always-ready transport must not park the write"),
        };
        assert_eq!(written, payload.len());

        let (transport, _) = stream.into_inner();
        assert_eq!(
            transport.writes.len(),
            1,
            "all sealed records must reach the transport in one write, got {:?}",
            transport.writes
        );
        assert!(
            transport.writes[0].len() >= 2,
            "20,000 bytes of plaintext must span more than one record: {:?}",
            transport.writes
        );
    }
}
