use std::{
    collections::VecDeque,
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use rand::RngExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    task::JoinHandle,
};

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    client_proxy_chain::ClientProxyChain,
    resolver::Resolver,
    tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
};

use super::{
    AsyncTlsRecordReader, DecodedAppRecord, RestlsCommand, RestlsKey, RestlsScript,
    RestlsServerAction, RestlsServerCore,
};

#[async_trait]
pub trait RestlsCamouflageConnector: Send + Sync + fmt::Debug {
    async fn connect(&self) -> io::Result<Box<dyn AsyncStream>>;
}

pub struct ClientChainRestlsConnector {
    location: NetLocation,
    chain: Arc<ClientProxyChain>,
    resolver: Arc<dyn Resolver>,
}

impl fmt::Debug for ClientChainRestlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientChainRestlsConnector")
            .field("location", &self.location)
            .field("chain", &self.chain)
            .finish_non_exhaustive()
    }
}

impl ClientChainRestlsConnector {
    pub fn new(
        host: &str,
        chain: ClientProxyChain,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        validate_host(host)?;
        Ok(Self {
            location: NetLocation::new(Address::from(host)?, 443),
            chain: Arc::new(chain),
            resolver,
        })
    }
}

#[async_trait]
impl RestlsCamouflageConnector for ClientChainRestlsConnector {
    async fn connect(&self) -> io::Result<Box<dyn AsyncStream>> {
        let result = self
            .chain
            .connect_tcp(self.location.clone().into(), &self.resolver)
            .await?;
        if result.early_data.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Restls camouflage connector returned unexpected early data",
            ));
        }
        Ok(result.client_stream)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RestlsRuntimeLimits {
    pub bridge_capacity: usize,
    pub max_pending_inner_bytes: usize,
    pub minimum_record_data: usize,
}

impl Default for RestlsRuntimeLimits {
    fn default() -> Self {
        Self {
            bridge_capacity: 64 * 1024,
            max_pending_inner_bytes: 256 * 1024,
            minimum_record_data: 15,
        }
    }
}

pub struct RestlsPluginServerHandler {
    key: RestlsKey,
    script: RestlsScript,
    connector: Arc<dyn RestlsCamouflageConnector>,
    inner: Arc<dyn TcpServerHandler>,
    limits: RestlsRuntimeLimits,
}

impl fmt::Debug for RestlsPluginServerHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestlsPluginServerHandler")
            .field("key", &self.key)
            .field("script", &self.script)
            .field("connector", &self.connector)
            .field("inner", &self.inner)
            .field("limits", &self.limits)
            .finish()
    }
}

impl RestlsPluginServerHandler {
    pub fn new(
        password: impl AsRef<[u8]>,
        script: RestlsScript,
        connector: Arc<dyn RestlsCamouflageConnector>,
        inner: Arc<dyn TcpServerHandler>,
        limits: RestlsRuntimeLimits,
    ) -> io::Result<Self> {
        if limits.bridge_capacity == 0
            || limits.max_pending_inner_bytes == 0
            || limits.minimum_record_data > u16::MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Restls runtime limits",
            ));
        }
        let script = if script.is_empty() {
            RestlsScript::mihomo_default().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid built-in Restls script: {error}"),
                )
            })?
        } else {
            script
        };
        Ok(Self {
            key: RestlsKey::derive(password)?,
            script,
            connector,
            inner,
            limits,
        })
    }
}

#[async_trait]
impl TcpServerHandler for RestlsPluginServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let camouflage = self.connector.connect().await?;
        let (client_read, client_write) = tokio::io::split(stream);
        let (camouflage_read, camouflage_write) = tokio::io::split(camouflage);
        let mut client_reader = AsyncTlsRecordReader::new(client_read);
        let mut camouflage_reader = AsyncTlsRecordReader::new(camouflage_read);
        let mut client_write = client_write;
        let mut camouflage_write = camouflage_write;
        let mut core = RestlsServerCore::from_key(self.key.clone());

        let first = loop {
            tokio::select! {
                client_record = client_reader.next_record() => {
                    let mut record = match client_record {
                        Ok(record) => record,
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            flush_fallback_buffers(
                                &mut client_reader,
                                &mut client_write,
                                &mut camouflage_reader,
                                &mut camouflage_write,
                            )
                            .await?;
                            return fallback_task(
                                client_reader.into_inner().unsplit(client_write),
                                camouflage_reader.into_inner().unsplit(camouflage_write),
                            );
                        }
                        Err(error) => return Err(error),
                    };
                    match core.on_client_record(&mut record) {
                        Ok(RestlsServerAction::Relay | RestlsServerAction::RelayMutated) => {
                            record.write_to(&mut camouflage_write).await?;
                            camouflage_write.flush().await?;
                        }
                        Ok(RestlsServerAction::Authenticated(first)) => break first,
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            record.write_to(&mut camouflage_write).await?;
                            flush_fallback_buffers(
                                &mut client_reader,
                                &mut client_write,
                                &mut camouflage_reader,
                                &mut camouflage_write,
                            )
                            .await?;
                            return fallback_task(
                                client_reader.into_inner().unsplit(client_write),
                                camouflage_reader.into_inner().unsplit(camouflage_write),
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                camouflage_record = camouflage_reader.next_record() => {
                    let mut record = match camouflage_record {
                        Ok(record) => record,
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            flush_fallback_buffers(
                                &mut client_reader,
                                &mut client_write,
                                &mut camouflage_reader,
                                &mut camouflage_write,
                            )
                            .await?;
                            return fallback_task(
                                client_reader.into_inner().unsplit(client_write),
                                camouflage_reader.into_inner().unsplit(camouflage_write),
                            );
                        }
                        Err(error) => return Err(error),
                    };
                    match core.on_camouflage_record(&mut record) {
                        Ok(RestlsServerAction::Relay | RestlsServerAction::RelayMutated) => {
                            record.write_to(&mut client_write).await?;
                            client_write.flush().await?;
                        }
                        Ok(RestlsServerAction::Authenticated(_)) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "camouflage direction produced Restls application data",
                            ));
                        }
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            record.write_to(&mut client_write).await?;
                            flush_fallback_buffers(
                                &mut client_reader,
                                &mut client_write,
                                &mut camouflage_reader,
                                &mut camouflage_write,
                            )
                            .await?;
                            return fallback_task(
                                client_reader.into_inner().unsplit(client_write),
                                camouflage_reader.into_inner().unsplit(camouflage_write),
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        };

        let (application, driver_side) = tokio::io::duplex(self.limits.bridge_capacity);
        let script = self.script.clone();
        let limits = self.limits;
        let driver = tokio::spawn(async move {
            run_application_driver(
                core,
                first,
                client_reader,
                client_write,
                camouflage_reader,
                camouflage_write,
                driver_side,
                script,
                limits,
            )
            .await
        });
        let application = RestlsApplicationStream {
            inner: application,
            driver: Some(driver),
        };
        self.inner
            .setup_server_stream_with_peer_addr(Box::new(application), peer_addr)
            .await
    }
}

async fn flush_fallback_buffers<CR, CW, HR, HW>(
    client_reader: &mut AsyncTlsRecordReader<CR>,
    client_write: &mut CW,
    camouflage_reader: &mut AsyncTlsRecordReader<HR>,
    camouflage_write: &mut HW,
) -> io::Result<()>
where
    CW: AsyncWrite + Unpin,
    HW: AsyncWrite + Unpin,
{
    let client_buffered = client_reader.take_buffered();
    let camouflage_buffered = camouflage_reader.take_buffered();
    if !client_buffered.is_empty() {
        camouflage_write.write_all(&client_buffered).await?;
        camouflage_write.flush().await?;
    }
    if !camouflage_buffered.is_empty() {
        client_write.write_all(&camouflage_buffered).await?;
        client_write.flush().await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_application_driver<CR, CW, HR, HW>(
    mut core: RestlsServerCore,
    first: DecodedAppRecord,
    mut client_reader: AsyncTlsRecordReader<CR>,
    mut client_write: CW,
    mut camouflage_reader: AsyncTlsRecordReader<HR>,
    mut camouflage_write: HW,
    mut inner: tokio::io::DuplexStream,
    script: RestlsScript,
    limits: RestlsRuntimeLimits,
) -> io::Result<()>
where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    HR: AsyncRead + Unpin,
    HW: AsyncWrite + Unpin,
{
    if !first.data.is_empty() {
        inner.write_all(&first.data).await?;
    }
    let mut forced_responses = match first.command {
        RestlsCommand::Noop => 0u32,
        RestlsCommand::Response(count) => u32::from(count),
    };
    // Whether the client is expected to speak before the conversation
    // continues. Restls has at most one such request outstanding: it is a
    // state of the exchange, not a number of records to count down.
    let mut awaiting = false;
    let mut pending = VecDeque::<u8>::new();
    let mut camouflage_open = true;
    let mut inner_open = true;
    let mut read_buffer = vec![0u8; 32 * 1024];

    loop {
        // Queued inner data goes out first, and every record it produces also
        // pays down what the client asked us to send: a response the client
        // requested is satisfied by a real record just as well as by padding.
        if (!awaiting || forced_responses > 0) && !pending.is_empty() {
            let (written, next_awaiting) =
                write_pending_records(&mut core, &script, limits, &mut client_write, &mut pending)
                    .await?;
            forced_responses = forced_responses.saturating_sub(written);
            awaiting = next_awaiting;
        }
        // Whatever the data did not cover goes out as records carrying none.
        if forced_responses > 0 {
            awaiting = write_owed_responses(
                &mut core,
                &script,
                limits,
                &mut client_write,
                &mut pending,
                forced_responses,
            )
            .await?;
            forced_responses = 0;
        }
        if !inner_open && pending.is_empty() && forced_responses == 0 {
            client_write.shutdown().await?;
            return Ok(());
        }

        tokio::select! {
            client_record = client_reader.next_record() => {
                let mut record = match client_record {
                    Ok(record) => record,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(error),
                };
                awaiting = false;
                log::trace!(
                    "restls from-client record: len={} owed={forced_responses}",
                    record.payload.len()
                );
                match core.on_client_record(&mut record)? {
                    RestlsServerAction::Authenticated(decoded) => {
                        if !decoded.data.is_empty() {
                            inner.write_all(&decoded.data).await?;
                        }
                        if let RestlsCommand::Response(count) = decoded.command {
                            forced_responses = forced_responses.saturating_add(u32::from(count));
                        }
                    }
                    _ => return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected handshake action after Restls authentication",
                    )),
                }
            }
            camouflage_record = camouflage_reader.next_record(), if camouflage_open => {
                match camouflage_record {
                    Ok(record) => {
                        core.relay_post_auth_camouflage_record(&record)?;
                        record.write_to(&mut client_write).await?;
                        client_write.flush().await?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        camouflage_open = false;
                    }
                    Err(error) => return Err(error),
                }
            }
            read = inner.read(&mut read_buffer), if inner_open && pending.len() < limits.max_pending_inner_bytes => {
                let read = read?;
                if read == 0 {
                    // The script may have already requested client response
                    // records. Keep the protocol driver alive until those and
                    // all queued response bytes have advanced the counters.
                    inner_open = false;
                    let _ = camouflage_write.shutdown().await;
                    continue;
                }
                if pending.len().saturating_add(read) > limits.max_pending_inner_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "Restls pending inner-data limit exceeded",
                    ));
                }
                pending.extend(&read_buffer[..read]);
            }
        }
    }
}

/// Emit one record to the client and report the command it carried.
///
/// A record that exists only to answer what the client asked for carries no
/// data, but the script still chooses its size, so it is indistinguishable on
/// the wire from one that does.
async fn write_one_record<W: AsyncWrite + Unpin>(
    core: &mut RestlsServerCore,
    script: &RestlsScript,
    limits: RestlsRuntimeLimits,
    client_write: &mut W,
    pending: &mut VecDeque<u8>,
    carry_data: bool,
) -> io::Result<RestlsCommand> {
    let counter = core
        .counters()
        .ok_or_else(|| io::Error::other("Restls counters unavailable"))?
        .0 as usize;
    let (target, command) = match script.line(counter) {
        Some(line) => (line.target_len(), line.command),
        None => {
            let minimum = limits.minimum_record_data + rand::rng().random_range(0..100usize);
            (pending.len().max(minimum).min(32768), RestlsCommand::Noop)
        }
    };
    let contiguous = pending.make_contiguous();
    let data = if carry_data { contiguous } else { &[][..] };
    let encoded = core.encode_to_client(data, target, command)?;
    // Both sides drive the same script from their own record counters, and a
    // disagreement about how many records are owed shows up only as a peer
    // that stops talking. The two sequences are what tells them apart.
    log::trace!(
        "restls to-client record: counter={counter} carry_data={carry_data} target={target} \
         command={:?}",
        encoded.command
    );
    encoded.record.write_to(client_write).await?;
    client_write.flush().await?;
    if carry_data {
        pending.drain(..encoded.consumed);
    }
    Ok(encoded.command)
}

/// Drain queued inner data into client records.
///
/// Stops as soon as a record carries a response command: the client is then
/// expected to speak before the conversation continues, and sending past that
/// point leaves both sides waiting on each other. Returns how many records
/// went out, so the caller can count them against what the client asked for,
/// and whether the client now owes us a record.
async fn write_pending_records<W: AsyncWrite + Unpin>(
    core: &mut RestlsServerCore,
    script: &RestlsScript,
    limits: RestlsRuntimeLimits,
    client_write: &mut W,
    pending: &mut VecDeque<u8>,
) -> io::Result<(u32, bool)> {
    let mut written = 0u32;
    while !pending.is_empty() {
        let command = write_one_record(core, script, limits, client_write, pending, true).await?;
        written = written.saturating_add(1);
        if let RestlsCommand::Response(count) = command {
            return Ok((written, count > 0));
        }
    }
    Ok((written, false))
}

/// Emit the records the client asked for that its own data did not cover.
///
/// A response command met here only records that the client is expected to
/// speak next. Treating it as more records to send would have each side answer
/// the other's answer.
async fn write_owed_responses<W: AsyncWrite + Unpin>(
    core: &mut RestlsServerCore,
    script: &RestlsScript,
    limits: RestlsRuntimeLimits,
    client_write: &mut W,
    pending: &mut VecDeque<u8>,
    owed: u32,
) -> io::Result<bool> {
    let mut awaiting = false;
    for _ in 0..owed {
        let command = write_one_record(core, script, limits, client_write, pending, false).await?;
        if let RestlsCommand::Response(count) = command {
            awaiting = count > 0;
        }
    }
    Ok(awaiting)
}

fn fallback_task<C, H>(mut client: C, mut camouflage: H) -> io::Result<TcpServerSetupResult>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Ok(TcpServerSetupResult::connection_task(async move {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut camouflage).await;
        let _ = client.shutdown().await;
        let _ = camouflage.shutdown().await;
        Ok(())
    }))
}

struct RestlsApplicationStream {
    inner: tokio::io::DuplexStream,
    driver: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for RestlsApplicationStream {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

impl AsyncRead for RestlsApplicationStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for RestlsApplicationStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for RestlsApplicationStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for RestlsApplicationStream {}

impl fmt::Debug for RestlsApplicationStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestlsApplicationStream")
            .field(
                "driver_running",
                &self.driver.as_ref().is_some_and(|task| !task.is_finished()),
            )
            .finish()
    }
}

fn validate_host(host: &str) -> io::Result<()> {
    let invalid = host.is_empty()
        || host.len() > 253
        || host.contains(['\0', '\r', '\n'])
        || host.trim() != host
        || (host.contains(':') && host.parse::<IpAddr>().is_err());
    if invalid {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Restls camouflage host",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
        time::{Duration, timeout},
    };

    use super::*;
    use crate::ss_plugins::restls::record::{RECORD_APPLICATION_DATA, TlsRecord};

    fn client_application_record(
        key: &RestlsKey,
        server_random: [u8; 32],
        data: &[u8],
    ) -> TlsRecord {
        const AUTH_LEN: usize = 8;
        const MASK_LEN: usize = 4;
        let mut payload = vec![0u8; AUTH_LEN + MASK_LEN + data.len()];
        payload[AUTH_LEN + MASK_LEN..].copy_from_slice(data);

        let mut mask = key.hasher();
        mask.update(&server_random);
        mask.update(b"client-to-server");
        mask.update(&0u64.to_be_bytes());
        mask.update(data);
        let mask = mask.finalize();
        let mut masked = [0u8; MASK_LEN];
        masked[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        for (byte, mask) in masked.iter_mut().zip(&mask.as_bytes()[..MASK_LEN]) {
            *byte ^= *mask;
        }
        payload[AUTH_LEN..AUTH_LEN + MASK_LEN].copy_from_slice(&masked);

        let mut record = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, payload).unwrap();
        let mut auth = key.hasher();
        auth.update(&server_random);
        auth.update(b"client-to-server");
        auth.update(&0u64.to_be_bytes());
        auth.update(&record.header());
        auth.update(&record.payload[AUTH_LEN..]);
        record.payload[..AUTH_LEN].copy_from_slice(&auth.finalize().as_bytes()[..AUTH_LEN]);
        record
    }

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, output)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, input)
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

    struct OneShotConnector(Mutex<Option<TestStream>>);

    impl fmt::Debug for OneShotConnector {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OneShotConnector")
        }
    }

    #[async_trait]
    impl RestlsCamouflageConnector for OneShotConnector {
        async fn connect(&self) -> io::Result<Box<dyn AsyncStream>> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("test connector lock poisoned"))?
                .take()
                .map(|stream| Box::new(stream) as Box<dyn AsyncStream>)
                .ok_or_else(|| io::Error::other("test connector already consumed"))
        }
    }

    #[derive(Debug)]
    struct NeverHandle;

    #[async_trait]
    impl TcpServerHandler for NeverHandle {
        async fn setup_server_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            panic!("fallback must not reach the inner handler")
        }
    }

    #[test]
    fn camouflage_host_is_pinned_to_port_443() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("2001:db8::1").is_ok());
        assert!(validate_host("example.com:8443").is_err());
        assert!(validate_host("[2001:db8::1]:8443").is_err());
        assert!(validate_host("bad\nhost").is_err());
    }

    #[test]
    fn handler_debug_never_exposes_password() {
        #[derive(Debug)]
        struct NeverConnect;
        #[async_trait]
        impl RestlsCamouflageConnector for NeverConnect {
            async fn connect(&self) -> io::Result<Box<dyn AsyncStream>> {
                Err(io::Error::other("unused"))
            }
        }
        let handler = RestlsPluginServerHandler::new(
            "do-not-log-this",
            RestlsScript::default(),
            Arc::new(NeverConnect),
            Arc::new(NeverHandle),
            RestlsRuntimeLimits::default(),
        )
        .unwrap();
        assert!(!format!("{handler:?}").contains("do-not-log-this"));
    }

    #[tokio::test]
    async fn invalid_probe_fallback_preserves_buffered_and_future_bytes() {
        let (mut client_peer, client_server) = duplex(4096);
        let (camouflage_server, mut camouflage_peer) = duplex(4096);
        let handler = RestlsPluginServerHandler::new(
            "password",
            RestlsScript::default(),
            Arc::new(OneShotConnector(Mutex::new(Some(TestStream(
                camouflage_server,
            ))))),
            Arc::new(NeverHandle),
            RestlsRuntimeLimits::default(),
        )
        .unwrap();

        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client_server)))
                .await
        });

        // The invalid header and the following bytes are deliberately written
        // together so the cancellation-safe decoder may buffer both.
        let initial = [0x99, 3, 3, 0, 0, 1, 2, 3, 4];
        client_peer.write_all(&initial).await.unwrap();
        let TcpServerSetupResult::ConnectionTask(task) = setup.await.unwrap().unwrap() else {
            panic!("fallback must return an owned connection task")
        };
        let fallback_task = tokio::spawn(task);

        client_peer.write_all(&[5, 6, 7]).await.unwrap();
        let mut forwarded = [0u8; 12];
        timeout(
            Duration::from_secs(1),
            camouflage_peer.read_exact(&mut forwarded),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(forwarded, [0x99, 3, 3, 0, 0, 1, 2, 3, 4, 5, 6, 7]);
        fallback_task.abort();
        let _ = fallback_task.await;
    }

    #[tokio::test]
    async fn inner_eof_does_not_discard_pending_data_while_awaiting_client_response() {
        let key = RestlsKey::derive("password").unwrap();
        let server_random = [4; 32];
        let core = RestlsServerCore::authenticated_for_test(key.clone(), server_random);
        let first = DecodedAppRecord {
            data: Vec::new(),
            command: RestlsCommand::Response(1),
        };
        let (client_driver, mut client_peer) = duplex(128 * 1024);
        let (client_read, client_write) = tokio::io::split(client_driver);
        let (camouflage_driver, _camouflage_peer) = duplex(1024);
        let (camouflage_read, camouflage_write) = tokio::io::split(camouflage_driver);
        let (mut application, driver_inner) = duplex(128 * 1024);
        let script: RestlsScript = "64<1,32768".parse().unwrap();

        let driver = tokio::spawn(run_application_driver(
            core,
            first,
            AsyncTlsRecordReader::new(client_read),
            client_write,
            AsyncTlsRecordReader::new(camouflage_read),
            camouflage_write,
            driver_inner,
            script,
            RestlsRuntimeLimits::default(),
        ));

        let forced = TlsRecord::read_from(&mut client_peer).await.unwrap();
        assert_eq!(forced.payload.len(), 12 + 64);

        let payload = vec![0x5a; 16 * 1024];
        application.write_all(&payload).await.unwrap();
        application.shutdown().await.unwrap();

        let mut premature = [0u8; 1];
        assert!(
            timeout(Duration::from_millis(50), client_peer.read(&mut premature))
                .await
                .is_err(),
            "driver closed the client connection while response data was pending"
        );

        client_application_record(&key, server_random, &[])
            .write_to(&mut client_peer)
            .await
            .unwrap();
        let first_response = timeout(
            Duration::from_secs(1),
            TlsRecord::read_from(&mut client_peer),
        )
        .await
        .expect("pending response was discarded after inner EOF")
        .unwrap();
        let first_data_len = (1 << 14) - 12;
        assert_eq!(
            &first_response.payload[12..12 + first_data_len],
            &payload[..first_data_len]
        );
        let second_response = timeout(
            Duration::from_secs(1),
            TlsRecord::read_from(&mut client_peer),
        )
        .await
        .expect("pending response tail was discarded after inner EOF")
        .unwrap();
        assert_eq!(
            &second_response.payload[12..12 + payload.len() - first_data_len],
            &payload[first_data_len..]
        );

        drop(client_peer);
        timeout(Duration::from_secs(1), driver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
