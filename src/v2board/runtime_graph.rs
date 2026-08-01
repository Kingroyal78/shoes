use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::config::BindLocation;
use crate::resolver::Resolver;

use super::mapper::RuntimeNode;

/// An immutable, fully validated runtime generation.
///
/// A graph may contain more than one listener (for example the loopback raw
/// Shadowsocks ingress and a public plugin edge).  Treating them as one value
/// prevents the control plane from acknowledging a partially started node.
#[derive(Clone)]
pub struct RuntimeGraph {
    pub tag: String,
    pub revision: Option<String>,
    pub applied_features: Vec<String>,
    nodes: Vec<RuntimeNode>,
}

impl RuntimeGraph {
    pub fn single(node: RuntimeNode) -> Self {
        Self {
            tag: node.tag.clone(),
            revision: None,
            applied_features: Vec::new(),
            nodes: vec![node],
        }
    }

    pub fn new(
        tag: String,
        revision: Option<String>,
        applied_features: Vec<String>,
        nodes: Vec<RuntimeNode>,
    ) -> std::io::Result<Self> {
        if nodes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "runtime graph must contain at least one node",
            ));
        }
        if nodes.iter().any(|node| node.tag != tag) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "all runtime graph nodes must have the graph tag",
            ));
        }
        for (index, node) in nodes.iter().enumerate() {
            if nodes[..index]
                .iter()
                .any(|previous| previous.bind_location == node.bind_location)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "runtime graph `{tag}` declares duplicate bind {}",
                        node.bind_location
                    ),
                ));
            }
        }
        let mut unique_features = HashSet::new();
        if applied_features
            .iter()
            .any(|feature| feature.is_empty() || !unique_features.insert(feature))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "runtime graph features must be non-empty and unique",
            ));
        }
        Ok(Self {
            tag,
            revision,
            applied_features,
            nodes,
        })
    }

    fn bind_locations(&self) -> impl Iterator<Item = &BindLocation> {
        self.nodes.iter().map(|node| &node.bind_location)
    }

    fn has_bind_overlap(&self, other: &Self) -> bool {
        self.bind_locations()
            .any(|left| other.bind_locations().any(|right| left == right))
    }

    async fn start(self, resolver: Arc<dyn Resolver>) -> std::io::Result<ActiveRuntimeGraph> {
        let mut handles = Vec::new();
        for node in self.nodes.iter().cloned() {
            match node.start(resolver.clone()).await {
                Ok(mut node_handles) => handles.append(&mut node_handles),
                Err(error) => {
                    abort_and_wait(&mut handles).await;
                    return Err(error);
                }
            }
        }

        // Give accept loops and immediately-failing workers a scheduling turn
        // before the generation can be acknowledged as live.
        sleep(Duration::from_millis(25)).await;
        if handles.iter().any(JoinHandle::is_finished) {
            abort_and_wait(&mut handles).await;
            return Err(std::io::Error::other(format!(
                "runtime graph `{}` worker exited during readiness gate",
                self.tag
            )));
        }
        for node in &self.nodes {
            if let Err(error) = node.readiness_probe().await {
                abort_and_wait(&mut handles).await;
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "runtime graph `{}` readiness probe failed at {}: {error}",
                        self.tag, node.bind_location
                    ),
                ));
            }
        }

        Ok(ActiveRuntimeGraph {
            graph: self,
            handles,
        })
    }
}

struct ActiveRuntimeGraph {
    graph: RuntimeGraph,
    handles: Vec<JoinHandle<()>>,
}

impl ActiveRuntimeGraph {
    async fn stop(mut self) {
        abort_and_wait(&mut self.handles).await;
    }
}

/// Owns the single committed generation for a V2Board node.
///
/// Disjoint listeners are started and health-gated before the old generation
/// is drained.  When a bind address is reused, the old generation must be
/// stopped first; a failed start then restores the exact previous graph.
#[derive(Default)]
pub struct RuntimeGraphSlot {
    active: Option<ActiveRuntimeGraph>,
}

impl RuntimeGraphSlot {
    pub fn is_empty(&self) -> bool {
        self.active.is_none()
    }

    pub fn active_revision(&self) -> Option<&str> {
        self.active
            .as_ref()
            .and_then(|active| active.graph.revision.as_deref())
    }

    pub fn active_features(&self) -> &[String] {
        self.active
            .as_ref()
            .map_or(&[], |active| active.graph.applied_features.as_slice())
    }

    pub async fn replace(
        &mut self,
        candidate: RuntimeGraph,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<()> {
        let Some(active) = self.active.take() else {
            self.active = Some(candidate.start(resolver).await?);
            return Ok(());
        };

        if !active.graph.has_bind_overlap(&candidate) {
            match candidate.start(resolver).await {
                Ok(next) => {
                    active.stop().await;
                    self.active = Some(next);
                    return Ok(());
                }
                Err(error) => {
                    self.active = Some(active);
                    return Err(error);
                }
            }
        }

        let previous = active.graph.clone();
        let previous_tag = previous.tag.clone();
        active.stop().await;
        match candidate.start(resolver.clone()).await {
            Ok(next) => {
                self.active = Some(next);
                Ok(())
            }
            Err(error) => {
                match previous.start(resolver).await {
                    Ok(restored) => {
                        log::warn!(
                            "restored previous runtime graph `{}` after candidate start failure: {error}",
                            restored.graph.tag
                        );
                        self.active = Some(restored);
                    }
                    Err(rollback_error) => {
                        log::error!(
                            "failed to restore runtime graph `{}` after candidate error `{error}`: {rollback_error}",
                            previous_tag
                        );
                    }
                }
                Err(error)
            }
        }
    }

    pub async fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            active.stop().await;
        }
    }
}

async fn abort_and_wait(handles: &mut Vec<JoinHandle<()>>) {
    let handles = std::mem::take(handles);
    for handle in &handles {
        handle.abort();
    }
    for result in futures::future::join_all(handles).await {
        if let Err(e) = result
            && !e.is_cancelled()
        {
            log::error!("task aborted with panic: {e}");
        }
    }
}

impl Drop for RuntimeGraphSlot {
    fn drop(&mut self) {
        for handle in self
            .active
            .as_mut()
            .into_iter()
            .flat_map(|active| active.handles.drain(..))
        {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

    use async_trait::async_trait;

    use super::*;
    use crate::address::{Address, NetLocation};
    use crate::async_stream::AsyncStream;
    use crate::config::TcpConfig;
    use crate::resolver::NativeResolver;
    use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

    struct NoopHandler;

    impl fmt::Debug for NoopHandler {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("NoopHandler")
        }
    }

    #[async_trait]
    impl TcpServerHandler for NoopHandler {
        async fn setup_server_stream(
            &self,
            _: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    fn bind(port: u16) -> BindLocation {
        BindLocation::Address(NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port).into())
    }

    fn node(tag: &str, port: u16) -> RuntimeNode {
        RuntimeNode::new_tcp(
            tag.to_string(),
            bind(port),
            Arc::new(NoopHandler),
            TcpConfig::default(),
        )
    }

    fn free_port() -> u16 {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn rejects_partial_or_ambiguous_generation_metadata() {
        assert!(RuntimeGraph::new("node".into(), None, vec![], vec![]).is_err());
        assert!(
            RuntimeGraph::new(
                "node".into(),
                None,
                vec![],
                vec![node("different", free_port())]
            )
            .is_err()
        );
        let duplicate_port = free_port();
        assert!(
            RuntimeGraph::new(
                "node".into(),
                None,
                vec![],
                vec![node("node", duplicate_port), node("node", duplicate_port)]
            )
            .is_err()
        );
        assert!(
            RuntimeGraph::new(
                "node".into(),
                None,
                vec!["adapter".into(), "adapter".into()],
                vec![node("node", free_port())]
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn restores_the_exact_overlapping_generation_after_partial_start_failure() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let old_port = free_port();
        let mut slot = RuntimeGraphSlot::default();
        let old = RuntimeGraph::new(
            "node".into(),
            Some("old-revision".into()),
            vec!["old-feature".into()],
            vec![node("node", old_port)],
        )
        .unwrap();
        slot.replace(old, resolver.clone()).await.unwrap();

        let blocked = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let blocked_port = blocked.local_addr().unwrap().port();
        let candidate = RuntimeGraph::new(
            "node".into(),
            Some("candidate-revision".into()),
            vec!["candidate-feature".into()],
            vec![node("node", old_port), node("node", blocked_port)],
        )
        .unwrap();

        assert!(slot.replace(candidate, resolver).await.is_err());
        assert_eq!(slot.active_revision(), Some("old-revision"));
        assert_eq!(slot.active_features(), ["old-feature"]);
        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, old_port))
            .await
            .expect("the prior listener must be live after rollback");

        drop(blocked);
        slot.stop().await;
    }
}
