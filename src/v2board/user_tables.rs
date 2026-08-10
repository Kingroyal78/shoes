//! Per-node user tables that outlive runtime generations.
//!
//! A V2Board node re-publishes its whole user list on every pull, and on a busy
//! node the list changes almost every interval. Rebuilding the listener stack
//! for each change retains memory without bound: every accepted connection
//! holds an `Arc` to the handler that accepted it, so each superseded
//! generation stays resident until its last connection closes.
//!
//! These slots are created once per node and handed to every generation, so a
//! user-list change becomes a pointer swap inside a container the listeners
//! already hold — see [`crate::shared_users`]. The control plane can then apply
//! a users-only sync without touching the listeners at all.

use std::sync::{Arc, OnceLock};

use crate::anytls::AnyTlsUsers;
use crate::hysteria2_server::Hysteria2UserTable;
use crate::naiveproxy::UserLookup;
use crate::shadowsocks::{ShadowsocksUsers, SharedSaltChecker, new_shared_salt_checker};
use crate::shared_users::{SharedUsers, SharedUsersSlot};
use crate::trojan_handler::TrojanUsers;
use crate::tuic_server::TuicUserTable;
use crate::vless::vless_server_handler::VlessUsers;
use crate::vmess::VmessUsers;

/// The user tables of one node's live listeners.
///
/// Cheap to clone; clones share the same slots.
#[derive(Clone, Default)]
pub struct NodeUserTables {
    inner: Arc<Slots>,
}

#[derive(Default)]
struct Slots {
    shadowsocks: SharedUsersSlot<ShadowsocksUsers>,
    vless: SharedUsersSlot<VlessUsers>,
    vmess: SharedUsersSlot<VmessUsers>,
    trojan: SharedUsersSlot<TrojanUsers>,
    anytls: SharedUsersSlot<AnyTlsUsers>,
    tuic: SharedUsersSlot<TuicUserTable>,
    hysteria2: SharedUsersSlot<Hysteria2UserTable>,
    naiveproxy: SharedUsersSlot<UserLookup>,
    /// Shared by every Shadowsocks generation of this node; see
    /// [`NodeUserTables::shadowsocks_salt_checker`].
    shadowsocks_salt_checker: OnceLock<SharedSaltChecker>,
}

impl NodeUserTables {
    pub fn new() -> Self {
        Self::default()
    }

    /// The node's Shadowsocks salt-replay checker, created on first use.
    ///
    /// Replay protection is memory, so it has to outlive the listener that
    /// holds it: a generation rebuilt for any non-user change would otherwise
    /// begin with an empty set and accept replays it had already seen.
    pub fn shadowsocks_salt_checker(&self) -> SharedSaltChecker {
        self.inner
            .shadowsocks_salt_checker
            .get_or_init(new_shared_salt_checker)
            .clone()
    }

    /// Publish a Shadowsocks user table and return the handle for a listener.
    pub fn publish_shadowsocks(
        &self,
        users: ShadowsocksUsers,
    ) -> Arc<SharedUsers<ShadowsocksUsers>> {
        self.inner.shadowsocks.publish(users)
    }

    /// Publish a VLESS user table and return the handle for a listener.
    pub fn publish_vless(&self, users: VlessUsers) -> Arc<SharedUsers<VlessUsers>> {
        self.inner.vless.publish(users)
    }

    /// Publish a VMess user table and return the handle for a listener.
    pub fn publish_vmess(&self, users: VmessUsers) -> Arc<SharedUsers<VmessUsers>> {
        self.inner.vmess.publish(users)
    }

    /// Publish a Trojan user table and return the handle for a listener.
    pub fn publish_trojan(&self, users: TrojanUsers) -> Arc<SharedUsers<TrojanUsers>> {
        self.inner.trojan.publish(users)
    }

    /// Publish an AnyTLS user table and return the handle for a listener.
    pub fn publish_anytls(&self, users: AnyTlsUsers) -> Arc<SharedUsers<AnyTlsUsers>> {
        self.inner.anytls.publish(users)
    }

    /// Publish a TUIC user table and return the handle for a listener.
    pub fn publish_tuic(&self, users: TuicUserTable) -> Arc<SharedUsers<TuicUserTable>> {
        self.inner.tuic.publish(users)
    }

    /// Publish a Hysteria2 user table and return the handle for a listener.
    pub fn publish_hysteria2(
        &self,
        users: Hysteria2UserTable,
    ) -> Arc<SharedUsers<Hysteria2UserTable>> {
        self.inner.hysteria2.publish(users)
    }

    /// Publish a NaiveProxy user table and return the handle for a listener.
    pub fn publish_naiveproxy(&self, users: UserLookup) -> Arc<SharedUsers<UserLookup>> {
        self.inner.naiveproxy.publish(users)
    }

    /// The Shadowsocks handle a listener was built with, if any.
    #[cfg(test)]
    pub fn shadowsocks(&self) -> Option<Arc<SharedUsers<ShadowsocksUsers>>> {
        self.inner.shadowsocks.get()
    }

    /// Whether any listener has been built against these tables yet. A
    /// users-only sync can only be applied in place once that has happened.
    pub fn is_published(&self) -> bool {
        self.inner.shadowsocks.get().is_some()
            || self.inner.vless.get().is_some()
            || self.inner.vmess.get().is_some()
            || self.inner.trojan.get().is_some()
            || self.inner.anytls.get().is_some()
            || self.inner.tuic.get().is_some()
            || self.inner.hysteria2.get().is_some()
            || self.inner.naiveproxy.get().is_some()
    }
}

impl std::fmt::Debug for NodeUserTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeUserTables")
            .field("published", &self.is_published())
            .finish()
    }
}
