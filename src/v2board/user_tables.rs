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

use parking_lot::{Mutex, RwLock};

use crate::anytls::AnyTlsUsers;
use crate::hysteria2_server::Hysteria2UserTable;
use crate::naiveproxy::UserLookup;
use crate::shadowsocks::{ShadowsocksUsers, SharedSaltChecker, new_shared_salt_checker};
use crate::shared_users::SharedUsers;
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
    shadowsocks: TableSlot<ShadowsocksUsers>,
    vless: TableSlot<VlessUsers>,
    vmess: TableSlot<VmessUsers>,
    trojan: TableSlot<TrojanUsers>,
    anytls: TableSlot<AnyTlsUsers>,
    tuic: TableSlot<TuicUserTable>,
    hysteria2: TableSlot<Hysteria2UserTable>,
    naiveproxy: TableSlot<UserLookup>,
    /// Shared by every Shadowsocks generation of this node; see
    /// [`NodeUserTables::shadowsocks_salt_checker`].
    shadowsocks_salt_checker: OnceLock<SharedSaltChecker>,
}

/// A small local equivalent of [`crate::shared_users::SharedUsersSlot`] with a two-phase install
/// operation.  The generic slot in `shared_users.rs` deliberately only
/// exposes immediate publication; the V2Board mapper needs to construct a
/// listener against a new handle without making that handle visible until the
/// runtime graph has passed its health gate.
#[derive(Debug)]
struct TableSlot<T> {
    shared: RwLock<Option<Arc<SharedUsers<T>>>>,
}

impl<T> Default for TableSlot<T> {
    fn default() -> Self {
        Self {
            shared: RwLock::new(None),
        }
    }
}

impl<T> TableSlot<T> {
    fn get(&self) -> Option<Arc<SharedUsers<T>>> {
        self.shared.read().clone()
    }

    fn publish(&self, users: T) -> Arc<SharedUsers<T>> {
        if let Some(shared) = self.get() {
            shared.store(users);
            return shared;
        }
        let mut slot = self.shared.write();
        if let Some(shared) = slot.as_ref() {
            let shared = shared.clone();
            drop(slot);
            shared.store(users);
            return shared;
        }
        let shared = SharedUsers::new(users);
        *slot = Some(shared.clone());
        shared
    }

    fn prepare(&self, users: T) -> PreparedTable<T> {
        if let Some(shared) = self.get() {
            return PreparedTable {
                shared,
                pending: Some(users),
                install: false,
            };
        }
        PreparedTable {
            shared: SharedUsers::new(users),
            pending: None,
            install: true,
        }
    }

    fn install(&self, shared: Arc<SharedUsers<T>>) {
        let mut slot = self.shared.write();
        if slot.is_none() {
            *slot = Some(shared);
        } else {
            // A transaction is committed under the controller sync gate, so
            // this branch is only a defensive fallback for a future caller
            // that races a first publication. Keep the already published
            // handle authoritative and update it below through `publish`.
            drop(slot);
        }
    }
}

struct PreparedTable<T> {
    shared: Arc<SharedUsers<T>>,
    pending: Option<T>,
    install: bool,
}

#[derive(Default)]
struct PendingTables {
    shadowsocks: Option<PreparedTable<ShadowsocksUsers>>,
    vless: Option<PreparedTable<VlessUsers>>,
    vmess: Option<PreparedTable<VmessUsers>>,
    trojan: Option<PreparedTable<TrojanUsers>>,
    anytls: Option<PreparedTable<AnyTlsUsers>>,
    tuic: Option<PreparedTable<TuicUserTable>>,
    hysteria2: Option<PreparedTable<Hysteria2UserTable>>,
    naiveproxy: Option<PreparedTable<UserLookup>>,
}

/// A table publication transaction.  Listener construction receives the
/// shared handle immediately, but replacement of an existing handle (or
/// installation of a new one) is deferred until [`Self::commit`]. Dropping a
/// transaction is an abort and has no effect on live listeners.
pub struct NodeUserTablesTxn {
    tables: NodeUserTables,
    pending: Mutex<PendingTables>,
}

impl std::fmt::Debug for NodeUserTablesTxn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeUserTablesTxn").finish_non_exhaustive()
    }
}

impl NodeUserTablesTxn {
    pub fn commit(self) {
        let pending = self.pending.into_inner();
        let slots = &self.tables.inner;
        commit_table(&slots.shadowsocks, pending.shadowsocks);
        commit_table(&slots.vless, pending.vless);
        commit_table(&slots.vmess, pending.vmess);
        commit_table(&slots.trojan, pending.trojan);
        commit_table(&slots.anytls, pending.anytls);
        commit_table(&slots.tuic, pending.tuic);
        commit_table(&slots.hysteria2, pending.hysteria2);
        commit_table(&slots.naiveproxy, pending.naiveproxy);
    }

    pub fn abort(self) {
        drop(self);
    }

    fn publish<T>(
        &self,
        pending: &mut Option<PreparedTable<T>>,
        slot: &TableSlot<T>,
        users: T,
    ) -> Arc<SharedUsers<T>> {
        if let Some(existing) = pending.as_mut() {
            // A protocol normally publishes exactly once per graph. If a
            // future builder publishes twice, retain the same candidate
            // handle and make the last table the committed value. Do not
            // store here: an existing handle is live and must remain old until
            // commit, while a new handle is not visible yet.
            existing.pending = Some(users);
            return existing.shared.clone();
        }
        let prepared = slot.prepare(users);
        let shared = prepared.shared.clone();
        *pending = Some(prepared);
        shared
    }
}

fn commit_table<T>(slot: &TableSlot<T>, pending: Option<PreparedTable<T>>) {
    let Some(prepared) = pending else { return };
    if prepared.install {
        if let Some(users) = prepared.pending {
            prepared.shared.store(users);
        }
        slot.install(prepared.shared);
    } else if let Some(users) = prepared.pending {
        prepared.shared.store(users);
    }
}

/// The mapper's user-table publication seam.  Keeping this object-safe lets
/// the existing immediate APIs and deferred graph construction share every
/// protocol builder without duplicating the large dispatch tree.
pub trait UserTableSink {
    fn publish_shadowsocks(&self, users: ShadowsocksUsers) -> Arc<SharedUsers<ShadowsocksUsers>>;
    fn publish_vless(&self, users: VlessUsers) -> Arc<SharedUsers<VlessUsers>>;
    fn publish_vmess(&self, users: VmessUsers) -> Arc<SharedUsers<VmessUsers>>;
    fn publish_trojan(&self, users: TrojanUsers) -> Arc<SharedUsers<TrojanUsers>>;
    fn publish_anytls(&self, users: AnyTlsUsers) -> Arc<SharedUsers<AnyTlsUsers>>;
    fn publish_tuic(&self, users: TuicUserTable) -> Arc<SharedUsers<TuicUserTable>>;
    fn publish_hysteria2(&self, users: Hysteria2UserTable) -> Arc<SharedUsers<Hysteria2UserTable>>;
    fn publish_naiveproxy(&self, users: UserLookup) -> Arc<SharedUsers<UserLookup>>;
    fn shadowsocks(&self) -> Option<Arc<SharedUsers<ShadowsocksUsers>>>;
    fn shadowsocks_salt_checker(&self) -> SharedSaltChecker;
}

impl NodeUserTables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a deferred publication transaction for a runtime candidate.
    pub fn transaction(&self) -> NodeUserTablesTxn {
        NodeUserTablesTxn {
            tables: self.clone(),
            pending: Mutex::new(PendingTables::default()),
        }
    }

    /// Explicit alias used by callers that model the publication as a
    /// begin/commit/abort transaction.
    pub fn begin(&self) -> NodeUserTablesTxn {
        self.transaction()
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

impl UserTableSink for NodeUserTables {
    fn publish_shadowsocks(&self, users: ShadowsocksUsers) -> Arc<SharedUsers<ShadowsocksUsers>> {
        self.inner.shadowsocks.publish(users)
    }

    fn publish_vless(&self, users: VlessUsers) -> Arc<SharedUsers<VlessUsers>> {
        self.inner.vless.publish(users)
    }

    fn publish_vmess(&self, users: VmessUsers) -> Arc<SharedUsers<VmessUsers>> {
        self.inner.vmess.publish(users)
    }

    fn publish_trojan(&self, users: TrojanUsers) -> Arc<SharedUsers<TrojanUsers>> {
        self.inner.trojan.publish(users)
    }

    fn publish_anytls(&self, users: AnyTlsUsers) -> Arc<SharedUsers<AnyTlsUsers>> {
        self.inner.anytls.publish(users)
    }

    fn publish_tuic(&self, users: TuicUserTable) -> Arc<SharedUsers<TuicUserTable>> {
        self.inner.tuic.publish(users)
    }

    fn publish_hysteria2(&self, users: Hysteria2UserTable) -> Arc<SharedUsers<Hysteria2UserTable>> {
        self.inner.hysteria2.publish(users)
    }

    fn publish_naiveproxy(&self, users: UserLookup) -> Arc<SharedUsers<UserLookup>> {
        self.inner.naiveproxy.publish(users)
    }

    fn shadowsocks(&self) -> Option<Arc<SharedUsers<ShadowsocksUsers>>> {
        self.shadowsocks()
    }

    fn shadowsocks_salt_checker(&self) -> SharedSaltChecker {
        self.shadowsocks_salt_checker()
    }
}

impl UserTableSink for NodeUserTablesTxn {
    fn publish_shadowsocks(&self, users: ShadowsocksUsers) -> Arc<SharedUsers<ShadowsocksUsers>> {
        let mut pending = self.pending.lock();
        self.publish(
            &mut pending.shadowsocks,
            &self.tables.inner.shadowsocks,
            users,
        )
    }

    fn publish_vless(&self, users: VlessUsers) -> Arc<SharedUsers<VlessUsers>> {
        let mut pending = self.pending.lock();
        self.publish(&mut pending.vless, &self.tables.inner.vless, users)
    }

    fn publish_vmess(&self, users: VmessUsers) -> Arc<SharedUsers<VmessUsers>> {
        let mut pending = self.pending.lock();
        self.publish(&mut pending.vmess, &self.tables.inner.vmess, users)
    }

    fn publish_trojan(&self, users: TrojanUsers) -> Arc<SharedUsers<TrojanUsers>> {
        let mut pending = self.pending.lock();
        self.publish(&mut pending.trojan, &self.tables.inner.trojan, users)
    }

    fn publish_anytls(&self, users: AnyTlsUsers) -> Arc<SharedUsers<AnyTlsUsers>> {
        let mut pending = self.pending.lock();
        self.publish(&mut pending.anytls, &self.tables.inner.anytls, users)
    }

    fn publish_tuic(&self, users: TuicUserTable) -> Arc<SharedUsers<TuicUserTable>> {
        let mut pending = self.pending.lock();
        self.publish(&mut pending.tuic, &self.tables.inner.tuic, users)
    }

    fn publish_hysteria2(&self, users: Hysteria2UserTable) -> Arc<SharedUsers<Hysteria2UserTable>> {
        let mut pending = self.pending.lock();
        self.publish(&mut pending.hysteria2, &self.tables.inner.hysteria2, users)
    }

    fn publish_naiveproxy(&self, users: UserLookup) -> Arc<SharedUsers<UserLookup>> {
        let mut pending = self.pending.lock();
        self.publish(
            &mut pending.naiveproxy,
            &self.tables.inner.naiveproxy,
            users,
        )
    }

    fn shadowsocks(&self) -> Option<Arc<SharedUsers<ShadowsocksUsers>>> {
        self.tables.shadowsocks()
    }

    fn shadowsocks_salt_checker(&self) -> SharedSaltChecker {
        self.tables.shadowsocks_salt_checker()
    }
}

impl std::fmt::Debug for NodeUserTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeUserTables")
            .field("published", &self.is_published())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::ShadowsocksCipher;
    use crate::tcp::tcp_handler::AuthenticatedUser;

    fn table(uid: u64) -> ShadowsocksUsers {
        let cipher: ShadowsocksCipher = "aes-128-gcm".try_into().unwrap();
        ShadowsocksUsers::legacy(
            &cipher,
            vec![crate::tcp::tcp_handler::ServerUser {
                credential: format!("password-{uid}"),
                authenticated_user: AuthenticatedUser {
                    node_tag: Arc::from("test"),
                    uid,
                    user_key: Arc::from(format!("key-{uid}")),
                    speed_limit: None,
                    device_limit: None,
                    recorder: None,
                    dedicated_ip: None,
                },
            }],
        )
    }

    #[test]
    fn aborted_transaction_keeps_existing_table_and_handle() {
        let tables = NodeUserTables::new();
        let current = tables.publish_shadowsocks(table(1));
        let txn = tables.transaction();
        let candidate = txn.publish_shadowsocks(table(2));

        assert!(Arc::ptr_eq(&current, &candidate));
        assert_eq!(current.load().len(), 1);
        assert!(current.load().contains_uid(1));
        txn.abort();
        assert!(
            tables
                .shadowsocks()
                .is_some_and(|shared| Arc::ptr_eq(&shared, &current))
        );
        assert!(current.load().contains_uid(1));
        assert!(!current.load().contains_uid(2));
    }

    #[test]
    fn committed_transaction_publishes_into_existing_handle() {
        let tables = NodeUserTables::new();
        let current = tables.publish_shadowsocks(table(1));
        let txn = tables.transaction();
        let candidate = txn.publish_shadowsocks(table(2));
        txn.commit();

        assert!(Arc::ptr_eq(&current, &candidate));
        assert!(current.load().contains_uid(2));
        assert!(!current.load().contains_uid(1));
    }

    #[test]
    fn aborted_transaction_does_not_install_a_new_slot() {
        let tables = NodeUserTables::new();
        let txn = tables.transaction();
        let candidate = txn.publish_shadowsocks(table(7));
        assert!(candidate.load().contains_uid(7));
        assert!(tables.shadowsocks().is_none());
        txn.abort();
        assert!(tables.shadowsocks().is_none());
    }

    #[test]
    fn duplicate_publication_overwrites_only_the_pending_candidate() {
        let tables = NodeUserTables::new();
        let current = tables.publish_shadowsocks(table(1));
        let txn = tables.transaction();
        txn.publish_shadowsocks(table(2));
        txn.publish_shadowsocks(table(3));
        assert!(current.load().contains_uid(1));
        assert!(!current.load().contains_uid(3));
        txn.commit();
        assert!(current.load().contains_uid(3));
        assert!(!current.load().contains_uid(2));
    }
}
