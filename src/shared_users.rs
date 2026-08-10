//! A user table that a running listener shares with the control plane.
//!
//! V2Board nodes re-publish their whole user list on every pull, and on a busy
//! node that list changes almost every interval. Rebuilding the listener stack
//! for each change is both wasteful and, worse, unbounded in memory: every
//! accepted connection holds an `Arc` to the handler that accepted it, so each
//! superseded generation stays resident until its last connection closes, and a
//! single stuck connection pins one forever. With a node carrying tens of
//! thousands of users -- let alone millions -- that retention dominates the
//! process heap.
//!
//! [`SharedUsers`] removes the coupling. A handler holds the container, not the
//! table, so a user-list change is a pointer swap: superseded tables are freed
//! as soon as the in-flight handshakes reading them finish, regardless of how
//! long the connections they authenticated live. Handlers built by later
//! generations share the same container, so even a genuine listener rebuild
//! (a server-config change) never duplicates the table.
//!
//! Authentication must therefore borrow the table only for the lookup itself
//! -- see [`SharedUsers::load`] -- and copy out the matched user's own
//! credentials. Holding the returned `Arc` for the lifetime of a connection
//! would reintroduce exactly the retention this type exists to prevent.

use std::sync::Arc;

use parking_lot::RwLock;

/// A replaceable table of authenticated users.
///
/// Cheap to clone as `Arc<SharedUsers<T>>`; every clone observes replacements.
#[derive(Debug)]
pub struct SharedUsers<T> {
    current: RwLock<Arc<T>>,
}

impl<T> SharedUsers<T> {
    pub fn new(users: T) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(Arc::new(users)),
        })
    }

    /// Borrow the table currently in effect.
    ///
    /// Drop the result as soon as the lookup is done: the previous table is
    /// freed only once no borrow of it remains.
    pub fn load(&self) -> Arc<T> {
        self.current.read().clone()
    }

    /// Publish a new table. Connections already authenticated keep running
    /// against the credentials they were admitted with; the next lookup sees
    /// the new table.
    pub fn store(&self, users: T) {
        let users = Arc::new(users);
        // Swap under the lock but drop the old table outside it, so freeing a
        // large table never blocks concurrent authentications.
        let previous = std::mem::replace(&mut *self.current.write(), users);
        drop(previous);
    }
}

/// A lazily created handle to one protocol's user table.
///
/// The control plane keeps a slot per protocol for the lifetime of the node.
/// The first publish creates the container that listeners are handed; every
/// later publish stores into that same container, so listeners built by later
/// runtime generations observe user changes without being rebuilt.
#[derive(Debug)]
pub struct SharedUsersSlot<T> {
    shared: RwLock<Option<Arc<SharedUsers<T>>>>,
}

impl<T> SharedUsersSlot<T> {
    /// Publish a table and return the handle to give to a listener.
    pub fn publish(&self, users: T) -> Arc<SharedUsers<T>> {
        let existing = self.shared.read().clone();
        if let Some(shared) = existing {
            shared.store(users);
            return shared;
        }
        let mut slot = self.shared.write();
        match slot.as_ref() {
            Some(shared) => {
                let shared = shared.clone();
                drop(slot);
                shared.store(users);
                shared
            }
            None => {
                let shared = SharedUsers::new(users);
                *slot = Some(shared.clone());
                shared
            }
        }
    }

    /// The handle already published, if any. `None` before the first publish,
    /// which means no listener has been built for this protocol yet.
    pub fn get(&self) -> Option<Arc<SharedUsers<T>>> {
        self.shared.read().clone()
    }
}

impl<T> Default for SharedUsersSlot<T> {
    fn default() -> Self {
        Self {
            shared: RwLock::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_reuses_the_same_container_across_publishes() {
        let slot: SharedUsersSlot<Vec<u32>> = SharedUsersSlot::default();
        assert!(slot.get().is_none());

        let first = slot.publish(vec![1]);
        let second = slot.publish(vec![2, 3]);

        // A later generation must be handed the same container, otherwise
        // listeners would keep observing the table they were built with.
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.load().as_slice(), [2, 3]);
    }

    #[test]
    fn store_replaces_the_visible_table() {
        let users = SharedUsers::new(vec!["a".to_string()]);
        assert_eq!(users.load().as_slice(), ["a".to_string()]);

        users.store(vec!["b".to_string(), "c".to_string()]);
        assert_eq!(users.load().as_slice(), ["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn replaced_table_is_freed_once_borrows_end() {
        let users = SharedUsers::new(vec![1_u32, 2, 3]);
        let borrowed = users.load();
        assert_eq!(Arc::strong_count(&borrowed), 2);

        users.store(vec![9_u32]);
        // The container no longer refers to the old table; only this borrow
        // keeps it alive, and dropping it releases the memory.
        assert_eq!(Arc::strong_count(&borrowed), 1);
        drop(borrowed);
        assert_eq!(users.load().as_slice(), [9_u32]);
    }

    #[test]
    fn clones_of_the_container_observe_replacements() {
        let users = SharedUsers::new(0_u32);
        let listener_copy = Arc::clone(&users);

        users.store(42);

        assert_eq!(*listener_copy.load(), 42);
    }
}
