//! An in-memory [`Store`] backed by a shared map. Clones share the same
//! underlying data, so a `MemoryStore` can stand in for a durable store
//! shared between multiple servers in tests, or serve as an ephemeral
//! store where durability is not required.
//!
//! Unlike a filesystem, an in-memory map can perform a real compare-and-set,
//! so `set_if_unchanged` is implemented atomically here rather than falling
//! back to the trait's unconditional default.

use super::{Result, Store, StoreError, WriteLease};
use async_trait::async_trait;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct MemoryStore {
    data: Arc<DashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct (non-trait) read of a stored value, for assertions.
    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.data.get(key).map(|v| v.value().clone())
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.data.get(key).map(|v| v.value().clone()))
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.data.insert(key.to_owned(), value);
        Ok(())
    }

    /// A real compare-and-set: the entry API holds the shard lock across
    /// both the comparison and the write, so no other writer can land in
    /// between. An in-memory map can offer this; a filesystem cannot, which
    /// is why the trait default writes unconditionally rather than
    /// emulating a CAS with a read.
    async fn set_if_unchanged(
        &self,
        key: &str,
        value: Vec<u8>,
        lease: &WriteLease,
    ) -> Result<WriteLease> {
        let conflict = || StoreError::LeaseConflict(format!("{} changed since it was read", key));
        match self.data.entry(key.to_owned()) {
            Entry::Occupied(mut entry) => {
                if *lease != WriteLease::for_value(Some(entry.get().as_slice())) {
                    return Err(conflict());
                }
                let next = WriteLease::for_value(Some(&value));
                entry.insert(value);
                Ok(next)
            }
            Entry::Vacant(entry) => {
                if *lease != WriteLease::Missing {
                    return Err(conflict());
                }
                let next = WriteLease::for_value(Some(&value));
                entry.insert(value);
                Ok(next)
            }
        }
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.data.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.data.contains_key(key))
    }
}
