//! Process-global cache of resolved `native.collection-envelope.v1` ports.
//!
//! Entries are keyed by origin, collection, port declaration identity, caller
//! fingerprint (the same digest as `caller_sha256`), content-head event id and
//! seq, authorization epoch, meta-tier digest, binding event seq, and the
//! server build. Seq and epoch can rewind after a restore or re-adoption under
//! the same `origin_db_id`; the head event UUID distinguishes those
//! coincidences. Schema-config and vocabulary writes move `meta_sha256` without
//! touching the content log or authorization epoch. A matching key can never
//! outlive a content, authorization, meta, or binding change; stale entries
//! become unreachable and age out under LRU bounds. Relation (governed SQL)
//! ports are never stored. Historical (`as_of`) renders never consult this
//! cache.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{json, Value};

use native_artifact_runtime::{mdx, mdx_v2};

const MAX_CACHE_ENTRIES: usize = 64;
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CollectionPortKey {
    pub origin_db_id: String,
    pub collection_id: String,
    pub declaration_sha256: String,
    pub caller_identity: String,
    pub snapshot_event_id: String,
    pub snapshot_event_seq: i64,
    pub authorization_revision: i64,
    pub meta_sha256: String,
    pub binding_event_seq: i64,
    pub build: String,
}

#[derive(Clone, Debug)]
pub(crate) struct CachedCollectionPort {
    pub envelope: Arc<Value>,
}

struct CacheEntry {
    value: CachedCollectionPort,
    bytes: usize,
    last_used: u64,
}

struct CollectionPortCache {
    entries: HashMap<CollectionPortKey, CacheEntry>,
    bytes: usize,
    clock: u64,
}

impl CollectionPortCache {
    fn with_bounds() -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            clock: 0,
        }
    }

    fn get(&mut self, key: &CollectionPortKey) -> Option<CachedCollectionPort> {
        self.clock = self.clock.saturating_add(1);
        let now = self.clock;
        let entry = self.entries.get_mut(key)?;
        entry.last_used = now;
        Some(entry.value.clone())
    }

    fn insert(
        &mut self,
        key: CollectionPortKey,
        value: CachedCollectionPort,
        payload_bytes: usize,
    ) {
        if let Some(replaced) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(replaced.bytes);
        }
        let bytes = key_bytes(&key).saturating_add(payload_bytes);
        if bytes > MAX_CACHE_BYTES {
            return;
        }
        self.clock = self.clock.saturating_add(1);
        self.entries.insert(
            key,
            CacheEntry {
                value,
                bytes,
                last_used: self.clock,
            },
        );
        self.bytes = self.bytes.saturating_add(bytes);
        while self.entries.len() > MAX_CACHE_ENTRIES || self.bytes > MAX_CACHE_BYTES {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            let Some(victim) = victim else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&victim) {
                self.bytes = self.bytes.saturating_sub(evicted.bytes);
            } else {
                break;
            }
        }
    }
}

fn key_bytes(key: &CollectionPortKey) -> usize {
    key.origin_db_id.len()
        + key.collection_id.len()
        + key.declaration_sha256.len()
        + key.caller_identity.len()
        + key.snapshot_event_id.len()
        + key.meta_sha256.len()
        + key.build.len()
        + std::mem::size_of::<i64>() * 3
}

fn cache() -> &'static Mutex<CollectionPortCache> {
    static CACHE: OnceLock<Mutex<CollectionPortCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(CollectionPortCache::with_bounds()))
}

fn lock() -> std::sync::MutexGuard<'static, CollectionPortCache> {
    cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn lookup(key: &CollectionPortKey) -> Option<CachedCollectionPort> {
    lock().get(key)
}

pub(crate) fn insert(key: CollectionPortKey, value: CachedCollectionPort, payload_bytes: usize) {
    lock().insert(key, value, payload_bytes);
}

pub(crate) fn declaration_identity(declaration: &mdx_v2::InputDecl) -> String {
    mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&json!({
        "envelope": declaration.envelope,
        "schema_sha256": declaration.schema_sha256,
        "relations": declaration.relations,
        "projection": declaration.projection,
    })))
}

pub(crate) fn server_build() -> String {
    format!("{}:{}", mdx_v2::ADAPTER_REVISION, crate::GIT_SHA)
}

#[cfg(test)]
pub(crate) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    let mut cache = lock();
    *cache = CollectionPortCache::with_bounds();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: usize) -> CollectionPortKey {
        CollectionPortKey {
            origin_db_id: "origin".into(),
            collection_id: format!("collection-{index}"),
            declaration_sha256: "decl".into(),
            caller_identity: "caller".into(),
            snapshot_event_id: "event-1".into(),
            snapshot_event_seq: 1,
            authorization_revision: 1,
            meta_sha256: "meta".into(),
            binding_event_seq: 1,
            build: "build".into(),
        }
    }

    fn envelope(index: usize) -> (CachedCollectionPort, usize) {
        let records = json!([{ "id": format!("record-{index}") }]);
        let payload_bytes = mdx_v2::canonical_json_bytes(&records).len();
        (
            CachedCollectionPort {
                envelope: Arc::new(json!({
                    "version": mdx_v2::COLLECTION_ENVELOPE,
                    "records": records,
                })),
            },
            payload_bytes,
        )
    }

    #[test]
    fn eviction_honours_entry_and_byte_bounds() {
        let mut cache = CollectionPortCache::with_bounds();
        let (zero, zero_bytes) = envelope(0);
        let (one, one_bytes) = envelope(1);
        cache.insert(key(0), zero, zero_bytes);
        cache.insert(key(1), one, one_bytes);
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.get(&key(0)).is_some(), "touch oldest");
        for index in 2..MAX_CACHE_ENTRIES {
            let (value, bytes) = envelope(index);
            cache.insert(key(index), value, bytes);
        }
        assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
        let (overflow, overflow_bytes) = envelope(MAX_CACHE_ENTRIES);
        cache.insert(key(MAX_CACHE_ENTRIES), overflow, overflow_bytes);
        assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
        assert!(cache.get(&key(0)).is_some(), "recently used survives");
        assert!(cache.get(&key(1)).is_none(), "least recently used evicts");

        let mut tight = CollectionPortCache {
            entries: HashMap::new(),
            bytes: 0,
            clock: 0,
        };
        let (zero, zero_bytes) = envelope(0);
        tight.insert(key(0), zero, zero_bytes);
        assert_eq!(tight.entries.len(), 1);
        let oversized = CachedCollectionPort {
            envelope: Arc::new(
                json!({ "records": ["x".repeat(MAX_CACHE_BYTES.saturating_mul(2))] }),
            ),
        };
        tight.insert(key(1), oversized, MAX_CACHE_BYTES.saturating_add(1));
        assert_eq!(tight.entries.len(), 1, "oversized insert is refused");
        assert!(tight.get(&key(0)).is_some());
        assert!(tight.get(&key(1)).is_none());
    }

    #[test]
    fn different_declaration_identity_is_a_distinct_key() {
        let mut cache = CollectionPortCache::with_bounds();
        let mut left = key(0);
        left.collection_id = "shared".into();
        left.declaration_sha256 = "collection".into();
        let mut right = left.clone();
        right.declaration_sha256 = "grouped-count".into();
        let (value, bytes) = envelope(0);
        cache.insert(left.clone(), value, bytes);
        assert!(cache.get(&left).is_some());
        assert!(
            cache.get(&right).is_none(),
            "a different port declaration on the same collection misses"
        );
    }

    #[test]
    fn distinct_head_event_ids_at_equal_seq_and_epoch_never_share_an_entry() {
        let mut cache = CollectionPortCache::with_bounds();
        let mut left = key(0);
        left.origin_db_id = "shared-origin".into();
        left.collection_id = "shared".into();
        left.snapshot_event_id = "event-a".into();
        left.snapshot_event_seq = 42;
        left.authorization_revision = 7;
        let mut right = left.clone();
        right.snapshot_event_id = "event-b".into();
        let (value, bytes) = envelope(0);
        cache.insert(left.clone(), value, bytes);
        assert!(cache.get(&left).is_some());
        assert!(
            cache.get(&right).is_none(),
            "equal seq and epoch under the same origin must not revive a different head event"
        );
    }

    #[test]
    fn distinct_meta_digests_never_share_an_entry() {
        let mut cache = CollectionPortCache::with_bounds();
        let mut left = key(0);
        left.meta_sha256 = "meta-a".into();
        let mut right = left.clone();
        right.meta_sha256 = "meta-b".into();
        let (value, bytes) = envelope(0);
        cache.insert(left.clone(), value, bytes);
        assert!(cache.get(&left).is_some());
        assert!(cache.get(&right).is_none());
    }

    #[test]
    fn distinct_binding_event_seqs_never_share_an_entry() {
        let mut cache = CollectionPortCache::with_bounds();
        let mut left = key(0);
        left.collection_id = "shared".into();
        left.binding_event_seq = 10;
        let mut right = left.clone();
        right.binding_event_seq = 20;
        let (value, bytes) = envelope(0);
        cache.insert(left.clone(), value, bytes);
        assert!(cache.get(&left).is_some());
        assert!(
            cache.get(&right).is_none(),
            "the same collection at two bindings must not restore the other seq"
        );
    }
}
