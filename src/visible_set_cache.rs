//! Per-principal visible-record-id cache (Tier 1.4, record `fd6c1f2`).
//!
//! Key: the principal bits the visibility view actually reads
//! (`credential`, `trusted_local_bypass`, `activity_read`, `is_member`) plus
//! two exact fences — `authorization_epoch` and `unit_seq_max`
//! (`COALESCE(MAX(creation_event_seq), 0)` over `semantic_units`).
//!
//! Why two fences: the visibility view excludes records whose authorization
//! subject appears in `semantic_units`, but no epoch trigger covers that
//! table — `project_unit_created` only `touch()`es `updated_at` /
//! `last_activity_at`, which are outside the trigger column list. A
//! unit-created projection can therefore flip a derived artifact from visible
//! to hidden with the epoch unmoved. Every live unit insertion takes its
//! `creation_event_seq` from the `AUTOINCREMENT` content log, so the max only
//! moves up; rows die only via record-DELETE cascade, which bumps the epoch.
//! The pair is exact on the SQLite live path (proof on `fd6c1f2`).
//!
//! `activity_read` does not affect the visible set (it gates only the
//! activity views) and the activity roster never reaches the view at all; both
//! are keyed (roster by exclusion, documented) so a future view change fails
//! safe toward misses rather than cross-principal reuse.
//!
//! Bound: LRU over entries and estimated bytes. An entry that alone exceeds
//! the byte cap is refused, never truncated — the caller falls back to live
//! evaluation. Worst case per handle is one refused-sized workspace plus the
//! cap, mirroring the snapshot store precedent.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

/// Entries held per database handle. Eight principals cover the realistic
/// concurrent-viewer set; the ninth distinct principal evicts the stalest.
pub(crate) const VISIBLE_SET_CACHE_MAX_ENTRIES: usize = 8;
/// Total estimated bytes across held sets per handle. Matches the workspace
/// index / snapshot-token budget deliberately: the cache can never hold more
/// than one more refused-sized index worth of ids.
pub(crate) const VISIBLE_SET_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Per-id overhead estimate for the `HashSet` node (string inline storage
/// plus hashing bookkeeping). Approximate on purpose: it gates the refusal
/// bound, not an allocator report.
const BYTES_PER_ID_OVERHEAD: usize = 64;

/// Exact cache key. Every field the visibility view reads about the caller,
/// plus every fence a supported write can move under the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VisibleSetCacheKey {
    pub credential: String,
    pub trusted_local_bypass: bool,
    pub activity_read: bool,
    pub is_member: bool,
    pub authorization_epoch: i64,
    pub unit_seq_max: i64,
}

#[derive(Debug)]
struct VisibleSetCacheEntry {
    key: VisibleSetCacheKey,
    // Shared ownership: hits clone the `Arc` (O(1)) instead of the set, so
    // a 50k-id hit never copies under the handle mutex.
    ids: Arc<HashSet<String>>,
    bytes: usize,
}

/// LRU visible-id sets for one `Db` handle. Clones share it through the
/// handle; reopening the same file starts cold.
#[derive(Debug, Default)]
pub(crate) struct VisibleSetCache {
    entries: VecDeque<VisibleSetCacheEntry>,
    bytes: usize,
    hits: u64,
    misses: u64,
}

fn entry_bytes(key: &VisibleSetCacheKey, ids: &HashSet<String>) -> usize {
    key.credential.len()
        + ids
            .iter()
            .map(|id| id.len() + BYTES_PER_ID_OVERHEAD)
            .sum::<usize>()
}

impl VisibleSetCache {
    /// Return the cached id set, recording a hit. The `Arc` clone is O(1);
    /// fence comparison is exact equality — no recency heuristic.
    pub(crate) fn get(&mut self, key: &VisibleSetCacheKey) -> Option<Arc<HashSet<String>>> {
        let index = self.entries.iter().position(|entry| &entry.key == key)?;
        let entry = self.entries.remove(index)?;
        let ids = Arc::clone(&entry.ids);
        self.entries.push_back(entry);
        self.hits += 1;
        Some(ids)
    }

    /// Store one evaluated set. Returns `false` (refused, caller stays on the
    /// live answer) when the single entry exceeds the byte cap; never stores
    /// a subset.
    pub(crate) fn insert(&mut self, key: VisibleSetCacheKey, ids: Arc<HashSet<String>>) -> bool {
        let bytes = entry_bytes(&key, &ids);
        if bytes > VISIBLE_SET_CACHE_MAX_BYTES {
            return false;
        }
        if let Some(index) = self.entries.iter().position(|entry| entry.key == key) {
            if let Some(replaced) = self.entries.remove(index) {
                self.bytes = self.bytes.saturating_sub(replaced.bytes);
            }
        }
        self.entries
            .push_back(VisibleSetCacheEntry { key, ids, bytes });
        self.bytes += bytes;
        while self.entries.len() > VISIBLE_SET_CACHE_MAX_ENTRIES
            || self.bytes > VISIBLE_SET_CACHE_MAX_BYTES
        {
            if let Some(evicted) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(evicted.bytes);
            } else {
                break;
            }
        }
        true
    }

    /// Record a lookup that found no entry (the caller evaluates live).
    /// Separate from `get` so miss accounting survives the live-fallback path.
    pub(crate) fn record_miss(&mut self) {
        self.misses += 1;
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(credential: &str, epoch: i64, unit_max: i64) -> VisibleSetCacheKey {
        VisibleSetCacheKey {
            credential: credential.to_string(),
            trusted_local_bypass: false,
            activity_read: false,
            is_member: true,
            authorization_epoch: epoch,
            unit_seq_max: unit_max,
        }
    }

    #[test]
    fn epoch_or_unit_move_is_a_miss_not_a_reuse() {
        let mut cache = VisibleSetCache::default();
        let ids: HashSet<String> = ["a".to_string()].into_iter().collect();
        assert!(cache.insert(key("alice", 7, 3), Arc::new(ids)));
        // Same epoch, unit fence moved: miss.
        assert!(cache.get(&key("alice", 7, 4)).is_none());
        // Same unit fence, epoch moved: miss.
        assert!(cache.get(&key("alice", 8, 3)).is_none());
        // Exact fences: hit.
        assert!(cache.get(&key("alice", 7, 3)).is_some());
        // Another principal never reuses the entry.
        assert!(cache.get(&key("bea", 7, 3)).is_none());
        let (hits, misses) = cache.stats();
        assert_eq!((hits, misses), (1, 0));
    }

    #[test]
    fn oversize_entry_is_refused_never_truncated() {
        let mut cache = VisibleSetCache::default();
        let big: HashSet<String> = ["x".repeat(VISIBLE_SET_CACHE_MAX_BYTES)]
            .into_iter()
            .collect();
        assert!(!cache.insert(key("alice", 1, 0), Arc::new(big)));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn hits_share_the_set_without_copying() {
        let mut cache = VisibleSetCache::default();
        let ids: HashSet<String> = ["a".to_string()].into_iter().collect();
        assert!(cache.insert(key("alice", 7, 3), Arc::new(ids)));
        let first = cache.get(&key("alice", 7, 3)).unwrap();
        let second = cache.get(&key("alice", 7, 3)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(first.contains("a"));
    }

    #[test]
    fn entries_evict_least_recently_used() {
        let mut cache = VisibleSetCache::default();
        for index in 0..VISIBLE_SET_CACHE_MAX_ENTRIES {
            let ids: HashSet<String> = [format!("id-{index}")].into_iter().collect();
            assert!(cache.insert(key(&format!("principal-{index}"), 1, 0), Arc::new(ids)));
        }
        assert_eq!(cache.len(), VISIBLE_SET_CACHE_MAX_ENTRIES);
        // Touch the stalest entry so it survives; the next insert evicts the
        // second-oldest instead.
        assert!(cache.get(&key("principal-0", 1, 0)).is_some());
        let ids: HashSet<String> = ["new".to_string()].into_iter().collect();
        assert!(cache.insert(key("new-principal", 1, 0), Arc::new(ids)));
        assert_eq!(cache.len(), VISIBLE_SET_CACHE_MAX_ENTRIES);
        assert!(cache.get(&key("principal-0", 1, 0)).is_some());
        assert!(cache.get(&key("principal-1", 1, 0)).is_none());
        assert!(cache.get(&key("new-principal", 1, 0)).is_some());
    }

    #[test]
    fn bytes_evict_oldest_first() {
        let mut cache = VisibleSetCache::default();
        // Each entry carries ~1/4 of the byte cap, so the fifth insert must
        // evict down to a within-cap suffix rather than refuse.
        let chunk = "x".repeat(VISIBLE_SET_CACHE_MAX_BYTES / 4);
        for index in 0..5 {
            let ids: HashSet<String> = [format!("{chunk}-{index}")].into_iter().collect();
            assert!(cache.insert(key(&format!("principal-{index}"), 1, 0), Arc::new(ids)));
        }
        assert!(cache.len() < 5);
        assert!(cache.get(&key("principal-4", 1, 0)).is_some());
        assert!(cache.get(&key("principal-0", 1, 0)).is_none());
    }
}
