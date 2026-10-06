//! Ephemeral, viewer-scoped fingerprints for declared on-request SQL keys.
//!
//! A table touch may schedule a comparison, but only a changed result digest
//! may advance a fingerprint or produce a hint. This state is owned by its
//! snapshot subscription and disappears with that subscription. Each
//! declared key (`graph.neighbours`, `folders.children`, `browse.children`)
//! holds its own 32-variant LRU so one key's session load can never evict
//! another.

use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};

pub const GRAPH_NEIGHBOURS_KEY: &str = "graph.neighbours";
pub const FOLDERS_CHILDREN_KEY: &str = "folders.children";
pub const BROWSE_CHILDREN_KEY: &str = "browse.children";
pub const MAX_VARIANTS_PER_KEY: usize = 32;

/// Declared on-request keys with keyed freshness. Graph and Folders
/// behaviour is retained; the independently authored Browse package's
/// children key is the third supported key, with its own variant LRU.
pub fn is_keyed_read_key(key: &str) -> bool {
    key == GRAPH_NEIGHBOURS_KEY || key == FOLDERS_CHILDREN_KEY || key == BROWSE_CHILDREN_KEY
}

/// Opaque handle returned with a governed read and echoed as the hint's
/// `key`. It names a declared need plus one parameter variant without
/// putting raw parameter values on the stream.
pub fn variant_handle(key: &str, params_digest: &str) -> String {
    format!("{key}:{params_digest}")
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyedFingerprint {
    pub key: String,
    pub params: Value,
    pub params_digest: String,
    pub revision: String,
    pub relations: std::collections::BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
struct PerKeyState {
    // Oldest first. Re-reading a variant moves it to the back.
    variants: VecDeque<KeyedFingerprint>,
    evicted: bool,
}

#[derive(Clone, Debug, Default)]
pub struct KeyedFreshness {
    keys: BTreeMap<String, PerKeyState>,
}

impl KeyedFreshness {
    /// Admit a governed read. An eviction is an explicit pull-only fallback
    /// for the displaced params of that declared key until they are read
    /// again. Returns true when this admission displaced a variant.
    pub fn admit(&mut self, fingerprint: KeyedFingerprint) -> bool {
        let state = self.keys.entry(fingerprint.key.clone()).or_default();
        if let Some(index) = state
            .variants
            .iter()
            .position(|item| item.params_digest == fingerprint.params_digest)
        {
            state.variants.remove(index);
        }
        state.variants.push_back(fingerprint);
        if state.variants.len() > MAX_VARIANTS_PER_KEY {
            state.variants.pop_front();
            state.evicted = true;
            return true;
        }
        false
    }

    pub fn evicted(&self, key: &str) -> bool {
        self.keys.get(key).is_some_and(|state| state.evicted)
    }

    pub fn evicted_keys(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(_, state)| state.evicted)
            .map(|(key, _)| key.clone())
            .collect()
    }

    pub fn variants(&self) -> impl Iterator<Item = &KeyedFingerprint> {
        self.keys.values().flat_map(|state| state.variants.iter())
    }

    pub fn variants_for(&self, key: &str) -> impl Iterator<Item = &KeyedFingerprint> {
        self.keys
            .get(key)
            .into_iter()
            .flat_map(|state| state.variants.iter())
    }

    pub fn variants_with_key(&self) -> impl Iterator<Item = (&str, &KeyedFingerprint)> {
        self.keys.iter().flat_map(|(key, state)| {
            state
                .variants
                .iter()
                .map(move |variant| (key.as_str(), variant))
        })
    }

    /// A hidden-only write produces the same viewer-visible result revision:
    /// no state moves, including the LRU order, and no signal is authorized.
    pub fn changed(&self, key: &str, params_digest: &str, revision: &str) -> bool {
        self.keys.get(key).is_some_and(|state| {
            state
                .variants
                .iter()
                .any(|item| item.params_digest == params_digest && item.revision != revision)
        })
    }

    pub fn revision(&self, key: &str, params_digest: &str) -> Option<&str> {
        self.keys.get(key).and_then(|state| {
            state
                .variants
                .iter()
                .find(|item| item.params_digest == params_digest)
                .map(|item| item.revision.as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fingerprint(seed: usize, revision: &str) -> KeyedFingerprint {
        KeyedFingerprint {
            key: GRAPH_NEIGHBOURS_KEY.to_string(),
            params: json!({"seed_id": seed.to_string()}),
            params_digest: seed.to_string(),
            revision: revision.to_string(),
            relations: ["records".to_string(), "links".to_string()].into(),
        }
    }

    fn folder_fingerprint(folder: &str, revision: &str) -> KeyedFingerprint {
        KeyedFingerprint {
            key: FOLDERS_CHILDREN_KEY.to_string(),
            params: json!({"folder_id": folder}),
            params_digest: folder.to_string(),
            revision: revision.to_string(),
            relations: ["records".to_string(), "facet_values".to_string()].into(),
        }
    }

    #[test]
    fn result_diff_only_and_params_isolation() {
        let mut state = KeyedFreshness::default();
        state.admit(fingerprint(1, "a"));
        state.admit(fingerprint(2, "b"));
        assert!(!state.changed(GRAPH_NEIGHBOURS_KEY, "1", "a")); // hidden-only write
        assert!(!state.changed(GRAPH_NEIGHBOURS_KEY, "2", "b"));
        assert!(state.changed(GRAPH_NEIGHBOURS_KEY, "2", "c")); // visible result change
        assert!(!state.changed(GRAPH_NEIGHBOURS_KEY, "1", "a"));
        assert_eq!(state.revision(GRAPH_NEIGHBOURS_KEY, "2"), Some("b"));
        assert_eq!(state.variants().count(), 2);
    }

    #[test]
    fn eviction_is_bounded_and_surfaced() {
        let mut state = KeyedFreshness::default();
        for seed in 0..MAX_VARIANTS_PER_KEY {
            assert!(!state.admit(fingerprint(seed, "same")));
        }
        assert!(state.admit(fingerprint(MAX_VARIANTS_PER_KEY, "same")));
        assert!(state.evicted(GRAPH_NEIGHBOURS_KEY));
        assert!(!state.evicted(FOLDERS_CHILDREN_KEY));
        assert_eq!(state.variants().count(), MAX_VARIANTS_PER_KEY);
        assert_eq!(state.revision(GRAPH_NEIGHBOURS_KEY, "0"), None); // pull-only until re-read
        state.admit(fingerprint(0, "new"));
        assert_eq!(state.revision(GRAPH_NEIGHBOURS_KEY, "0"), Some("new"));
    }

    #[test]
    fn keys_hold_independent_lrus() {
        let mut state = KeyedFreshness::default();
        for seed in 0..MAX_VARIANTS_PER_KEY {
            assert!(!state.admit(fingerprint(seed, "same")));
        }
        // Filling Graph to eviction must not evict an admitted Folders key.
        assert!(state.admit(fingerprint(MAX_VARIANTS_PER_KEY, "same")));
        assert!(!state.admit(folder_fingerprint("folder-a", "rev")));
        assert_eq!(
            state.revision(FOLDERS_CHILDREN_KEY, "folder-a"),
            Some("rev")
        );
        assert_eq!(state.evicted_keys(), vec![GRAPH_NEIGHBOURS_KEY.to_string()]);
        assert_eq!(
            variant_handle(FOLDERS_CHILDREN_KEY, "abc"),
            format!("{}:abc", FOLDERS_CHILDREN_KEY)
        );
    }
}
