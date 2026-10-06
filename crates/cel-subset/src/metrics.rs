//! Cached value metrics (PR 1a increment 3, design §1.3).
//!
//! Every aggregate value carries `nodes(v)` and `bytes(v)`, rolled up
//! at construction in O(1) per node from its children's cached
//! metrics (no deep walk) and updated incrementally on in-place
//! append. Amounts reuse the fork's existing constants
//! ([`LIST_ELEM_BYTES`](crate::charges::LIST_ELEM_BYTES),
//! [`MAP_ENTRY_BYTES`](crate::charges::MAP_ENTRY_BYTES)) and payload
//! lengths, so switching the deep-charging walk to these cached
//! reads changes no charge.
//!
//! Definitions (must match the old `charge_value` walk exactly):
//! - atoms: nodes 1, bytes 8;
//! - string/bytes: nodes 1, bytes payload length;
//! - list: nodes 1 + Σ child nodes, bytes 32 × len + Σ child bytes;
//! - map: nodes 1 + Σ value nodes, bytes 64 × len + Σ key bytes +
//!   Σ value bytes (string keys charge their length, others 8);
//! - optional: nodes 1 (+ inner nodes if present), bytes 8 (+ inner
//!   bytes if present);
//! - unknown `Val` impls: nodes 1, bytes 16.

use indexmap::IndexMap;

use crate::charges::{LIST_ELEM_BYTES, MAP_ENTRY_BYTES};
use crate::common::types::CelMapKey as Key;
use crate::common::value::Val;

/// Rolled-up size metrics stored on aggregate values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Metrics {
    pub nodes: u64,
    pub bytes: u64,
}

/// Roll up list metrics from children's cached metrics.
pub(crate) fn rollup_list(elems: &[Box<dyn Val>]) -> Metrics {
    let mut nodes: u64 = 1;
    let mut bytes: u64 = LIST_ELEM_BYTES.saturating_mul(elems.len() as u64);
    for e in elems {
        nodes = nodes.saturating_add(e.cached_nodes());
        bytes = bytes.saturating_add(e.cached_bytes());
    }
    Metrics { nodes, bytes }
}

/// Roll up map metrics from children's cached metrics.
pub(crate) fn rollup_map(entries: &IndexMap<Key, Box<dyn Val>>) -> Metrics {
    let mut nodes: u64 = 1;
    let mut bytes: u64 = MAP_ENTRY_BYTES.saturating_mul(entries.len() as u64);
    for (k, v) in entries {
        bytes = bytes.saturating_add(key_bytes(k));
        nodes = nodes.saturating_add(v.cached_nodes());
        bytes = bytes.saturating_add(v.cached_bytes());
    }
    Metrics { nodes, bytes }
}

/// Map-key bytes: string keys charge their length, others 8 (same as
/// the old deep-charging walk).
pub(crate) fn key_bytes(k: &Key) -> u64 {
    match k {
        Key::String(s) => s.inner().len() as u64,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{
        CelBytes, CelList, CelMap, CelMapKey, CelOptional, CelString, Kind,
    };
    use crate::{check, evaluate, Bindings, Policy};

    /// Naive recursive reference walk reproducing the old
    /// deep-charging amounts as (nodes, bytes). Test-only: production
    /// code must read the cached metrics, never walk.
    fn reference(v: &dyn Val) -> (u64, u64) {
        match v.get_type().kind() {
            Kind::List => {
                if let Some(l) = v.downcast_ref::<CelList>() {
                    let mut nodes = 1;
                    let mut bytes = LIST_ELEM_BYTES * l.len() as u64;
                    for e in l.inner() {
                        let (n, b) = reference(e.as_ref());
                        nodes += n;
                        bytes += b;
                    }
                    (nodes, bytes)
                } else {
                    (1, 16)
                }
            }
            Kind::Map => {
                if let Some(m) = v.downcast_ref::<CelMap>() {
                    let mut nodes = 1;
                    let mut bytes = MAP_ENTRY_BYTES * m.len() as u64;
                    for (k, val) in m.inner() {
                        bytes += match k {
                            CelMapKey::String(s) => s.inner().len() as u64,
                            _ => 8,
                        };
                        let (n, b) = reference(val.as_ref());
                        nodes += n;
                        bytes += b;
                    }
                    (nodes, bytes)
                } else {
                    (1, 16)
                }
            }
            Kind::String => {
                if let Some(s) = v.downcast_ref::<CelString>() {
                    (1, s.inner().len() as u64)
                } else {
                    (1, 16)
                }
            }
            Kind::Bytes => {
                if let Some(b) = v.downcast_ref::<CelBytes>() {
                    (1, b.inner().len() as u64)
                } else {
                    (1, 16)
                }
            }
            Kind::Opaque => {
                if let Some(o) = v.downcast_ref::<CelOptional>() {
                    match o.inner() {
                        Some(inner) => {
                            let (n, b) = reference(inner);
                            (1 + n, 8 + b)
                        }
                        None => (1, 8),
                    }
                } else {
                    (1, 16)
                }
            }
            _ => (1, 8),
        }
    }

    /// Evaluate `src` through the public path and convert to `dyn Val`.
    fn eval_to_dyn(src: &str) -> Box<dyn Val> {
        let prepared = check(src, &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&prepared, &Bindings::new(), &Policy::P0_INTERIM);
        Box::<dyn Val>::try_from(report.result.expect("eval")).expect("convert")
    }

    fn assert_cached_matches_reference(v: &dyn Val) {
        let (nodes, bytes) = reference(v);
        assert_eq!(v.cached_nodes(), nodes, "nodes");
        assert_eq!(v.cached_bytes(), bytes, "bytes");
    }

    #[test]
    fn literals_match_reference() {
        for src in [
            "[1, 2, 3]",
            "[1, [2, [3]]]",
            "{'a': 1, 'bb': [true, 'x']}",
            "'hello'",
            "{'n': {'m': {'o': []}}}",
            "[{'a': 1}, {'b': 2}]",
            "[]",
            "{}",
        ] {
            assert_cached_matches_reference(eval_to_dyn(src).as_ref());
        }
    }

    #[test]
    fn concat_matches_reference() {
        for src in ["[1, 2] + [3, [4]]", "'ab' + 'cde'"] {
            assert_cached_matches_reference(eval_to_dyn(src).as_ref());
        }
    }

    #[test]
    fn decode_matches_reference() {
        // `to_value` builds fresh containers; their rollups must agree.
        let decoded = crate::ser::to_value(vec![vec![1, 2], vec![3]]).expect("decode");
        let boxed = Box::<dyn Val>::try_from(decoded).expect("convert");
        assert_cached_matches_reference(boxed.as_ref());

        let mut map = std::collections::HashMap::new();
        map.insert("k".to_string(), vec![true, false]);
        let decoded = crate::ser::to_value(map).expect("decode");
        let boxed = Box::<dyn Val>::try_from(decoded).expect("convert");
        assert_cached_matches_reference(boxed.as_ref());
    }

    #[test]
    fn push_updates_incrementally() {
        use crate::common::types::list::DefaultList;
        use crate::common::types::CelInt;

        let mut list = DefaultList::from(vec![]);
        assert_eq!(list.cached_nodes(), 1);
        assert_eq!(list.cached_bytes(), 0);
        for i in 0..10 {
            let nested: Box<dyn Val> = Box::new(CelInt::from(i));
            list.push(nested);
            assert_cached_matches_reference(&list);
        }
        // Push a nested aggregate: only the increment is added.
        let before = (list.cached_nodes(), list.cached_bytes());
        let inner = DefaultList::from(vec![Box::new(CelInt::from(1)) as Box<dyn Val>]);
        let (in_nodes, in_bytes) = (inner.cached_nodes(), inner.cached_bytes());
        list.push(Box::new(inner));
        assert_eq!(list.cached_nodes(), before.0 + in_nodes);
        assert_eq!(list.cached_bytes(), before.1 + LIST_ELEM_BYTES + in_bytes);
        assert_cached_matches_reference(&list);
    }
}
