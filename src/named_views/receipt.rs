//! Host-only completeness and root roll-up for the closed v3 carrier.
use super::{
    closure::Closure, contract::Dependency, retained_facets::Drift, source_proof::ComparisonReason,
    Pin,
};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn unavailable() -> Error {
    Error::engine("view_revision_unavailable: incomplete generated diagnostic evidence")
}
fn reason_rank(reason: ComparisonReason) -> u8 {
    match reason {
        ComparisonReason::Integrity => 3,
        ComparisonReason::Unsupported => 2,
        ComparisonReason::Budget => 1,
    }
}

pub(crate) fn generated_summaries(plan: &Closure) -> Result<Option<Value>> {
    let nodes: BTreeMap<_, _> = plan.nodes.iter().map(|n| (&n.pin, n)).collect();
    let mut expected = BTreeSet::new();
    for n in &plan.nodes {
        match plan.retained.get(&n.pin).ok_or_else(unavailable)?.v {
            1 => {}
            2 => {
                expected.insert(n.pin.clone());
            }
            _ => return Err(unavailable()),
        }
    }
    if plan
        .generated_drift
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(unavailable());
    }
    let unknown: BTreeSet<_> = plan
        .generated_drift
        .iter()
        .filter(|(_, d)| **d == Drift::Unknown)
        .map(|(p, _)| p.clone())
        .collect();
    if plan
        .generated_unknown_reason
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != unknown
    {
        return Err(unavailable());
    }
    if expected.is_empty() {
        return Ok(None);
    }
    let mut covered = BTreeSet::new();
    let mut summaries = Vec::new();
    // BTreeMap order is strict ASCII root-alias order, independent of binding
    // names and traversal order. Only already-disclosed root names leave here.
    for (root, alias) in &plan.roots {
        let root_node = plan
            .nodes
            .iter()
            .find(|n| &n.alias == alias)
            .ok_or_else(unavailable)?;
        let mut pending = vec![root_node.pin.clone()];
        let mut seen = BTreeSet::<Pin>::new();
        let mut drift = Drift::Unchanged;
        let mut reason = None;
        let mut generated = false;
        while let Some(pin) = pending.pop() {
            if !seen.insert(pin.clone()) {
                continue;
            }
            if seen.len() > 16 {
                return Err(unavailable());
            }
            let node = nodes.get(&pin).ok_or_else(unavailable)?;
            if expected.contains(&pin) {
                covered.insert(pin.clone());
                generated = true;
                match plan.generated_drift[&pin] {
                    Drift::Unknown => {
                        drift = Drift::Unknown;
                        let next = plan.generated_unknown_reason[&pin];
                        if reason.is_none_or(|old| reason_rank(next) > reason_rank(old)) {
                            reason = Some(next);
                        }
                    }
                    Drift::Changed if drift != Drift::Unknown => drift = Drift::Changed,
                    _ => {}
                }
            }
            pending.extend(
                node.definition
                    .query
                    .relations
                    .values()
                    .filter_map(|d| match d {
                        Dependency::View(p) => Some(p.clone()),
                        _ => None,
                    }),
            );
        }
        if generated {
            summaries.push(json!({"root":root,"drift":drift,"unknown_reason":reason}));
        }
    }
    if covered != expected || summaries.is_empty() || summaries.len() > 8 {
        return Err(unavailable());
    }
    Ok(Some(Value::Array(summaries)))
}
