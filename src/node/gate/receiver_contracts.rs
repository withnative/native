//! A finite custody-only contract relation. Global schema matching stays exact.
//!
//! These artifacts were captured from production constructors, independently of
//! the append-only TEST history. They never establish current hosted evidence.
//! Only the caller's authenticated, namespace-bound discovery can do that.
use super::*;
use crate::mcp::executor_prototype::NodeHoldingContract;
use std::collections::BTreeMap;
use std::sync::OnceLock;

type Contracts = BTreeMap<String, NodeHoldingContract>;

fn captured() -> Option<&'static (Contracts, Contracts)> {
    static PAIRS: OnceLock<Option<(Contracts, Contracts)>> = OnceLock::new();
    PAIRS
        .get_or_init(|| {
            let old: Contracts = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/receiver-shapes/contracts94.json"
            )))
            .ok()?;
            let new: Contracts = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/receiver-shapes/contracts95.json"
            )))
            .ok()?;
            let names = ["attach_text", "manage_links.add", "update_record"];
            if old.keys().map(String::as_str).collect::<Vec<_>>() != names
                || new.keys().map(String::as_str).collect::<Vec<_>>() != names
                || old.iter().chain(&new).any(|(operation, contract)| {
                    !contract.valid_hosted_evidence("records_write", operation)
                })
            {
                return None;
            }
            Some((old, new))
        })
        .as_ref()
}

fn exact(actual: &NodeHoldingContract, frozen: &NodeHoldingContract) -> bool {
    // Retained evidence omits source prose by its existing codec. The exact
    // public digest still binds that prose; no behavioral member is removed.
    actual
        .for_custody()
        .is_some_and(|a| frozen.for_custody().is_some_and(|b| a == b))
}

pub(super) fn no_observation_pair(
    executor: &str,
    operation: &str,
    arguments: &Value,
    original: &NodeHoldingContract,
    local: &NodeHoldingContract,
    hosted: &NodeHoldingContract,
) -> bool {
    if !super::v2_holding::eligible(executor, operation, arguments)
        || ["observed", "observed_act", "observed_basis"]
            .iter()
            .any(|key| arguments.get(*key).is_some())
        || !hosted.valid_hosted_evidence(executor, operation)
    {
        return false;
    }
    let Some((old, new)) = captured() else {
        return false;
    };
    let Some((old, new)) = old.get(operation).zip(new.get(operation)) else {
        return false;
    };
    // This A increment qualifies the executing local94 decoder only. A future
    // B binary cannot infer retained94 working execution from this relation.
    exact(original, old)
        && exact(local, old)
        && exact(hosted, new)
        && jsonschema::validator_for(&old.description["input_schema"])
            .is_ok_and(|schema| schema.is_valid(arguments))
        && jsonschema::validator_for(&new.description["input_schema"])
            .is_ok_and(|schema| schema.is_valid(arguments))
}

/// A journal PUBLIC digest, never a normalized descriptor/request fingerprint.
pub(super) struct RecordedLocalDigest<'a>(pub &'a str);

/// Installed-working v7 is existing-note update append only. Its original=None
/// is preserved; this lookup is transient local provenance, not hosted evidence.
pub(super) fn recorded_v7(
    executor: &str,
    operation: &str,
    digest: RecordedLocalDigest<'_>,
    local: &NodeHoldingContract,
) -> Option<&'static NodeHoldingContract> {
    if executor != "records_write" || operation != "update_record" {
        return None;
    }
    let old = captured()?.0.get(operation)?;
    (old.description["contract_digest"].as_str() == Some(digest.0) && exact(local, old))
        .then_some(old)
}
