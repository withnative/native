//! Retained interpreter 2. Change semantics by adding another catalogue version.
//! Storage-free first-party relationship semantics. No kernel authority or SQL.
use crate::error::{Error, Result};
use crate::package_manifest::{DefinitionEntry, OperationDescriptor, PackageManifest};
use serde::{Deserialize, Serialize};

pub const NAMESPACE: &str = "native.relationship";
pub const PACKAGE: &str = "relates-to";
pub const RELATIONSHIP: &str = "relates_to.v1";
pub const PROVIDER: &str = "host.relates-to/1";
pub const DEFINITION: &str = include_str!("relates_to_v2.defn.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub source_id: String,
    pub from: String,
    pub to: String,
    pub claimed_author: Option<String>,
    pub claimed_timestamp: String,
    pub note: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Command {
    Assert { sources: Vec<Source> },
    Retract { assertion_id: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub id: String,
    pub sources: Vec<Source>,
    pub retracted: bool,
    pub asserted_by: Option<String>,
    pub asserted_at: String,
    pub asserted_seq: i64,
    pub retracted_by: Option<String>,
    pub retracted_at: Option<String>,
    pub retracted_seq: Option<i64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub left: String,
    pub right: String,
    pub assertions: Vec<Assertion>,
}
impl State {
    pub fn active(&self) -> bool {
        self.assertions.iter().any(|a| !a.retracted)
    }
}

pub fn pair<'a>(a: &'a str, b: &'a str) -> Result<(&'a str, &'a str)> {
    if a == b {
        return Err(Error::engine("relationship self-link refused"));
    }
    Ok(if a < b { (a, b) } else { (b, a) })
}
#[derive(Debug, Clone)]
pub struct HostStamp {
    pub principal: String,
    pub timestamp: String,
    pub event_seq: i64,
}
pub fn fold(
    command: &Command,
    left: &str,
    right: &str,
    assertion_id: &str,
    current: Option<&State>,
    stamp: &HostStamp,
) -> Result<State> {
    let mut state = current.cloned().unwrap_or_else(|| State {
        left: left.into(),
        right: right.into(),
        assertions: vec![],
    });
    if state.left != left || state.right != right {
        return Err(Error::engine("relationship aggregate mismatch"));
    }
    match command {
        Command::Assert { sources } => {
            if sources.len() > 128 {
                return Err(Error::engine("relationship provenance bound exceeded"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for source in sources {
                if source.source_id.trim().is_empty()
                    || source.source_id.len() > 256
                    || source.claimed_timestamp.len() > 64
                    || chrono::DateTime::parse_from_rfc3339(&source.claimed_timestamp).is_err()
                    || source.note.as_ref().is_some_and(|n| n.len() > 4096)
                    || source
                        .claimed_author
                        .as_ref()
                        .is_some_and(|a| a.trim().is_empty() || a.len() > 256)
                    || !seen.insert(&source.source_id)
                    || pair(&source.from, &source.to)? != (left, right)
                {
                    return Err(Error::engine("invalid relationship provenance"));
                }
            }
            if state.assertions.iter().any(|a| a.id == assertion_id) {
                return Err(Error::conflict("relationship assertion already exists"));
            }
            state.assertions.push(Assertion {
                id: assertion_id.into(),
                sources: sources.clone(),
                retracted: false,
                asserted_by: Some(stamp.principal.clone()),
                asserted_at: stamp.timestamp.clone(),
                asserted_seq: stamp.event_seq,
                retracted_by: None,
                retracted_at: None,
                retracted_seq: None,
            });
        }
        Command::Retract { assertion_id } => {
            let assertion = state
                .assertions
                .iter_mut()
                .find(|a| a.id == *assertion_id)
                .ok_or_else(|| Error::engine("unknown relationship assertion"))?;
            if assertion.retracted {
                return Err(Error::conflict("relationship assertion already retracted"));
            }
            assertion.retracted = true;
            assertion.retracted_by = Some(stamp.principal.clone());
            assertion.retracted_at = Some(stamp.timestamp.clone());
            assertion.retracted_seq = Some(stamp.event_seq);
        }
    }
    Ok(state)
}
/// Dispatch names reserved while this service is selected.
pub fn reserves(predicate: &str) -> bool {
    matches!(predicate, "relates_to" | RELATIONSHIP)
}

pub fn relationship_ref() -> serde_json::Value {
    serde_json::json!({"namespace":NAMESPACE,"package":PACKAGE,"version":1,"relationship":RELATIONSHIP})
}
pub fn package() -> PackageManifest {
    PackageManifest{namespace:NAMESPACE.into(),name:PACKAGE.into(),version:1,definitions:vec![DefinitionEntry{family:"native.relationship.relates_to".into(),version:1,artifact_bytes:DEFINITION.into(),digest:crate::meta::definition_artifact::digest_artifact_bytes(DEFINITION.as_bytes())}],behaviour:None,surface:None,declared_reads:vec!["record:view".into()],operations:vec![OperationDescriptor{name:"relates_to".into(),description:"Assert or retract one symmetric relates_to.v1 via the kernel commit port; View both endpoints and Edit the eligible anchor. Retains provenance.".into(),provider:PROVIDER.into(),family:"native.relationship.relates_to".into(),kind:"relation".into(),source_field:"body".into(),reads:vec!["record:view".into()],effects:vec![]}]}
}
pub fn pins() -> crate::kernel::InterpretationPins {
    let mut pins = super::relates_to_v1::pins();
    pins.provider = "host.relates-to/2".into();
    pins.decoder = "relates_to.payload/2".into();
    pins.reducer = "relates_to.fold/2".into();
    pins.payload_version = 2;
    pins
}
