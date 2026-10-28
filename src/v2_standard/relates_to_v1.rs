//! Retained interpreter 1. Immutable semantics for already recorded outcomes.
//! Storage-free first-party relationship semantics. No kernel authority or SQL.
use crate::error::{Error, Result};
use crate::package_manifest::{DefinitionEntry, OperationDescriptor, PackageManifest};
use serde::{Deserialize, Serialize};

pub const NAMESPACE: &str = "native.relationship";
pub const PACKAGE: &str = "relates-to";
pub const RELATIONSHIP: &str = "relates_to.v1";
pub const PROVIDER: &str = "host.relates-to/1";
pub const DEFINITION: &str = include_str!("relates_to_v1.defn.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub source_id: String,
    pub from: String,
    pub to: String,
    pub author: Option<String>,
    pub timestamp: String,
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
pub fn prepare(
    command: &Command,
    left: &str,
    right: &str,
    assertion_id: &str,
    current: Option<&State>,
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
                    || source.timestamp.trim().is_empty()
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
    PackageManifest{namespace:NAMESPACE.into(),name:PACKAGE.into(),version:1,definitions:vec![DefinitionEntry{family:"native.relationship.relates_to".into(),version:1,artifact_bytes:DEFINITION.into(),digest:crate::meta::definition_artifact::digest_artifact_bytes(DEFINITION.as_bytes())}],behaviour:None,surface:None,declared_reads:vec!["record:view".into()],operations:vec![OperationDescriptor{name:"relates_to".into(),description:"Assert or retract one symmetric relates_to.v1 via the kernel commit port; View both endpoints and Edit the eligible anchor. Retains provenance.".into(),provider:PROVIDER.into(),family:"native.relationship.relates_to".into(),kind:"relation".into(),source_field:"body".into(),reads:vec!["record:view".into()],effects:vec![],executable:None}]}
}
pub fn pins() -> crate::kernel::InterpretationPins {
    let manifest = package();
    let identity = manifest.identity().expect("compiled manifest");
    crate::kernel::InterpretationPins {
        package: crate::kernel::PackageSelection {
            namespace: identity.namespace,
            name: identity.name,
            version: identity.version,
            digest: identity.digest,
        },
        relationship: crate::meta::definition_artifact::RevisionIdentity {
            family: manifest.definitions[0].family.clone(),
            version: 1,
            digest: manifest.definitions[0].digest.clone(),
        },
        provider:
            "host.relates-to/1:0b01f4006ee5d6218d921f26e0262412825ec9e062a7d8b16415567f392c8ee0"
                .into(),
        decoder: "relates_to.payload/1".into(),
        reducer: "relates_to.fold/1".into(),
        payload_version: 1,
    }
}
