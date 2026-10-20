//! Retained storage-free claims interpreter 1. Authority and storage are host-owned.
use crate::error::{Error, Result};
use crate::package_manifest::{DefinitionEntry, OperationDescriptor, PackageManifest};
use serde::{Deserialize, Serialize};

pub const NAMESPACE: &str = "native.coordination";
pub const PACKAGE: &str = "claims";
pub const PROVIDER: &str = "host.claims/1";
pub const PROVIDER_KEY: &str = "claims.v1";
pub const FAMILY: &str = "native.coordination.claims";
pub const DEFINITION: &str = include_str!("claims_v1.defn.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Command {
    Claim,
    /// Explicit holder plus generation AND head: even same-run ABA is fenced.
    Release {
        holder_run_id: String,
        generation: u64,
        head: i64,
    },
}
impl Command {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Claim => "claims.claim",
            Self::Release { .. } => "claims.release",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holder {
    pub principal: String,
    pub run_id: String,
    pub receipt_id: String,
    pub claimed_at: String,
    pub claimed_seq: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub record_id: String,
    pub generation: u64,
    pub holder: Option<Holder>,
}
pub struct HostStamp<'a> {
    pub principal: &'a str,
    pub run_id: &'a str,
    pub receipt_id: &'a str,
    pub timestamp: &'a str,
    pub seq: i64,
    pub head: Option<i64>,
}
/// None is a same-holder/run no-op. The host still checks every admission fence.
pub fn fold(
    command: &Command,
    record: &str,
    current: Option<&State>,
    stamp: &HostStamp<'_>,
) -> Result<Option<State>> {
    let mut state = current.cloned().unwrap_or(State {
        record_id: record.into(),
        generation: 0,
        holder: None,
    });
    if state.record_id != record {
        return Err(Error::engine("claims aggregate mismatch"));
    }
    match command {
        Command::Claim => {
            if let Some(holder) = &state.holder {
                if holder.principal == stamp.principal && holder.run_id == stamp.run_id {
                    return Ok(None);
                }
                return Err(Error::conflict("already_claimed"));
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or_else(|| Error::engine("claims generation exhausted"))?;
            state.holder = Some(Holder {
                principal: stamp.principal.into(),
                run_id: stamp.run_id.into(),
                receipt_id: stamp.receipt_id.into(),
                claimed_at: stamp.timestamp.into(),
                claimed_seq: stamp.seq,
            });
        }
        Command::Release {
            holder_run_id,
            generation,
            head,
        } => {
            let holder = state
                .holder
                .as_ref()
                .ok_or_else(|| Error::conflict("unclaimed"))?;
            if holder.principal != stamp.principal {
                return Err(Error::conflict("already_claimed"));
            }
            if &holder.run_id != holder_run_id
                || state.generation != *generation
                || stamp.head != Some(*head)
            {
                return Err(Error::conflict("stale_claim"));
            }
            state.holder = None;
        }
    }
    Ok(Some(state))
}
/// Package-governed eligibility, deliberately no authored evaluator or type restriction.
pub fn eligible(live: bool) -> bool {
    live
}
pub fn package() -> PackageManifest {
    PackageManifest {
        namespace: NAMESPACE.into(),
        name: PACKAGE.into(),
        version: 1,
        definitions: vec![DefinitionEntry {
            family: FAMILY.into(),
            version: 1,
            artifact_bytes: DEFINITION.into(),
            digest: crate::meta::definition_artifact::digest_artifact_bytes(DEFINITION.as_bytes()),
        }],
        behaviour: None,
        surface: None,
        declared_reads: vec!["record:view".into()],
        operations: vec![
            OperationDescriptor::any_record(
                "claim",
                "Claim eligible LIVE record occupancy through the kernel commit port.",
                PROVIDER,
            ),
            OperationDescriptor::any_record(
                "release",
                "Release own explicit holder with generation and head fences.",
                PROVIDER,
            ),
        ],
    }
}
pub fn known_package(manifest: &PackageManifest) -> bool {
    *manifest == package()
}
pub fn pins() -> crate::kernel::InterpretationPins {
    let p = package();
    let id = p.identity().expect("compiled claims manifest");
    crate::kernel::InterpretationPins {
        package: crate::kernel::PackageSelection {
            namespace: id.namespace,
            name: id.name,
            version: id.version,
            digest: id.digest,
        },
        relationship: crate::meta::definition_artifact::RevisionIdentity {
            family: FAMILY.into(),
            version: 1,
            digest: p.definitions[0].digest.clone(),
        },
        provider: format!("host.claims/1:{}", super::claims_retained::SOURCE_SHA),
        decoder: "claims.payload/1".into(),
        reducer: "claims.fold/1".into(),
        payload_version: 1,
    }
}
