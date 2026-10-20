//! Recorded interpreter catalogue. Adding a port/version adds one entry; the
//! dispatcher never knows its payload or stored-state Rust type.
use super::InterpretationPins;
use crate::{
    error::{Error, Result},
    package_manifest::PackageManifest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Kernel storage facts extracted by the recorded decoder. Domain payloads stay opaque.
pub(crate) struct ProjectionFacts {
    pub pins: InterpretationPins,
    pub stream_id: String,
    /// An aggregate ID permanently identifies one provider key and subject list.
    /// Decoders must emit the same ordered list across outcomes and retained
    /// versions; projection refuses changes before folding or storage writes.
    /// A per-record occupancy aggregate has one fixed subject, that record.
    pub aggregate_id: String,
    pub provider_key: String,
    pub subjects: Vec<String>,
    pub principal: String,
    pub operation: String,
    pub operation_key: String,
    pub receipt_id: String,
    pub receipt_request: Value,
}
pub(crate) struct Decoded {
    pub facts: ProjectionFacts,
    pub domain: Value,
}
pub(crate) struct FoldInput<'a> {
    pub decoded: &'a Decoded,
    pub principal: &'a str,
    pub timestamp: &'a str,
    pub event_seq: i64,
}
pub(crate) type ValidationFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredState {
    pub pins: InterpretationPins,
    pub state: Value,
    pub attribution: Value,
}
pub(crate) struct Folded {
    pub state: Value,
    pub attribution: Value,
}
pub(crate) struct Entry {
    pub pins: fn() -> InterpretationPins,
    pub package: fn() -> PackageManifest,
    pub source: &'static str,
    pub source_sha256: &'static str,
    /// Kernel host adapter checks recorded witnesses and live admission.
    /// Semantic decode/fold/codec callbacks below receive values only.
    pub validate_recorded: for<'a> fn(
        &'a mut sqlx::SqliteConnection,
        &'a crate::events::EventRow,
        &'a Decoded,
        bool,
    ) -> ValidationFuture<'a>,
    pub admit: for<'a> fn(
        &'a mut sqlx::SqliteConnection,
        &'a crate::events::EventRow,
    ) -> ValidationFuture<'a>,
    pub decode: fn(&Value) -> Result<Decoded>,
    pub fold: fn(&FoldInput<'_>, Option<&StoredState>) -> Result<Folded>,
    pub state_codec: fn(&StoredState) -> Result<Value>,
}
const ENTRIES: &[Entry] = &[
    crate::v2_standard::claims_retained::V1,
    crate::v2_standard::relates_to_retained::V1,
    crate::v2_standard::relates_to_retained::V2,
    crate::v2_standard::relates_to_retained::V3,
];
pub(crate) fn entries() -> &'static [Entry] {
    ENTRIES
}
pub(crate) fn lookup(pins: &InterpretationPins) -> Result<&'static Entry> {
    lookup_in(pins, entries())
}
pub(super) fn lookup_in<'a>(pins: &InterpretationPins, entries: &'a [Entry]) -> Result<&'a Entry> {
    let entry = entries
        .iter()
        .find(|e| (e.pins)() == *pins)
        .ok_or_else(|| Error::engine("unknown retained provider interpretation pins"))?;
    if crate::meta::definition_artifact::digest_artifact_bytes(entry.source.as_bytes())
        != entry.source_sha256
    {
        return Err(Error::engine(
            "retained interpreter source checksum mismatch",
        ));
    }
    let package = (entry.package)();
    let identity = package.identity()?;
    if identity.namespace != pins.package.namespace
        || identity.name != pins.package.name
        || identity.version != pins.package.version
        || identity.digest != pins.package.digest
        || !package.definitions.iter().any(|d| {
            d.family == pins.relationship.family
                && d.version == pins.relationship.version
                && d.digest == pins.relationship.digest
        })
    {
        return Err(Error::engine("retained interpreter package/pin mismatch"));
    }
    Ok(entry)
}
pub(crate) fn recorded(payload: &Value) -> Result<&'static Entry> {
    recorded_in(payload, entries())
}
pub(super) fn recorded_in<'a>(payload: &Value, entries: &'a [Entry]) -> Result<&'a Entry> {
    // Pin locations are envelope grammar, never inference from an outcome field.
    let pins = match (payload.get("pins"), payload.pointer("/request/pins")) {
        (Some(p), None) | (None, Some(p)) => p,
        _ => return Err(Error::engine("missing or ambiguous recorded provider pins")),
    };
    lookup_in(&serde_json::from_value(pins.clone())?, entries)
}
impl StoredState {
    pub fn view(&self) -> Result<Value> {
        (lookup(&self.pins)?.state_codec)(self)
    }
}
