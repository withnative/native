//! Recorded interpreter catalogue. Adding a port/version adds one entry; the
//! dispatcher never knows its payload or stored-state Rust type.
use super::InterpretationPins;
use crate::{
    error::{Error, Result},
    package_manifest::PackageManifest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

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
    /// Derived read data from this exact interpreter view; never authority.
    pub link_read: Option<fn(Value) -> Result<super::provider_link_reads::LinkView>>,
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
    static COMPILED: OnceLock<CompiledCatalogue<'static>> = OnceLock::new();
    COMPILED
        .get_or_init(|| CompiledCatalogue::new(entries()))
        .lookup(pins)
}

#[derive(Default)]
struct CompiledEntry {
    pins: OnceLock<InterpretationPins>,
    validated: OnceLock<()>,
}

/// Only the immutable, compiled catalogue uses this memo. Persisted pins still
/// require exact membership on every lookup; database state and admission are
/// never retained here. Custom catalogues use the fresh validator below.
struct CompiledCatalogue<'a> {
    entries: &'a [Entry],
    compiled: Vec<CompiledEntry>,
}
impl<'a> CompiledCatalogue<'a> {
    fn new(entries: &'a [Entry]) -> Self {
        Self {
            entries,
            compiled: (0..entries.len())
                .map(|_| CompiledEntry::default())
                .collect(),
        }
    }
    fn lookup(&self, pins: &InterpretationPins) -> Result<&'a Entry> {
        for (entry, compiled) in self.entries.iter().zip(&self.compiled) {
            // Lazy, ordered evaluation retains first-match and failure order.
            if compiled.pins.get_or_init(entry.pins) != pins {
                continue;
            }
            if compiled.validated.get().is_none() {
                validate_entry(entry, pins)?;
                // Concurrent cold calls may repeat pure validation. Only a
                // successful validation can publish this marker.
                let _ = compiled.validated.set(());
            }
            return Ok(entry);
        }
        Err(Error::engine(
            "unknown retained provider interpretation pins",
        ))
    }
}

pub(super) fn lookup_in<'a>(pins: &InterpretationPins, entries: &'a [Entry]) -> Result<&'a Entry> {
    let entry = entries
        .iter()
        .find(|e| (e.pins)() == *pins)
        .ok_or_else(|| Error::engine("unknown retained provider interpretation pins"))?;
    validate_entry(entry, pins)?;
    Ok(entry)
}

fn validate_entry(entry: &Entry, pins: &InterpretationPins) -> Result<()> {
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
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PIN_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PACKAGE_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn counted_pins() -> InterpretationPins {
        PIN_CALLS.fetch_add(1, Ordering::SeqCst);
        (crate::v2_standard::claims_retained::V1.pins)()
    }
    fn counted_package() -> PackageManifest {
        PACKAGE_CALLS.fetch_add(1, Ordering::SeqCst);
        (crate::v2_standard::claims_retained::V1.package)()
    }
    fn wrong_package() -> PackageManifest {
        PACKAGE_CALLS.fetch_add(1, Ordering::SeqCst);
        // Valid metadata for another compiled package reaches the pin mismatch
        // check; mutating a claims manifest is refused by its own validator.
        (crate::v2_standard::relates_to_retained::V3.package)()
    }
    fn counted_entry() -> Entry {
        let mut entry = crate::v2_standard::claims_retained::V1;
        entry.pins = counted_pins;
        entry.package = counted_package;
        entry
    }
    fn unvisited_pins() -> InterpretationPins {
        panic!("an entry after the first match must not be evaluated")
    }
    fn assert_engine(result: Result<&Entry>, expected: &str) {
        match result {
            Err(Error::Engine(message)) => assert_eq!(message, expected),
            Err(error) => panic!("unexpected refusal: {error}"),
            Ok(_) => panic!("expected {expected}"),
        }
    }

    #[test]
    fn compiled_catalogue_is_lazy_and_reuses_only_successful_validation() {
        let pins = (crate::v2_standard::claims_retained::V1.pins)();
        let mut later = crate::v2_standard::claims_retained::V1;
        later.pins = unvisited_pins;
        let entries = [counted_entry(), later];
        let catalogue = CompiledCatalogue::new(&entries);
        catalogue.lookup(&pins).unwrap();
        assert_eq!(PIN_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(PACKAGE_CALLS.load(Ordering::SeqCst), 1);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..64 {
                        assert!(std::ptr::eq(catalogue.lookup(&pins).unwrap(), &entries[0]));
                    }
                });
            }
        });
        assert_eq!(PIN_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(PACKAGE_CALLS.load(Ordering::SeqCst), 1);

        // Failed metadata validation must never publish a successful marker.
        let mut damaged = counted_entry();
        damaged.source = "damaged compiled source";
        let damaged_entries = [damaged];
        let damaged_catalogue = CompiledCatalogue::new(&damaged_entries);
        for _ in 0..2 {
            assert_engine(
                damaged_catalogue.lookup(&pins),
                "retained interpreter source checksum mismatch",
            );
        }
        let mut wrong = counted_entry();
        wrong.package = wrong_package;
        let wrong_entries = [wrong];
        let wrong_catalogue = CompiledCatalogue::new(&wrong_entries);
        for _ in 0..2 {
            assert_engine(
                wrong_catalogue.lookup(&pins),
                "retained interpreter package/pin mismatch",
            );
        }
        assert_eq!(PACKAGE_CALLS.load(Ordering::SeqCst), 3);

        // Cold races can duplicate pure validation, but all select the same
        // entry and the hot path performs no further package reconstruction.
        let cold_entries = [counted_entry()];
        let cold = CompiledCatalogue::new(&cold_entries);
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    barrier.wait();
                    assert!(std::ptr::eq(cold.lookup(&pins).unwrap(), &cold_entries[0]));
                });
            }
        });
        let calls = PACKAGE_CALLS.load(Ordering::SeqCst);
        assert!((4..=11).contains(&calls));
        cold.lookup(&pins).unwrap();
        assert_eq!(PACKAGE_CALLS.load(Ordering::SeqCst), calls);
    }

    #[test]
    fn compiled_and_fresh_catalogues_retain_exact_membership_and_custom_refusals() {
        for entry in entries() {
            let pins = (entry.pins)();
            for _ in 0..2 {
                assert!(std::ptr::eq(
                    lookup(&pins).unwrap(),
                    lookup_in(&pins, entries()).unwrap()
                ));
            }
            let mut unknown = pins.clone();
            unknown.package.digest.push_str("-unknown");
            assert_engine(
                lookup(&unknown),
                "unknown retained provider interpretation pins",
            );
        }
        // A warmed production catalogue cannot bypass custom-entry checks.
        let pins = (crate::v2_standard::claims_retained::V1.pins)();
        lookup(&pins).unwrap();
        let mut damaged = crate::v2_standard::claims_retained::V1;
        damaged.source = "damaged custom source";
        assert_engine(
            lookup_in(&pins, &[damaged]),
            "retained interpreter source checksum mismatch",
        );
        for payload in [json!({}), json!({"pins":pins,"request":{"pins":pins}})] {
            assert_engine(
                recorded(&payload),
                "missing or ambiguous recorded provider pins",
            );
        }
    }
}
