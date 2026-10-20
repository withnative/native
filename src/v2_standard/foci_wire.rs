//! Pin-aware wire adapter for `native.foci.saved_view@1` (§4.2).
//!
//! The stored shape drops the inner `version` member: the retained pin
//! versions the storage shape. The app wire contract still carries
//! `version: 1` (v1 app readers require it:
//! `web/apps/src/apps/tracker/savedView.ts:35-39` and
//! `web/apps/src/apps/docs/savedView.ts:16-18`), so this adapter
//! reconstructs it on open and strips it on capture.
//!
//! [`WIRE_VERSION`] is a constant of the app contract. It is never derived
//! from the family or package version, and an app wire change is versioned
//! separately. Unknown pins refuse: both directions take the retained pin
//! and refuse anything but `native.foci.saved_view` @1 with rule
//! `wire-pin`; capture additionally requires wire `version: 1`, and open
//! refuses a stored definition that already carries one (the stored shape
//! must not carry it).

use serde_json::Value;

use super::foci_consumer::Refusal;

/// The app-wire definition version. App-contract constant, not derived
/// from `native.foci.saved_view` family version 1 or package version 1.
pub const WIRE_VERSION: u32 = 1;

/// The retained pin this adapter serves: exactly `native.foci.saved_view` @1.
pub const SAVED_VIEW_FAMILY: &str = "native.foci.saved_view";
/// The retained definition version this adapter serves.
pub const SAVED_VIEW_VERSION: u32 = 1;

/// A retained definition pin: family plus definition version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin<'a> {
    pub family: &'a str,
    pub version: u32,
}

/// The pin this adapter serves.
pub const SAVED_VIEW_PIN: Pin<'static> = Pin {
    family: SAVED_VIEW_FAMILY,
    version: SAVED_VIEW_VERSION,
};

fn check_pin(pin: Pin<'_>) -> Result<(), Refusal> {
    if pin != SAVED_VIEW_PIN {
        return Err(Refusal::new(
            "wire-pin",
            format!(
                "adapter serves native.foci.saved_view @1, not {} @{}",
                pin.family, pin.version
            ),
        ));
    }
    Ok(())
}

/// Open: storage → app wire under `pin`. Adds `version: 1` to the
/// definition object. Refuses any other pin, a stored definition that
/// already carries `version` (unknown pin material in storage), or a
/// non-object.
pub fn wire_open(pin: Pin<'_>, stored_definition: &Value) -> Result<Value, Refusal> {
    check_pin(pin)?;
    let stored = stored_definition.as_object().ok_or_else(|| {
        Refusal::new(
            "wire-shape",
            "stored definition is not an object".to_string(),
        )
    })?;
    if stored.contains_key("version") {
        return Err(Refusal::new(
            "wire-version",
            "stored definition already carries version: unknown pin".to_string(),
        ));
    }
    let mut wire = stored.clone();
    wire.insert("version".to_string(), Value::from(WIRE_VERSION));
    Ok(Value::Object(wire))
}

/// Capture: app wire → storage under `pin`. Requires `version: 1` and
/// strips it. Refuses any other pin, a missing version, or any other
/// version (unknown pins refuse).
pub fn wire_capture(pin: Pin<'_>, app_definition: &Value) -> Result<Value, Refusal> {
    check_pin(pin)?;
    let app = app_definition
        .as_object()
        .ok_or_else(|| Refusal::new("wire-shape", "app definition is not an object".to_string()))?;
    match app.get("version") {
        Some(Value::Number(n)) if n.as_u64() == Some(u64::from(WIRE_VERSION)) => (),
        _ => {
            return Err(Refusal::new(
                "wire-version",
                "app definition version is not 1: unknown pin".to_string(),
            ));
        }
    }
    let mut stored = app.clone();
    stored.remove("version");
    Ok(Value::Object(stored))
}

/// True when `wire_capture` then `wire_open` under `pin` returns the stored
/// value unchanged (used by the round-trip fixtures).
pub fn round_trip_is_identity(pin: Pin<'_>, stored_definition: &Value) -> bool {
    wire_open(pin, stored_definition)
        .and_then(|wire| wire_capture(pin, &wire))
        .is_ok_and(|back| &back == stored_definition)
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn open_adds_version_1_and_capture_strips_it() {
        let stored = json!({"app": "agent.docs", "target": {"record_id": "native:root"}});
        let wire = wire_open(SAVED_VIEW_PIN, &stored).unwrap();
        assert_eq!(wire["version"], json!(1));
        assert_eq!(wire["app"], json!("agent.docs"));
        let back = wire_capture(SAVED_VIEW_PIN, &wire).unwrap();
        assert_eq!(back, stored);
        assert!(round_trip_is_identity(SAVED_VIEW_PIN, &stored));

        let tracker = json!({"app": "agent.tracker", "format": "tracker-query/1",
            "filter": {"combine": "all", "terms": []}, "sort": []});
        let wire = wire_open(SAVED_VIEW_PIN, &tracker).unwrap();
        assert_eq!(wire["version"], json!(1));
        assert_eq!(wire_capture(SAVED_VIEW_PIN, &wire).unwrap(), tracker);
        assert!(round_trip_is_identity(SAVED_VIEW_PIN, &tracker));
    }

    #[test]
    fn wrong_pin_refuses_both_directions() {
        let stored = json!({"app": "agent.docs"});
        let wire = json!({"version": 1, "app": "agent.docs"});
        for pin in [
            Pin {
                family: "native.foci.focus",
                version: 1,
            },
            Pin {
                family: SAVED_VIEW_FAMILY,
                version: 2,
            },
            Pin {
                family: "acme.widgets",
                version: 1,
            },
        ] {
            assert_eq!(wire_open(pin, &stored).unwrap_err().rule, "wire-pin");
            assert_eq!(wire_capture(pin, &wire).unwrap_err().rule, "wire-pin");
            assert!(!round_trip_is_identity(pin, &stored));
        }
    }

    #[test]
    fn capture_refuses_version_2_or_missing() {
        let v2 = json!({"version": 2, "app": "agent.docs"});
        assert_eq!(
            wire_capture(SAVED_VIEW_PIN, &v2).unwrap_err().rule,
            "wire-version"
        );
        let missing = json!({"app": "agent.docs"});
        assert_eq!(
            wire_capture(SAVED_VIEW_PIN, &missing).unwrap_err().rule,
            "wire-version"
        );
        let string_version = json!({"version": "1", "app": "agent.docs"});
        assert_eq!(
            wire_capture(SAVED_VIEW_PIN, &string_version)
                .unwrap_err()
                .rule,
            "wire-version"
        );
        // A stored definition already carrying a version is unknown pin
        // material: open refuses rather than overwriting silently.
        let stored_with_version = json!({"version": 1, "app": "agent.docs"});
        assert_eq!(
            wire_open(SAVED_VIEW_PIN, &stored_with_version)
                .unwrap_err()
                .rule,
            "wire-version"
        );
        assert!(!round_trip_is_identity(
            SAVED_VIEW_PIN,
            &stored_with_version
        ));
    }

    #[test]
    fn non_objects_refuse_both_ways() {
        assert_eq!(
            wire_open(SAVED_VIEW_PIN, &json!([])).unwrap_err().rule,
            "wire-shape"
        );
        assert_eq!(
            wire_capture(SAVED_VIEW_PIN, &json!("x")).unwrap_err().rule,
            "wire-shape"
        );
    }
}
