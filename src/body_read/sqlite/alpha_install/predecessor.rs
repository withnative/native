//! Frozen reader-local stored transition extraction. No IO or ordinary history walker.
use super::*;
use serde::{
    de::{value::MapAccessDeserializer, DeserializeOwned, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{fmt, marker::PhantomData};

// Keep the original stream's MapAccess: the closed derived field decoder must
// still see duplicate/unknown fields. Never normalize through serde_json::Value.
fn map_only<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a closed object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(PhantomData))
}

fn optional_map_only<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct OptionalObject<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for OptionalObject<T> {
        type Value = Option<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("null or a closed object")
        }

        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Option<T>, E> {
            Ok(None)
        }

        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Option<T>, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> std::result::Result<Option<T>, D::Error> {
            map_only(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(OptionalObject(PhantomData))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReaderPredecessorPinV1 {
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub consented_source_revision: String,
    pub declaration_digest: String,
    pub consented_declaration: Value,
    pub adoption: String,
    pub request: Option<String>,
    pub previous_event_id: Option<String>,
}

// Derived only by the original-byte typed decoder below. Not serialized,
// deserialized, exposed in the pin DTO, or supplied as a caller flag.
enum RequestEvidence {
    Pin,
    HumanReceiptWithoutRequest,
}
pub(super) struct ReaderPredecessorV1 {
    pub pin: ReaderPredecessorPinV1,
    request_evidence: RequestEvidence,
}
impl ReaderPredecessorV1 {
    // Current is the intrinsically validated actual v2 from the preceding CPU
    // stage, not a request DTO. This exception affects display metadata only.
    pub(super) fn request_matches(
        &self,
        current: &AlphaTabAdoptV2Payload,
        display: Option<&str>,
    ) -> bool {
        if !optional_text(display, 500) {
            return false;
        }
        let current_receipt = current.adoption == "shell_adopt.v1"
            && current
                .receipt_id
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty())
            && current
                .preview_session
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty())
            && current.launch_id.is_none()
            && current.authored_run_key.is_none()
            && current.request.is_none();
        if current_receipt
            && matches!(
                self.request_evidence,
                RequestEvidence::HumanReceiptWithoutRequest
            )
            && self.pin.request.is_none()
        {
            return true;
        }
        display == current.request.as_deref().or(self.pin.request.as_deref())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderUpdatePayloadV1 {
    account_id: String,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    consented_source_revision: String,
    declaration_digest: String,
    consented_declaration: Value,
    previous_event_id: String,
    previous_pin_digest: String,
    status: String,
    request: Option<String>,
    command_digest: String,
    adoption: String,
    adoption_basis: String,
    #[serde(default, deserialize_with = "optional_map_only")]
    adoption_provenance: Option<ReaderProvenanceV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderImportResetPayloadV1 {
    #[serde(deserialize_with = "map_only")]
    pin: ReaderPredecessorPinV1,
    status: String,
    adoption_provenance: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderProvenanceV1 {
    carried_from_event_id: Option<String>,
    original_adoption_event_id: String,
    original_adoption_method: String,
    adopted_declaration_digest: String,
    canonicalization_version: String,
    original_source_revision: String,
    original_bundle_digest: String,
    reviewed_source_revision: Option<String>,
    reviewed_bundle_digest: Option<String>,
    launch_id: Option<String>,
    authored_run_key: Option<String>,
}

pub(super) fn decode<T: DeserializeOwned>(raw: &str) -> Result<T> {
    if raw
        .bytes()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        != Some(b'{')
    {
        return Err(Failure::SourceIntegrity);
    }
    serde_json::from_str(raw).map_err(|_| Failure::SourceIntegrity)
}

fn bounded(value: &str, bytes: usize) -> bool {
    value.len() <= bytes && !value.trim().is_empty()
}
fn optional_text(value: Option<&str>, chars: usize) -> bool {
    value.is_none_or(|v| bounded(v, chars * 4) && v.chars().count() <= chars)
}
fn combined(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(super::super::super::digest)
}

pub(super) fn envelope(event: &ControlEventRow) -> Result<()> {
    if !uuid(&event.id)
        || event.schema_version != 1
        || event.seq <= 0
        || event.seq as u64 > super::super::super::JS_SAFE
        || event
            .act
            .is_some_and(|a| a < 0 || a as u64 > super::super::super::JS_SAFE)
        || !bounded(&event.idempotency_key, 1024)
        || !bounded(&event.event_type, 64)
        || event.aggregate_kind != "alpha_tab"
        || !bounded(&event.aggregate_id, 512)
        || !bounded(&event.actor, 256)
        || !bounded(&event.reason, 4096)
        || event.run_key.as_deref().is_some_and(|r| r.len() > 1024)
        || event.created_at.len() > 128
        || chrono::DateTime::parse_from_rfc3339(&event.created_at).is_err()
        || event.payload.len() as u64 > PROVENANCE
    {
        return Err(Failure::SourceIntegrity);
    }
    Ok(())
}

fn pin(value: &ReaderPredecessorPinV1, event: &ControlEventRow, viewer: &str) -> Result<()> {
    use crate::alpha_tab_body_admission_v1 as frozen;
    if value.account_id != viewer
        || !trusted_input(&value.account_id)
        || !package_valid(&value.package)
        || !version(&value.version)
        || !trusted_input(&value.artifact_id)
        || !trusted_input(&value.consented_source_revision)
        || !combined(&value.digest)
        || !super::super::super::digest(&value.declaration_digest)
        || !optional_text(value.request.as_deref(), 500)
        || value
            .previous_event_id
            .as_deref()
            .is_some_and(|id| !uuid(id))
        || event.aggregate_id != crate::control::alpha_tab_aggregate_id(viewer, &value.package)
        || !frozen::has_body_descriptor(&value.consented_declaration)
            .map_err(|_| Failure::SourceIntegrity)?
        || frozen::declaration_digest(&value.consented_declaration)
            .map_err(|_| Failure::SourceIntegrity)?
            != value.declaration_digest
    {
        return Err(Failure::SourceIntegrity);
    }
    Ok(())
}

impl ReaderProvenanceV1 {
    fn check(&self, declaration: &str, method: &str) -> Result<()> {
        if !uuid(&self.original_adoption_event_id)
            || self
                .carried_from_event_id
                .as_deref()
                .is_some_and(|id| !uuid(id))
            || self.original_adoption_method != method
            || self.adopted_declaration_digest != declaration
            || self.canonicalization_version != "alpha-tab-declaration.v1"
            || !trusted_input(&self.original_source_revision)
            || !combined(&self.original_bundle_digest)
            || !optional_text(self.launch_id.as_deref(), 256)
            || !optional_text(self.authored_run_key.as_deref(), 256)
        {
            return Err(Failure::SourceIntegrity);
        }
        match method {
            "shell_adopt.v1"
                if self.reviewed_source_revision.as_ref()
                    == Some(&self.original_source_revision)
                    && self.reviewed_bundle_digest.as_ref()
                        == Some(&self.original_bundle_digest)
                    && self.launch_id.is_none()
                    && self.authored_run_key.is_none() =>
            {
                Ok(())
            }
            "shell_auto.v1"
                if self.reviewed_source_revision.is_none()
                    && self.reviewed_bundle_digest.is_none() =>
            {
                Ok(())
            }
            _ => Err(Failure::SourceIntegrity),
        }
    }
}

fn adopted(
    value: crate::control::AlphaTabAdoptPayload,
) -> Result<(ReaderPredecessorPinV1, RequestEvidence)> {
    let receipt = match value.adoption.as_str() {
        "shell_adopt.v1" => {
            value
                .receipt_id
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty())
                && value
                    .preview_session
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty())
                && value.launch_id.is_none()
                && value.authored_run_key.is_none()
                && value.request.is_none()
        }
        "shell_auto.v1" => {
            value.receipt_id.is_none()
                && value.preview_session.is_none()
                && optional_text(value.launch_id.as_deref(), 256)
                && optional_text(value.authored_run_key.as_deref(), 256)
        }
        _ => false,
    };
    if !receipt || !uuid(&value.previous_event_id) {
        return Err(Failure::SourceIntegrity);
    }
    let evidence = if value.adoption == "shell_adopt.v1" {
        RequestEvidence::HumanReceiptWithoutRequest
    } else {
        RequestEvidence::Pin
    };
    Ok((
        ReaderPredecessorPinV1 {
            account_id: value.account_id,
            package: value.package,
            version: value.version,
            digest: value.digest,
            artifact_id: value.artifact_id,
            consented_source_revision: value.consented_source_revision,
            declaration_digest: value.declaration_digest,
            consented_declaration: value.consented_declaration,
            adoption: value.adoption,
            request: value.request,
            previous_event_id: Some(value.previous_event_id),
        },
        evidence,
    ))
}

pub(super) fn extract_reader_predecessor_v1(
    event: &ControlEventRow,
    viewer: &str,
) -> Result<ReaderPredecessorV1> {
    envelope(event)?;
    let mut request_evidence = RequestEvidence::Pin;
    let value = match event.event_type.as_str() {
        "alpha_tab.updated" => {
            let v: ReaderUpdatePayloadV1 = decode(&event.payload)?;
            if !matches!(v.status.as_str(), "installed" | "disabled")
                || v.status != "installed"
                || !uuid(&v.previous_event_id)
                || !super::super::super::digest(&v.previous_pin_digest)
                || !super::super::super::digest(&v.command_digest)
            {
                return Err(Failure::SourceIntegrity);
            }
            match (
                v.adoption_basis.as_str(),
                v.adoption.as_str(),
                v.adoption_provenance.as_ref(),
            ) {
                ("requires_adoption", "caller_asserted", None) => (),
                ("carried", "shell_adopt.v1" | "shell_auto.v1", Some(p)) => {
                    p.check(&v.declaration_digest, &v.adoption)?
                }
                _ => return Err(Failure::SourceIntegrity),
            }
            ReaderPredecessorPinV1 {
                account_id: v.account_id,
                package: v.package,
                version: v.version,
                digest: v.digest,
                artifact_id: v.artifact_id,
                consented_source_revision: v.consented_source_revision,
                declaration_digest: v.declaration_digest,
                consented_declaration: v.consented_declaration,
                adoption: v.adoption,
                request: v.request,
                previous_event_id: Some(v.previous_event_id),
            }
        }
        "alpha_tab.import_reset" => {
            let v: ReaderImportResetPayloadV1 = decode(&event.payload)?;
            if v.status != "installed"
                || v.pin.adoption != "caller_asserted"
                || v.adoption_provenance.is_some()
                || v.pin.previous_event_id.is_none()
            {
                return Err(Failure::SourceIntegrity);
            }
            v.pin
        }
        "alpha_tab.installed" | "alpha_tab.restored" => {
            let v: ReaderPredecessorPinV1 = decode(&event.payload)?;
            // Stored restore keeps its historical intrinsic semantics. New append
            // restore still requires caller_asserted at the canonical control gate.
            if !matches!(v.adoption.as_str(), "caller_asserted" | "shell_adopt.v1") {
                return Err(Failure::SourceIntegrity);
            }
            v
        }
        "alpha_tab.adopted" => {
            let (pin, evidence) = adopted(decode(&event.payload)?)?;
            request_evidence = evidence;
            pin
        }
        "alpha_tab.adopted.v2" => {
            let v: AlphaTabAdoptV2Payload = decode(&event.payload)?;
            crate::control::validate_alpha_tab_adopt_v2(event, &v)
                .map_err(|_| Failure::SourceIntegrity)?;
            let (pin, evidence) = adopted(crate::control::AlphaTabAdoptPayload {
                account_id: v.account_id,
                package: v.package,
                version: v.version,
                digest: v.digest,
                artifact_id: v.artifact_id,
                consented_source_revision: v.consented_source_revision,
                declaration_digest: v.declaration_digest,
                consented_declaration: v.consented_declaration,
                adoption: v.adoption,
                previous_event_id: v.previous_event_id,
                receipt_id: v.receipt_id,
                preview_session: v.preview_session,
                launch_id: v.launch_id,
                authored_run_key: v.authored_run_key,
                request: v.request,
            })?;
            request_evidence = evidence;
            pin
        }
        _ => return Err(Failure::SourceIntegrity),
    };
    pin(&value, event, viewer)?;
    Ok(ReaderPredecessorV1 {
        pin: value,
        request_evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(kind: &str, payload: Value) -> ControlEventRow {
        ControlEventRow {
            seq: 2,
            id: "11111111-1111-4111-8111-111111111111".into(),
            idempotency_key: "fixed-reader-proof".into(),
            event_type: kind.into(),
            schema_version: 1,
            aggregate_kind: "alpha_tab".into(),
            aggregate_id: crate::control::alpha_tab_aggregate_id("acct_alice", "fixture.fixed"),
            actor: "canonical_import".into(),
            reason: "Frozen intrinsic fixture".into(),
            run_key: None,
            payload: payload.to_string(),
            created_at: "2026-10-02T00:00:00Z".into(),
            act: Some(0),
        }
    }
    fn state() -> Value {
        let declaration = json!({"needs":[{"need":"records.body.read.v1","scope":"viewer-visible-current-bodies"}],"effects":[]});
        json!({"account_id":"acct_alice","package":"fixture.fixed","version":"1.0.0",
            "digest":format!("sha256:{}", "a".repeat(64)),"artifact_id":"opaque-artifact",
            "consented_source_revision":"opaque-source","declaration_digest":crate::alpha_tab_body_admission_v1::declaration_digest(&declaration).unwrap(),
            "consented_declaration":declaration,"adoption":"caller_asserted","request":null,
            "previous_event_id":"22222222-2222-4222-8222-222222222222"})
    }
    fn updated() -> Value {
        let mut p = state();
        p["previous_pin_digest"] = json!("b".repeat(64));
        p["command_digest"] = json!("c".repeat(64));
        p["status"] = json!("installed");
        p["adoption_basis"] = json!("requires_adoption");
        p["adoption_provenance"] = Value::Null;
        p
    }

    fn carried(human: bool) -> Value {
        let mut p = updated();
        let method = if human {
            "shell_adopt.v1"
        } else {
            "shell_auto.v1"
        };
        p["adoption"] = json!(method);
        p["adoption_basis"] = json!("carried");
        p["adoption_provenance"] = json!({
            "carried_from_event_id":"33333333-3333-4333-8333-333333333333",
            "original_adoption_event_id":"44444444-4444-4444-8444-444444444444",
            "original_adoption_method":method,
            "adopted_declaration_digest":p["declaration_digest"],
            "canonicalization_version":"alpha-tab-declaration.v1",
            "original_source_revision":"old-retained-source",
            "original_bundle_digest":format!("sha256:{}", "d".repeat(64)),
            "reviewed_source_revision":if human { json!("old-retained-source") } else { Value::Null },
            "reviewed_bundle_digest":if human { json!(format!("sha256:{}", "d".repeat(64))) } else { Value::Null },
            "launch_id":if human { Value::Null } else { json!("actual-asserted-launch") },
            "authored_run_key":if human { Value::Null } else { json!("actual-asserted-run") }
        });
        p
    }

    #[test]
    fn nested_import_pin_requires_object_not_complete_positional_array() {
        let valid = json!({"pin":state(),"status":"installed","adoption_provenance":null});
        assert!(extract_reader_predecessor_v1(
            &event("alpha_tab.import_reset", valid.clone()),
            "acct_alice"
        )
        .is_ok());
        // EXACT derived-struct field order, all eleven otherwise-valid values.
        let fields = [
            "account_id",
            "package",
            "version",
            "digest",
            "artifact_id",
            "consented_source_revision",
            "declaration_digest",
            "consented_declaration",
            "adoption",
            "request",
            "previous_event_id",
        ];
        let array = Value::Array(fields.iter().map(|k| valid["pin"][*k].clone()).collect());
        assert_eq!(array.as_array().unwrap().len(), 11);
        for bad in [array, json!("scalar"), json!(7), json!(false), Value::Null] {
            let mut p = valid.clone();
            p["pin"] = bad;
            assert!(extract_reader_predecessor_v1(
                &event("alpha_tab.import_reset", p),
                "acct_alice"
            )
            .is_err());
        }
        for request in [None, Some(Value::Null)] {
            let mut p = valid.clone();
            match request {
                Some(v) => p["pin"]["request"] = v,
                None => {
                    p["pin"].as_object_mut().unwrap().remove("request");
                }
            }
            assert!(extract_reader_predecessor_v1(
                &event("alpha_tab.import_reset", p),
                "acct_alice"
            )
            .is_ok());
        }
    }

    #[test]
    fn nested_carried_provenance_requires_object_for_human_and_asserted_roots() {
        let fields = [
            "carried_from_event_id",
            "original_adoption_event_id",
            "original_adoption_method",
            "adopted_declaration_digest",
            "canonicalization_version",
            "original_source_revision",
            "original_bundle_digest",
            "reviewed_source_revision",
            "reviewed_bundle_digest",
            "launch_id",
            "authored_run_key",
        ];
        for human in [false, true] {
            let valid = carried(human);
            assert!(extract_reader_predecessor_v1(
                &event("alpha_tab.updated", valid.clone()),
                "acct_alice"
            )
            .is_ok());
            let array = Value::Array(
                fields
                    .iter()
                    .map(|k| valid["adoption_provenance"][*k].clone())
                    .collect(),
            );
            assert_eq!(array.as_array().unwrap().len(), 11);
            for bad in [array, json!("scalar"), json!(7), json!(false), Value::Null] {
                let mut p = valid.clone();
                p["adoption_provenance"] = bad;
                assert!(extract_reader_predecessor_v1(
                    &event("alpha_tab.updated", p),
                    "acct_alice"
                )
                .is_err());
            }
        }
        // Absence/null still means None; the intrinsic basis check is unchanged.
        for basis in ["requires_adoption", "carried"] {
            for absent in [false, true] {
                let mut p = updated();
                p["adoption_basis"] = json!(basis);
                if absent {
                    p.as_object_mut().unwrap().remove("adoption_provenance");
                }
                let result =
                    extract_reader_predecessor_v1(&event("alpha_tab.updated", p), "acct_alice");
                assert_eq!(result.is_ok(), basis == "requires_adoption");
            }
        }
    }

    #[test]
    fn nested_object_adapters_preserve_raw_duplicate_unknown_and_required_fields() {
        let pin = state();
        let pin_raw = pin.to_string();
        let import = |raw: &str| {
            format!("{{\"pin\":{raw},\"status\":\"installed\",\"adoption_provenance\":null}}")
        };
        let mut e = event("alpha_tab.import_reset", Value::Null);
        for inserted in [
            "\"account_id\":\"acct_alice\",",
            "\"\\u0061ccount_id\":\"acct_alice\",",
            "\"extra\":false,",
        ] {
            e.payload = import(&pin_raw.replacen('{', &format!("{{{inserted}"), 1));
            assert!(extract_reader_predecessor_v1(&e, "acct_alice").is_err());
        }
        let mut missing = pin;
        missing.as_object_mut().unwrap().remove("package");
        e.payload = import(&missing.to_string());
        assert!(extract_reader_predecessor_v1(&e, "acct_alice").is_err());
        for human in [false, true] {
            let valid = carried(human);
            let raw = valid.to_string();
            let provenance_raw = valid["adoption_provenance"].to_string();
            for inserted in [
                "\"original_adoption_method\":\"shell_auto.v1\",",
                "\"extra\":false,",
            ] {
                let corrupt = provenance_raw.replacen('{', &format!("{{{inserted}"), 1);
                let mut e = event("alpha_tab.updated", Value::Null);
                // Preserve duplicate bytes all the way into the typed decoder.
                e.payload = raw.replacen(&provenance_raw, &corrupt, 1);
                assert_ne!(e.payload, raw);
                assert!(extract_reader_predecessor_v1(&e, "acct_alice").is_err());
            }
            let mut missing = valid;
            missing["adoption_provenance"]
                .as_object_mut()
                .unwrap()
                .remove("original_adoption_event_id");
            assert!(extract_reader_predecessor_v1(
                &event("alpha_tab.updated", missing),
                "acct_alice"
            )
            .is_err());
        }
    }
    fn receipt_payload() -> Value {
        let mut p = state();
        p["adoption"] = json!("shell_adopt.v1");
        p["receipt_id"] = json!("actual-receipt");
        p["preview_session"] = json!("actual-session");
        p["launch_id"] = Value::Null;
        p["authored_run_key"] = Value::Null;
        p["runtime"] = json!("native.html.v1");
        p["bundle_sha256"] = json!("b".repeat(64));
        p["body_read_admission"] = p["consented_declaration"]["needs"][0].clone();
        p["digest"] = json!(crate::alpha_tab_body_admission_v1::install_digest(
            &"b".repeat(64),
            p["declaration_digest"].as_str().unwrap(),
            "native.html.v1"
        ));
        p
    }
    fn v1_receipt_payload() -> Value {
        let mut p = receipt_payload();
        for k in ["runtime", "bundle_sha256", "body_read_admission"] {
            p.as_object_mut().unwrap().remove(k);
        }
        p
    }
    #[test]
    fn retained_request_exception_requires_actual_receipt_variants_and_bounded_display() {
        let e = event("alpha_tab.adopted.v2", receipt_payload());
        let current: AlphaTabAdoptV2Payload = decode(&e.payload).unwrap();
        crate::control::validate_alpha_tab_adopt_v2(&e, &current).unwrap();
        for (kind, p) in [
            ("alpha_tab.adopted", v1_receipt_payload()),
            ("alpha_tab.adopted.v2", receipt_payload()),
        ] {
            let prior =
                extract_reader_predecessor_v1(&event(kind, p.clone()), "acct_alice").unwrap();
            assert!(prior.request_matches(&current, Some("retained original intent")));
            assert!(prior.request_matches(&current, None));
            assert!(prior.request_matches(&current, Some(&"🦀".repeat(500))));
            for bad in ["".to_string(), " ".into(), "a".repeat(501)] {
                assert!(!prior.request_matches(&current, Some(&bad)));
            }
            for (field, v) in [
                ("receipt_id", Value::Null),
                ("preview_session", json!(" ")),
                ("launch_id", json!("asserted")),
                ("request", json!("nonempty audit")),
                ("request", json!(7)),
            ] {
                let mut bad = p.clone();
                bad[field] = v;
                assert!(extract_reader_predecessor_v1(&event(kind, bad), "acct_alice").is_err());
            }
            let mut authored = current.clone();
            authored.adoption = "shell_auto.v1".into();
            authored.receipt_id = None;
            authored.preview_session = None;
            authored.request = Some("exact authored echo".into());
            assert!(prior.request_matches(&authored, Some("exact authored echo")));
            assert!(!prior.request_matches(&authored, Some("retained original intent")));
            let mut bad_current = current.clone();
            bad_current.request = Some("nonempty receipt audit".into());
            assert!(!prior.request_matches(&bad_current, Some("retained original intent")));
            let mut missing = current.clone();
            missing.receipt_id = None;
            assert!(!prior.request_matches(&missing, Some("retained original intent")));
        }
        let mut authored = v1_receipt_payload();
        authored["adoption"] = json!("shell_auto.v1");
        authored["receipt_id"] = Value::Null;
        authored["preview_session"] = Value::Null;
        let authored =
            extract_reader_predecessor_v1(&event("alpha_tab.adopted", authored), "acct_alice")
                .unwrap();
        assert!(!authored.request_matches(&current, Some("retained original intent")));
        assert!(authored.request_matches(&current, None));
        for (kind, p) in [
            ("alpha_tab.installed", state()),
            ("alpha_tab.restored", state()),
            ("alpha_tab.updated", updated()),
            (
                "alpha_tab.import_reset",
                json!({"pin":state(),"status":"installed","adoption_provenance":null}),
            ),
        ] {
            let prior = extract_reader_predecessor_v1(&event(kind, p), "acct_alice").unwrap();
            assert!(!prior.request_matches(&current, Some("retained original intent")));
            assert!(prior.request_matches(&current, None));
        }
        let mut install = state();
        install["adoption"] = json!("shell_adopt.v1");
        let prior =
            extract_reader_predecessor_v1(&event("alpha_tab.installed", install), "acct_alice")
                .unwrap();
        assert!(!prior.request_matches(&current, Some("retained original intent")));
        for kind in ["alpha_tab.disabled", "alpha_tab.removed"] {
            assert!(extract_reader_predecessor_v1(&event(kind, state()), "acct_alice").is_err());
        }
    }

    #[test]
    fn fixed_update_old_guard_is_not_new_pin_and_raw_dto_refuses_corruption() {
        let valid = updated();
        assert!(extract_reader_predecessor_v1(
            &event("alpha_tab.updated", valid.clone()),
            "acct_alice"
        )
        .is_ok());
        for field in [
            "previous_event_id",
            "previous_pin_digest",
            "command_digest",
            "status",
            "adoption_basis",
            "consented_declaration",
            "account_id",
        ] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                extract_reader_predecessor_v1(&event("alpha_tab.updated", missing), "acct_alice")
                    .is_err(),
                "missing {field}"
            );
            let mut null = valid.clone();
            null[field] = Value::Null;
            assert!(
                extract_reader_predecessor_v1(&event("alpha_tab.updated", null), "acct_alice")
                    .is_err(),
                "null {field}"
            );
        }
        for patch in [
            json!({"status":"disabled"}),
            json!({"adoption_basis":"carried"}),
            json!({"command_digest":"C".repeat(64)}),
            json!({"request":7}),
            json!({"extra":true}),
        ] {
            let mut p = valid.clone();
            p.as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(
                extract_reader_predecessor_v1(&event("alpha_tab.updated", p), "acct_alice")
                    .is_err()
            );
        }
        let mut e = event("alpha_tab.updated", valid);
        e.payload = e.payload.replacen('{', "{\"status\":\"installed\",", 1);
        assert!(extract_reader_predecessor_v1(&e, "acct_alice").is_err());
        for raw in ["[]", "null", "[{}]", "{} trailing"] {
            e.payload = raw.into();
            assert!(extract_reader_predecessor_v1(&e, "acct_alice").is_err());
        }
    }
    #[test]
    fn fixed_carried_provenance_separates_asserted_and_reviewed_without_history_walk() {
        let mut p = updated();
        p["adoption"] = json!("shell_auto.v1");
        p["adoption_basis"] = json!("carried");
        p["adoption_provenance"] = json!({
            "carried_from_event_id":"33333333-3333-4333-8333-333333333333",
            "original_adoption_event_id":"44444444-4444-4444-8444-444444444444",
            "original_adoption_method":"shell_auto.v1",
            "adopted_declaration_digest":p["declaration_digest"],
            "canonicalization_version":"alpha-tab-declaration.v1",
            "original_source_revision":"old-retained-source",
            "original_bundle_digest":format!("sha256:{}", "d".repeat(64)),
            "reviewed_source_revision":null,"reviewed_bundle_digest":null,
            "launch_id":"actual-asserted-launch","authored_run_key":"actual-asserted-run"
        });
        assert!(extract_reader_predecessor_v1(
            &event("alpha_tab.updated", p.clone()),
            "acct_alice"
        )
        .is_ok());
        let mut forged = p.clone();
        forged["adoption_provenance"]["reviewed_source_revision"] = json!("old-retained-source");
        assert!(
            extract_reader_predecessor_v1(&event("alpha_tab.updated", forged), "acct_alice")
                .is_err()
        );
        let mut unknown = p.clone();
        unknown["adoption_provenance"]["extra"] = json!(true);
        assert!(
            extract_reader_predecessor_v1(&event("alpha_tab.updated", unknown), "acct_alice")
                .is_err()
        );
        p["adoption"] = json!("shell_adopt.v1");
        p["adoption_provenance"]["original_adoption_method"] = json!("shell_adopt.v1");
        p["adoption_provenance"]["launch_id"] = Value::Null;
        p["adoption_provenance"]["authored_run_key"] = Value::Null;
        p["adoption_provenance"]["reviewed_source_revision"] =
            p["adoption_provenance"]["original_source_revision"].clone();
        p["adoption_provenance"]["reviewed_bundle_digest"] =
            p["adoption_provenance"]["original_bundle_digest"].clone();
        assert!(extract_reader_predecessor_v1(
            &event("alpha_tab.updated", p.clone()),
            "acct_alice"
        )
        .is_ok());
        p["adoption_provenance"]["reviewed_bundle_digest"] =
            json!(format!("sha256:{}", "e".repeat(64)));
        assert!(
            extract_reader_predecessor_v1(&event("alpha_tab.updated", p), "acct_alice").is_err()
        );
    }
    #[test]
    fn fixed_import_actor_is_not_viewer_but_account_null_and_nested_shape_are_checked() {
        let valid = json!({"pin":state(),"status":"installed","adoption_provenance":null});
        assert!(extract_reader_predecessor_v1(
            &event("alpha_tab.import_reset", valid.clone()),
            "acct_alice"
        )
        .is_ok());
        assert!(extract_reader_predecessor_v1(
            &event("alpha_tab.import_reset", valid.clone()),
            "acct_bea"
        )
        .is_err());
        for patch in [
            json!({"pin":[]}),
            json!({"adoption_provenance":{}}),
            json!({"status":"removed"}),
            json!({"extra":false}),
        ] {
            let mut p = valid.clone();
            p.as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(extract_reader_predecessor_v1(
                &event("alpha_tab.import_reset", p),
                "acct_alice"
            )
            .is_err());
        }
        let mut p = valid;
        p["pin"]
            .as_object_mut()
            .unwrap()
            .remove("previous_event_id");
        assert!(
            extract_reader_predecessor_v1(&event("alpha_tab.import_reset", p), "acct_alice")
                .is_err()
        );
    }
    #[test]
    fn fixed_control_envelope_accepts_zero_act_and_refuses_unsafe_or_malformed_values() {
        let mut e = event("alpha_tab.updated", updated());
        envelope(&e).unwrap();
        e.act = None;
        envelope(&e).unwrap();
        e.act = Some(-1);
        assert!(envelope(&e).is_err());
        e.act = None;
        e.seq = 9_007_199_254_740_992;
        assert!(envelope(&e).is_err());
        e.seq = 2;
        e.created_at = "yesterday".into();
        assert!(envelope(&e).is_err());
        e.created_at = "2026-10-02T00:00:00Z".into();
        e.reason = " ".into();
        assert!(envelope(&e).is_err());
    }
}
