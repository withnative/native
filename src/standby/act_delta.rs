//! Closed, transport-independent canonical authority act-delta document.
//!
//! Slice P0 of cb551d7. This is the canonical document and its digest only: it
//! builds from a locally observed [`AuthorityActCut`] that retains the
//! [`AuthorityActHeadV2`] read in the same transaction, serializes to RFC 8785
//! canonical JSON, and validates those bytes back into an opaque
//! [`ValidatedAuthorityActDelta`]. It ships no transport endpoint, no handle,
//! and no receiver application: it never calls
//! [`crate::standby::receiver::ingest_authority_act_cut`], never mutates a
//! database, never projects, and never advances status, generation or
//! `act_state`.
//!
//! The document is deliberately narrow. It carries exactly a closed
//! manifest/contract header, the authority head evidence, the
//! from-exclusive/to-inclusive act bounds, the thirteen act-stamped sections in
//! [`crate::act::ACT_STAMPED_TABLES`] order, and the thirteen immutable
//! companion sections in
//! [`crate::standby::companion_closure::COMPANION_TABLES`] order. It carries no
//! projection rows, no pinned table inventory, no file artifact digest, and no
//! engine-schema or DDL identity: destination-schema pinning happens at R1
//! apply time, and the advisory engine schema is deliberately not replicated on
//! this wire. `authorization_revision` is a database-local derived coordinate
//! and never appears here.
//!
//! The digest is self-contained: `content_sha256` is the lowercase SHA-256 of
//! the canonical JSON of the document with that one field removed, so it covers
//! the contract/version, head evidence, bounds, and both ordered section lanes
//! without referencing itself. There is exactly one canonical cell codec and
//! one canonical-JSON encoder: the sections reuse [`crate::interchange`]'s
//! [`Section`]/[`Cell`] encoding and `serde_jcs`.
//!
//! # Provenance honesty
//!
//! The native revision-5 declarations and `content_sha256` are **structural and
//! integrity only**. They declare the format a producer claims and detect
//! accidental or after-the-fact edits to the document bytes; they are **not**
//! authenticity, authorship or a signature. `content_sha256` is unsigned and
//! any producer can recompute it after editing a document. The load-bearing
//! authentication for a real transfer is the hosted transport and origin pin
//! on the authenticated path, which is deliberately outside this
//! transport-independent P0 core.
//!
//! # Coverage boundary
//!
//! For a non-empty interval, P0 proves **act coverage**, not per-act row
//! completeness or companion reachability. [`AuthorityActCut::validate`]
//! requires every act in `(from, to]` to appear at least once *somewhere* among
//! the thirteen sections; it does not prove that every row an authority held
//! for an act is present, nor that the companion sections are the exact bounded
//! closure of the carried act rows. R2 must re-derive and compare the
//! companion closure (and its own destination state) before committing, and
//! must treat a wire document as a claim about an authority, never as proof.
//! An empty interval is stronger: it carries no act rows, so no companion row
//! is reachable and any carried companion row refuses.
//!
//! Receiver validation is fail-closed and ordered: parse closed structs (deny
//! unknown fields), require the input bytes to equal their canonical
//! reserialization (so duplicate keys, alternate key order, whitespace, and
//! alternate number spellings are refused), validate format/version/digest
//! syntax, recompute and compare the digest, validate the head and cut
//! invariants, then apply the cross-consistency checks. There is no
//! compatibility upgrader: a head or section that carries a revision other
//! than 5 refuses rather than being relabelled.

#![allow(dead_code)] // P0 core; the R2 transport and receiver application wires it later.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::interchange::Section;
use crate::standby::act_cut::AuthorityActCut;
use crate::standby::authority_probe::{
    ActCutoverV1, AuthorityActHeadCoordinates, AuthorityActHeadV2, BindingSystemSeedV1,
    ContentCausalCutoverV1, LogMaxSeqV1, NonSequencedMaxActV1, StoragePortabilityPolicyHeadV1,
};

/// Closed contract identity for the canonical authority act-delta document.
pub(crate) const AUTHORITY_ACT_DELTA_CONTRACT: &str = "native.standby-authority-act-delta.v1";
/// The only document version this core understands.
pub(crate) const AUTHORITY_ACT_DELTA_VERSION: u32 = 1;

/// The authority head evidence carried by a delta document: the closed
/// [`AuthorityActHeadV2`] contract minus its advisory `source_engine_schema`.
///
/// The engine/DDL identity is intentionally omitted from the wire (it never
/// gates materialisation), so the evidence carries every other coordinate
/// verbatim: the head contract/version identity, origin, head act, native
/// interchange revision, per-log and non-sequenced watermarks, the portability
/// policy pin, the act cutovers, the governed binding seeds, and the webhook
/// pins. `authorization_revision` is a database-local derived coordinate and is
/// never replicated. A receiver validates exactly the shared coordinate set
/// the authority observed, minus the one field it deliberately does not
/// replicate, and it never reconstructs a full [`AuthorityActHeadV2`] from the
/// wire.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorityActDeltaHeadV1 {
    contract: String,
    version: u32,
    origin_database_id: String,
    head_act: i64,
    native_interchange_revision: u64,
    per_log_max_seq: Vec<LogMaxSeqV1>,
    non_sequenced_max_acts: Vec<NonSequencedMaxActV1>,
    storage_portability_policy: Option<StoragePortabilityPolicyHeadV1>,
    act_cutovers: Vec<ActCutoverV1>,
    content_causal_cutover: ContentCausalCutoverV1,
    binding_systems: Vec<BindingSystemSeedV1>,
    webhook_endpoint_count: i64,
    webhook_credential_count: i64,
}

impl AuthorityActDeltaHeadV1 {
    /// Project an observed authority head into the replicated evidence. The
    /// advisory source engine schema is the only field not replicated.
    ///
    /// `pub(super)` so the authenticated transport's head probe can publish the
    /// same replicated coordinate set without constructing a full wire delta.
    pub(super) fn from_head(head: &AuthorityActHeadV2) -> Self {
        Self {
            contract: head.contract.clone(),
            version: head.version,
            origin_database_id: head.origin_database_id.clone(),
            head_act: head.head_act,
            native_interchange_revision: head.native_interchange_revision,
            per_log_max_seq: head.per_log_max_seq.clone(),
            non_sequenced_max_acts: head.non_sequenced_max_acts.clone(),
            storage_portability_policy: head.storage_portability_policy.clone(),
            act_cutovers: head.act_cutovers.clone(),
            content_causal_cutover: head.content_causal_cutover.clone(),
            binding_systems: head.binding_systems.clone(),
            webhook_endpoint_count: head.webhook_endpoint_count,
            webhook_credential_count: head.webhook_credential_count,
        }
    }

    /// Validate every shared closed-contract invariant the evidence carries.
    /// The advisory source engine schema is deliberately not carried and so is
    /// not validated: its absence is honest, not a default. This validates a
    /// coordinate view directly and never fabricates an [`AuthorityActHeadV2`].
    pub(crate) fn validate(&self) -> Result<()> {
        self.coordinates().validate()
    }

    /// The shared coordinate view used by the one closed-contract validator.
    fn coordinates(&self) -> AuthorityActHeadCoordinates<'_> {
        AuthorityActHeadCoordinates {
            contract: &self.contract,
            version: self.version,
            origin_database_id: &self.origin_database_id,
            head_act: self.head_act,
            native_interchange_revision: self.native_interchange_revision,
            per_log_max_seq: &self.per_log_max_seq,
            non_sequenced_max_acts: &self.non_sequenced_max_acts,
            storage_portability_policy: self.storage_portability_policy.as_ref(),
            act_cutovers: &self.act_cutovers,
            content_causal_cutover: &self.content_causal_cutover,
            binding_systems: &self.binding_systems,
            webhook_endpoint_count: self.webhook_endpoint_count,
            webhook_credential_count: self.webhook_credential_count,
        }
    }

    pub(crate) fn contract(&self) -> &str {
        &self.contract
    }

    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn origin_database_id(&self) -> &str {
        &self.origin_database_id
    }

    pub(crate) fn head_act(&self) -> i64 {
        self.head_act
    }

    pub(crate) fn native_interchange_revision(&self) -> u64 {
        self.native_interchange_revision
    }

    pub(crate) fn per_log_max_seq(&self) -> &[LogMaxSeqV1] {
        &self.per_log_max_seq
    }

    pub(crate) fn non_sequenced_max_acts(&self) -> &[NonSequencedMaxActV1] {
        &self.non_sequenced_max_acts
    }

    pub(crate) fn storage_portability_policy(&self) -> Option<&StoragePortabilityPolicyHeadV1> {
        self.storage_portability_policy.as_ref()
    }

    pub(crate) fn act_cutovers(&self) -> &[ActCutoverV1] {
        &self.act_cutovers
    }

    pub(crate) fn content_causal_cutover(&self) -> &ContentCausalCutoverV1 {
        &self.content_causal_cutover
    }

    pub(crate) fn binding_systems(&self) -> &[BindingSystemSeedV1] {
        &self.binding_systems
    }

    pub(crate) fn webhook_endpoint_count(&self) -> i64 {
        self.webhook_endpoint_count
    }

    pub(crate) fn webhook_credential_count(&self) -> i64 {
        self.webhook_credential_count
    }

    /// True when two delta head evidences agree on every replicated
    /// coordinate. Both operands are assumed already validated by
    /// [`Self::validate`]; this is a pure coordinate comparison, not a
    /// validation. The advisory `source_engine_schema` is not replicated and so
    /// is not compared, and `authorization_revision` is a database-local
    /// derived coordinate that never appears on this wire.
    pub(crate) fn replicated_coordinates_equal(&self, other: &Self) -> bool {
        self.contract == other.contract
            && self.version == other.version
            && self.origin_database_id == other.origin_database_id
            && self.head_act == other.head_act
            && self.native_interchange_revision == other.native_interchange_revision
            && self.per_log_max_seq == other.per_log_max_seq
            && self.non_sequenced_max_acts == other.non_sequenced_max_acts
            && self.storage_portability_policy == other.storage_portability_policy
            && self.act_cutovers == other.act_cutovers
            && self.content_causal_cutover == other.content_causal_cutover
            && self.binding_systems == other.binding_systems
            && self.webhook_endpoint_count == other.webhook_endpoint_count
            && self.webhook_credential_count == other.webhook_credential_count
    }

    /// True when this replicated evidence agrees with an authority head on
    /// every replicated coordinate. Both operands are assumed already
    /// validated; this is a pure coordinate projection, not a validation. This
    /// is the explicit projection R2 and tests use to compare wire evidence
    /// against a locally observed head; the advisory `source_engine_schema` is
    /// intentionally excluded because the wire does not carry it, and
    /// `authorization_revision` is never replicated.
    pub(crate) fn matches_authority_head(&self, head: &AuthorityActHeadV2) -> bool {
        self.contract == head.contract
            && self.version == head.version
            && self.origin_database_id == head.origin_database_id
            && self.head_act == head.head_act
            && self.native_interchange_revision == head.native_interchange_revision
            && self.per_log_max_seq == head.per_log_max_seq
            && self.non_sequenced_max_acts == head.non_sequenced_max_acts
            && self.storage_portability_policy == head.storage_portability_policy
            && self.act_cutovers == head.act_cutovers
            && self.content_causal_cutover == head.content_causal_cutover
            && self.binding_systems == head.binding_systems
            && self.webhook_endpoint_count == head.webhook_endpoint_count
            && self.webhook_credential_count == head.webhook_credential_count
    }
}

/// The closed document. Fields are private to this module and there is no raw
/// constructor: the only authoring path is [`build_authority_act_delta`] and
/// the only receiving path is [`validate_authority_act_delta`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityActDeltaDocument {
    contract: String,
    version: u32,
    authority_head: AuthorityActDeltaHeadV1,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    act_sections: Vec<Section>,
    companion_sections: Vec<Section>,
    content_sha256: String,
}

impl AuthorityActDeltaDocument {
    /// The digest payload: the document with the digest field removed, so the
    /// digest never covers itself. Canonicalized with JCS over the exact same
    /// representation the wire uses.
    fn digest_payload(&self) -> Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| Error::engine("authority act delta is not a JSON object"))?
            .remove("content_sha256");
        Ok(value)
    }

    fn computed_content_sha256(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(
            &self.digest_payload()?,
        )?)))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_jcs::to_vec(self).map_err(Into::into)
    }

    fn into_canonical_bytes(mut self) -> Result<Vec<u8>> {
        self.content_sha256 = self.computed_content_sha256()?;
        self.canonical_bytes()
    }
}

/// An integrity-checked delta document. Sibling slices can inspect the
/// validated head evidence and cut, but cannot construct or mutate a value that
/// bypasses [`validate_authority_act_delta`]: the type derives no
/// `Deserialize`, exposes no field, and holds no public or crate-visible
/// constructor.
pub(crate) struct ValidatedAuthorityActDelta {
    authority_head: AuthorityActDeltaHeadV1,
    act_cut: AuthorityActCut,
    content_sha256: String,
}

impl ValidatedAuthorityActDelta {
    /// Borrow the validated authority head evidence. This is the P0 boundary
    /// R2 uses to read the head without a raw constructor.
    pub(crate) fn authority_head(&self) -> &AuthorityActDeltaHeadV1 {
        &self.authority_head
    }

    /// Borrow the validated whole-act cut. The cut has already passed
    /// [`AuthorityActCut::validate`] and the cross-consistency checks in
    /// [`validate_authority_act_delta`].
    pub(crate) fn act_cut(&self) -> &AuthorityActCut {
        &self.act_cut
    }

    pub(crate) fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// Rebuild the canonical document from the validated parts and serialize
    /// it. Proven byte-identical to the input bytes by the receiver tests.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.document().canonical_bytes()
    }

    fn document(&self) -> AuthorityActDeltaDocument {
        AuthorityActDeltaDocument {
            contract: AUTHORITY_ACT_DELTA_CONTRACT.into(),
            version: AUTHORITY_ACT_DELTA_VERSION,
            authority_head: self.authority_head.clone(),
            from_exclusive_act: self.act_cut.from_exclusive_act(),
            to_inclusive_act: self.act_cut.to_inclusive_act(),
            act_sections: self.act_cut.sections().to_vec(),
            companion_sections: self.act_cut.companions().to_vec(),
            content_sha256: self.content_sha256.clone(),
        }
    }
}

/// Build the canonical bytes of a delta document from a locally observed
/// whole-act cut.
///
/// The cut is re-validated, and its **embedded** observed head is the only head
/// used: the caller cannot supply an independent head from another authority or
/// instant, so same-observation holds by construction. A cut reconstructed from
/// wire bytes carries no local observation and refuses here. The cut must end
/// exactly at that observed head; the advisory engine schema is not carried.
pub(crate) fn build_authority_act_delta(cut: &AuthorityActCut) -> Result<Vec<u8>> {
    cut.validate()?;
    let observed_head = cut.observed_head().ok_or_else(|| {
        Error::engine(
            "authority act delta cannot be built from a cut with no locally observed head",
        )
    })?;
    require(
        cut.to_inclusive_act() == observed_head.head_act,
        "authority act delta must end exactly at the observed authority head",
    )?;

    let document = AuthorityActDeltaDocument {
        contract: AUTHORITY_ACT_DELTA_CONTRACT.into(),
        version: AUTHORITY_ACT_DELTA_VERSION,
        authority_head: AuthorityActDeltaHeadV1::from_head(observed_head),
        from_exclusive_act: cut.from_exclusive_act(),
        to_inclusive_act: cut.to_inclusive_act(),
        act_sections: cut.sections().to_vec(),
        companion_sections: cut.companions().to_vec(),
        content_sha256: String::new(),
    };
    document.into_canonical_bytes()
}

/// Parse and fully validate canonical delta bytes into an opaque value.
///
/// The order is the contract: closed parse, canonical-bytes equality,
/// format/version/digest syntax, digest, head and cut structural validation,
/// then cross-consistency. Any failure refuses the whole document.
pub(crate) fn validate_authority_act_delta(bytes: &[u8]) -> Result<ValidatedAuthorityActDelta> {
    // 1. Closed parse. Every struct denies unknown fields, and the
    //    canonical-bytes check below catches anything serde would quietly
    //    ignore (for example extra fields inside an adjacently tagged cell).
    let document: AuthorityActDeltaDocument = serde_json::from_slice(bytes).map_err(|error| {
        Error::engine(format!(
            "authority act delta is not a closed canonical document: {error}"
        ))
    })?;

    // 2. Canonical bytes exactly. Duplicate keys, alternative whitespace, key
    //    order and number spellings all reserialize differently and refuse.
    require(
        document.canonical_bytes()? == bytes,
        "authority act delta input is not canonical JSON",
    )?;

    // 3. Format, version and digest syntax.
    require(
        document.contract == AUTHORITY_ACT_DELTA_CONTRACT,
        "unknown authority act delta contract",
    )?;
    require(
        document.version == AUTHORITY_ACT_DELTA_VERSION,
        "unknown authority act delta contract version",
    )?;
    require_lowercase_hex_64(
        &document.content_sha256,
        "authority act delta content_sha256",
    )?;

    // 4. Digest.
    require(
        constant_time_eq_hex(
            &document.computed_content_sha256()?,
            &document.content_sha256,
        ),
        "authority act delta content digest does not match",
    )?;

    // 5. Head structural invariants.
    document.authority_head.validate()?;

    let AuthorityActDeltaDocument {
        authority_head,
        from_exclusive_act,
        to_inclusive_act,
        act_sections,
        companion_sections,
        content_sha256,
        ..
    } = document;

    // 6. Cross-consistency before the cut proof, so a bound/head mismatch is
    //    named rather than surfacing as a coverage gap.
    require(
        to_inclusive_act == authority_head.head_act,
        "authority act delta must end exactly at the carried authority head",
    )?;

    let act_cut = AuthorityActCut::from_wire_parts(
        from_exclusive_act,
        to_inclusive_act,
        authority_head.head_act,
        act_sections,
        companion_sections,
    );

    // 7. Cut structural validation: exact 13/13 inventory and order, revision-5
    //    shape with strictly increasing primary keys, exact in-range acts, the
    //    whole-act coverage proof, and companion classification/portability.
    act_cut.validate()?;

    // 8. Native revision 5 everywhere, tied to the head's own revision.
    for section in act_cut.sections().iter().chain(act_cut.companions()) {
        require(
            section.revision == authority_head.native_interchange_revision,
            "authority act delta section revision disagrees with the authority head",
        )?;
    }

    // 9. An empty interval has no act rows, and therefore no companion row is
    //    reachable through the fixed closure edges. A carried companion row is
    //    a fabricated row and refuses.
    if act_cut.from_exclusive_act() == act_cut.to_inclusive_act() {
        require(
            act_cut
                .companions()
                .iter()
                .all(|section| section.rows.is_empty()),
            "authority act delta empty interval carries companion rows",
        )?;
    }

    Ok(ValidatedAuthorityActDelta {
        authority_head,
        act_cut,
        content_sha256,
    })
}

fn require_lowercase_hex_64(value: &str, field: &str) -> Result<()> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        &format!("{field} must be 64 lowercase hexadecimal characters"),
    )
}

/// Compare two hex strings without an early-exit on the first differing byte.
/// The length is not secret (both are fixed 64-hex digests), so the length
/// check is outside the loop; the byte comparison always walks the whole
/// string. No `subtle` dependency exists in this crate, so this is the
/// local, dependency-free constant-time-ish comparison.
fn constant_time_eq_hex(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.bytes().zip(right.bytes()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::engine(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::interchange::{Cell, Column, REVISION, SECTION_FORMAT};
    use crate::standby::authority_probe::read_authority_act_head;

    const RECORD_ID: &str = "1a7e4000-0000-4000-8000-0000000000e1";

    async fn fresh_authority() -> crate::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    async fn append_record(db: &crate::Db, record_id: &str, name: &str) {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    async fn head_act(db: &crate::Db) -> i64 {
        read_authority_act_head(db).await.unwrap().head_act
    }

    /// An empty-interval delta ending at the observed head. The observed head
    /// is embedded in the cut, not supplied separately.
    async fn empty_delta(db: &crate::Db) -> (AuthorityActCut, Vec<u8>) {
        let observed = head_act(db).await;
        let cut = crate::standby::act_cut::read_authority_act_cut(db, observed, observed)
            .await
            .unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        (cut, bytes)
    }

    /// A one-act delta from `base` to `base + 1`, ending at the observed head.
    async fn one_act_delta(db: &crate::Db, base: i64) -> (AuthorityActCut, Vec<u8>) {
        let observed = head_act(db).await;
        assert_eq!(observed, base + 1);
        let cut = crate::standby::act_cut::read_authority_act_cut(db, base, observed)
            .await
            .unwrap();
        let bytes = build_authority_act_delta(&cut).unwrap();
        (cut, bytes)
    }

    fn value_of(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        serde_jcs::to_vec(value).unwrap()
    }

    /// Recompute the digest after a structural mutation, so a refusal is
    /// attributable to the structural check rather than the digest.
    fn resign(value: &mut serde_json::Value) {
        let mut payload = value.clone();
        payload.as_object_mut().unwrap().remove("content_sha256");
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap()));
        value["content_sha256"] = serde_json::Value::String(digest);
    }

    fn section_names(value: &serde_json::Value, lane: &str) -> Vec<String> {
        value[lane]
            .as_array()
            .unwrap()
            .iter()
            .map(|section| section["name"].as_str().unwrap().to_string())
            .collect()
    }

    fn assert_refuses(bytes: &[u8]) {
        assert!(
            validate_authority_act_delta(bytes).is_err(),
            "document must refuse"
        );
    }

    /// Build a head evidence from a validated head for equality checks.
    fn evidence(head: &AuthorityActHeadV2) -> AuthorityActDeltaHeadV1 {
        AuthorityActDeltaHeadV1::from_head(head)
    }

    #[tokio::test]
    async fn authority_build_round_trips_canonically_and_preserves_head_and_cut() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta round trip").await;
        let (cut, bytes) = one_act_delta(&db, base).await;
        let head = cut
            .observed_head()
            .expect("an authority-local cut retains its observed head")
            .clone();

        let validated = validate_authority_act_delta(&bytes).unwrap();
        assert_eq!(
            validated.canonical_bytes().unwrap(),
            bytes,
            "the validated document must reserialize byte-identically"
        );
        assert_eq!(validated.authority_head(), &evidence(&head));
        assert!(
            validated.authority_head().matches_authority_head(&head),
            "the wire evidence agrees with the observed head on every replicated coordinate"
        );
        assert!(
            validated.act_cut().observed_head().is_none(),
            "a wire-reconstructed cut claims no local observation"
        );
        assert_eq!(
            validated.authority_head().origin_database_id(),
            head.origin_database_id.as_str()
        );
        assert_eq!(validated.authority_head().head_act(), head.head_act);
        assert_eq!(
            validated.authority_head().native_interchange_revision(),
            crate::interchange::REVISION
        );
        // The observed head is fully retained, including the policy pin, but
        // the delta wire does not carry the advisory engine schema.
        assert_eq!(
            validated.authority_head().storage_portability_policy(),
            head.storage_portability_policy.as_ref()
        );
        assert_eq!(
            validated.act_cut().from_exclusive_act(),
            cut.from_exclusive_act()
        );
        assert_eq!(
            validated.act_cut().to_inclusive_act(),
            cut.to_inclusive_act()
        );
        assert_eq!(validated.act_cut().head_act(), cut.head_act());
        assert_eq!(
            serde_json::to_value(validated.act_cut().sections()).unwrap(),
            serde_json::to_value(cut.sections()).unwrap(),
            "act sections must be preserved exactly"
        );
        assert_eq!(
            serde_json::to_value(validated.act_cut().companions()).unwrap(),
            serde_json::to_value(cut.companions()).unwrap(),
            "companions must be preserved exactly"
        );
        assert!(validated.content_sha256().len() == 64);
        db.close().await;
    }

    #[tokio::test]
    async fn identical_logical_input_yields_identical_bytes_and_digest() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta determinism").await;
        let (cut, first) = one_act_delta(&db, base).await;

        let second = build_authority_act_delta(&cut).unwrap();
        assert_eq!(first, second, "builds must be byte-identical");
        let first_digest = value_of(&first)["content_sha256"].clone();
        let second_digest = value_of(&second)["content_sha256"].clone();
        assert_eq!(first_digest, second_digest);
        db.close().await;
    }

    #[tokio::test]
    async fn empty_interval_validates_with_empty_sections_and_companions() {
        let db = fresh_authority().await;
        let (cut, bytes) = empty_delta(&db).await;

        for section in cut.sections() {
            assert!(section.rows.is_empty());
        }
        for section in cut.companions() {
            assert!(section.rows.is_empty());
        }
        let validated = validate_authority_act_delta(&bytes).unwrap();
        assert_eq!(
            validated.act_cut().from_exclusive_act(),
            validated.act_cut().to_inclusive_act()
        );

        // A fabricated companion row on the empty interval refuses, even with a
        // recomputed digest, because the closure is unreachable. The row is
        // width- and cell-valid so the refusal is the empty-interval closure
        // rule rather than a shape error.
        let mut fabricated = value_of(&bytes);
        let width = fabricated["companion_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .len();
        let null_row = (0..width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        fabricated["companion_sections"][0]["rows"] = serde_json::json!([null_row]);
        resign(&mut fabricated);
        assert_refuses(&canonical(&fabricated));

        // A fabricated act row on the empty interval refuses too.
        let mut fabricated_act = value_of(&bytes);
        let act_width = fabricated_act["act_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .len();
        let null_act_row = (0..act_width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        fabricated_act["act_sections"][0]["rows"] = serde_json::json!([null_act_row]);
        resign(&mut fabricated_act);
        assert_refuses(&canonical(&fabricated_act));
        db.close().await;
    }

    /// A non-empty interval keeps its whole-act coverage proof: a missing act
    /// in range refuses even after the digest is recomputed.
    #[tokio::test]
    async fn non_empty_interval_whole_act_proof_is_retained() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta coverage").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        let mut gap = value_of(&bytes);
        // Widen the bounds without adding the row for the new act.
        gap["to_inclusive_act"] = serde_json::json!(base + 2);
        gap["authority_head"]["head_act"] = serde_json::json!(base + 2);
        resign(&mut gap);
        assert_refuses(&canonical(&gap));
        db.close().await;
    }

    /// P0's honest coverage boundary. On a non-empty interval P0 proves act
    /// coverage, not per-act row completeness or companion reachability: a
    /// shape-valid extra companion row can be added and re-signed and is
    /// structurally admitted. R2 owns re-deriving and comparing the companion
    /// closure (and destination state) before commit. The empty-interval
    /// refusal is separate and is not weakened.
    #[tokio::test]
    async fn non_empty_interval_admits_a_resigned_extra_companion() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta closure boundary").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;
        validate_authority_act_delta(&bytes).unwrap();

        let mut value = value_of(&bytes);
        let width = value["companion_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .len();
        let primary_key_name = value["companion_sections"][0]["primary_key"][0]
            .as_str()
            .unwrap()
            .to_string();
        let primary_key_index = value["companion_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|column| column["name"].as_str() == Some(primary_key_name.as_str()))
            .expect("a companion section declares its primary key");
        let mut row = (0..width)
            .map(|_| serde_json::json!({"type": "null"}))
            .collect::<Vec<_>>();
        row[primary_key_index] =
            serde_json::json!({"type": "text", "value": "fabricated-companion"});
        value["companion_sections"][0]["rows"] = serde_json::json!([row]);
        resign(&mut value);

        // Admitted for a non-empty interval: this is the boundary R2 must
        // re-derive the closure for, not a claim P0 makes.
        validate_authority_act_delta(&canonical(&value)).unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn digest_covers_every_semantically_relevant_field() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta digest").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        let mutations: [(&str, serde_json::Value); 8] = [
            (
                "contract",
                serde_json::json!("native.standby-authority-act-delta.v9"),
            ),
            ("version", serde_json::json!(2)),
            ("from_exclusive_act", serde_json::json!(base + 5)),
            ("to_inclusive_act", serde_json::json!(base + 9)),
            ("authority_head", serde_json::json!({"tampered": true})),
            ("act_sections", serde_json::json!([])),
            ("companion_sections", serde_json::json!([])),
            ("content_sha256", serde_json::json!("0".repeat(64))),
        ];
        for (field, replacement) in mutations {
            let mut tampered = value_of(&bytes);
            tampered[field] = replacement;
            assert_refuses(&canonical(&tampered));
        }

        // One cell, one act, and one companion row each move the digest.
        let mut cell = value_of(&bytes);
        let cell_index = cell["act_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|column| column["name"] == "name" || column["name"] == "summary")
            .unwrap_or(0);
        cell["act_sections"][0]["rows"][0][cell_index] =
            serde_json::json!({"type": "text", "value": "tampered"});
        assert_refuses(&canonical(&cell));

        // One act: a row's act cell moves off the interval without the bounds
        // moving with it.
        let mut tampered_act = value_of(&bytes);
        let act_index = tampered_act["act_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|column| column["name"] == "act")
            .expect("act-stamped sections carry an act column");
        tampered_act["act_sections"][0]["rows"][0][act_index] =
            serde_json::json!({"type": "integer", "value": base + 7});
        assert_refuses(&canonical(&tampered_act));
        db.close().await;
    }

    /// Digest isolation: field-preserving mutations that stay parse-valid and
    /// structurally valid refuse only because `content_sha256` was not
    /// recomputed, and the exact same mutation is admitted once re-signed.
    #[tokio::test]
    async fn digest_is_the_only_gate_for_field_preserving_mutations() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta digest isolation").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        // A different but valid origin id.
        let mut origin = value_of(&bytes);
        origin["authority_head"]["origin_database_id"] =
            serde_json::json!("ndb_0123456789abcdef0123456789abcdef");
        assert_refuses(&canonical(&origin));
        resign(&mut origin);
        validate_authority_act_delta(&canonical(&origin)).unwrap();

        // A different non-empty cutover timestamp.
        let mut cutover = value_of(&bytes);
        cutover["authority_head"]["content_causal_cutover"]["cutover_at"] =
            serde_json::json!("2026-01-01T00:00:00.000Z");
        assert_refuses(&canonical(&cutover));
        resign(&mut cutover);
        validate_authority_act_delta(&canonical(&cutover)).unwrap();

        // A different primary-key text in an act-stamped row.
        let mut cell = value_of(&bytes);
        let id_index = cell["act_sections"][0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|column| column["name"] == "id")
            .expect("content_events carries an id column");
        cell["act_sections"][0]["rows"][0][id_index] =
            serde_json::json!({"type": "text", "value": "1a7e4000-0000-4000-8000-0000000000e9"});
        assert_refuses(&canonical(&cell));
        resign(&mut cell);
        validate_authority_act_delta(&canonical(&cell)).unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn digest_detects_section_and_companion_reordering() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta order").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        // Reordering arrays changes the canonical bytes and the digest.
        let mut reordered = value_of(&bytes);
        let acts = reordered["act_sections"].as_array_mut().unwrap();
        acts.swap(0, 1);
        assert_refuses(&canonical(&reordered));

        let mut reordered_companions = value_of(&bytes);
        let companions = reordered_companions["companion_sections"]
            .as_array_mut()
            .unwrap();
        companions.swap(0, 1);
        assert_refuses(&canonical(&reordered_companions));
        db.close().await;
    }

    #[tokio::test]
    async fn structural_tampering_refuses_even_with_a_recomputed_digest() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta structural").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        // Reorder act sections.
        let mut reordered = value_of(&bytes);
        reordered["act_sections"].as_array_mut().unwrap().swap(0, 1);
        resign(&mut reordered);
        assert_refuses(&canonical(&reordered));

        // Rename an act section.
        let mut renamed = value_of(&bytes);
        renamed["act_sections"][0]["name"] = serde_json::json!("not_a_canonical_table");
        resign(&mut renamed);
        assert_refuses(&canonical(&renamed));

        // Reorder companions.
        let mut companion_order = value_of(&bytes);
        companion_order["companion_sections"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        resign(&mut companion_order);
        assert_refuses(&canonical(&companion_order));

        // Rename a companion.
        let mut companion_name = value_of(&bytes);
        companion_name["companion_sections"][0]["name"] = serde_json::json!("not_a_companion");
        resign(&mut companion_name);
        assert_refuses(&canonical(&companion_name));

        // Head act disagreeing with the upper bound.
        let mut head_mismatch = value_of(&bytes);
        head_mismatch["authority_head"]["head_act"] = serde_json::json!(base + 3);
        resign(&mut head_mismatch);
        assert_refuses(&canonical(&head_mismatch));

        // A section at revision 4.
        let mut revision_four = value_of(&bytes);
        revision_four["act_sections"][0]["revision"] = serde_json::json!(4);
        resign(&mut revision_four);
        assert_refuses(&canonical(&revision_four));

        // A section whose format is not the canonical section.
        let mut wrong_format = value_of(&bytes);
        wrong_format["act_sections"][0]["format"] =
            serde_json::json!("native.canonical-interchange.section.v0");
        resign(&mut wrong_format);
        assert_refuses(&canonical(&wrong_format));

        // An extra act section beyond the fixed inventory.
        let mut extra = value_of(&bytes);
        let extra_section = extra["act_sections"][0].clone();
        extra["act_sections"]
            .as_array_mut()
            .unwrap()
            .push(extra_section);
        resign(&mut extra);
        assert_refuses(&canonical(&extra));
        db.close().await;
    }

    #[tokio::test]
    async fn unknown_and_noncanonical_input_refuses() {
        let db = fresh_authority().await;
        let (_cut, bytes) = empty_delta(&db).await;

        // Unknown top-level field.
        let mut unknown_top = value_of(&bytes);
        unknown_top["future_coordinate"] = serde_json::json!(1);
        assert_refuses(&canonical(&unknown_top));

        // Unknown field inside the head evidence.
        let mut unknown_head = value_of(&bytes);
        unknown_head["authority_head"]["future_coordinate"] = serde_json::json!(1);
        assert_refuses(&canonical(&unknown_head));

        // Noncanonical whitespace / pretty printing.
        let pretty = serde_json::to_vec_pretty(&value_of(&bytes)).unwrap();
        assert_refuses(&pretty);

        // Reordered top-level keys: the document parses, but its bytes are not
        // the canonical key order and refuse.
        let reordered_value = value_of(&bytes);
        let original = reordered_value.as_object().unwrap().clone();
        let mut reordered_map = serde_json::Map::new();
        for key in original.keys().rev() {
            reordered_map.insert(key.clone(), original[key].clone());
        }
        let reordered = serde_json::to_vec(&serde_json::Value::Object(reordered_map)).unwrap();
        assert!(serde_json::from_slice::<AuthorityActDeltaDocument>(&reordered).is_ok());
        assert_refuses(&reordered);

        // Alternate number spelling for an integer field.
        let alternate = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("\"version\":1", "\"version\":1.0");
        assert_refuses(alternate.as_bytes());

        db.close().await;
    }

    /// Known struct fields are typed, and serde's derived struct deserializer
    /// reports a duplicated field (for example, `duplicate field version`)
    /// before any canonical-byte comparison. This pins the top-level and the
    /// nested head cases and asserts the refusal reason is the parse.
    #[tokio::test]
    async fn duplicate_known_fields_refuse_at_parse() {
        let db = fresh_authority().await;
        let (_cut, bytes) = empty_delta(&db).await;
        let original = String::from_utf8(bytes.clone()).unwrap();

        let top_level = original.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert!(serde_json::from_slice::<AuthorityActDeltaDocument>(top_level.as_bytes()).is_err());
        assert_refuses(top_level.as_bytes());

        let head_act = value_of(&bytes)["authority_head"]["head_act"].clone();
        let needle = format!("\"head_act\":{head_act}");
        let nested = original.replacen(&needle, &format!("{needle},{needle}"), 1);
        assert!(serde_json::from_slice::<AuthorityActDeltaDocument>(nested.as_bytes()).is_err());
        assert_refuses(nested.as_bytes());
        db.close().await;
    }

    /// A `Cell` is adjacently tagged, so its generated deserializer ignores
    /// unknown fields and a duplicated unknown key still parses. Exact
    /// canonical reserialization, which drops every copy of the unknown key, is
    /// what refuses it. This is the fallback the canonical-bytes check exists
    /// for, distinct from the typed duplicate-field refusal above.
    #[tokio::test]
    async fn duplicate_unknown_cell_key_refuses_via_canonical_bytes() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta duplicate cell key").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        // A serde_json map cannot hold a duplicate key, so inject one unknown
        // field first and duplicate it by text surgery on the canonical bytes.
        let mut value = value_of(&bytes);
        value["act_sections"][0]["rows"][0][0]["extra"] = serde_json::json!(1);
        let single = canonical(&value);
        let duplicated = String::from_utf8(single).unwrap().replacen(
            "\"extra\":1",
            "\"extra\":1,\"extra\":1",
            1,
        );
        let input = duplicated.as_bytes();

        assert!(
            serde_json::from_slice::<AuthorityActDeltaDocument>(input).is_ok(),
            "an adjacently tagged Cell must ignore unknown fields and parse"
        );
        assert_refuses(input);
        db.close().await;
    }

    #[tokio::test]
    async fn native_revision_four_and_upgraded_shapes_refuse_without_relabelling() {
        let db = fresh_authority().await;
        let (_cut, bytes) = empty_delta(&db).await;

        // A head that carries a revision other than 5 refuses.
        let mut rev4_head = value_of(&bytes);
        rev4_head["authority_head"]["native_interchange_revision"] = serde_json::json!(4);
        resign(&mut rev4_head);
        assert_refuses(&canonical(&rev4_head));

        // A rev5-shaped section with a rev4 revision refuses, even though the
        // document otherwise looks current: the source revision is preserved
        // honestly and never upgraded to 5.
        let mut rev4_section = value_of(&bytes);
        rev4_section["companion_sections"][0]["revision"] = serde_json::json!(4);
        resign(&mut rev4_section);
        assert_refuses(&canonical(&rev4_section));

        // A document claiming the delta contract but a different version is
        // not silently accepted.
        let mut wrong_version = value_of(&bytes);
        wrong_version["version"] = serde_json::json!(2);
        resign(&mut wrong_version);
        assert_refuses(&canonical(&wrong_version));

        // The revision-4 head is not relabelled: the same bytes with an
        // in-range revision of 5 is the only shape that validates.
        assert!(validate_authority_act_delta(&bytes).is_ok());
        db.close().await;
    }

    #[tokio::test]
    async fn wire_document_omits_destination_and_engine_coordinates() {
        let db = fresh_authority().await;
        let (_cut, bytes) = empty_delta(&db).await;
        let text = String::from_utf8(bytes.clone()).unwrap();
        for forbidden in [
            "source_engine_schema",
            "authorization_revision",
            "ddl",
            "ddl_sha256",
            "artifact_sha256",
            "file_artifact",
        ] {
            assert!(
                !text.contains(forbidden),
                "wire document must not carry `{forbidden}`"
            );
        }
        let value = value_of(&bytes);
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                "act_sections",
                "authority_head",
                "companion_sections",
                "content_sha256",
                "contract",
                "from_exclusive_act",
                "to_inclusive_act",
                "version",
            ],
            "the closed document carries exactly the contracted fields"
        );
        // The head evidence is the head contract minus the one advisory field;
        // its exact key inventory proves the engine schema is not carried.
        let head_keys = value["authority_head"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            head_keys,
            vec![
                "act_cutovers",
                "binding_systems",
                "content_causal_cutover",
                "contract",
                "head_act",
                "native_interchange_revision",
                "non_sequenced_max_acts",
                "origin_database_id",
                "per_log_max_seq",
                "storage_portability_policy",
                "version",
                "webhook_credential_count",
                "webhook_endpoint_count",
            ],
            "head evidence carries exactly the head contract minus the engine schema"
        );
        assert!(section_names(&value, "act_sections") == crate::act::ACT_STAMPED_TABLES);
        assert!(
            section_names(&value, "companion_sections")
                == crate::standby::companion_closure::COMPANION_TABLES
        );

        // The wire says the delta document version and the authority-head
        // protocol accurately: a v1 delta carrying a v2 head.
        assert_eq!(
            value["contract"],
            serde_json::json!("native.standby-authority-act-delta.v1")
        );
        assert_eq!(value["version"], serde_json::json!(1));
        assert_eq!(
            value["authority_head"]["contract"],
            serde_json::json!("native.standby-authority-act-head.v2")
        );
        assert_eq!(value["authority_head"]["version"], serde_json::json!(2));
        db.close().await;
    }

    #[tokio::test]
    async fn build_refuses_a_cut_that_does_not_end_at_its_observed_head() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta bounds").await;
        // An empty cut ending before the observed head is structurally valid on
        // its own, but it does not reach the head the cut itself observed. The
        // builder has no independent head parameter to mismatch: it uses the
        // embedded observation.
        let short = crate::standby::act_cut::read_authority_act_cut(&db, base, base)
            .await
            .unwrap();
        assert_eq!(short.observed_head().unwrap().head_act, base + 1);
        // An authority-local observed cut keeps its supported sub-range
        // semantics: it validates even though `to` precedes the observed head.
        short.validate().unwrap();
        let error = build_authority_act_delta(&short).unwrap_err();
        assert!(
            error.to_string().contains("observed authority head"),
            "{error}"
        );

        // A wire-reconstructed cut claims no local observation, so it cannot be
        // authored into a delta at all. It is built here ending exactly at its
        // head act, which is the only range a headless wire cut may claim, so
        // the refusal is the missing observation rather than the range rule.
        let observed_head_act = short.head_act();
        let wire = AuthorityActCut::from_wire_parts(
            observed_head_act,
            observed_head_act,
            observed_head_act,
            short.sections().to_vec(),
            short.companions().to_vec(),
        );
        assert!(wire.observed_head().is_none());
        wire.validate().unwrap();
        let error = build_authority_act_delta(&wire).unwrap_err();
        assert!(
            error.to_string().contains("no locally observed head"),
            "{error}"
        );
        db.close().await;
    }

    /// The retained observation is load-bearing: a cut whose observed head has
    /// drifted (here an invalid origin) refuses, even though its rows were read
    /// from a real authority. This is what keeps origin and the policy pin from
    /// being silently dropped.
    #[tokio::test]
    async fn act_cut_validation_revalidates_the_retained_observed_head() {
        let db = fresh_authority().await;
        let observed = read_authority_act_head(&db).await.unwrap();
        let cut = crate::standby::act_cut::read_authority_act_cut(
            &db,
            observed.head_act,
            observed.head_act,
        )
        .await
        .unwrap();
        cut.validate().unwrap();
        assert!(cut.observed_head().is_some());

        let mut tampered = observed.clone();
        tampered.origin_database_id = "not-a-database-id".into();
        let tampered_cut = AuthorityActCut::from_observed_head(
            tampered,
            cut.from_exclusive_act(),
            cut.to_inclusive_act(),
            cut.sections().to_vec(),
            cut.companions().to_vec(),
        );
        assert!(tampered_cut.validate().is_err());
        db.close().await;
    }

    /// The storage portability policy pin is an unwatermarked coordinate: it
    /// allocates no act, but it must travel with the delta head evidence.
    #[tokio::test]
    async fn authority_delta_retains_the_policy_pin() {
        let db = fresh_authority().await;
        crate::storage_profile::update_portability_policy(
            &db,
            crate::storage_profile::PortabilityPolicyUpdate {
                if_policy_revision: 0,
                enforcement: crate::storage_profile::PortabilityEnforcement::Off,
                target_profiles: vec![],
                allow_conversions: vec![],
            },
        )
        .await
        .unwrap();

        let (cut, bytes) = empty_delta(&db).await;
        let observed = cut.observed_head().unwrap();
        assert!(
            observed.storage_portability_policy.is_some(),
            "the observed head carries the policy pin"
        );
        let validated = validate_authority_act_delta(&bytes).unwrap();
        assert_eq!(
            validated.authority_head().storage_portability_policy(),
            observed.storage_portability_policy.as_ref(),
            "the wire evidence carries the same policy pin"
        );
        assert!(validated.authority_head().matches_authority_head(observed));
        db.close().await;
    }

    /// The replicated-coordinate projection R2 borrows compares the full wire
    /// evidence against a head while explicitly omitting the advisory
    /// source engine schema and never fabricating a full head from the wire.
    #[tokio::test]
    async fn replicated_coordinate_projection_omits_engine_schema() {
        let db = fresh_authority().await;
        let observed = read_authority_act_head(&db).await.unwrap();
        let (_cut, bytes) = empty_delta(&db).await;
        let validated = validate_authority_act_delta(&bytes).unwrap();
        let wire = validated.authority_head();

        assert!(wire.matches_authority_head(&observed));
        assert!(wire.replicated_coordinates_equal(wire));

        // Two heads that differ only in the advisory engine schema compare
        // equal on the replicated projection, which is exactly the omission.
        let mut engine_only = observed.clone();
        engine_only.source_engine_schema += 1;
        assert!(wire.matches_authority_head(&engine_only));

        // A replicated coordinate that differs is caught.
        let mut changed = observed.clone();
        changed.head_act += 1;
        assert!(!wire.matches_authority_head(&changed));
        assert!(!wire.replicated_coordinates_equal(&evidence(&changed)));
        db.close().await;
    }

    #[tokio::test]
    async fn digest_syntax_and_digest_mismatch_refuse() {
        let db = fresh_authority().await;
        let (_cut, bytes) = empty_delta(&db).await;

        let mut uppercase = value_of(&bytes);
        uppercase["content_sha256"] =
            serde_json::json!(uppercase["content_sha256"].as_str().unwrap().to_uppercase());
        assert_refuses(&canonical(&uppercase));

        let mut short = value_of(&bytes);
        short["content_sha256"] = serde_json::json!("abcd");
        assert_refuses(&canonical(&short));

        let mut mismatch = value_of(&bytes);
        mismatch["content_sha256"] = serde_json::json!("f".repeat(64));
        assert_refuses(&canonical(&mismatch));
        db.close().await;
    }

    /// The canonical-bytes fallback test for an ignored field inside a `Cell`.
    /// A `Column` denies unknown fields, which would refuse at parse; a `Cell`
    /// is an adjacently tagged enum that ignores an extra field, so the input
    /// parses and only the canonical reserialization (which drops the field)
    /// catches it. This exercises the fallback rather than the closed parser.
    #[tokio::test]
    async fn extra_nested_cell_field_refuses_via_canonical_bytes() {
        let db = fresh_authority().await;
        let base = head_act(&db).await;
        append_record(&db, RECORD_ID, "delta cell fallback").await;
        let (_cut, bytes) = one_act_delta(&db, base).await;

        let mut value = value_of(&bytes);
        value["act_sections"][0]["rows"][0][0]["extra"] = serde_json::json!(1);
        let input = canonical(&value);
        assert!(
            serde_json::from_slice::<AuthorityActDeltaDocument>(&input).is_ok(),
            "an ignored field inside a Cell must parse, not fail closed at parse"
        );
        assert_refuses(&input);
        db.close().await;
    }

    /// The single cell codec is shared: a hand-built section in the delta uses
    /// the same `Column`/`Cell` encoding as interchange.
    #[test]
    fn delta_uses_the_canonical_interchange_section_shape() {
        let section = Section {
            format: SECTION_FORMAT.into(),
            revision: REVISION,
            name: "content_events".into(),
            columns: vec![Column {
                name: "id".into(),
                declared_type: "TEXT".into(),
            }],
            primary_key: vec!["id".into()],
            rows: vec![vec![Cell::Text("row".into())]],
        };
        assert_eq!(section.format, crate::interchange::SECTION_FORMAT);
        assert_eq!(section.revision, crate::interchange::REVISION);
        assert_eq!(crate::interchange::REVISION, 5);
    }
}
