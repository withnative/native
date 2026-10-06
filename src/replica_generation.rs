//! Shared replica envelope, contract `native.replica-generation.v2`
//! (contract c323277 rev 5 §1.3, §1.5, §2.6, §4.4, §5, §7.1).
//!
//! One manifest contract, one admission core, one lifecycle; the owner is
//! scope everything. The manifest reuses the standby sub-types for producer
//! engine identity ([`StandbySnapshotEngineIdentity`]), the declared consumer
//! ([`StandbyConsumerIdentity`]), byte identity ([`StandbySnapshotBytes`])
//! and materialization ([`StandbyGenerationMaterialization`]) rather than
//! duplicating them. Scope, ordering, holding and profile are the declared
//! dimensions whose values differ per scope.
//!
//! Owner-only slots (rev 5 §1.3 Envelope row, R5, §2.6): `frontier`
//! (`CanonicalFrontierV1`) and `head_act` exist only on scope everything.
//! A member manifest carries neither — R5 omits counter-bearing fields
//! rather than zeroing or nulling them, so a client cannot mistake a local
//! value for a comparable workspace coordinate. `head_act` lives in the
//! owner `Act` ordering; `frontier` is a top-level optional slot.
//!
//! `schema_incomplete_for` lives in the manifest, not in the holding: §2.1
//! fixes the holding's member values without it, while §3.3 rule 6 assigns
//! it to the generation ("the generation then records
//! `schema_incomplete_for`"). The consumer reads it at admission alongside
//! the manifest: `[]` means the schema gate passed everywhere, `["global"]`
//! means a global row was withheld, otherwise the listed visible collection
//! ids are the only collections whose schema surfaces must refuse.
//!
//! No authorization-fence field exists anywhere here (D2, §1.3): the fence
//! is server-internal, never sent to the client and never in the identity.
//!
//! ## Generation identity
//!
//! `generation_id = H(contract ‖ origin ‖ scope_ref ‖ profile ‖ ordering
//! position ‖ content_digest)`, where `H` is SHA-256 (lowercase hex) over
//! the JCS bytes (RFC 8785, via [`crate::canonical_json`]) of the JSON
//! array
//!
//! ```json
//! ["native.replica-generation.v2", origin_database_id, scope_ref,
//!  profile_id, ordering_position, content_digest]
//! ```
//!
//! with:
//! - `scope_ref`: the member `scope_ref`, or `""` for scope everything
//!   (there is one everything, so the empty string collides with nothing);
//! - `profile_id`: `"canonical-engine"`, or
//!   `"member-read-v1/<member_schema_digest>"` so a profile change mints a
//!   new identity;
//! - `ordering_position`: the `head_act` (number or null) for act orderings,
//!   the `ordinal` (number) for scoped orderings;
//! - `content_digest`: the §1.4 digest hex.
//!
//! Two generations are equivalent exactly when they share scope and
//! `content_digest`. `own_writes`, capture times and byte identity are
//! deliberately outside it: they say when and how the copy was cut, not
//! what the member holds.

use serde::{Deserialize, Serialize};

use crate::canonical_json::{canonical_json, digest_json};
use crate::error::{Error, Result};
use crate::holding::{HoldingDisclosureV2, HoldingWindow, ReplicaScope};
use crate::standby_snapshot::{
    CanonicalFrontierV1, StandbyConsumerIdentity, StandbyGenerationMaterialization,
    StandbySnapshotBytes, StandbySnapshotEngineIdentity,
};

pub const REPLICA_GENERATION_CONTRACT: &str = "native.replica-generation.v2";
pub const REPLICA_GENERATION_VERSION: u32 = 2;
pub const MEMBER_OWN_WRITES_CONTRACT: &str = "native.member-own-writes.v1";

/// 64 lowercase hex (content digests, schema digests): the shape check the
/// envelope applies before any compiled comparison at admission.
fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Ordering dimension of the envelope (§1.3): the canonical act tail for
/// the owner, the lazy scoped ordinal for a member. Slimmer than the
/// holding ordering is wrong direction: this one additionally carries
/// `head_act` and `window` (see [`crate::holding::HoldingOrdering`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplicaOrdering {
    Act {
        head_act: Option<i64>,
        window: HoldingWindow,
    },
    Scoped {
        ordinal: i64,
    },
}

/// Read profile dimension (§1.3). The member variant carries the compiled
/// member-schema digest the consumer must match at admission (§3.1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplicaProfile {
    CanonicalEngine,
    MemberReadV1 { member_schema_digest: String },
}

impl ReplicaProfile {
    /// The `profile` component of the generation identity.
    pub fn profile_id(&self) -> String {
        match self {
            Self::CanonicalEngine => "canonical-engine".to_owned(),
            Self::MemberReadV1 {
                member_schema_digest,
            } => format!("member-read-v1/{member_schema_digest}"),
        }
    }
}

/// Reserved own-write visibility (§5). Causal inclusion, not a visibility
/// guarantee; never part of `content_digest` or the generation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaOwnWrites {
    pub contract: String,
    pub through_caller_ordinal: Option<i64>,
}

impl ReplicaOwnWrites {
    pub fn not_computed() -> Self {
        Self {
            contract: MEMBER_OWN_WRITES_CONTRACT.to_owned(),
            through_caller_ordinal: None,
        }
    }
}

/// The shared envelope manifest. Closed (`deny_unknown_fields`): a consumer
/// whose compiled profile differs refuses admission (§3.1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaGenerationManifest {
    pub contract: String,
    pub version: u32,
    pub origin_database_id: String,
    pub hosted_route_database_id: String,
    /// Cut boundary: the read transaction's view, before packaging.
    pub captured_at: String,
    pub snapshot_completed_at: String,
    pub producer: StandbySnapshotEngineIdentity,
    pub consumer: StandbyConsumerIdentity,
    pub bytes: StandbySnapshotBytes,
    pub materialization: StandbyGenerationMaterialization,
    pub scope: ReplicaScope,
    pub ordering: ReplicaOrdering,
    pub holding: HoldingDisclosureV2,
    pub profile: ReplicaProfile,
    pub content_digest: String,
    pub own_writes: ReplicaOwnWrites,
    /// Owner-only canonical coordinates (rev 5 §1.3 Envelope row, §2.6).
    /// Present only for scope everything; a member manifest must omit it
    /// (R5: omitted, not nulled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier: Option<CanonicalFrontierV1>,
    /// Schema-gate fallout (§3.3 rule 6): `[]` when the gate passed
    /// everywhere, `["global"]` when a global row was withheld, otherwise
    /// the visible collection ids whose schema surfaces must refuse.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_incomplete_for: Vec<String>,
}

impl ReplicaGenerationManifest {
    /// The `scope_ref` component of the generation identity.
    fn scope_ref(&self) -> &str {
        match &self.scope {
            ReplicaScope::Everything => "",
            ReplicaScope::Member { scope_ref } => scope_ref,
        }
    }

    /// The `ordering_position` component of the generation identity.
    fn ordering_position(&self) -> serde_json::Value {
        match &self.ordering {
            ReplicaOrdering::Act { head_act, .. } => (*head_act).into(),
            ReplicaOrdering::Scoped { ordinal } => (*ordinal).into(),
        }
    }

    /// `generation_id = H(contract ‖ origin ‖ scope_ref ‖ profile ‖
    /// ordering position ‖ content_digest)` (§1.3); byte encoding in the
    /// module docs.
    pub fn generation_id(&self) -> String {
        digest_json(&serde_json::json!([
            REPLICA_GENERATION_CONTRACT,
            self.origin_database_id,
            self.scope_ref(),
            self.profile.profile_id(),
            self.ordering_position(),
            self.content_digest,
        ]))
    }

    /// Canonical bytes of the manifest itself (JCS). Not the generation
    /// identity: the identity covers what the member holds, this covers the
    /// whole declaration for transport pinning.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json(&serde_json::to_value(self).expect("manifest is JSON"))
    }

    /// Fail-closed receipt check: contract, shape, time order, digest shape,
    /// the scope/ordering/profile pairing (§1.3), and the own-writes
    /// contract. Producer/consumer build-identity details belong to
    /// transport admission, not to this shape check.
    pub fn validate(&self) -> Result<()> {
        if self.contract != REPLICA_GENERATION_CONTRACT
            || self.version != REPLICA_GENERATION_VERSION
        {
            return Err(Error::engine("unknown replica generation contract"));
        }
        if !crate::identity::is_database_id(&self.origin_database_id)
            || self.hosted_route_database_id.trim().is_empty()
            || self.hosted_route_database_id.len() > 256
        {
            return Err(Error::engine(
                "replica generation database identity is invalid",
            ));
        }
        let captured = chrono::DateTime::parse_from_rfc3339(&self.captured_at)
            .map_err(|_| Error::engine("replica generation capture time is invalid"))?;
        let completed = chrono::DateTime::parse_from_rfc3339(&self.snapshot_completed_at)
            .map_err(|_| Error::engine("replica generation completion time is invalid"))?;
        if captured > completed {
            return Err(Error::engine(
                "replica generation capture time follows completion",
            ));
        }
        if !is_lower_hex64(&self.content_digest) {
            return Err(Error::engine(
                "replica generation content digest is invalid",
            ));
        }
        match (&self.scope, &self.ordering, &self.profile) {
            (
                ReplicaScope::Everything,
                ReplicaOrdering::Act { .. },
                ReplicaProfile::CanonicalEngine,
            ) => {
                // N4: an owner manifest must not carry a member holding (or
                // any other inconsistent window); the owner arm validates
                // the owner holding shape too.
                self.holding.validate_owner().map_err(|e| {
                    Error::engine(format!("owner generation holding is invalid: {e}"))
                })?;
            }
            (
                ReplicaScope::Member { scope_ref },
                ReplicaOrdering::Scoped { ordinal },
                ReplicaProfile::MemberReadV1 {
                    member_schema_digest,
                },
            ) => {
                if scope_ref.trim().is_empty() {
                    return Err(Error::engine(
                        "member generation scope_ref must not be empty",
                    ));
                }
                // N5: the schema digest is a 64-hex shape like the content
                // digest (the admission-time compiled comparison is separate).
                if !is_lower_hex64(member_schema_digest) {
                    return Err(Error::engine("member generation schema digest is invalid"));
                }
                // R5 (rev 5 §2.6): no counter-bearing slot on a member
                // manifest — frontier, act ordering and act-valued holding
                // are owner-only. Deserialising one with them is rejected
                // here, not admitted.
                if self.frontier.is_some() {
                    return Err(Error::engine("member generation must omit the frontier"));
                }
                self.holding.validate_member().map_err(|e| {
                    Error::engine(format!("member generation holding is invalid: {e}"))
                })?;
                // N3: the holding must agree with the envelope it rides in —
                // same scope_ref, same ordinal — or the two can diverge
                // while the generation identity stays fixed.
                if self.holding.scope != self.scope {
                    return Err(Error::engine(
                        "member generation holding scope must match the envelope scope",
                    ));
                }
                let holding_ordinal = match &self.holding.ordering {
                    crate::holding::HoldingOrdering::Scoped { ordinal } => *ordinal,
                    _ => {
                        return Err(Error::engine(
                            "member generation holding ordering must be scoped",
                        ));
                    }
                };
                if holding_ordinal != *ordinal {
                    return Err(Error::engine(
                        "member generation holding ordinal must match the envelope ordinal",
                    ));
                }
            }
            _ => {
                return Err(Error::engine(
                    "replica generation scope, ordering and profile must pair",
                ));
            }
        }
        if let Some(frontier) = &self.frontier {
            frontier.validate()?;
        }
        if self.own_writes.contract != MEMBER_OWN_WRITES_CONTRACT {
            return Err(Error::engine("unknown member own-writes contract"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::standby_snapshot::{
        StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
    };

    fn member_manifest() -> ReplicaGenerationManifest {
        ReplicaGenerationManifest {
            contract: REPLICA_GENERATION_CONTRACT.to_owned(),
            version: REPLICA_GENERATION_VERSION,
            origin_database_id: format!("ndb_{}", "3".repeat(32)),
            hosted_route_database_id: "route-test".to_owned(),
            captured_at: "2026-09-29T00:00:00Z".to_owned(),
            snapshot_completed_at: "2026-09-29T00:00:01Z".to_owned(),
            producer: StandbySnapshotEngineIdentity {
                name: "native-ce".to_owned(),
                source_sha: "a".repeat(40),
                schema_version: 1,
                ddl_sha256: "b".repeat(64),
            },
            consumer: StandbyConsumerIdentity {
                contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
                version: 1,
                platform: StandbyConsumerPlatform::LinuxX8664,
                source_sha: "c".repeat(40),
                artifact_sha256: "d".repeat(64),
                engine_schema_version: 1,
                ddl_sha256: "e".repeat(64),
            },
            bytes: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.to_owned(),
                size_bytes: 1024,
                sha256: "f".repeat(64).replace('f', "0"),
            },
            materialization: StandbyGenerationMaterialization::Snapshot,
            scope: ReplicaScope::Member {
                scope_ref: "scope-ref-1".to_owned(),
            },
            ordering: ReplicaOrdering::Scoped { ordinal: 7 },
            holding: HoldingDisclosureV2::member("scope-ref-1".to_owned(), 7),
            profile: ReplicaProfile::MemberReadV1 {
                member_schema_digest: "1".repeat(64),
            },
            content_digest: "2".repeat(64),
            own_writes: ReplicaOwnWrites::not_computed(),
            frontier: None,
            schema_incomplete_for: Vec::new(),
        }
    }

    fn owner_manifest() -> ReplicaGenerationManifest {
        let mut manifest = member_manifest();
        manifest.scope = ReplicaScope::Everything;
        manifest.ordering = ReplicaOrdering::Act {
            head_act: Some(41207),
            window: HoldingWindow::Infinity,
        };
        manifest.holding = HoldingDisclosureV2::everything(
            crate::holding::ActRange {
                from: None,
                through: 41207,
            },
            HoldingWindow::Infinity,
            41207,
            None,
        );
        manifest.profile = ReplicaProfile::CanonicalEngine;
        manifest.frontier = Some(CanonicalFrontierV1 {
            contract: crate::standby_snapshot::STANDBY_FRONTIER_CONTRACT.to_owned(),
            version: 1,
            content_event_seq: 0,
            policy_event_seq: 0,
            awareness_event_seq: 0,
            notification_candidate_event_seq: 0,
            binding_audit_seq: 0,
            database_identity_audit_seq: 0,
            meta_event_seq: 0,
            control_event_seq: 0,
            derivation_event_seq: 0,
            relationship_event_seq: 0,
            authorization_revision_epoch: 0,
            storage_portability_policy_revision: 0,
        });
        manifest
    }

    #[test]
    fn manifest_round_trips_and_validates() {
        let manifest = member_manifest();
        manifest.validate().expect("fixture must validate");
        let value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(
            value.get("contract"),
            Some(&json!(REPLICA_GENERATION_CONTRACT))
        );
        // No fence fields anywhere (D2): the serialized manifest must not
        // name the authorization counters, the catalog epoch, or any act.
        for forbidden in [
            "authorization_revision",
            "authorization_grant_revision",
            "activity_epoch",
            "head_act",
            "frontier",
        ] {
            assert!(
                !value.to_string().contains(forbidden),
                "manifest must not carry {forbidden}"
            );
        }
        let back: ReplicaGenerationManifest = serde_json::from_value(value).unwrap();
        assert_eq!(back, manifest);
        assert_eq!(back.generation_id(), manifest.generation_id());
    }

    #[test]
    fn manifest_rejects_unknown_fields() {
        let mut value = serde_json::to_value(member_manifest()).unwrap();
        value["smuggled"] = json!(1);
        assert!(
            serde_json::from_value::<ReplicaGenerationManifest>(value).is_err(),
            "closed manifests refuse unknown fields"
        );
    }

    #[test]
    fn owner_manifest_carries_frontier_and_act_ordering() {
        let manifest = owner_manifest();
        manifest.validate().expect("owner fixture must validate");
        assert!(manifest.frontier.is_some(), "owner keeps its coordinates");
        let back: ReplicaGenerationManifest =
            serde_json::from_value(serde_json::to_value(&manifest).unwrap()).unwrap();
        assert_eq!(back, manifest);
        // Owner and member generations are never equivalent identities.
        assert_ne!(
            back.generation_id(),
            member_manifest().generation_id(),
            "scope is in the identity"
        );
    }

    #[test]
    fn member_manifest_rejects_owner_only_slots() {
        // frontier smuggled into a member manifest deserialises (closed
        // shape still parses) but validate() refuses it.
        let mut value = serde_json::to_value(member_manifest()).unwrap();
        value["frontier"] = serde_json::to_value(&owner_manifest().frontier).unwrap();
        let manifest: ReplicaGenerationManifest = serde_json::from_value(value).unwrap();
        assert!(
            manifest.validate().is_err(),
            "member scope must omit the frontier (R5)"
        );
        // Act ordering on a member scope is rejected by the pairing rule.
        let mut mismatched = member_manifest();
        mismatched.ordering = ReplicaOrdering::Act {
            head_act: None,
            window: HoldingWindow::CurrentStateOnly,
        };
        assert!(
            mismatched.validate().is_err(),
            "member scope needs a scoped ordering"
        );
        // A non-member holding on a member scope is rejected through the
        // holding check.
        let mut bad_holding = member_manifest();
        bad_holding.holding = HoldingDisclosureV2::everything(
            crate::holding::ActRange {
                from: None,
                through: 7,
            },
            HoldingWindow::Infinity,
            7,
            None,
        );
        assert!(
            bad_holding.validate().is_err(),
            "member scope needs the member holding"
        );
    }

    /// Contract §7.2 item 8 (manifest scope): walk a member manifest
    /// recursively and assert no counter-bearing key or token appears.
    /// Local helper for now; unified with the other branch's copy at merge.
    fn assert_no_counter_bearing_fields(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) => {}
            serde_json::Value::Number(_) => {}
            serde_json::Value::String(text) => {
                for prefix in ["rec:", "obs:"] {
                    if text.starts_with(prefix)
                        && !text[prefix.len()..].is_empty()
                        && text[prefix.len()..].bytes().all(|b| b.is_ascii_digit())
                    {
                        panic!("counter token {text:?} at {path}");
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_counter_bearing_fields(item, &format!("{path}[{index}]"));
                }
            }
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    let at = format!("{path}.{key}");
                    if matches!(
                        key.as_str(),
                        "act"
                            | "head_act"
                            | "frontier"
                            | "as_of_seq"
                            | "content_head_seq"
                            | "previous_seq"
                            | "local_seq"
                            | "event_seq"
                            | "seq"
                    ) || key.ends_with("_seq")
                        || key.starts_with("authorization_revision")
                    {
                        panic!("counter-bearing key {key:?} at {at}");
                    }
                    if key == "acts" && !item.is_null() {
                        panic!("non-null acts at {at}");
                    }
                    assert_no_counter_bearing_fields(item, &at);
                }
            }
        }
    }

    #[test]
    fn member_manifest_carries_no_counter_bearing_field() {
        let value = serde_json::to_value(member_manifest()).unwrap();
        assert_no_counter_bearing_fields(&value, "$");
        // The walker is not vacuous: it fires on an owner manifest and on
        // planted tokens.
        let owner = serde_json::to_value(owner_manifest()).unwrap();
        let fired = std::panic::catch_unwind(|| {
            assert_no_counter_bearing_fields(&owner, "$");
        });
        assert!(fired.is_err(), "owner frontier/head_act must trip the walk");
        let planted = json!({"records": [{"version": "rec:41207"}]});
        let fired = std::panic::catch_unwind(|| {
            assert_no_counter_bearing_fields(&planted, "$");
        });
        assert!(fired.is_err(), "rec:<seq> tokens must trip the walk");
    }

    #[test]
    fn generation_id_tracks_content_not_cut_metadata() {
        let manifest = member_manifest();
        let id = manifest.generation_id();
        // Every identity input moves the id.
        let mut moved = manifest.clone();
        moved.origin_database_id = format!("ndb_{}", "4".repeat(32));
        assert_ne!(moved.generation_id(), id, "origin moves the id");
        let mut moved = manifest.clone();
        moved.scope = ReplicaScope::Member {
            scope_ref: "scope-ref-2".to_owned(),
        };
        assert_ne!(moved.generation_id(), id, "scope_ref moves the id");
        let mut moved = manifest.clone();
        moved.profile = ReplicaProfile::MemberReadV1 {
            member_schema_digest: "9".repeat(64),
        };
        assert_ne!(moved.generation_id(), id, "profile moves the id");
        let mut moved = manifest.clone();
        moved.ordering = ReplicaOrdering::Scoped { ordinal: 8 };
        assert_ne!(moved.generation_id(), id, "ordinal moves the id");
        let mut moved = manifest.clone();
        moved.content_digest = "5".repeat(64);
        assert_ne!(moved.generation_id(), id, "content_digest moves the id");
        // Cut metadata does not: same logical content for m is equivalent.
        let mut same = manifest.clone();
        same.own_writes.through_caller_ordinal = Some(3);
        same.captured_at = "2026-09-29T00:05:00Z".to_owned();
        same.snapshot_completed_at = "2026-09-29T00:05:01Z".to_owned();
        same.bytes.sha256.clone_from(&"6".repeat(64));
        same.bytes.size_bytes = 2048;
        assert_eq!(
            same.generation_id(),
            id,
            "cut metadata must not move the id"
        );
    }

    #[test]
    fn manifest_validation_rejects_mispaired_and_malformed() {
        let mut bad = member_manifest();
        bad.ordering = ReplicaOrdering::Act {
            head_act: None,
            window: HoldingWindow::Infinity,
        };
        assert!(
            bad.validate().is_err(),
            "member scope needs a scoped ordering"
        );
        let mut bad = member_manifest();
        bad.profile = ReplicaProfile::CanonicalEngine;
        assert!(
            bad.validate().is_err(),
            "member scope needs the member profile"
        );
        let mut bad = member_manifest();
        bad.contract = "native.replica-generation.v1".to_owned();
        assert!(bad.validate().is_err(), "contract must match");
        let mut bad = member_manifest();
        bad.captured_at = "2026-09-29T00:00:02Z".to_owned();
        assert!(
            bad.validate().is_err(),
            "capture must not follow completion"
        );
        let mut bad = member_manifest();
        bad.content_digest = "zz".to_owned();
        assert!(bad.validate().is_err(), "content digest must be 64 hex");
        let mut bad = member_manifest();
        bad.own_writes.contract = "native.member-own-writes.v9".to_owned();
        assert!(bad.validate().is_err(), "own-writes contract must match");
        // schema_incomplete_for defaults to complete and omits itself.
        let value = serde_json::to_value(member_manifest()).unwrap();
        assert!(
            value.get("schema_incomplete_for").is_none(),
            "empty schema_incomplete_for is omitted"
        );
        let mut incomplete = member_manifest();
        incomplete.schema_incomplete_for = vec!["global".to_owned()];
        incomplete
            .validate()
            .expect("withheld global schema still validates");
        let back: ReplicaGenerationManifest =
            serde_json::from_value(serde_json::to_value(&incomplete).unwrap()).unwrap();
        assert_eq!(back.schema_incomplete_for, vec!["global".to_owned()]);
    }

    #[test]
    fn manifest_validation_cross_checks_holding_and_owner_shape() {
        // N3: the holding must agree with the envelope — same scope_ref,
        // same ordinal — or the two diverge while the identity stays fixed.
        let mut bad = member_manifest();
        bad.holding.scope = ReplicaScope::Member {
            scope_ref: "scope-ref-2".to_owned(),
        };
        assert!(
            bad.validate().is_err(),
            "holding scope_ref must match the envelope scope_ref"
        );
        let mut bad = member_manifest();
        bad.holding.ordering = crate::holding::HoldingOrdering::Scoped { ordinal: 8 };
        assert!(
            bad.validate().is_err(),
            "holding ordinal must match the envelope ordinal"
        );
        // N5: the schema digest is shape-checked like the content digest.
        let mut bad = member_manifest();
        bad.profile = ReplicaProfile::MemberReadV1 {
            member_schema_digest: "abc".to_owned(),
        };
        assert!(
            bad.validate().is_err(),
            "schema digest must be 64 lowercase hex"
        );
        // N4: an owner manifest must not carry a member holding (or any
        // other inconsistent owner shape).
        let mut bad = owner_manifest();
        bad.holding = HoldingDisclosureV2::member("scope-ref-1".to_owned(), 7);
        assert!(
            bad.validate().is_err(),
            "owner manifest must not carry a member holding"
        );
        let mut bad = owner_manifest();
        bad.holding.window = HoldingWindow::CurrentStateOnly;
        assert!(
            bad.validate().is_err(),
            "owner holding window must never be current_state_only"
        );
        owner_manifest()
            .validate()
            .expect("owner fixture must validate");
    }
}
