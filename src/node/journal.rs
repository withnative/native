//! Write-ahead journal for writes the node forwards to hosted (slice 2A).
//!
//! Every forwarded write is saved here *before* it is sent, then settled when
//! hosted answers. The journal exists so that a crash, a restart or a lost
//! reply leaves an honest, inspectable record of what may or may not have
//! been applied. It is never a replay queue: nothing in this module sends
//! anything, and entries left in flight at startup become `uncertain`.
//!
//! Layout: one JSON file per entry in `<socket_directory>/journal/`
//! (directory 0700, files 0600), written by temp-file + fsync + rename. Entry
//! files carry the call's arguments and so may hold record bodies; settled
//! entries drop them and are pruned after a short retention.
use super::hold;
#[cfg(feature = "v2-kernel-probe")]
mod enrolled_custody;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod working_v2;
use super::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Mutex as StdMutex;

/// Still 1 after slice 2B, deliberately. Every field 2B adds is optional or
/// defaulted and absent from entries that don't use it, so a 2B build reads
/// slice 2A files unchanged. The reverse matters more: a 2A build refuses a
/// file whose `version` is newer than its own and counts it only as an
/// "unreadable file". At version 1 it parses a held entry, meets the state
/// `pending` it does not know, files it as `Unrecognised` and leaves it alone,
/// which is the rollback behaviour the format reserved `pending` for, and it
/// keeps showing that entry in its state counts. Raise this only for a change
/// an older reader could misread, not for new optional fields.
pub(super) const ENTRY_VERSION: u32 = 1;
/// Custody-only compatibility changes what a local fork may execute. Older
/// readers must leave these files unreadable, rather than ignore a new flag
/// on a v1 entry and preview its ordinary arguments during rollback.
pub(super) const DESCRIPTION_CUSTODY_VERSION: u32 = 4;
pub(super) const V2_EVIDENCE_VERSION: u32 = 6;
const WORKING_MANAGER_VERSION: u32 = 5;
/// Installed working custody is distinct from ordinary v2 contract evidence.
pub(super) const INSTALLED_WORKING_VERSION: u32 = 7;
// Format 8 adds provider-owned final-ID create originals. Never convert v7.
pub(super) const INSTALLED_CREATE_VERSION: u32 = 8;
/// Fresh operation-tagged record-family originals. Formats 7/8 are never converted.
pub(super) const INSTALLED_RECORD_VERSION: u32 = 9;

/// Declare the same discriminated formats validated by `read_entry`, rather
/// than a misleading readable version range. Conditions are still checked on
/// every entry; decoding alone grants no replay or reconciliation authority.
pub(super) fn runtime_declaration() -> Value {
    use super::format_declaration as format;
    let ordinary = &[
        "owned_bounded_file",
        "entry_state_and_operation",
        "account_route_origin_binding",
    ];
    let custody = &[
        "owned_bounded_file",
        "valid_custody_binding",
        "original_contract_and_keyed_hosted_settlement",
    ];
    let working = cfg!(feature = "v2-kernel-probe");
    let mut formats = vec![
        format(
            "node_journal",
            "ordinary",
            ENTRY_VERSION.into(),
            true,
            ("production", true),
            &["mcp-executor-prototype"],
            ordinary,
        ),
        format(
            "node_journal",
            "conditional_merge",
            2,
            true,
            ("production", true),
            &["mcp-executor-prototype"],
            &[
                "is_merge",
                "prepared_or_lineage_required",
                "frozen_predecessor_and_result",
            ],
        ),
        format(
            "node_journal",
            "legacy_custody",
            3,
            true,
            ("test_only", true),
            &["mcp-executor-prototype"],
            &[
                "valid_legacy_custody",
                "no_original_contract",
                "restricted_operations",
                "not_keyed_original_reconciliation",
            ],
        ),
        format(
            "node_journal",
            "description_custody",
            DESCRIPTION_CUSTODY_VERSION.into(),
            true,
            ("promotion_from_retained_v1", true),
            &["mcp-executor-prototype"],
            &[
                "valid_description_custody",
                "source_description_rule",
                "not_executable_fork_authority",
            ],
        ),
        format(
            "node_journal",
            "contract_evidence",
            V2_EVIDENCE_VERSION.into(),
            true,
            ("production", true),
            &["mcp-executor-prototype"],
            custody,
        ),
    ];
    // The working implementation is compiled only with the kernel feature;
    // these numbers alone cannot make an entry a valid working proposal.
    for (variant, version) in [
        ("working_manager", WORKING_MANAGER_VERSION),
        ("installed_append", INSTALLED_WORKING_VERSION),
        ("installed_create", INSTALLED_CREATE_VERSION),
        ("installed_record", INSTALLED_RECORD_VERSION),
    ] {
        formats.push(format(
            "node_journal",
            variant,
            version.into(),
            working,
            (if working { "production" } else { "unavailable" }, working),
            &["mcp-executor-prototype", "v2-kernel-probe"],
            &[
                "valid_working_original",
                "account_route_origin_history_binding",
                "pinned_base",
                "matching_manager_or_installed_location",
                "retained_original_not_format_conversion",
                "hosted_contract_required_for_reconciliation",
            ],
        ));
    }
    json!({"source":"src/node/journal.rs#read_entry","formats":formats,
        "unknown_format":"preserve_opaque_file_count_unreadable_do_not_continue",
        "unknown_state":"decode_as_unrecognised_retain_do_not_send_not_round_tripped_on_rewrite_no_semantic_continuation",
        "unknown_hold_reason":"decode_as_other_not_round_tripped_on_rewrite_not_semantic_rollback_qualification",
        "unknown_fields":"outer_entry_ignored_not_round_tripped_on_rewrite_typed_custody_envelopes_strict",
        "decoder_exceptions":[{"version":0,"behavior":"incidental_legacy_decoder_behavior",
            "contract_status":"not_supported_contract","fresh_writer":"none",
            "qualified_continuation":false}],
        "semantics":"parsing_preservation_and_continuation_are_distinct"})
}

pub(super) fn installed_working_version(version: u32) -> bool {
    matches!(
        version,
        INSTALLED_WORKING_VERSION | INSTALLED_CREATE_VERSION | INSTALLED_RECORD_VERSION
    )
}
pub(super) const SOURCE_DESCRIPTION_RULE: u32 = 1;
pub(super) const MAX_CONTRACT_EVIDENCE_BYTES: u64 = 256 * 1024;
const V6_METADATA_BYTES: u64 = 4096;
const MAX_ENTRY_BYTES: u64 = MAX_FRAME as u64 * 2 + 64 * 1024;
// A typed merge freezes the draft, predecessor, prepared submission and exact
// result. JSON escaping and the full clash receipt all count toward this cap.
const MAX_MERGE_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
/// Settled entries are kept this long so a person can see what just happened.
pub(super) const CONFIRMED_RETENTION: Duration = Duration::from_secs(60 * 60);
const PRUNE_EVERY: Duration = Duration::from_secs(60);

/// Entry states. `pending` (slice 2B) is a write the node has accepted on the
/// caller's behalf and will send later. A build that predates it reads the
/// state as `Unrecognised` and leaves the entry alone, neither settling nor
/// sending it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum EntryState {
    /// Saved, and being (or about to be) sent. Not a terminal state.
    Sent,
    /// Hosted gave a definitive answer: a receipt, or a refusal.
    Confirmed,
    /// Every attempt failed before anything reached hosted.
    NotSent,
    /// The outcome is unknown. Only the caller (or a person) can settle it.
    Uncertain,
    /// Accepted by the node while hosted could not take writes, and waiting to
    /// be sent in sequence order. Keeps its arguments; never pruned.
    Pending,
    /// Hosted durably accepted the write but has not reported a canonical
    /// outcome. Never pruned or automatically sent by the node.
    HostedPending,
    /// Home committed, but the keyed outcome still needs recovery.
    CommittedUnrecovered,
    /// A result cannot yet be durably recovered; blocks later record saves.
    ResultUnrecovered,
    /// Operator reconciled the outcome against canonical history. Never replayed or pruned.
    Acknowledged,
    /// A state written by a newer build.
    #[serde(other)]
    Unrecognised,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum KeyOrigin {
    Caller,
    Node,
}

/// Why the node took a write over instead of forwarding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HoldReason {
    /// The hosted operation requires a newer client; updater is unavailable.
    ClientUpdateRequired,
    /// Hosted answered `DEPLOYMENT_READ_ONLY`.
    DeploymentReadOnly,
    /// Hosted was unreachable on a forward and on a follow-up check.
    HostedUnreachable,
    /// A reason written by a newer build.
    #[serde(other)]
    Other,
}

impl HoldReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentReadOnly => "deployment_read_only",
            Self::ClientUpdateRequired => "client_update_required",
            Self::HostedUnreachable => "hosted_unreachable",
            Self::Other => "other",
        }
    }
}

/// Verified portable account and exact hosted database identity. No bearer
/// material is retained in a pending entry or used as its namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyBinding {
    pub account_id: String,
    pub database_id: String,
    pub origin_database_id: String,
    pub history_lineage: String,
    pub resource_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_id: Option<String>,
}
impl CustodyBinding {
    pub(super) fn valid(&self) -> bool {
        [
            &self.account_id,
            &self.database_id,
            &self.origin_database_id,
            &self.history_lineage,
            &self.resource_origin,
        ]
        .iter()
        .all(|field| !field.trim().is_empty())
            && self.install_id.as_deref().is_none_or(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KernelV2Custody {
    pub engine: String,
    pub binding: CustodyBinding,
    pub contract_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<OriginalContract>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalContract {
    pub rule: u32,
    #[serde(deserialize_with = "deserialize_original_contract")]
    pub contract: crate::mcp::executor_prototype::NodeHoldingContract,
}

// Strictness belongs to frozen v6 evidence; keep existing discovery cache
// deserialization tolerant of unrelated outer metadata, as before.
fn deserialize_original_contract<'de, D>(
    deserializer: D,
) -> std::result::Result<crate::mcp::executor_prototype::NodeHoldingContract, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StoredContract {
        description: Value,
        catalog: Value,
    }
    let stored = StoredContract::deserialize(deserializer)?;
    Ok(crate::mcp::executor_prototype::NodeHoldingContract {
        description: stored.description,
        catalog: stored.catalog,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CompatibilityBlock {
    Incompatible,
    EvidenceMissing,
    LegacyDigestDrift,
    /// Strict old readers cannot decode this barrier and preserve opaque custody.
    OriginalResolution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CustodyCompatibility {
    SourceDescriptionOnly,
    PriorAttemptUnverified,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Entry {
    pub(super) version: u32,
    #[cfg(feature = "v2-kernel-probe")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    working_original: Option<working_v2::OriginalAppend>,
    #[cfg(feature = "v2-kernel-probe")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    working_resolution: Option<working_v2::WorkingResolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) kernel_v2_custody: Option<KernelV2Custody>,
    pub(super) id: String,
    pub(super) state: EntryState,
    pub(super) received_at: String,
    pub(super) received_unix_ms: u64,
    pub(super) updated_at: String,
    pub(super) executor: String,
    pub(super) operation: String,
    /// The MCP tool name the call arrived under (`call_executor` or an executor).
    pub(super) tool: String,
    pub(super) run_key: Option<String>,
    pub(super) client_info: Option<Value>,
    /// Non-secret exact native/app carrier; never contains proof bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) app_identity: Option<String>,
    /// `None` when the operation's contract has no `idempotency_key`.
    pub(super) idempotency_key: Option<String>,
    pub(super) key_origin: Option<KeyOrigin>,
    pub(super) attempts: u32,
    /// SHA-256 of the operation arguments (including the key).
    pub(super) arguments_digest: String,
    pub(super) arguments_bytes: usize,
    /// Present while the outcome is open; dropped once settled.
    pub(super) arguments: Option<Value>,
    /// `receipt` or `refused`, once hosted has answered.
    pub(super) answer: Option<String>,
    pub(super) detail: Option<String>,
    pub(super) resolved_by: Option<String>,
    // Added in slice 2B. All defaulted, and absent from the file unless used.
    /// Order of receipt, monotonic across restarts. Millisecond times can
    /// tie, so the send queue orders by this. 0 on entries from slice 2A.
    #[serde(default)]
    pub(super) seq: u64,
    /// The run that started the calling run, for status and bootstrap views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) parent_key: Option<String>,
    /// The record's title, where the arguments give one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) title: Option<String>,
    /// The record this write creates or changes. For a held create it is the
    /// node-chosen ID, returned to the caller before anything is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) hold_reason: Option<HoldReason>,
    /// Every record a held `create_many` creates, in input order. Node-chosen
    /// where the caller gave none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) record_ids: Vec<String>,
    /// The call's envelope without its `arguments`: `run_key`, `parent_key`,
    /// `format`. With `arguments`, `executor`, `operation` and `tool` it is
    /// enough to rebuild the request exactly. Kept only while the entry is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) envelope: Option<Value>,
    /// Digest of what the caller asked (key set, node-chosen IDs left out),
    /// so a repeat of the same call can be recognised whatever the node added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) intent_digest: Option<String>,
    /// The write was already in flight when the node took it over, so it may
    /// have been applied. Resending with its key settles that either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) maybe_applied: bool,
    /// What a repeat of a held call is answered with once the node has sent
    /// it: hosted's receipt or refusal, or the node's own note. Bounded;
    /// absent when too large, and a repeat then goes to hosted with its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reply: Option<String>,
    /// A queue send of this entry was started and its outcome not yet saved.
    /// Found set at startup, it means the node died mid-send.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) in_flight: bool,
    /// The held write this one was refused for depending on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) refused_because: Option<String>,
    /// Hosted's custody handle, distinct from this node journal's entry id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) hosted_journal_entry: Option<String>,
    /// Local operator assertion, not a hosted receipt or a remote cancellation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) operator_audit: Option<OperatorAudit>,
    /// Opt-in preview reconstruction only; never used by the hosted sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) fork_arguments: Option<Value>,
    /// Custody admitted by description-only compatibility, without granting
    /// speculative local execution. Missing on older exact-contract entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) custody_compatibility: Option<CustodyCompatibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) compatibility_block: Option<CompatibilityBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) waiting_for: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) fork_run_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) fork_accepted_act: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) merge_intent: Option<MergeIntent>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) prepared: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) lineage_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) merge_preparation: Option<super::lineage::PreparedMerge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) merge_result: Option<MergeResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) merge_aliases: Vec<MergeAlias>,
    /// Terminal typed-key custody after private payload retention ends.
    /// Keeps every accepted key from ever becoming a new draft again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) merge_key_tombstone: bool,
    #[serde(default)]
    pub(super) not_before_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) recovery_item: Option<String>,
}

/// Node-only draft identity. Slice 3 freezes the declared base directly;
/// lineage preparation remains a prerequisite for enabling body merge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct MergeIntent {
    pub(super) declared_base_version: String,
    pub(super) declared_base_text: String,
    pub(super) draft_text: String,
    pub(super) editor: String,
    pub(super) made_at_ms: Option<u64>,
    pub(super) wait: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct MergeAlias {
    pub(super) key: String,
    pub(super) intent_digest: String,
}

/// A received result is recorded before any recovery or lineage side effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct MergeResult {
    pub(super) kind: String,
    pub(super) body: Value,
    pub(super) reply: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) recovery_ids: Vec<String>,
}

impl Entry {
    #[cfg(feature = "v2-kernel-probe")]
    pub(in crate::node) fn working_original_ref(&self) -> Option<&working_v2::OriginalAppend> {
        self.working_original.as_ref()
    }
    #[cfg(feature = "v2-kernel-probe")]
    pub(in crate::node) fn working_resolution_ref(&self) -> Option<&working_v2::WorkingResolution> {
        self.working_resolution.as_ref()
    }
    #[cfg(feature = "v2-kernel-probe")]
    pub(in crate::node) fn working_annotations(&self) -> Option<crate::store::EventAnnotations> {
        self.working_original
            .as_ref()
            .map(|original| original.annotations())
    }
    pub(super) fn ordinary_v2(&self) -> bool {
        matches!(self.version, 3 | V2_EVIDENCE_VERSION) && self.kernel_v2_custody.is_some()
    }

    fn valid_v6(&self) -> bool {
        #[cfg(feature = "v2-kernel-probe")]
        if self.working_original.is_some() {
            return false;
        }
        let Some(c) = &self.kernel_v2_custody else {
            return false;
        };
        self.version == V2_EVIDENCE_VERSION
            && c.engine == "native-kernel-v2"
            && c.binding.valid()
            && valid_contract_digest(&c.contract_digest)
            && c.original.as_ref().is_some_and(|original| {
                original.rule == SOURCE_DESCRIPTION_RULE
                    && original.contract.valid_evidence(
                        &self.executor,
                        &self.operation,
                        &c.contract_digest,
                    )
                    && serde_json::to_vec(original)
                        .is_ok_and(|b| b.len() as u64 <= MAX_CONTRACT_EVIDENCE_BYTES)
            })
            && self.custody_compatibility.is_none()
            && self.app_identity.is_none()
            && self.executor == "records_write"
            && matches!(
                self.operation.as_str(),
                "update_record" | "manage_links.add" | "attach_text"
            )
            && self
                .waiting_for
                .as_ref()
                .is_none_or(|id| uuid::Uuid::parse_str(id).is_ok())
    }

    pub(super) fn compatibility_message(&self) -> Option<&'static str> {
        if self.state != EntryState::Pending {
            return None;
        }
        if self.waiting_for.is_some() {
            return Some("Waiting behind a write that needs you.");
        }
        match self.compatibility_block? {
            CompatibilityBlock::EvidenceMissing => Some("Waiting to reconnect. Your text is kept on this device."),
            CompatibilityBlock::OriginalResolution => Some("Original status recovery is pending. Your content is retained privately; use owner recovery to inspect it."),
            _ if self.maybe_applied || self.in_flight => Some("This write may already have gone through. Your text is kept on this device. Check its history before sending again."),
            _ => Some("Not sent yet. Your text is kept on this device and will be sent when it can be. To send it differently instead, discard this one first."),
        }
    }

    #[cfg(feature = "v2-kernel-probe")]
    fn native_operation(&self) -> &str {
        if let Some(original) = self.working_original.as_ref() {
            return original.source_tool();
        }
        match crate::mcp::kernel_v2::writes::replay::RecordOperation::from_catalog(
            &self.executor,
            &self.operation,
        ) {
            Some(operation) => operation.source_tool(),
            None => &self.operation,
        }
    }

    pub(super) fn installed_working(&self) -> bool {
        installed_working_version(self.version) && self.is_working()
    }

    fn is_working(&self) -> bool {
        #[cfg(feature = "v2-kernel-probe")]
        {
            matches!(
                self.version,
                WORKING_MANAGER_VERSION
                    | INSTALLED_WORKING_VERSION
                    | INSTALLED_CREATE_VERSION
                    | INSTALLED_RECORD_VERSION
            ) && self
                .working_original
                .as_ref()
                .is_some_and(|original| original.valid_entry(self))
        }
        #[cfg(not(feature = "v2-kernel-probe"))]
        {
            false
        }
    }
    fn valid_description_custody(&self) -> bool {
        self.version == DESCRIPTION_CUSTODY_VERSION
            && self.kernel_v2_custody.is_none()
            && self.custody_compatibility.is_some()
            && (self.custody_compatibility != Some(CustodyCompatibility::PriorAttemptUnverified)
                || self.maybe_applied)
            && self.app_identity.is_none()
            && self.operation != "merge_body"
            && hold::HOLDABLE.contains(&(self.executor.as_str(), self.operation.as_str()))
            && self
                .idempotency_key
                .as_deref()
                .is_some_and(|key| !key.trim().is_empty())
            && self.key_origin.is_some()
            && self.fork_arguments.is_none()
            && self.fork_run_key.is_none()
            && self.fork_accepted_act.is_none()
            && self.merge_intent.is_none()
            && self.merge_preparation.is_none()
            && self.merge_result.is_none()
            && self.merge_aliases.is_empty()
            && match self.arguments.as_ref() {
                Some(arguments) => {
                    self.envelope.as_ref().is_some_and(Value::is_object)
                        && hold::is_holdable(&self.executor, &self.operation, arguments)
                        && arguments.get("idempotency_key").and_then(Value::as_str)
                            == self.idempotency_key.as_deref()
                        && self.arguments_digest == scoped_arguments_digest(arguments, None)
                        && self.arguments_bytes == arguments.to_string().len()
                }
                None => {
                    self.state == EntryState::Confirmed
                        && self.answer.as_deref() == Some("receipt")
                        && self.envelope.is_none()
                }
            }
    }
    pub(super) fn merge_identity_matches(&self, key: &str, digest: &str, editor: &str) -> bool {
        self.merge_intent
            .as_ref()
            .is_some_and(|intent| intent.editor == editor)
            && ((self.idempotency_key.as_deref() == Some(key)
                && self.intent_digest.as_deref() == Some(digest))
                || self
                    .merge_aliases
                    .iter()
                    .any(|alias| alias.key == key && alias.intent_digest == digest))
    }

    pub(super) fn is_merge(&self) -> bool {
        self.version == 2
            && self.executor == "records_write"
            && self.operation == "merge_body"
            && self.intent.as_deref() == Some("body.merge")
            && self.merge_intent.is_some()
    }

    pub(super) fn merge_open(&self) -> bool {
        self.is_merge()
            && !self.merge_key_tombstone
            && !matches!(
                self.state,
                EntryState::Confirmed | EntryState::Acknowledged | EntryState::NotSent
            )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct OperatorAudit {
    pub(super) action: String,
    pub(super) outcome: Option<String>,
    pub(super) reason: String,
    pub(super) uid: u32,
    pub(super) pid: Option<i32>,
    pub(super) at: String,
    pub(super) previous_state: EntryState,
}

/// What a `node_status` read asks for. Every field narrows the list.
#[derive(Clone, Debug, Default)]
pub(super) struct StatusFilter {
    pub(super) run: Option<String>,
    pub(super) parent_run: Option<String>,
    /// View states: pending, hosted_pending, sent, refused, uncertain,
    /// not_sent, unrecognised.
    pub(super) states: Vec<String>,
    pub(super) limit: usize,
    /// List the newest writes first (`order: "newest_first"`). The default is
    /// the order they were accepted in.
    pub(super) newest_first: bool,
}

/// A stored reply larger than this is dropped rather than kept.
pub(super) const MAX_STORED_REPLY: usize = 256 * 1024;

/// What the caller provides for a new entry.
pub(super) struct NewEntry {
    pub(super) executor: String,
    pub(super) operation: String,
    pub(super) tool: String,
    pub(super) run_key: Option<String>,
    pub(super) client_info: Option<Value>,
    pub(super) app_identity: Option<String>,
    pub(super) idempotency_key: Option<String>,
    pub(super) key_origin: Option<KeyOrigin>,
    pub(super) arguments: Value,
    pub(super) parent_key: Option<String>,
    pub(super) title: Option<String>,
    pub(super) record_id: Option<String>,
    pub(super) record_ids: Vec<String>,
    pub(super) envelope: Option<Value>,
    pub(super) intent_digest: Option<String>,
}

pub(super) fn arguments_digest(arguments: &Value) -> String {
    crate::canonical_json::digest_json(arguments)
}

pub(super) fn scoped_arguments_digest(arguments: &Value, app: Option<&str>) -> String {
    match app {
        Some(app) => arguments_digest(&json!({"app":app,"arguments":arguments})),
        None => arguments_digest(arguments),
    }
}

/// Canonical argument equivalence for same-key settlement. Both sides with
/// retained arguments compare canonical digests directly; a settled receipt
/// drops its arguments, so a retained earlier entry re-digests canonically
/// against the receipt's stored digest. Stored-digest equality stays as a
/// fallback for entries written before the canonical digest. All branches
/// preserve array order through the canonical form.
fn arguments_equivalent(earlier: &Entry, settled: &Entry) -> bool {
    if earlier.app_identity != settled.app_identity {
        return false;
    }
    let digest = |a: &Value| scoped_arguments_digest(a, settled.app_identity.as_deref());
    match (&earlier.arguments, &settled.arguments) {
        (Some(a), Some(b)) => digest(a) == digest(b),
        (Some(a), None) => {
            let canonical = digest(a);
            canonical == settled.arguments_digest
                || earlier.arguments_digest == settled.arguments_digest
        }
        (None, _) => earlier.arguments_digest == settled.arguments_digest,
    }
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(super) struct Journal {
    directory: PathBuf,
    custody_binding: Option<CustodyBinding>,
    entries: StdMutex<BTreeMap<String, Entry>>,
    last_prune: StdMutex<std::time::Instant>,
    retention: Duration,
    /// How long a refused held write is kept. A refusal is not dropped after
    /// the usual retention: it is the answer to "what didn't make it".
    pub(super) refusal_retention: Duration,
    /// Entries found on disk that this build cannot read or does not own.
    unreadable: usize,
    #[cfg(feature = "v2-kernel-probe")]
    enrolled_sequence: Option<enrolled_custody::Sequence>,
    /// The next sequence number recovered from the durable counter or old entries.
    next_seq: std::sync::atomic::AtomicU64,
    // Installed working publication and its real canonical queue producer use
    // this same authority fence; never a second proposal/receipt queue.
    #[cfg(feature = "v2-kernel-probe")]
    pub(super) working_serial: Arc<tokio::sync::Mutex<()>>,
    /// Test hook: fail the write after this many more (negative: never).
    #[cfg(test)]
    pub(super) fail_after: std::sync::atomic::AtomicI64,
}

impl Journal {
    /// Open (creating if needed) and recover. Entries left `sent` by a
    /// previous process become `uncertain`; nothing is sent.
    #[cfg(test)]
    pub(super) fn open(socket_directory: &Path, retention: Duration) -> Result<Self> {
        Self::open_with(socket_directory, retention, retention)
    }

    /// As `open`, with the (usually longer) retention for refused held
    /// writes in force from the start, so the pruning done at startup cannot
    /// drop a refusal earlier than the running node would.
    pub(super) fn open_with(
        socket_directory: &Path,
        retention: Duration,
        refusal_retention: Duration,
    ) -> Result<Self> {
        Self::open_bound(socket_directory, retention, refusal_retention, None)
    }

    pub(super) fn open_bound(
        socket_directory: &Path,
        retention: Duration,
        refusal_retention: Duration,
        custody_binding: Option<CustodyBinding>,
    ) -> Result<Self> {
        Self::open_bound_with_reader(
            socket_directory,
            retention,
            refusal_retention,
            custody_binding,
            read_entry,
        )
    }

    // Reader injection lets rollback proofs exercise the same recovery/pruning path
    // with the previous format admission rule, without building an old node binary.
    pub(super) fn open_bound_with_reader(
        socket_directory: &Path,
        retention: Duration,
        refusal_retention: Duration,
        custody_binding: Option<CustodyBinding>,
        read: fn(&Path) -> Result<Entry>,
    ) -> Result<Self> {
        let directory = socket_directory.join("journal");
        validate_credential_path(&directory, "node journal directory")?;
        match fs::symlink_metadata(&directory) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(Error::engine("invalid node journal directory"));
                }
                check_owned(&meta, 0o700)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                // The new directory's entry lives in its parent: until that
                // is on disk, every fsynced entry file inside could vanish
                // with it. Failing here fails startup.
                File::open(socket_directory)?.sync_all()?;
            }
            Err(e) => return Err(e.into()),
        }
        #[cfg(feature = "v2-kernel-probe")]
        let enrolled_sequence = custody_binding
            .as_ref()
            .filter(|binding| binding.install_id.is_some())
            .map(|binding| enrolled_custody::Sequence::open(socket_directory, binding))
            .transpose()?;
        let mut journal = Self {
            directory,
            #[cfg(feature = "v2-kernel-probe")]
            enrolled_sequence,
            custody_binding,
            entries: StdMutex::new(BTreeMap::new()),
            last_prune: StdMutex::new(std::time::Instant::now()),
            retention,
            refusal_retention,
            unreadable: 0,
            next_seq: std::sync::atomic::AtomicU64::new(1),
            #[cfg(feature = "v2-kernel-probe")]
            working_serial: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            fail_after: std::sync::atomic::AtomicI64::new(-1),
        };
        journal.load(read)?;
        journal.prune();
        Ok(journal)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }

    fn load(&mut self, read: fn(&Path) -> Result<Entry>) -> Result<()> {
        let mut entries = BTreeMap::new();
        for item in fs::read_dir(&self.directory)? {
            let path = item?.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned();
            if name.contains(".tmp") {
                // A write that never reached its rename: the entry it was
                // about to create or replace is still intact (or absent).
                let _ = fs::remove_file(&path);
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                self.unreadable += 1;
                continue;
            };
            match read(&path) {
                Ok(entry)
                    if entry.id == id
                        && match (&self.custody_binding, &entry.kernel_v2_custody) {
                            (Some(binding), Some(custody)) => {
                                (entry.ordinary_v2() || entry.is_working())
                                    && &custody.binding == binding
                            }
                            (None, None) => !matches!(entry.version, 3 | V2_EVIDENCE_VERSION),
                            _ => false,
                        } =>
                {
                    entries.insert(entry.id.clone(), entry);
                }
                _ => self.unreadable += 1,
            }
        }
        let top = entries.values().map(|entry| entry.seq).max().unwrap_or(0);
        #[cfg(feature = "v2-kernel-probe")]
        let top = if let Some(counter) = &self.enrolled_sequence {
            let saved = counter.high_water();
            if saved < top {
                return Err(Error::engine(
                    "installed journal sequence counter was restored",
                ));
            }
            saved
        } else {
            top
        };
        let next = top
            .checked_add(1)
            .ok_or_else(|| Error::engine("journal sequence exhausted"))?;
        for entry in entries.values_mut() {
            if entry.state == EntryState::Sent && !entry.is_merge() {
                entry.state = EntryState::Uncertain;
                entry.fork_arguments = None;
                entry.fork_run_key = None;
                entry.fork_accepted_act = None;
                entry.detail = Some(
                    "the node stopped while this write was in flight; whether hosted applied it is unknown".into(),
                );
                entry.updated_at = stamp();
                self.write(entry)?;
            }
        }
        // Repair terminal preview metadata written by earlier proof versions.
        // Preserve retention age; this is metadata cleanup, not new activity.
        for entry in entries.values_mut() {
            if entry.version == ENTRY_VERSION
                && entry.state != EntryState::Pending
                && !(entry.state == EntryState::Confirmed
                    && entry.answer.as_deref() == Some("receipt")
                    && entry.fork_accepted_act.is_some())
                && (entry.fork_arguments.is_some()
                    || entry.fork_run_key.is_some()
                    || entry.fork_accepted_act.is_some())
            {
                entry.fork_arguments = None;
                entry.fork_run_key = None;
                entry.fork_accepted_act = None;
                self.write(entry)?;
            }
        }
        // A queue send the node died in the middle of. Resending with its key
        // is safe and stays on the table, but the write may already have been
        // applied, and every later reply says so.
        for entry in entries.values_mut() {
            if !entry.in_flight {
                continue;
            }
            entry.in_flight = false;
            entry.updated_at = stamp();
            if matches!(
                entry.state,
                EntryState::Pending
                    | EntryState::CommittedUnrecovered
                    | EntryState::ResultUnrecovered
            ) {
                entry.maybe_applied = true;
                entry.detail = Some(
                    "the node stopped while sending this write; it may already have been applied. Automatic replay may stop for reconciliation; inspect node_status".into(),
                );
            }
            self.write(entry)?;
        }
        *self.next_seq.get_mut() = next;
        *self.entries.get_mut().expect("journal entries") = entries;
        Ok(())
    }

    fn write(&self, entry: &Entry) -> Result<()> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering::SeqCst;
            // After this many more successful writes, fail one.
            let left = self.fail_after.load(SeqCst);
            if left == 0 {
                self.fail_after.store(-1, SeqCst);
                return Err(Error::engine("injected journal write failure"));
            }
            if left > 0 {
                self.fail_after.store(left - 1, SeqCst);
            }
        }
        #[cfg(feature = "v2-kernel-probe")]
        if let Some(sequence) = &self.enrolled_sequence {
            sequence.reserve(entry.seq)?;
        }
        let path = self.path(&entry.id);
        let temporary = self
            .directory
            .join(format!("{}.{}.tmp", entry.id, uuid::Uuid::new_v4()));
        let result = (|| {
            let bytes = serde_json::to_vec(entry)?;
            if bytes.len() as u64
                > if entry.is_merge() {
                    MAX_MERGE_ENTRY_BYTES
                } else {
                    entry_size_limit(entry.version)
                }
            {
                return Err(Error::engine("journal entry exceeds bound"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, &path)?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Save a new entry in state `sent`. Failure means nothing may be sent.
    pub(super) fn begin(&self, new: NewEntry) -> Result<Entry> {
        self.begin_inner(new, None, None, None)
    }

    pub(super) fn begin_kernel_v2(
        &self,
        new: NewEntry,
        contract_digest: String,
        original: OriginalContract,
    ) -> Result<Entry> {
        if self.custody_binding.is_none() {
            return Err(Error::engine("missing v2 custody binding"));
        }
        let mut entry = self.make_entry(new, None, None, Some(contract_digest))?;
        entry.version = V2_EVIDENCE_VERSION;
        entry
            .kernel_v2_custody
            .as_mut()
            .expect("v2 custody")
            .original = Some(original);
        if !entry.valid_v6() {
            return Err(Error::engine("invalid original v2 contract evidence"));
        }
        self.write(&entry)?;
        self.entries
            .lock()
            .expect("journal entries")
            .insert(entry.id.clone(), entry.clone());
        Ok(entry)
    }

    #[cfg(test)]
    fn begin_legacy_kernel_v2(&self, new: NewEntry, contract_digest: String) -> Result<Entry> {
        self.begin_inner(new, None, None, Some(contract_digest))
    }

    pub(super) fn begin_merge(&self, new: NewEntry, intent: MergeIntent) -> Result<Entry> {
        // Only the last save on this record may be coalesced. Crossing a
        // different editor or a legacy write would change record ordering.
        let mut entries = self.entries.lock().expect("journal entries");
        let candidate = entries
            .values()
            .filter(|entry| {
                !matches!(
                    entry.state,
                    EntryState::Confirmed | EntryState::Acknowledged | EntryState::NotSent
                ) && (entry.record_id == new.record_id
                    || new
                        .record_id
                        .as_ref()
                        .is_some_and(|id| entry.record_ids.contains(id)))
            })
            .max_by_key(|entry| entry.seq);
        if let Some(current) = candidate.filter(|entry| {
            entry.is_merge()
                && entry.lineage_required
                && !entry.prepared
                && entry.merge_result.is_none()
                && entry.state == EntryState::Pending
                && entry.merge_intent.as_ref().is_some_and(|prior| {
                    prior.editor == intent.editor
                        && prior.declared_base_version == intent.declared_base_version
                        && prior.declared_base_text == intent.declared_base_text
                })
        }) {
            let mut next = current.clone();
            if let (Some(key), Some(digest)) = (&current.idempotency_key, &current.intent_digest) {
                next.merge_aliases.push(MergeAlias {
                    key: key.clone(),
                    intent_digest: digest.clone(),
                });
            }
            next.idempotency_key = new.idempotency_key;
            next.key_origin = new.key_origin;
            next.arguments_digest = scoped_arguments_digest(&new.arguments, None);
            next.arguments_bytes = new.arguments.to_string().len();
            next.arguments = Some(new.arguments);
            next.intent_digest = new.intent_digest;
            next.envelope = new.envelope;
            next.run_key = new.run_key;
            next.parent_key = new.parent_key;
            next.client_info = new.client_info;
            next.merge_intent = Some(intent);
            next.updated_at = stamp();
            self.write(&next)?;
            entries.insert(next.id.clone(), next.clone());
            return Ok(next);
        }
        drop(entries);
        self.begin_inner(new, Some(intent), None, None)
    }

    pub(super) fn has_open_merge(&self, record: &str, editor: &str) -> bool {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|entry| {
                entry.merge_open()
                    && entry.record_id.as_deref() == Some(record)
                    && entry
                        .merge_intent
                        .as_ref()
                        .is_some_and(|intent| intent.editor == editor)
            })
    }

    pub(super) fn merge_entries(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|entry| entry.is_merge())
            .cloned()
            .collect()
    }

    /// Explicit account-boundary erasure, serialized against all sends.
    pub(super) fn forget_merges(&self) -> Result<usize> {
        // Unknown files may contain merge drafts. Removing only the parsed
        // subset would falsely claim that account-boundary erasure completed.
        if self.unreadable != 0 {
            return Err(Error::engine(
                "cannot establish complete body-merge erasure while journal files are unreadable",
            ));
        }
        let mut entries = self.entries.lock().expect("journal entries");
        let ids = entries
            .values()
            .filter(|entry| entry.is_merge())
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>();
        for id in &ids {
            match fs::remove_file(self.path(id)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            entries.remove(id);
        }
        File::open(&self.directory)?.sync_all()?;
        Ok(ids.len())
    }

    pub(super) fn begin_merge_refused(
        &self,
        new: NewEntry,
        intent: MergeIntent,
        body: Value,
    ) -> Result<Entry> {
        self.begin_inner(
            new,
            Some(intent),
            Some(MergeResult {
                kind: "refused".into(),
                body,
                reply: None,
                recovery_ids: Vec::new(),
            }),
            None,
        )
    }

    fn begin_inner(
        &self,
        new: NewEntry,
        merge: Option<MergeIntent>,
        result: Option<MergeResult>,
        contract_digest: Option<String>,
    ) -> Result<Entry> {
        let entry = self.make_entry(new, merge, result, contract_digest)?;
        self.write(&entry)?;
        self.entries
            .lock()
            .expect("journal entries")
            .insert(entry.id.clone(), entry.clone());
        self.maybe_prune();
        Ok(entry)
    }

    fn make_entry(
        &self,
        new: NewEntry,
        merge: Option<MergeIntent>,
        result: Option<MergeResult>,
        contract_digest: Option<String>,
    ) -> Result<Entry> {
        #[cfg(feature = "v2-kernel-probe")]
        if self
            .enrolled_qualification()
            .is_some_and(|proof| proof.get().is_none())
        {
            return Err(Error::engine(
                "enrolled journal continuity has not been verified",
            ));
        }
        let merging = merge.is_some();
        let digest = scoped_arguments_digest(&new.arguments, new.app_identity.as_deref());
        let bytes = new.arguments.to_string().len();
        let received_ms = now_ms();
        let entry = Entry {
            #[cfg(feature = "v2-kernel-probe")]
            working_original: None,
            #[cfg(feature = "v2-kernel-probe")]
            working_resolution: None,
            version: if self.custody_binding.is_some() {
                3
            } else if merging {
                2
            } else {
                ENTRY_VERSION
            },
            kernel_v2_custody: match (&self.custody_binding, contract_digest) {
                (Some(binding), Some(contract_digest)) => Some(KernelV2Custody {
                    engine: "native-kernel-v2".into(),
                    binding: binding.clone(),
                    contract_digest,
                    original: None,
                }),
                (None, None) => None,
                _ => return Err(Error::engine("invalid v2 custody construction")),
            },
            id: uuid::Uuid::new_v4().to_string(),
            state: if merging {
                EntryState::Pending
            } else {
                EntryState::Sent
            },
            received_at: stamp(),
            received_unix_ms: received_ms,
            updated_at: stamp(),
            executor: new.executor,
            operation: new.operation,
            tool: new.tool,
            run_key: new.run_key,
            client_info: new.client_info,
            app_identity: new.app_identity,
            idempotency_key: new.idempotency_key,
            key_origin: new.key_origin,
            attempts: 0,
            arguments_digest: digest,
            arguments_bytes: bytes,
            arguments: Some(new.arguments),
            answer: None,
            detail: None,
            resolved_by: None,
            seq: self
                .next_seq
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |sequence| sequence.checked_add(1),
                )
                .map_err(|_| Error::engine("journal sequence exhausted"))?,
            parent_key: new.parent_key,
            title: new.title,
            record_id: new.record_id,
            hold_reason: None,
            record_ids: new.record_ids,
            envelope: new.envelope,
            intent_digest: new.intent_digest,
            maybe_applied: false,
            reply: None,
            in_flight: false,
            refused_because: None,
            hosted_journal_entry: None,
            operator_audit: None,
            intent: merging.then(|| "body.merge".into()),
            merge_intent: merge,
            prepared: false,
            lineage_required: merging,
            merge_preparation: None,
            merge_result: result,
            merge_aliases: Vec::new(),
            merge_key_tombstone: false,
            not_before_ms: 0,
            recovery_item: None,
            fork_arguments: None,
            custody_compatibility: None,
            compatibility_block: None,
            waiting_for: None,
            fork_run_key: None,
            fork_accepted_act: None,
        };
        Ok(entry)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn canonical_working_verdict(
        &self,
        verdict: &super::gate::queue::WorkingVerdict,
    ) -> Result<Entry> {
        self.update_checked(
            verdict.id(),
            |entry| verdict.apply(entry),
            |current, _| verdict.matches(current),
            true,
        )
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) async fn prepare_working_create(
        &self,
        actor: &str,
        original: &crate::mcp::kernel_v2::writes::replay::CapturedFirstPartyCreate,
        prepared: Option<&Value>,
    ) -> Result<crate::mcp::kernel_v2::writes::replay::ReplayProposal> {
        let _serial = self.working_serial.lock().await;
        let entries = self.entries.lock().expect("journal entries");
        let key = original.source()["idempotency_key"]
            .as_str()
            .ok_or_else(|| Error::engine("original create key missing"))?;
        if let Some(entry) = entries.values().find(|e| {
            e.executor == "records_write"
                && e.operation == "create_record"
                && e.idempotency_key.as_deref() == Some(key)
        }) {
            if !entry.installed_working()
                || entry
                    .working_original
                    .as_ref()
                    .is_none_or(|o| o.actor() != actor)
            {
                return Err(Error::conflict(
                    "create key belongs to another original custody entry",
                ));
            }
            return original.prepare(actor, entry.arguments.as_ref());
        }
        original.prepare(actor, prepared)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn enrolled_qualification(&self) -> Option<&tokio::sync::OnceCell<()>> {
        self.enrolled_sequence
            .as_ref()
            .map(|sequence| &sequence.qualification)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn enrolled_original_sequences(
        &self,
        install: &str,
    ) -> Result<(u64, BTreeMap<u64, String>, std::collections::BTreeSet<u64>)> {
        let unavailable = || Error::engine("enrolled journal scope or sequence is unverified");
        let binding = self.custody_binding.as_ref().ok_or_else(unavailable)?;
        if binding.install_id.as_deref() != Some(install) || self.unreadable != 0 {
            return Err(unavailable());
        }
        let high_water = self
            .enrolled_sequence
            .as_ref()
            .ok_or_else(unavailable)?
            .high_water();
        let mut seen = BTreeMap::new();
        let mut confirmed = std::collections::BTreeSet::new();
        for entry in self.entries.lock().expect("journal entries").values() {
            if !installed_working_version(entry.version)
                || entry.seq == 0
                || entry.seq > high_water
                || entry.kernel_v2_custody.as_ref().map(|c| &c.binding) != Some(binding)
            {
                return Err(unavailable());
            }
            let original = working_v2::settlement_original(entry)?;
            if seen
                .insert(entry.seq, original.expected_binding_sha256)
                .is_some()
            {
                return Err(unavailable());
            }
            if entry.state == EntryState::Confirmed
                && entry.answer.as_deref() == Some("receipt")
                && entry.working_resolution.is_none()
            {
                confirmed.insert(entry.seq);
            }
        }
        Ok((high_water, seen, confirmed))
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn working_ordinal(&self, id: &str) -> Option<i64> {
        let entries = self.entries.lock().expect("journal entries");
        let mut originals: Vec<_> = entries
            .values()
            .filter(|entry| installed_working_version(entry.version))
            .collect();
        originals.sort_by_key(|entry| entry.seq);
        originals
            .iter()
            .position(|entry| entry.id == id)
            .and_then(|ordinal| i64::try_from(ordinal).ok()?.checked_add(1))
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn installed_working_target(
        &self,
        compatible: impl Fn(&Entry) -> bool,
    ) -> Result<Option<(String, String)>> {
        if self.unreadable > 0 {
            return Err(Error::engine(
                "opaque scoped custody cannot establish a complete working view",
            ));
        }
        let entries = self.entries.lock().expect("journal entries");
        let mut target: Option<(String, String)> = None;
        for entry in entries
            .values()
            .filter(|entry| installed_working_version(entry.version))
        {
            if !compatible(entry) {
                return Err(Error::engine("retained working operation needs its exact current contract; original retained"));
            }
            let next = (
                entry
                    .record_id
                    .clone()
                    .ok_or_else(|| Error::engine("working original missing target"))?,
                entry
                    .kernel_v2_custody
                    .as_ref()
                    .ok_or_else(|| Error::engine("working scope missing"))?
                    .contract_digest
                    .clone(),
            );
            if target.is_none() {
                target = Some(next);
            }
        }
        Ok(target)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn working_terminal(
        &self,
        actor: &str,
        proposal: &crate::mcp::kernel_v2::writes::replay::ReplayProposal,
    ) -> Result<Option<String>> {
        let entries = self.entries.lock().expect("journal entries");
        let Some(entry) = entries.values().find(|entry| {
            (entry.ordinary_v2() || entry.installed_working())
                && entry.native_operation() == proposal.tool()
                && entry.app_identity.is_none()
                && entry.idempotency_key.as_deref() == proposal.idempotency_key()
                && (entry.ordinary_v2()
                    || entry
                        .working_original
                        .as_ref()
                        .is_some_and(|original| original.actor() == actor))
        }) else {
            return Ok(None);
        };
        // Existing ordinary v2 custody is never promoted or duplicated. Only an
        // exact retained terminal answer can be returned; anything else waits
        // for its original queue owner.
        if entry.ordinary_v2() {
            if entry.arguments.as_ref() == Some(proposal.args())
                && entry.state == EntryState::Confirmed
                && matches!(entry.answer.as_deref(), Some("receipt" | "refused"))
                && entry.reply.is_some()
            {
                return Ok(entry.reply.clone());
            }
            return Err(Error::conflict(if entry.version == 3 {
                "key already belongs to existing v3 custody; it cannot be converted or duplicated"
            } else {
                "key already belongs to existing v2 evidence custody; it cannot be converted or duplicated"
            }));
        }
        let original = entry
            .working_original
            .as_ref()
            .expect("validated installed original");
        if original.native_arguments().or(entry.arguments.as_ref()) != Some(proposal.args())
            || original.fingerprint().as_bytes() != proposal.request_fingerprint().as_bytes()
        {
            return Err(Error::conflict(
                "working proposal key is reserved for different original bytes",
            ));
        }
        if entry.state == EntryState::Confirmed
            && entry
                .answer
                .as_deref()
                .is_some_and(|answer| matches!(answer, "receipt" | "refused"))
        {
            return Ok(entry.reply.clone());
        }
        Ok(None)
    }

    /// Apply `change` to an entry and persist it. The in-memory copy changes
    /// only if the write succeeds.
    pub(super) fn update(&self, id: &str, change: impl FnOnce(&mut Entry)) -> Result<Entry> {
        self.update_checked(id, change, |_, _| Ok(()), false)
    }
    fn update_checked(
        &self,
        id: &str,
        change: impl FnOnce(&mut Entry),
        validate: impl FnOnce(&Entry, &Entry) -> Result<()>,
        canonical: bool,
    ) -> Result<Entry> {
        let mut entries = self.entries.lock().expect("journal entries");
        let Some(current) = entries.get(id) else {
            return Err(Error::engine("journal entry missing"));
        };
        let mut next = current.clone();
        change(&mut next);
        validate(current, &next)?;
        #[cfg(feature = "v2-kernel-probe")]
        if !canonical && current.working_resolution != next.working_resolution {
            return Err(Error::engine(
                "resolution evidence requires its real producer",
            ));
        }
        #[cfg(feature = "v2-kernel-probe")]
        if (next.attempts != current.attempts || (!current.in_flight && next.in_flight))
            && entries
                .values()
                .any(|entry| entry.working_resolution.is_some())
        {
            return Err(Error::engine("working original resolution pauses dispatch"));
        }

        #[cfg(feature = "v2-kernel-probe")]
        if current.working_resolution.is_some()
            && (next.working_original != current.working_original
                || next.compatibility_block != Some(CompatibilityBlock::OriginalResolution)
                || next.working_resolution.is_none()
                || next.version != current.version)
        {
            return Err(Error::engine("original resolution custody is immutable"));
        }

        #[cfg(feature = "v2-kernel-probe")]
        if installed_working_version(current.version)
            && !canonical
            && (current.answer != next.answer || current.reply != next.reply)
        {
            return Err(Error::engine(
                "installed working verdict requires the verified canonical queue producer",
            ));
        }
        #[cfg(not(feature = "v2-kernel-probe"))]
        let _ = canonical;
        #[cfg(feature = "v2-kernel-probe")]
        if (current.working_original.is_some() || next.working_original.is_some())
            && (!current.is_working()
                || !next.is_working()
                || current.working_original != next.working_original
                || current.arguments != next.arguments
                || current.envelope != next.envelope
                || current.kernel_v2_custody != next.kernel_v2_custody
                || current.idempotency_key != next.idempotency_key
                || current.seq != next.seq)
        {
            return Err(Error::engine(
                "working proposal identity and retained request are immutable",
            ));
        }
        if current.kernel_v2_custody != next.kernel_v2_custody
            || (current.kernel_v2_custody.is_some() && current.version != next.version)
        {
            return Err(Error::engine("v2 custody binding is immutable"));
        }

        if current.version == V2_EVIDENCE_VERSION {
            let retired = next.state == EntryState::Confirmed
                && next.answer.as_deref() == Some("receipt")
                && next.arguments.is_none()
                && next.envelope.is_none();
            if !next.valid_v6()
                || next.id != current.id
                || next.received_at != current.received_at
                || next.received_unix_ms != current.received_unix_ms
                || next.executor != current.executor
                || next.operation != current.operation
                || next.tool != current.tool
                || next.run_key != current.run_key
                || next.client_info != current.client_info
                || next.parent_key != current.parent_key
                || next.record_id != current.record_id
                || next.record_ids != current.record_ids
                || (current.maybe_applied && !next.maybe_applied)
                || next.idempotency_key != current.idempotency_key
                || next.key_origin != current.key_origin
                || next.arguments_digest != current.arguments_digest
                || next.intent_digest != current.intent_digest
                || next.arguments_bytes != current.arguments_bytes
                || next.seq != current.seq
                || (!retired
                    && (next.arguments != current.arguments || next.envelope != current.envelope))
            {
                return Err(Error::engine(
                    "original v2 contract and request are immutable",
                ));
            }
        }

        if next.version == DESCRIPTION_CUSTODY_VERSION
            || current.version == DESCRIPTION_CUSTODY_VERSION
        {
            let promotion = current.version == ENTRY_VERSION
                && matches!(current.state, EntryState::Sent | EntryState::Uncertain)
                && next.state == EntryState::Pending;
            let request_retired = next.state == EntryState::Confirmed
                && next.answer.as_deref() == Some("receipt")
                && next.arguments.is_none()
                && next.envelope.is_none();
            if (!promotion && current.version != DESCRIPTION_CUSTODY_VERSION)
                || (current.version == DESCRIPTION_CUSTODY_VERSION
                    && (next.version != current.version
                        || next.custody_compatibility != current.custody_compatibility))
                || !next.valid_description_custody()
                || next.executor != current.executor
                || next.operation != current.operation
                || next.tool != current.tool
                || next.run_key != current.run_key
                || next.idempotency_key != current.idempotency_key
                || next.key_origin != current.key_origin
                || next.arguments_digest != current.arguments_digest
                || next.arguments_bytes != current.arguments_bytes
                || (!request_retired
                    && (next.arguments != current.arguments || next.envelope != current.envelope))
            {
                return Err(Error::engine(
                    "custody-only journal identity or format is immutable",
                ));
            }
        } else if next.custody_compatibility.is_some() {
            return Err(Error::engine(
                "custody-only compatibility requires journal format v4",
            ));
        }
        if current.is_merge()
            && (current.prepared || current.merge_result.is_some())
            && (current.idempotency_key != next.idempotency_key
                || current.envelope != next.envelope
                || current.arguments != next.arguments
                || current.record_id != next.record_id
                || current.version != next.version
                || current.intent != next.intent
                || current.executor != next.executor
                || current.operation != next.operation
                || current.lineage_required != next.lineage_required
                || serde_json::to_value(&current.merge_preparation).ok()
                    != serde_json::to_value(&next.merge_preparation).ok()
                || serde_json::to_value(&current.merge_aliases).ok()
                    != serde_json::to_value(&next.merge_aliases).ok()
                || current.prepared != next.prepared
                || current
                    .merge_intent
                    .as_ref()
                    .map(|i| serde_json::to_value(i).ok())
                    != next
                        .merge_intent
                        .as_ref()
                        .map(|i| serde_json::to_value(i).ok()))
        {
            return Err(Error::engine("prepared body merge request is immutable"));
        }
        if current.is_merge()
            && current.merge_result.is_some()
            && serde_json::to_value(&current.merge_result).ok()
                != serde_json::to_value(&next.merge_result).ok()
        {
            return Err(Error::engine("recorded body merge result is immutable"));
        }
        next.updated_at = stamp();
        if next.version == ENTRY_VERSION
            && next.state != EntryState::Pending
            && !(next.state == EntryState::Confirmed
                && next.answer.as_deref() == Some("receipt")
                && next.fork_accepted_act.is_some())
        {
            next.fork_arguments = None;
            next.fork_run_key = None;
            next.fork_accepted_act = None;
        }
        self.write(&next)?;
        entries.insert(id.to_owned(), next.clone());
        Ok(next)
    }

    /// Compare state and persist the operator decision under the journal mutex.
    /// The gate additionally excludes sends and hosted settlement across this call.
    pub(super) fn operator_decision(
        &self,
        id: &str,
        outcome: Option<&str>,
        reason: &str,
        uid: u32,
        pid: Option<i32>,
    ) -> Result<Entry> {
        let reason = reason.trim();
        if reason.is_empty() || reason.len() > 2048 {
            return Err(Error::engine("reason must contain 1..=2048 bytes"));
        }
        if outcome.is_some_and(|o| !matches!(o, "landed" | "not_applied" | "superseded")) {
            return Err(Error::engine(
                "outcome must be landed, not_applied or superseded",
            ));
        }
        let mut entries = self.entries.lock().expect("journal entries");
        let current = entries
            .get(id)
            .ok_or_else(|| Error::engine("journal entry missing"))?;
        // Local maintenance commands are not canonical verdict producers for
        // installed W. Check the format itself, including malformed installed state.
        if installed_working_version(current.version) {
            return Err(Error::engine(
                "installed working proposals require qualified reconciliation; operator decision refused; nothing changed",
            ));
        }
        if current.in_flight || current.operator_audit.is_some() {
            return Err(Error::engine(
                "journal entry is in flight or already has an operator decision",
            ));
        }
        let allowed = if outcome.is_some() {
            matches!(
                current.state,
                EntryState::Uncertain | EntryState::HostedPending | EntryState::NotSent
            ) || (current.state == EntryState::Pending
                && current
                    .compatibility_block
                    .is_some_and(|b| b != CompatibilityBlock::EvidenceMissing))
                || (current.state == EntryState::Confirmed
                    && current.answer.as_deref() == Some("refused"))
        } else {
            current.state == EntryState::Pending && !current.maybe_applied
        };
        if !allowed {
            return Err(Error::engine(
                "journal state does not permit this decision; nothing changed",
            ));
        }
        let mut next = current.clone();
        let at = stamp();
        next.operator_audit = Some(OperatorAudit {
            action: if outcome.is_some() {
                "acknowledge"
            } else {
                "withdraw"
            }
            .into(),
            outcome: outcome.map(str::to_owned),
            reason: reason.into(),
            uid,
            pid,
            at: at.clone(),
            previous_state: current.state,
        });
        next.updated_at = at;
        if outcome.is_some() {
            next.state = EntryState::Acknowledged;
            if next.ordinary_v2() {
                next.reply = super::tool_reply(
                    Some(&Value::Null),
                    json!({
                        "isError":false,"content":[{"type":"text","text":"This write was reconciled locally and will not be sent again. This is not a hosted receipt."}],
                        "structuredContent":{"outcome":"acknowledged","canonical":false,"journal_entry":next.id,"idempotency_key":next.idempotency_key,"operator_audit":next.operator_audit}
                    }),
                    true,
                );
            }
            // Retain arguments, digest, custody handle and prior answer as evidence.
        } else {
            next.state = EntryState::Confirmed;
            next.answer = Some("refused".into());
            next.detail = Some(
                "withdrawn by the local operator; no further dispatch; no possibly applied attempt"
                    .into(),
            );
            next.reply = frame_error(
                Some(&Value::Null),
                "Held write withdrawn by the local operator; it will not be dispatched again",
                json!({
                    "outcome":"refused", "applied":false, "reason":"operator_withdrawn",
                    "journal_entry":next.id, "idempotency_key":next.idempotency_key,
                }),
            );
        }
        if next.version == ENTRY_VERSION {
            next.fork_arguments = None;
            next.fork_run_key = None;
            next.fork_accepted_act = None;
        }
        self.write(&next)?;
        entries.insert(id.into(), next.clone());
        drop(entries);
        if next.state == EntryState::Acknowledged {
            // The decision is already durable; follower labels are best-effort.
            if let Err(error) = self.contract_block(&next, None) {
                tracing::warn!(target: "native_ce::node::journal", %error, "acknowledgement retained; follower waiting markers unavailable");
            }
        }
        Ok(next)
    }

    /// Record that an attempt is about to be made. Saved before the send.
    pub(super) fn note_attempt(&self, id: &str) -> Result<Entry> {
        self.update(id, |entry| entry.attempts += 1)
    }

    pub(super) fn settle(
        &self,
        id: &str,
        state: EntryState,
        answer: Option<&str>,
        detail: Option<String>,
    ) -> Result<Entry> {
        let entry = self.update(id, |entry| {
            entry.maybe_applied |= state == EntryState::Uncertain;
            entry.state = state;
            entry.answer = answer.map(str::to_owned);
            entry.detail = detail;
            if !matches!(
                state,
                EntryState::Uncertain | EntryState::Pending | EntryState::HostedPending
            ) && (entry.version != V2_EVIDENCE_VERSION || answer == Some("receipt"))
            {
                // Settled: keep the shape of the call, not its content.
                entry.arguments = None;
                entry.envelope = None;
            }
        })?;
        Ok(entry)
    }

    /// The node takes this write over: it stays on disk with its arguments,
    /// in order, until it is sent. From `sent` (a forward hosted refused as
    /// read-only, or could not be reached for) or from `uncertain` (a keyed
    /// write that may already have landed, which resending with its key
    /// settles safely). Any other state is left as it is.
    #[cfg(test)]
    pub(super) fn hold(
        &self,
        id: &str,
        reason: HoldReason,
        detail: String,
        maybe_applied: bool,
    ) -> Result<Entry> {
        self.hold_with_contract(id, reason, detail, maybe_applied, None)
    }

    pub(super) fn hold_with_contract(
        &self,
        id: &str,
        reason: HoldReason,
        detail: String,
        maybe_applied: bool,
        custody_compatibility: Option<CustodyCompatibility>,
    ) -> Result<Entry> {
        if custody_compatibility.is_some()
            && self
                .get(id)
                .is_none_or(|entry| entry.version != ENTRY_VERSION)
        {
            return Err(Error::engine(
                "description compatibility requires an ordinary v1 journal entry",
            ));
        }
        self.update(id, |entry| {
            if entry.app_identity.is_none()
                && matches!(entry.state, EntryState::Sent | EntryState::Uncertain)
            {
                entry.state = EntryState::Pending;
                entry.hold_reason = Some(reason);
                entry.detail = Some(detail);
                entry.maybe_applied = maybe_applied;
                entry.custody_compatibility = custody_compatibility;
                if custody_compatibility.is_some() {
                    entry.version = DESCRIPTION_CUSTODY_VERSION;
                    entry.fork_arguments = None;
                    entry.fork_run_key = None;
                    entry.fork_accepted_act = None;
                }
            }
        })
    }

    pub(super) fn hosted_pending(
        &self,
        id: &str,
        hosted_journal_entry: Option<String>,
    ) -> Result<Entry> {
        self.update(id, |entry| {
            entry.state = EntryState::HostedPending;
            entry.hosted_journal_entry = hosted_journal_entry;
            entry.answer = None;
            entry.reply = None;
            entry.in_flight = false;
            entry.detail = Some(if entry.app_identity.is_some() {
                "held by hosted; app custody remains unconfirmed; no automatic node polling or replay"
            } else {
                "held by hosted; not yet a canonical receipt; the node checks hosted in the background"
            }.into());
        })
    }

    /// Stable order for bounded, rotating hosted status sweeps.
    pub(super) fn hosted_entries(&self, after: u64, limit: usize) -> Vec<Entry> {
        let entries = self.entries.lock().expect("journal entries");
        let mut ordered: Vec<_> = entries
            .values()
            .filter(|e| e.state == EntryState::HostedPending)
            .collect();
        ordered.sort_by_key(|e| e.seq);
        let split = ordered.partition_point(|e| e.seq <= after);
        ordered.rotate_left(split);
        // Clone requests only for the bounded batch, not the entire backlog.
        ordered.into_iter().take(limit).cloned().collect()
    }

    pub(super) fn node_id_for_hosted(
        &self,
        hosted: &str,
        app_identity: Option<&str>,
    ) -> Option<String> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.hosted_journal_entry.as_deref() == Some(hosted)
                    && e.app_identity.as_deref() == app_identity
            })
            .min_by_key(|e| e.seq)
            .map(|e| e.id.clone())
    }

    /// A status read may race a caller receipt. Never overwrite a newer state.
    /// Refused proposals retain their request so the person's work is recoverable.
    pub(super) fn finish_hosted(
        &self,
        expected: &Entry,
        refused: bool,
        detail: String,
        reply: Option<String>,
        refused_because: Option<String>,
    ) -> Result<Entry> {
        self.update(&expected.id, |entry| {
            if entry.state != EntryState::HostedPending
                || entry.hosted_journal_entry != expected.hosted_journal_entry
            {
                return;
            }
            entry.state = EntryState::Confirmed;
            entry.answer = Some(if refused { "refused" } else { "receipt" }.into());
            entry.detail = Some(detail);
            entry.reply = reply.filter(|r| r.len() <= MAX_STORED_REPLY);
            entry.refused_because = refused_because;
            entry.in_flight = false;
            if !refused {
                entry.arguments = None;
                entry.envelope = None;
            }
        })
    }

    /// Do not send a dependent node-held write ahead of a create that hosted
    /// still holds. Its caller's canonical retry can resolve that custody.
    pub(super) fn hosted_pending_creator_of(&self, entry: &Entry) -> bool {
        let Some(arguments) = &entry.arguments else {
            return false;
        };
        let wanted = hold::references(&entry.operation, arguments);
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|prior| {
                prior.state == EntryState::HostedPending
                    && prior.seq < entry.seq
                    && hold::creates(&prior.operation)
                    && prior
                        .record_ids
                        .iter()
                        .chain(prior.record_id.iter())
                        .any(|id| wanted.contains(id))
            })
    }

    /// The selector may skip a hosted create's dependants to let unrelated
    /// work progress. Once no eligible work remains, retain the same custody
    /// barrier the drain used before eligibility-aware selection.
    pub(super) fn has_pending_hosted_creator_dependency(&self, merge_only: bool) -> bool {
        let entries = self.entries.lock().expect("journal entries");
        entries
            .values()
            .filter(|entry| {
                matches!(
                    entry.state,
                    EntryState::Pending
                        | EntryState::CommittedUnrecovered
                        | EntryState::ResultUnrecovered
                ) && (!merge_only || entry.is_merge())
            })
            .any(|entry| {
                let Some(arguments) = &entry.arguments else {
                    return false;
                };
                let wanted = hold::references(&entry.operation, arguments);
                entries.values().any(|prior| {
                    prior.state == EntryState::HostedPending
                        && prior.seq < entry.seq
                        && hold::creates(&prior.operation)
                        && prior
                            .record_ids
                            .iter()
                            .chain(prior.record_id.iter())
                            .any(|id| wanted.contains(id))
                })
            })
    }

    /// Save that a queue send of this entry is about to start: one more
    /// attempt, in flight. One write, before the send; if it fails the caller
    /// must not send. An in-flight marker that survived an earlier attempt
    /// whose outcome could not be saved means that attempt may have been
    /// applied: it is promoted to `maybe_applied` in this same write, before the
    /// marker is replaced, and `maybe_applied` is never cleared afterwards.
    pub(super) fn begin_queue_send(&self, id: &str) -> Result<Entry> {
        if self.get(id).is_some_and(|entry| {
            entry.is_merge() && (!entry.prepared || entry.merge_result.is_some())
        }) {
            return Err(Error::engine("body merge is not ready for a home attempt"));
        }
        self.update_checked(
            id,
            |entry| {
                entry.maybe_applied |= entry.in_flight;
                entry.attempts += 1;
                entry.in_flight = true;
            },
            |current, _| {
                if installed_working_version(current.version) && current.not_before_ms > now_ms() {
                    return Err(Error::engine("working retry is not due"));
                }
                Ok(())
            },
            false,
        )
    }

    /// Read-only advisory admission: never reorder or mutate typed custody.
    pub(super) fn fork_blocked_by_merge(&self, touched: &[String]) -> bool {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|entry| {
                entry.merge_open()
                    && entry
                        .record_id
                        .iter()
                        .chain(entry.record_ids.iter())
                        .any(|id| touched.contains(id))
            })
    }

    pub(super) fn fork_entries(&self, base_act: i64) -> Result<Vec<Entry>> {
        let all: Vec<Entry> = self
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .cloned()
            .collect();
        let mut retained: Vec<_> = all
            .into_iter()
            .filter(|e| {
                e.version == ENTRY_VERSION
                    && (e.state == EntryState::Pending
                        || (e.state == EntryState::Confirmed
                            && e.answer.as_deref() == Some("receipt")
                            && e.fork_arguments.is_some()
                            && e.fork_accepted_act.is_some_and(|act| act > base_act)))
            })
            .collect();
        retained.sort_by_key(|e| e.seq);
        Ok(retained)
    }

    /// Maintenance only: preserve retention timestamps when dropping preview data.
    pub(super) fn retire_fork_payloads(&self, base_act: Option<i64>) -> Result<()> {
        let mut entries = self.entries.lock().expect("journal entries");
        for entry in entries.values_mut() {
            if entry.version == ENTRY_VERSION
                && (entry.fork_arguments.is_some()
                    || entry.fork_run_key.is_some()
                    || entry.fork_accepted_act.is_some())
                && (base_act.is_none()
                    || entry
                        .fork_accepted_act
                        .is_some_and(|act| act <= base_act.unwrap()))
            {
                let mut next = entry.clone();
                next.fork_arguments = None;
                next.fork_run_key = None;
                next.fork_accepted_act = None;
                self.write(&next)?;
                *entry = next;
            }
        }
        Ok(())
    }

    /// The oldest pending entry: the next to be sent.
    pub(super) fn oldest_pending(&self) -> Option<Entry> {
        self.next_pending(false)
    }

    /// Skip parked heads and all later writes depending on them. Keeping the
    /// blocked set transitive also protects creates that themselves depend on
    /// an older parked record. Sequence order remains the only tie breaker.
    pub(super) fn next_pending(&self, merge_only: bool) -> Option<Entry> {
        let entries = self.entries.lock().expect("journal entries");
        let mut ordered: Vec<_> = entries.values().collect();
        ordered.sort_by_key(|e| e.seq);
        let mut blocked = std::collections::HashSet::<String>::new();
        let mut merge_only_blocked = std::collections::HashSet::<String>::new();
        for entry in ordered {
            let open = matches!(
                entry.state,
                EntryState::Pending
                    | EntryState::Sent
                    | EntryState::HostedPending
                    | EntryState::CommittedUnrecovered
                    | EntryState::ResultUnrecovered
                    | EntryState::Uncertain
            );
            if !open {
                continue;
            }
            // Legacy sent/uncertain writes remain caller-owned, as before:
            // they must not stop the legacy held queue. A typed merge still
            // waits for their record's outcome before it can be prepared/sent.
            if !installed_working_version(entry.version)
                && !entry.is_merge()
                && matches!(entry.state, EntryState::Sent | EntryState::Uncertain)
            {
                merge_only_blocked.extend(entry.record_id.iter().cloned());
                merge_only_blocked.extend(entry.record_ids.iter().cloned());
                continue;
            }
            let mut references = entry
                .arguments
                .as_ref()
                .map(|a| hold::references(&entry.operation, a))
                .unwrap_or_default();
            if entry.version == INSTALLED_RECORD_VERSION {
                references.extend(entry.record_ids.iter().cloned());
            }
            let blocked_here = entry.not_before_ms > now_ms()
                || references
                    .iter()
                    .chain(entry.record_id.iter())
                    .any(|id| blocked.contains(id))
                || (entry.is_merge()
                    && references
                        .iter()
                        .chain(entry.record_id.iter())
                        .any(|id| merge_only_blocked.contains(id)));
            let sendable = matches!(
                entry.state,
                EntryState::Pending
                    | EntryState::CommittedUnrecovered
                    | EntryState::ResultUnrecovered
            );
            let sendable = sendable
                || (installed_working_version(entry.version)
                    && entry.state == EntryState::Uncertain);
            if !blocked_here && sendable && (!merge_only || entry.is_merge()) {
                return Some(entry.clone());
            }
            blocked.extend(entry.record_id.iter().cloned());
            blocked.extend(entry.record_ids.iter().cloned());
        }
        None
    }

    pub(super) fn next_retry_delay(&self) -> Option<Duration> {
        let now = now_ms();
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.merge_open() && e.state != EntryState::HostedPending && e.not_before_ms > now
            })
            .map(|e| Duration::from_millis(e.not_before_ms - now))
            .min()
    }

    pub(super) fn has_opaque_custody(&self) -> bool {
        self.unreadable > 0
    }

    /// Cross-kind body admission uses the same conservative open states as
    /// queue ordering. Terminal receipts/refusals no longer block new work.
    pub(super) fn has_open_body_custody(&self, record: &str, merges: bool) -> bool {
        // An opaque retained file may hold the predecessor for any record.
        // Its absence cannot be established by scanning only parsed entries.
        if self.unreadable > 0 {
            return true;
        }
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|entry| {
                (entry.record_id.as_deref() == Some(record)
                    || (entry.version == INSTALLED_RECORD_VERSION
                        && entry.record_ids.iter().any(|id| id == record)))
                    && if merges {
                        entry.merge_open()
                    } else {
                        (entry.ordinary_v2() || entry.installed_working())
                            && (entry.operation == "update_record"
                                || entry.version == INSTALLED_RECORD_VERSION)
                            && matches!(
                                entry.state,
                                EntryState::Sent
                                    | EntryState::Pending
                                    | EntryState::HostedPending
                                    | EntryState::Uncertain
                                    | EntryState::CommittedUnrecovered
                                    | EntryState::ResultUnrecovered
                            )
                    }
            })
    }

    pub(super) fn pending_count(&self) -> usize {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                matches!(
                    e.state,
                    EntryState::Pending
                        | EntryState::CommittedUnrecovered
                        | EntryState::ResultUnrecovered
                )
            })
            .count()
    }

    /// A held write the node has since settled, found by its key, for
    /// answering a repeat of the call.
    pub(super) fn settled_held_with_key(
        &self,
        executor: &str,
        operation: &str,
        key: &str,
        app_identity: Option<&str>,
    ) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                (e.state == EntryState::Confirmed
                    || (e.state == EntryState::Acknowledged && e.ordinary_v2()))
                    && (e.hold_reason.is_some() || e.hosted_journal_entry.is_some())
                    && e.reply.is_some()
                    && e.app_identity.as_deref() == app_identity
                    && e.executor == executor
                    && e.operation == operation
                    && e.idempotency_key.as_deref() == Some(key)
            })
            .max_by_key(|e| e.seq)
            .cloned()
    }

    /// A refused held create that `entry` refers to: it would have made a
    /// record the entry needs. Read from what is on disk, so it holds across a
    /// crash between a refusal and the refusals that follow from it.
    pub(super) fn refused_creator_of(&self, entry: &Entry) -> Option<(Entry, Vec<String>)> {
        let wanted = hold::references(&entry.operation, entry.arguments.as_ref()?);
        if wanted.is_empty() {
            return None;
        }
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|r| {
                r.id != entry.id
                    && r.seq < entry.seq
                    && r.state == EntryState::Confirmed
                    && r.answer.as_deref() == Some("refused")
                    && (r.hold_reason.is_some() || r.hosted_journal_entry.is_some())
                    && hold::creates(&r.operation)
            })
            .filter_map(|r| {
                let matched: Vec<String> = r
                    .record_ids
                    .iter()
                    .chain(r.record_id.iter())
                    .filter(|id| wanted.contains(id))
                    .cloned()
                    .collect();
                (!matched.is_empty()).then(|| (r.clone(), matched))
            })
            .min_by_key(|(r, _)| r.seq)
    }

    /// Pending entries after `seq` that refer to any of `ids`, by the
    /// fields that hold references (see [`hold::references`]).
    pub(super) fn pending_referring_to(&self, ids: &[String], after_seq: u64) -> Vec<Entry> {
        let mut found: Vec<Entry> = self
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.state == EntryState::Pending
                    && e.seq > after_seq
                    && e.arguments.as_ref().is_some_and(|a| {
                        hold::references(&e.operation, a)
                            .iter()
                            .any(|reference| ids.contains(reference))
                    })
            })
            .cloned()
            .collect();
        found.sort_by_key(|e| e.seq);
        found
    }

    /// Settle a held write the node has sent (or refused to send). A refused
    /// write keeps its arguments, so what did not make it can be recovered.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_held(
        &self,
        id: &str,
        state: EntryState,
        answer: Option<&str>,
        detail: String,
        reply: Option<String>,
        keep_arguments: bool,
        refused_because: Option<String>,
    ) -> Result<Entry> {
        self.update(id, |entry| {
            entry.state = state;
            entry.answer = answer.map(str::to_owned);
            entry.detail = Some(detail);
            if entry.version == ENTRY_VERSION && entry.fork_arguments.is_some() {
                entry.fork_accepted_act = super::failover::receipt_act(reply.as_deref());
                if answer == Some("refused") {
                    entry.fork_arguments = None;
                    entry.fork_run_key = None;
                }
            }
            entry.reply = reply.filter(|r| entry.version == 2 || r.len() <= MAX_STORED_REPLY);
            entry.refused_because = refused_because;
            entry.maybe_applied |= state == EntryState::Uncertain && entry.in_flight;
            entry.in_flight = false;
            if !keep_arguments {
                entry.arguments = None;
                entry.envelope = None;
            }
        })
    }

    /// The pending entry, if any, that holds this keyed call.
    pub(super) fn merge_with_key(&self, key: &str) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.is_merge()
                    && (e.idempotency_key.as_deref() == Some(key)
                        || e.merge_aliases.iter().any(|alias| alias.key == key))
            })
            .min_by_key(|e| e.seq)
            .cloned()
    }

    pub(super) fn pending_with_key(
        &self,
        executor: &str,
        operation: &str,
        key: &str,
        app_identity: Option<&str>,
    ) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                matches!(
                    e.state,
                    EntryState::Pending
                        | EntryState::CommittedUnrecovered
                        | EntryState::ResultUnrecovered
                ) && e.app_identity.as_deref() == app_identity
                    && e.executor == executor
                    && e.operation == operation
                    && e.idempotency_key.as_deref() == Some(key)
            })
            .min_by_key(|e| e.seq)
            .cloned()
    }

    pub(super) fn hosted_pending_with_key(
        &self,
        executor: &str,
        operation: &str,
        key: &str,
        app_identity: Option<&str>,
    ) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.state == EntryState::HostedPending
                    && e.app_identity.as_deref() == app_identity
                    && e.executor == executor
                    && e.operation == operation
                    && e.idempotency_key.as_deref() == Some(key)
            })
            .min_by_key(|e| e.seq)
            .cloned()
    }

    /// 1 for the entry next to be sent: pending entries up to and including
    /// this sequence number.
    pub(super) fn pending_entries(&self) -> Vec<Entry> {
        let mut entries: Vec<_> = self
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| e.state == EntryState::Pending)
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.seq);
        entries
    }

    pub(super) fn contract_block(
        &self,
        head: &Entry,
        block: Option<CompatibilityBlock>,
    ) -> Result<()> {
        for entry in self.pending_entries() {
            #[cfg(feature = "v2-kernel-probe")]
            if entry.working_resolution.is_some() {
                continue;
            }
            let (reason, waiting) = if entry.id == head.id {
                (block, None)
            } else if entry.seq > head.seq
                && block.is_some_and(|b| b != CompatibilityBlock::EvidenceMissing)
            {
                (entry.compatibility_block, Some(head.id.clone()))
            } else if entry.waiting_for.as_deref() == Some(&head.id) {
                (entry.compatibility_block, None)
            } else {
                continue;
            };
            if entry.compatibility_block != reason || entry.waiting_for != waiting {
                self.update(&entry.id, |e| {
                    e.compatibility_block = reason;
                    e.waiting_for = waiting;
                })?;
            }
        }
        Ok(())
    }

    pub(super) fn pending_position(&self, seq: u64) -> usize {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| e.state == EntryState::Pending && e.seq <= seq)
            .count()
    }

    /// An agent that retried an uncertain call with its returned key and got
    /// an answer has settled the earlier entry too. Match on the same
    /// executor, operation, key *and* arguments: the same key with different
    /// content is a different question. Arguments compare under RFC 8785
    /// canonical JSON (array order preserved), so reordered object fields
    /// still match while different values, array order or calls do not.
    /// Entries written before the canonical digest keep working through a
    /// stored-digest fallback; settled entries drop their arguments, so a
    /// retained earlier entry re-digests canonically against the receipt's
    /// stored digest. Only `uncertain`/`hosted_pending` entries settle, and both sides must
    /// carry the same key: an unkeyed earlier entry never matches.
    pub(super) fn resolve_earlier(&self, settled: &Entry) {
        // Only a receipt says what the earlier call became; a refusal of the
        // retry (read-only, auth, validation) leaves that question open.
        if settled.state != EntryState::Confirmed || settled.answer.as_deref() != Some("receipt") {
            return;
        }
        let Some(key) = settled.idempotency_key.as_deref() else {
            return;
        };
        let earlier: Vec<String> = self
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                matches!(e.state, EntryState::Uncertain | EntryState::HostedPending)
                    && e.id != settled.id
                    && e.app_identity == settled.app_identity
                    && e.executor == settled.executor
                    && e.operation == settled.operation
                    && e.idempotency_key.as_deref() == Some(key)
                    && arguments_equivalent(e, settled)
            })
            .map(|e| e.id.clone())
            .collect();
        for id in earlier {
            let by = settled.id.clone();
            let answer = settled.answer.clone();
            let _ = self.update(&id, |entry| {
                if !matches!(
                    entry.state,
                    EntryState::Uncertain | EntryState::HostedPending
                ) {
                    return;
                }
                entry.state = EntryState::Confirmed;
                entry.answer = answer;
                entry.arguments = None;
                entry.envelope = None;
                entry.resolved_by = Some(by.clone());
                entry.detail = Some(format!(
                    "settled by a canonical outcome for the same keyed request (entry {by})"
                ));
            });
        }
    }

    fn maybe_prune(&self) {
        let due = {
            let mut last = self.last_prune.lock().expect("journal prune clock");
            if last.elapsed() < PRUNE_EVERY {
                false
            } else {
                *last = std::time::Instant::now();
                true
            }
        };
        if due {
            self.prune();
        }
    }

    /// Remove settled entries older than the retention. Uncertain and pending
    /// entries are never pruned: they are the open questions, and a pending
    /// entry is the only copy of a write the caller was told was accepted.
    pub(super) fn prune(&self) {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.retention.as_millis() as u64);
        let refusal_cutoff = now.saturating_sub(self.refusal_retention.as_millis() as u64);
        let mut entries = self.entries.lock().expect("journal entries");
        // Every accepted typed key must outlive payload retention. Reusing
        // even a no-op or refused draft as fresh work can undo later edits or
        // apply an earlier refusal. Preserve primary and coalesced keys under
        // their original id, removing their private payloads instead.
        let compact: Vec<Entry> = entries
            .values()
            .filter(|entry| {
                let refused_held = (entry.hold_reason.is_some()
                    || entry.hosted_journal_entry.is_some())
                    && entry.state == EntryState::Confirmed
                    && entry.answer.as_deref() == Some("refused");
                let limit = if refused_held { refusal_cutoff } else { cutoff };
                entry.is_merge()
                    && entry.lineage_required
                    && !entry.merge_key_tombstone
                    && matches!(
                        entry.state,
                        EntryState::Confirmed | EntryState::Acknowledged | EntryState::NotSent
                    )
                    && chrono::DateTime::parse_from_rfc3339(&entry.updated_at)
                        .map(|time| (time.timestamp_millis().max(0) as u64) < limit)
                        .unwrap_or(false)
            })
            .cloned()
            .collect();
        for mut entry in compact {
            entry.arguments = None;
            entry.envelope = None;
            entry.merge_preparation = None;
            entry.merge_result = None;
            entry.reply = None;
            entry.in_flight = false;
            if let Some(intent) = &mut entry.merge_intent {
                intent.declared_base_text.clear();
                intent.draft_text.clear();
            }
            entry.merge_key_tombstone = true;
            // Atomic persistence must succeed before memory is compacted.
            // On failure retain the full entry and retry next pruning pass.
            if self.write(&entry).is_ok() {
                entries.insert(entry.id.clone(), entry);
            }
        }
        let expired: Vec<String> = entries
            .values()
            .filter(|e| {
                if e.is_working() {
                    return false;
                }
                let refused_held = (e.hold_reason.is_some() || e.hosted_journal_entry.is_some())
                    && e.state == EntryState::Confirmed
                    && e.answer.as_deref() == Some("refused");
                let limit = if refused_held { refusal_cutoff } else { cutoff };
                e.operator_audit.is_none()
                    && !e.merge_key_tombstone
                    && !(e.is_merge() && (e.lineage_required || !e.merge_aliases.is_empty()))
                    && (e.recovery_item.is_none() || e.lineage_required)
                    && (e.version != ENTRY_VERSION || e.fork_arguments.is_none())
                    && matches!(e.state, EntryState::Confirmed | EntryState::NotSent)
                    && chrono::DateTime::parse_from_rfc3339(&e.updated_at)
                        .map(|t| (t.timestamp_millis().max(0) as u64) < limit)
                        .unwrap_or(false)
            })
            .map(|e| e.id.clone())
            .collect();
        for id in expired {
            if fs::remove_file(self.path(&id)).is_ok() {
                entries.remove(&id);
            }
        }
    }

    /// Durable minimal recovery custody. This directory is outside the ordinary
    /// journal's retention and is never pruned automatically. Slice 4 will own
    /// its local read/dismiss interface; no draft text is exposed by status.
    pub(super) fn save_merge_recovery(
        &self,
        entry: &Entry,
        kind: &str,
        reply: Option<&str>,
    ) -> Result<String> {
        let parent = self
            .directory
            .parent()
            .ok_or_else(|| Error::engine("journal has no parent"))?;
        let directory = parent.join("body-merge-recovery");
        validate_credential_path(&directory, "body merge recovery directory")?;
        match fs::symlink_metadata(&directory) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(Error::engine("invalid body merge recovery directory"));
                }
                check_owned(&meta, 0o700)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                File::open(parent)?.sync_all()?;
            }
            Err(e) => return Err(e.into()),
        }
        let item = json!({"version":2,"id":entry.id,"kind":kind,"record_id":entry.record_id,
            "intent":entry.merge_intent,"arguments":entry.arguments,"idempotency_key":entry.idempotency_key,"reply":reply});
        let bytes = serde_json::to_vec(&item)?;
        let temporary = directory.join(format!("{}.{}.tmp", entry.id, uuid::Uuid::new_v4()));
        let result = (|| {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, directory.join(format!("{}.json", entry.id)))?;
            File::open(&directory)?.sync_all()?;
            Ok(entry.id.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(super) fn get(&self, id: &str) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .get(id)
            .cloned()
    }

    /// Where a write stands, in the words a person uses. `None` for a write
    /// that was never held and has settled: only the open questions and the
    /// held writes are listed.
    fn view_state(entry: &Entry) -> Option<&'static str> {
        let held = installed_working_version(entry.version)
            || entry.is_merge()
            || entry.hold_reason.is_some()
            || entry.hosted_journal_entry.is_some();
        match entry.state {
            EntryState::Acknowledged => Some("acknowledged"),
            EntryState::Pending => Some(if entry.waiting_for.is_some() {
                "waiting_behind"
            } else if entry
                .compatibility_block
                .is_some_and(|b| b != CompatibilityBlock::EvidenceMissing)
            {
                "needs_you"
            } else {
                "pending"
            }),
            EntryState::CommittedUnrecovered => Some("committed_unrecovered"),
            EntryState::ResultUnrecovered => Some("result_unrecovered"),
            EntryState::HostedPending => Some("hosted_pending"),
            EntryState::Unrecognised => Some("unrecognised"),
            EntryState::Confirmed if held => Some(match entry.answer.as_deref() {
                Some("key_conflict" | "merged_with_clashes") => "needs_you",
                Some("refused")
                    if installed_working_version(entry.version) && entry.maybe_applied =>
                {
                    "uncertain"
                }
                Some("refused") => "refused",
                _ => "sent",
            }),
            EntryState::Uncertain => Some("uncertain"),
            EntryState::NotSent if held => Some("not_sent"),
            _ => None,
        }
    }

    /// Held, sent and refused writes, filtered, for `node_status`. Never
    /// carries record bodies.
    pub(super) fn held_writes(&self, filter: &StatusFilter, record_base: Option<&str>) -> Value {
        let entries = self.entries.lock().expect("journal entries");
        let mut counts = serde_json::Map::new();
        let mut rows: Vec<&Entry> = Vec::new();
        for entry in entries.values() {
            let Some(state) = Self::view_state(entry) else {
                continue;
            };
            let wanted = filter
                .run
                .as_ref()
                .is_none_or(|r| entry.run_key.as_ref() == Some(r))
                && filter
                    .parent_run
                    .as_ref()
                    .is_none_or(|p| entry.parent_key.as_ref() == Some(p))
                && (filter.states.is_empty() || filter.states.iter().any(|s| s == state));
            if !wanted {
                continue;
            }
            let count = counts.entry(state).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
            rows.push(entry);
        }
        rows.sort_by_key(|e| e.seq);
        if filter.newest_first {
            rows.reverse();
        }
        let matched = rows.len();
        let limit = filter.limit.max(1);
        let writes: Vec<Value> = rows
            .into_iter()
            .take(limit)
            .map(|entry| {
                let state = Self::view_state(entry).unwrap_or("unknown");
                let mut view = json!({
                    "id": entry.id,
                    "state": state,
                    "app_identity": entry.app_identity,
                    "operation": entry.operation,
                    "title": entry.title,
                    "accepted_at": entry.received_at,
                    "updated_at": entry.updated_at,
                    "reason": entry.hold_reason.map(HoldReason::as_str),
                    "detail": entry.compatibility_message().map(str::to_owned).or_else(|| entry.detail.clone()),
                    "compatibility_block": entry.compatibility_block,
                    "waiting_for": entry.waiting_for,
                    "idempotency_key": entry.idempotency_key,
                    "run_key": entry.run_key,
                    "parent_key": entry.parent_key,
                    "seq": entry.seq,
                    "attempts": entry.attempts,
                    "may_already_be_applied": entry.maybe_applied,
                    "arguments_bytes": entry.arguments_bytes,
                    "hosted_journal_entry": entry.hosted_journal_entry,
                    "operator_audit": entry.operator_audit,
                    "recovery_item": entry.recovery_item,
                    "not_before_ms": entry.not_before_ms,
                });
                let object = view.as_object_mut().expect("object");
                if let Some(cause) = &entry.refused_because {
                    object.insert("depends_on".into(), json!(cause));
                }
                // A record to point at once there is one: what a sent create
                // made, or the record an append, link or attachment is on.
                // A create that is still waiting has made nothing yet.
                let exists = state == "sent"
                    || !matches!(entry.operation.as_str(), "create_record" | "create_many");
                if exists && state != "refused" {
                    let ids: Vec<&String> = if entry.record_ids.is_empty() {
                        entry.record_id.iter().collect()
                    } else {
                        entry.record_ids.iter().collect()
                    };
                    if !ids.is_empty() {
                        object.insert("record_ids".into(), json!(ids));
                        if let Some(base) = record_base {
                            let links: Vec<String> =
                                ids.iter().map(|id| format!("{base}/{id}")).collect();
                            object.insert("record_links".into(), json!(links));
                        }
                    }
                }
                view
            })
            .collect();
        json!({
            "matched": matched,
            "shown": writes.len(),
            "order": if filter.newest_first { "newest_first" } else { "oldest_first" },
            "counts": counts,
            "writes": writes,
        })
    }

    /// Counts of held writes by state for one run, and for the runs it started.
    pub(super) fn held_counts_for_run(&self, run: &str) -> (Value, Value) {
        let entries = self.entries.lock().expect("journal entries");
        let mut own = serde_json::Map::new();
        let mut children = serde_json::Map::new();
        for entry in entries.values() {
            if entry.state == EntryState::Acknowledged {
                continue;
            }
            let Some(state) = Self::view_state(entry) else {
                continue;
            };
            let target = if entry.run_key.as_deref() == Some(run) {
                &mut own
            } else if entry.parent_key.as_deref() == Some(run) {
                &mut children
            } else {
                continue;
            };
            let count = target.entry(state).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
        }
        (Value::Object(own), Value::Object(children))
    }

    /// Account-bound journal backlog, including forwards from earlier runs.
    /// Only counts and the oldest acceptance time cross the bootstrap boundary.
    pub(super) fn waiting_summary(&self) -> Value {
        let entries = self.entries.lock().expect("journal entries");
        let mut counts = serde_json::Map::new();
        let mut oldest: Option<&Entry> = None;
        let mut waiting = 0_u64;
        for entry in entries.values() {
            let Some(state) = Self::view_state(entry) else {
                continue;
            };
            if !matches!(
                state,
                "pending"
                    | "needs_you"
                    | "waiting_behind"
                    | "hosted_pending"
                    | "uncertain"
                    | "not_sent"
                    | "refused"
                    | "unrecognised"
            ) {
                continue;
            }
            waiting += 1;
            let count = counts.entry(state).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
            if oldest.is_none_or(|previous| {
                (entry.received_unix_ms, entry.seq) < (previous.received_unix_ms, previous.seq)
            }) {
                oldest = Some(entry);
            }
        }
        json!({"waiting":waiting,"counts":counts,"oldest_accepted_at":oldest.map(|e| &e.received_at)})
    }

    /// When the oldest write that still needs attention was accepted: the same
    /// states a status reader counts as waiting (pending, hosted_pending,
    /// uncertain, not_sent, refused, unrecognised), not just the send queue.
    fn oldest_waiting(&self) -> Option<String> {
        let entries = self.entries.lock().expect("journal entries");
        entries
            .values()
            .filter(|e| {
                e.state == EntryState::Uncertain
                    || matches!(
                        Self::view_state(e),
                        Some(
                            "pending"
                                | "needs_you"
                                | "waiting_behind"
                                | "hosted_pending"
                                | "uncertain"
                                | "not_sent"
                                | "refused"
                                | "unrecognised"
                        )
                    )
            })
            .min_by_key(|e| (e.seq, e.received_unix_ms))
            .map(|e| e.received_at.clone())
    }

    /// The queue: how many writes wait and how much they hold.
    pub(super) fn queue_summary(&self) -> Value {
        let oldest_waiting = self.oldest_waiting();
        let entries = self.entries.lock().expect("journal entries");
        let pending: Vec<&Entry> = entries
            .values()
            .filter(|e| {
                matches!(
                    e.state,
                    EntryState::Pending
                        | EntryState::CommittedUnrecovered
                        | EntryState::ResultUnrecovered
                )
            })
            .collect();
        json!({
            "pending": pending.len(),
            "bytes": pending.iter().map(|e| e.arguments_bytes).sum::<usize>(),
            "oldest_accepted_at": pending.iter().min_by_key(|e| e.seq).map(|e| e.received_at.clone()),
            "oldest_waiting_accepted_at": oldest_waiting,
        })
    }

    /// Entries a build that does not know their state left on disk. They are
    /// never sent or settled here.
    pub(super) fn unrecognised(&self) -> Vec<Value> {
        let entries = self.entries.lock().expect("journal entries");
        let mut found: Vec<&Entry> = entries
            .values()
            .filter(|e| e.state == EntryState::Unrecognised)
            .collect();
        found.sort_by_key(|e| e.seq);
        found
            .into_iter()
            .map(|e| {
                json!({
                    "id": e.id, "operation": e.operation, "title": e.title,
                    "accepted_at": e.received_at, "idempotency_key": e.idempotency_key,
                    "run_key": e.run_key, "record_id": e.record_id,
                })
            })
            .collect()
    }

    /// Bodies are deliberately left out: the entry file on disk holds them.
    #[cfg(test)]
    pub(super) fn status(&self) -> Value {
        self.status_for(&StatusFilter::default())
    }

    /// As `status`, with the `uncertain` list narrowed by the same `run`,
    /// `parent_run` and `state` filters as the held-writes view. The counts
    /// stay whole: they say what the journal holds, not what was asked about.
    pub(super) fn status_for(&self, filter: &StatusFilter) -> Value {
        let entries = self.entries.lock().expect("journal entries");
        let mut counts = serde_json::Map::new();
        let mut uncertain = Vec::new();
        for entry in entries.values() {
            let key = serde_json::to_value(entry.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            let count = counts.entry(key).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
            let wanted = filter
                .run
                .as_ref()
                .is_none_or(|r| entry.run_key.as_ref() == Some(r))
                && filter
                    .parent_run
                    .as_ref()
                    .is_none_or(|p| entry.parent_key.as_ref() == Some(p))
                && (filter.states.is_empty() || filter.states.iter().any(|s| s == "uncertain"));
            if entry.state == EntryState::Uncertain && wanted {
                uncertain.push(json!({
                    "id": entry.id,
                    "parent_key": entry.parent_key,
                    "executor": entry.executor,
                    "app_identity": entry.app_identity,
                    "operation": entry.operation,
                    "idempotency_key": entry.idempotency_key,
                    "key_origin": entry.key_origin,
                    "run_key": entry.run_key,
                    "received_at": entry.received_at,
                    "updated_at": entry.updated_at,
                    "attempts": entry.attempts,
                    "reason": entry.detail,
                    "arguments_bytes": entry.arguments_bytes,
                }));
            }
        }
        uncertain.sort_by(|a, b| a["received_at"].as_str().cmp(&b["received_at"].as_str()));
        let has_keyed = entries
            .values()
            .any(|e| e.state == EntryState::Uncertain && e.idempotency_key.is_some());
        let has_keyless = entries
            .values()
            .any(|e| e.state == EntryState::Uncertain && e.idempotency_key.is_none());
        let compatibility_wait = entries.values().any(|e| {
            e.state == EntryState::Pending
                && (e.compatibility_block.is_some() || e.waiting_for.is_some())
        });
        let mut how_to_settle = match (has_keyed, has_keyless) {
            (false, false) if compatibility_wait => "Some pending writes need review or discovery before sending. Their text is kept on this device. Repeat the original keyed call for status. Before deliberate resubmission, reconcile and acknowledge the original; check canonical history if it may already have applied.",
            (false, false) => "No uncertain entries. Pending writes are sent automatically.",
            (true, false) => "Before writing again, inspect canonical history. For safely keyed single writes, repeat the original call with its idempotency_key to retrieve its receipt.",
            (false, true) => "Keyless uncertain writes cannot be settled by adding a key: inspect canonical history and reconcile before writing again; never retry blindly.",
            (true, true) => "Keyed single writes can retrieve their receipt with the original idempotency_key. Keyless writes require reconciliation: inspect canonical history before writing again; never retry blindly.",
        }.to_owned();
        if entries.values().any(|e| {
            e.state == EntryState::Uncertain
                && e.executor == "records_write"
                && e.operation == "create_many"
        }) {
            how_to_settle.push_str(" For create_many, reconcile every batch item before writing again; a key alone does not qualify safe batch replay.");
        }
        if has_keyed || has_keyless {
            how_to_settle.push_str(" The node does not replay uncertain writes. After reconciling, use the local node journal acknowledge command with an outcome and reason. Pending writes remain the node's queue and are sent automatically unless withdrawn.");
        }
        // Admission/rollback count is global, never narrowed by run/state or
        // a page limit. The inspectable list is independently bounded.
        let app_open = |e: &&Entry| {
            e.app_identity.is_some()
                && matches!(
                    e.state,
                    EntryState::Sent
                        | EntryState::Uncertain
                        | EntryState::HostedPending
                        | EntryState::Pending
                        | EntryState::Unrecognised
                )
        };
        let app_outstanding_count = entries.values().filter(app_open).count();
        let app_outstanding_limit = filter.limit.clamp(1, 500);
        let app_outstanding: Vec<Value> = entries
            .values()
            .filter(app_open)
            .take(app_outstanding_limit)
            .map(|e| json!({"id":e.id,"state":e.state,"app_identity":e.app_identity}))
            .collect();
        json!({
            "merge_body_nonterminal_count": entries.values().filter(|e| e.merge_open()).count(),
            "app_outstanding_count": app_outstanding_count,
            "app_outstanding_truncated": app_outstanding_count > app_outstanding.len(),
            "app_outstanding_limit": app_outstanding_limit,
            "app_outstanding": app_outstanding,
            "journal_directory": self.directory.display().to_string(),
            "entry_counts": counts,
            "outstanding_count": entries.values().filter(|e| !matches!(e.state, EntryState::Confirmed | EntryState::Acknowledged)).count(),
            "v6_custody_entries": entries.values().filter(|e| e.version == V2_EVIDENCE_VERSION).count(),
            "installed_working_entries": entries.values().filter(|e| installed_working_version(e.version)).count(),
            "unreadable_files": self.unreadable,
            "unreadable_custody": if self.unreadable > 0 { json!({"status":"needs_you","count":self.unreadable,
                "recovery":"This node cannot read some retained writes. Their content is kept on this device. Use a compatible node or inspect the retained files before resolving them; do not delete them to unblock writes."}) } else { Value::Null },
            "uncertain": uncertain,
            "how_to_settle": how_to_settle,
        })
    }
}

fn valid_contract_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

fn entry_size_limit(version: u32) -> u64 {
    MAX_ENTRY_BYTES
        + if version == V2_EVIDENCE_VERSION {
            MAX_CONTRACT_EVIDENCE_BYTES + V6_METADATA_BYTES
        } else {
            0
        }
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) fn read_before_v6(path: &Path) -> Result<Entry> {
    // Previous nodes reject version 6, including Sent entries, before recovery.
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    if value["version"]
        .as_u64()
        .is_some_and(|v| v >= V2_EVIDENCE_VERSION as u64)
    {
        return Err(Error::engine("journal entry from a newer node"));
    }
    read_entry(path)
}

/// Read-only inventory classification uses the same bounded, owned-file and
/// codec validation as journal recovery. Unknown/retired formats stay opaque.
#[cfg(feature = "v2-kernel-probe")]
pub(super) fn retained_working_entry_may_exist(path: &Path) -> bool {
    let Ok(entry) = read_entry(path) else {
        return true;
    };
    if path.file_stem().and_then(|name| name.to_str()) != Some(entry.id.as_str()) {
        return true;
    }
    // read_entry accepted evidence 6 only through its strict valid_v6 codec;
    // an old working-6 original has no such evidence and was refused above.
    entry.version >= INSTALLED_WORKING_VERSION
}

fn read_entry(path: &Path) -> Result<Entry> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = input.metadata()?;
    check_owned(&meta, 0o600)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_MERGE_ENTRY_BYTES {
        return Err(Error::engine("invalid node journal entry"));
    }
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    let entry: Entry = serde_json::from_slice(&bytes)?;
    if !entry.is_merge() && meta.len() > entry_size_limit(entry.version) {
        return Err(Error::engine("journal entry exceeds bound"));
    }
    let supported_v3 = entry.version == 3
        && entry.custody_compatibility.is_none()
        && entry.kernel_v2_custody.as_ref().is_some_and(|custody| {
            custody.original.is_none()
                && custody.engine == "native-kernel-v2"
                && custody.binding.valid()
                && custody.contract_digest.len() == 64
                && custody
                    .contract_digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                && entry.executor == "records_write"
                && matches!(
                    entry.operation.as_str(),
                    "update_record" | "manage_links.add" | "attach_text"
                )
                && entry.app_identity.is_none()
        });
    let supported_v6 = entry.valid_v6();
    let supported_v4 = entry.valid_description_custody();
    let supported_working = entry.is_working();
    #[cfg(feature = "v2-kernel-probe")]
    if entry.working_original.is_some() && !supported_working {
        return Err(Error::engine("invalid working proposal journal format"));
    }
    if (entry.kernel_v2_custody.is_some() && !supported_v3 && !supported_v6 && !supported_working)
        || (entry.custody_compatibility.is_some() && !supported_v4)
        || (entry.version > ENTRY_VERSION
            && !supported_v3
            && !supported_v6
            && !supported_v4
            && !supported_working
            && !(entry.version == 2
                && entry.is_merge()
                && (entry.prepared || entry.lineage_required)))
    {
        return Err(Error::engine("journal entry from a newer node"));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod merge_key_retention_tests {
    use super::*;

    fn draft(key: &str, text: &str) -> (NewEntry, MergeIntent) {
        (
            NewEntry {
                executor: "records_write".into(),
                operation: "merge_body".into(),
                tool: "records_write".into(),
                run_key: None,
                client_info: None,
                app_identity: None,
                idempotency_key: Some(key.into()),
                key_origin: Some(KeyOrigin::Caller),
                arguments: json!({"base_text":"private base", "my_text":text,"idempotency_key":key}),
                parent_key: None,
                title: None,
                record_id: Some("record".into()),
                record_ids: Vec::new(),
                envelope: Some(json!({"private":"private envelope"})),
                intent_digest: Some(format!("digest-{key}")),
            },
            MergeIntent {
                declared_base_version: "rec:1".into(),
                declared_base_text: "private base".into(),
                draft_text: text.into(),
                editor: "editor".into(),
                made_at_ms: None,
                wait: "none".into(),
            },
        )
    }

    #[test]
    fn coalesced_keys_survive_payload_retention_restart_and_failed_compaction() {
        use std::sync::atomic::Ordering::SeqCst;
        let root = tempfile::tempdir().unwrap();
        let journal = Journal::open(root.path(), Duration::ZERO).unwrap();
        let (request, intent) = draft("old-key", "private first draft");
        let first = journal.begin_merge(request, intent).unwrap();
        let (request, intent) = draft("new-key", "private latest draft");
        let latest = journal.begin_merge(request, intent).unwrap();
        assert_eq!(first.id, latest.id);
        let mut terminal = journal
            .update(&latest.id, |entry| {
                entry.state = EntryState::Confirmed;
                entry.answer = Some("merged_with_clashes".into());
                entry.recovery_item = Some("recovery-id".into());
                entry.prepared = true;
                entry.reply = Some("private reply".into());
                entry.merge_result = Some(MergeResult {
                    kind: "merged_with_clashes".into(),
                    body: json!({"private":"private result"}),
                    reply: None,
                    recovery_ids: vec!["recovery-id".into()],
                });
            })
            .unwrap();
        terminal.updated_at = "2000-01-01T00:00:00Z".into();
        journal.write(&terminal).unwrap();
        journal
            .entries
            .lock()
            .unwrap()
            .insert(terminal.id.clone(), terminal.clone());
        journal.fail_after.store(0, SeqCst);
        journal.prune();
        let retained = journal.merge_with_key("old-key").unwrap();
        assert!(!retained.merge_key_tombstone);
        assert!(retained.arguments.is_some());
        journal.prune();
        let compact = journal.merge_with_key("old-key").unwrap();
        assert!(compact.merge_key_tombstone);
        assert!(compact.is_merge());
        assert!(!compact.merge_open());
        assert!(compact.merge_identity_matches("old-key", "digest-old-key", "editor"));
        assert!(compact.merge_identity_matches("new-key", "digest-new-key", "editor"));
        assert_eq!(compact.seq, terminal.seq);
        assert_eq!(compact.answer, terminal.answer);
        assert_eq!(compact.recovery_item, terminal.recovery_item);
        assert!(
            compact.arguments.is_none() && compact.envelope.is_none() && compact.reply.is_none()
        );
        assert!(compact.merge_preparation.is_none() && compact.merge_result.is_none());
        let persisted = fs::read_to_string(journal.path(&terminal.id)).unwrap();
        assert!(!persisted.contains("private"));
        drop(journal);
        let journal = Journal::open(root.path(), Duration::ZERO).unwrap();
        journal.prune();
        assert!(
            journal
                .merge_with_key("old-key")
                .unwrap()
                .merge_key_tombstone
        );
        assert_eq!(journal.merge_with_key("new-key").unwrap().id, terminal.id);
        assert!(journal.oldest_pending().is_none());
        assert!(!journal.has_open_merge("record", "editor"));
    }
    #[test]
    fn account_erasure_refuses_unknown_journal_custody() {
        let root = tempfile::tempdir().unwrap();
        let journal = Journal::open(root.path(), CONFIRMED_RETENTION).unwrap();
        let (request, intent) = draft("key", "private draft");
        let entry = journal.begin_merge(request, intent).unwrap();
        let unknown = journal.directory.join("unknown.json");
        fs::write(&unknown, b"{malformed private draft").unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o600)).unwrap();
        drop(journal);
        let journal = Journal::open(root.path(), CONFIRMED_RETENTION).unwrap();
        assert!(journal.forget_merges().is_err());
        assert!(journal.path(&entry.id).exists());
        assert_eq!(fs::read(&unknown).unwrap(), b"{malformed private draft");
    }
}
