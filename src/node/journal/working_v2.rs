//! A sealed adapter over the real write-ahead journal. W consumes these
//! fsynced proposals; it cannot create their authority or hosted verdicts.
#![allow(dead_code)]
use super::*;
use crate::fork::working_v2::WorkingBinding;
use crate::mcp::kernel_v2::writes::replay::RecordOperation;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

// v3 hosted custody and v4 description custody remain separate formats.
const WORKING_VERSION: u32 = WORKING_MANAGER_VERSION;
// First-party update fingerprints are canonical provider JSON: the bounded
// 1MiB argument object plus its fixed schema/app/arguments envelope.
const MAX_ORIGINAL_FINGERPRINT_BYTES: usize = 1024 * 1024 + 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node) struct OriginalAppend {
    actor: String,
    request_fingerprint: String,
    identity: FirstPartyIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_arguments: Option<Value>,
    #[serde(default, skip_serializing_if = "OriginalAnnotations::is_empty")]
    annotations: OriginalAnnotations,
}
/// Same-journal owner-resolution evidence. Original payload/provenance stays
/// in its existing codec and is never copied into a second receipt queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkingResolution {
    Requested {
        schema: String,
        expected_binding_sha256: String,
        diagnostic: Option<String>,
    },
    Verified {
        schema: String,
        expected_binding_sha256: String,
        answer: Value,
    },
}
impl WorkingResolution {
    pub(crate) fn binding(&self) -> &str {
        match self {
            Self::Requested {
                expected_binding_sha256,
                ..
            }
            | Self::Verified {
                expected_binding_sha256,
                ..
            } => expected_binding_sha256,
        }
    }
    pub(crate) fn answer(&self) -> Option<&Value> {
        match self {
            Self::Verified { answer, .. } => Some(answer),
            _ => None,
        }
    }
    pub(crate) fn answer_sha256(&self) -> Option<String> {
        let answer = serde_json::to_vec(self.answer()?).ok()?;
        Some(hex::encode(Sha256::digest(answer)))
    }
    fn valid(&self, entry: &Entry) -> bool {
        let schema = match self {
            Self::Requested { schema, .. } | Self::Verified { schema, .. } => schema,
        };
        if schema != "native.node-original-resolution.v1" {
            return false;
        }
        let Ok(original) = settlement_original(entry) else {
            return false;
        };
        if self.binding() != original.expected_binding_sha256 {
            return false;
        }
        match self {
            Self::Requested { diagnostic, .. } => diagnostic.as_ref().is_none_or(|v| {
                matches!(
                    v.as_str(),
                    "transport_unavailable"
                        | "status_required"
                        | "binding_changed"
                        | "response_unverified"
                )
            }),
            Self::Verified { answer, .. } => {
                validate_settlement_for_entry(entry, &original, answer).is_ok()
            }
        }
    }
}

/// Export SOURCE args and catalog coordinates separately. No Caller is loaded
/// from disk; the current verified owner must independently match this actor.
pub(in crate::node) fn settlement_original(
    entry: &Entry,
) -> Result<crate::kernel::original_settlement::Original> {
    use crate::kernel::original_settlement::{recompute_binding, Original};
    let original = entry
        .working_original_ref()
        .ok_or_else(|| Error::engine("working original missing"))?;
    if !installed_working_version(entry.version) {
        return Err(Error::engine("resolution requires installed original"));
    }
    let custody = entry
        .kernel_v2_custody
        .as_ref()
        .ok_or_else(|| Error::engine("working scope missing"))?;
    let args = original
        .native_arguments()
        .or(entry.arguments.as_ref())
        .ok_or_else(|| Error::engine("working arguments missing"))?;
    let identity = original.proposal_identity();
    let mut exported = Original {
        account_id: custody.binding.account_id.clone(),
        principal_id: original.actor.clone(),
        database_id: custody.binding.database_id.clone(),
        origin_database_id: custody.binding.origin_database_id.clone(),
        operation: original.source_tool().into(),
        operation_key: entry
            .idempotency_key
            .clone()
            .ok_or_else(|| Error::engine("working key missing"))?,
        journal_variant: entry.version,
        retained_contract_digest: custody.contract_digest.clone(),
        catalog_executor: entry.executor.clone(),
        catalog_operation: entry.operation.clone(),
        retained_provider_fingerprint: original.request_fingerprint.clone(),
        arguments: args.clone(),
        assertion: "first_party".into(),
        app: identity.app,
        mint_context: identity.mint_context,
        delegation_ref: None,
        asserting_client_id: None,
        asserting_device_id: None,
        expected_binding_sha256: String::new(),
    };
    let (binding, fingerprint) = recompute_binding(&exported)?;
    if fingerprint != original.request_fingerprint
        || args["idempotency_key"].as_str() != Some(&exported.operation_key)
    {
        return Err(Error::engine(
            "working resolution original fingerprint changed",
        ));
    }
    exported.expected_binding_sha256 = binding;
    Ok(exported)
}

pub(in crate::node) fn validate_settlement_for_entry(
    entry: &Entry,
    original: &crate::kernel::original_settlement::Original,
    answer: &Value,
) -> Result<()> {
    let install = entry
        .kernel_v2_custody
        .as_ref()
        .and_then(|custody| custody.binding.install_id.as_deref());
    match install {
        Some(install) => crate::kernel::original_settlement::installed::validate_answer(
            original, install, answer,
        ),
        None => validate_settlement_answer(original, answer),
    }
}

pub(in crate::node) fn validate_settlement_answer(
    original: &crate::kernel::original_settlement::Original,
    answer: &Value,
) -> Result<()> {
    let object = answer
        .as_object()
        .ok_or_else(|| Error::engine("settlement answer object required"))?;
    if object.keys().any(|k| {
        ![
            "schema",
            "verdict",
            "binding_verified",
            "original_binding_sha256",
            "namespace_sha256",
            "receipt",
            "fence",
            "terminal",
        ]
        .contains(&k.as_str())
    }) || answer["schema"] != "native.original-settlement.answer.v1"
        || answer["binding_verified"] != true
        || answer["original_binding_sha256"].as_str() != Some(&original.expected_binding_sha256)
        || !answer["namespace_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(Error::engine("settlement binding unverified"));
    }
    let reference = match answer["verdict"].as_str() {
        Some("accepted") if answer.get("fence").is_none() && answer.get("terminal").is_none() => {
            let receipt = &answer["receipt"];
            let identity = &receipt["identity"];
            if identity["principal_id"] != original.principal_id
                || identity["operation"] != original.operation
                || identity["operation_key"] != original.operation_key
                || !identity["receipt_sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                || receipt.get("raw_json").is_some()
            {
                return Err(Error::engine("settlement receipt identity differs"));
            }
            let native: crate::NativeFenceReference =
                serde_json::from_value(receipt["native"].clone())?;
            if identity["canonical_event_id"] != native.canonical_event_id {
                return Err(Error::engine("settlement receipt event differs"));
            }
            native
        }
        Some("unapplied_terminal")
            if answer["terminal"] == true && answer.get("receipt").is_none() =>
        {
            let fence = &answer["fence"];
            if fence["schema"] != "native.original-fence.v1"
                || fence["reason"] != "owner_abandoned_unapplied"
                || fence["scope"] != "entire_idempotency_namespace"
                || !fence["fence_id"]
                    .as_str()
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                || !fence["fenced_original_binding_sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(Error::engine("settlement terminal proof differs"));
            }
            serde_json::from_value(fence["native"].clone())?
        }
        _ => return Err(Error::engine("settlement outcome remains unresolved")),
    };
    if reference.origin_database_id != original.origin_database_id
        || reference.local_seq <= 0
        || reference.act <= 0
        || reference.genesis_event_id.is_empty()
        || reference.canonical_event_id.is_empty()
    {
        return Err(Error::engine("settlement native reference differs"));
    }
    Ok(())
}

fn resolution_barrier_valid(entry: &Entry) -> bool {
    match &entry.working_resolution {
        None => entry.compatibility_block.is_none(),
        Some(resolution) => {
            entry.compatibility_block == Some(CompatibilityBlock::OriginalResolution)
                && resolution.valid(entry)
        }
    }
}

impl Journal {
    pub(in crate::node) fn has_working_resolution(&self) -> bool {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|e| e.working_resolution.is_some())
    }
    pub(in crate::node) fn request_working_resolution(&self, id: &str) -> Result<Entry> {
        let current = self
            .get(id)
            .ok_or_else(|| Error::engine("working original missing"))?;
        let original = settlement_original(&current)?;
        self.update_checked(
            id,
            |entry| {
                if entry.working_resolution.is_none() {
                    entry.working_resolution = Some(WorkingResolution::Requested {
                        schema: "native.node-original-resolution.v1".into(),
                        expected_binding_sha256: original.expected_binding_sha256.clone(),
                        diagnostic: None,
                    });
                    entry.compatibility_block = Some(CompatibilityBlock::OriginalResolution);
                }
            },
            |before, after| {
                if before.working_original != current.working_original
                    || before.kernel_v2_custody != current.kernel_v2_custody
                    || after
                        .working_resolution
                        .as_ref()
                        .is_none_or(|r| !r.valid(after))
                {
                    return Err(Error::engine("working resolution original changed"));
                }
                Ok(())
            },
            true,
        )
    }
    pub(in crate::node) fn working_resolution_diagnostic(
        &self,
        id: &str,
        diagnostic: &str,
    ) -> Result<()> {
        self.update_checked(
            id,
            |entry| {
                if let Some(WorkingResolution::Requested {
                    diagnostic: saved, ..
                }) = &mut entry.working_resolution
                {
                    *saved = Some(diagnostic.into());
                }
            },
            |_, after| {
                if after
                    .working_resolution
                    .as_ref()
                    .is_none_or(|r| !r.valid(after))
                {
                    return Err(Error::engine("resolution diagnostic invalid"));
                }
                Ok(())
            },
            true,
        )?;
        Ok(())
    }
    pub(in crate::node) fn verified_working_settlement(
        &self,
        verdict: &super::super::gate::queue::WorkingSettlementVerdict,
    ) -> Result<Entry> {
        self.update_checked(
            verdict.id(),
            |entry| entry.working_resolution = Some(verdict.resolution()),
            |before, after| {
                verdict.matches(before)?;
                if after
                    .working_resolution
                    .as_ref()
                    .is_none_or(|r| !r.valid(after))
                {
                    return Err(Error::engine("settlement evidence invalid"));
                }
                Ok(())
            },
            true,
        )
    }
}

/// Original event decoration is data, never replay identity or authority.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalAnnotations {
    run_key: Option<String>,
    parent_key: Option<String>,
    intent: Option<String>,
}
impl OriginalAnnotations {
    fn is_empty(&self) -> bool {
        self.run_key.is_none() && self.parent_key.is_none() && self.intent.is_none()
    }
    fn capture(value: crate::store::EventAnnotations) -> Self {
        Self {
            run_key: value.run_key,
            parent_key: value.parent_key,
            intent: value.intent,
        }
    }
    fn replay(&self) -> crate::store::EventAnnotations {
        crate::store::EventAnnotations {
            run_key: self.run_key.clone(),
            parent_key: self.parent_key.clone(),
            intent: self.intent.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FirstPartyIdentity {
    FirstParty,
    FirstPartyCreate { context: String },
    Record(RecordIdentity),
}
/// Format 9's additional fields are strict without changing 7/8 decoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordIdentity {
    operation: RecordOperation,
    mint_context: Option<String>,
}
impl OriginalAppend {
    fn operation(&self) -> &str {
        match &self.identity {
            FirstPartyIdentity::FirstParty => "update_record",
            FirstPartyIdentity::FirstPartyCreate { .. } => "create_record",
            FirstPartyIdentity::Record(identity) => identity.operation.catalog_operation(),
        }
    }
    pub(in crate::node) fn source_tool(&self) -> &str {
        match &self.identity {
            FirstPartyIdentity::Record(identity) => identity.operation.source_tool(),
            _ => self.operation(),
        }
    }
    fn record_operation(&self) -> Option<RecordOperation> {
        match &self.identity {
            FirstPartyIdentity::Record(identity) => Some(identity.operation),
            _ => None,
        }
    }
    fn proposal_identity(&self) -> crate::mcp::kernel_v2::writes::replay::ProposalIdentity {
        crate::mcp::kernel_v2::writes::replay::ProposalIdentity {
            app: None,
            mint_context: match &self.identity {
                FirstPartyIdentity::FirstParty => None,
                FirstPartyIdentity::FirstPartyCreate { context } => Some(context.clone()),
                FirstPartyIdentity::Record(identity) => identity.mint_context.clone(),
            },
        }
    }
    pub(in crate::node) fn native_arguments(&self) -> Option<&Value> {
        self.native_arguments.as_ref()
    }
    pub(in crate::node) fn annotations(&self) -> crate::store::EventAnnotations {
        self.annotations.replay()
    }
    pub(in crate::node) fn actor(&self) -> &str {
        &self.actor
    }
    pub(in crate::node) fn fingerprint(&self) -> &str {
        &self.request_fingerprint
    }
    fn valid(&self) -> bool {
        !self.actor.trim().is_empty()
            && self.actor.len() <= 4096
            && !self.request_fingerprint.is_empty()
            && self.request_fingerprint.len() <= MAX_ORIGINAL_FINGERPRINT_BYTES
    }
    pub(super) fn valid_entry(&self, entry: &Entry) -> bool {
        if entry.version == INSTALLED_RECORD_VERSION {
            return self.valid_record_entry(entry);
        }
        self.valid()
            && self.native_arguments.is_none()
            && matches!(
                entry.version,
                WORKING_VERSION | INSTALLED_WORKING_VERSION | INSTALLED_CREATE_VERSION
            )
            && entry.executor == "records_write"
            && entry.operation == self.operation()
            && match (&self.identity, entry.version) {
                (FirstPartyIdentity::FirstParty, WORKING_VERSION | INSTALLED_WORKING_VERSION) => {
                    true
                }
                (FirstPartyIdentity::FirstPartyCreate { context }, INSTALLED_CREATE_VERSION) => {
                    context == "first-party"
                }
                _ => false,
            }
            && entry.tool == "records_write"
            && (installed_working_version(entry.version) || entry.state != EntryState::Sent)
            && entry.answer.as_deref().is_none_or(|answer| {
                matches!(answer, "receipt" | "refused")
                    || (installed_working_version(entry.version)
                        && matches!(answer, "already_applied" | "hosted_pending"))
            })
            && (!installed_working_version(entry.version)
                || (matches!(
                    entry.state,
                    EntryState::Pending
                        | EntryState::Sent
                        | EntryState::Uncertain
                        | EntryState::HostedPending
                        | EntryState::Confirmed
                ) && (entry.state != EntryState::Confirmed
                    || entry.answer.as_deref().is_some_and(|answer| {
                        matches!(answer, "receipt" | "refused" | "already_applied")
                    }))))
            && entry.key_origin == Some(KeyOrigin::Caller)
            && entry.run_key.is_none()
            && entry.client_info.is_none()
            && entry.parent_key.is_none()
            && entry.record_ids.is_empty()
            && entry.envelope.as_ref() == Some(&json!({}))
            && entry.merge_intent.is_none()
            && entry.merge_preparation.is_none()
            && entry.merge_result.is_none()
            && entry.merge_aliases.is_empty()
            && !entry.prepared
            && !entry.lineage_required
            && !entry.merge_key_tombstone
            && (installed_working_version(entry.version)
                || (!entry.in_flight && !entry.maybe_applied))
            && entry.app_identity.is_none()
            && entry.custody_compatibility.is_none()
            && entry.fork_arguments.is_none()
            && entry.fork_run_key.is_none()
            && entry.fork_accepted_act.is_none()
            && entry.kernel_v2_custody.as_ref().is_some_and(|scope| {
                (!installed_working_version(entry.version)
                    || (scope.original.is_none()
                        && resolution_barrier_valid(entry)
                        && entry.waiting_for.is_none()))
                    && scope.engine == "native-kernel-v2"
                    && scope.binding.valid()
                    && scope.contract_digest.len() == 64
                    && scope.contract_digest.bytes().all(|b| b.is_ascii_hexdigit())
            })
            && entry.arguments.as_ref().is_some_and(|args| {
                (if self.operation() == "create_record" {
                    let mut source = args.clone();
                    if let Some(object) = source.as_object_mut() {
                        object.remove("id");
                        object.remove("id_nonce");
                    }
                    crate::mcp::kernel_v2::writes::replay::validate_first_party_create_source(
                        &source,
                    )
                    .is_ok()
                        && args
                            .get("id")
                            .and_then(Value::as_str)
                            .zip(args.get("id_nonce").and_then(Value::as_str))
                            .is_some_and(|(id, nonce)| {
                                crate::record_id::verify(
                                    &crate::record_id::qualified_principal(&self.actor),
                                    "first-party",
                                    id,
                                    nonce,
                                )
                            })
                } else {
                    crate::fork::validate_shape_kernel_v2("update_record", args, 1024 * 1024)
                        .is_ok()
                }) && args.get("idempotency_key").and_then(Value::as_str)
                    == entry.idempotency_key.as_deref()
                    && entry
                        .idempotency_key
                        .as_deref()
                        .is_some_and(|key| !key.trim().is_empty())
                    && args.get("id").and_then(Value::as_str).is_some_and(|id| {
                        uuid::Uuid::parse_str(id).is_ok() && entry.record_id.as_deref() == Some(id)
                    })
                    && entry.arguments_bytes == args.to_string().len()
                    && entry.arguments_digest == arguments_digest(args)
                    && crate::mcp::kernel_v2::writes::replay::ReplayProposal::from_original(
                        self.operation(),
                        args.clone(),
                        entry.idempotency_key.clone(),
                        &self.proposal_identity(),
                    )
                    .is_ok_and(|proposal| {
                        proposal.request_fingerprint().as_bytes()
                            == self.request_fingerprint.as_bytes()
                    })
            })
    }
    fn valid_record_entry(&self, entry: &Entry) -> bool {
        let Some(operation) = self.record_operation() else {
            return false;
        };
        let Some(native) = self.native_arguments.as_ref() else {
            return false;
        };
        let Some(wire) = entry.arguments.as_ref() else {
            return false;
        };
        let identity = self.proposal_identity();
        let context_matches = if operation == RecordOperation::Create {
            identity.mint_context.as_deref() == Some("first-party")
                && native["id"]
                    .as_str()
                    .zip(native["id_nonce"].as_str())
                    .is_some_and(|(id, nonce)| {
                        crate::record_id::verify(
                            &crate::record_id::qualified_principal(&self.actor),
                            "first-party",
                            id,
                            nonce,
                        )
                    })
        } else {
            identity.mint_context.is_none()
        };
        let mut source = native.clone();
        if operation == RecordOperation::Create {
            let Some(object) = source.as_object_mut() else {
                return false;
            };
            object.remove("id");
            object.remove("id_nonce");
        }
        let projection_matches =
            crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()
                .and_then(|contracts| {
                    if !matches!(
                        contracts.validate(
                            operation.executor(),
                            operation.catalog_operation(),
                            &json!({"arguments":wire}),
                            true
                        ),
                        Some(Ok(()))
                    ) {
                        return Err(Error::engine(
                            "record wire schema differs from its compiled operation",
                        ));
                    }
                    contracts.working_native_arguments(
                        operation.executor(),
                        operation.catalog_operation(),
                        wire,
                    )
                })
                .is_ok_and(|(tool, args)| tool == operation.source_tool() && &args == native);
        let primary = operation.primary_target(native);
        !self.actor.trim().is_empty()
            && self.actor.len() <= 4096
            && !self.request_fingerprint.is_empty()
            && self.request_fingerprint.len() <= 1024 * 1024 + 1024
            && context_matches
            && projection_matches
            && operation.validate(&source).is_ok()
            && entry.executor == operation.executor()
            && entry.tool == operation.executor()
            && entry.operation == operation.catalog_operation()
            && entry.key_origin == Some(KeyOrigin::Caller)
            && wire["idempotency_key"].as_str() == entry.idempotency_key.as_deref()
            && native["idempotency_key"].as_str() == entry.idempotency_key.as_deref()
            && entry.record_id.as_deref() == primary
            && primary.is_some()
            && entry.record_ids
                == operation
                    .targets(native)
                    .into_iter()
                    .filter(|id| Some(id.as_str()) != primary)
                    .collect::<Vec<_>>()
            && entry.arguments_bytes == wire.to_string().len()
            && entry.arguments_digest == arguments_digest(wire)
            && entry.envelope.as_ref() == Some(&json!({}))
            && entry.run_key.is_none()
            && entry.parent_key.is_none()
            && entry.client_info.is_none()
            && entry.app_identity.is_none()
            && entry.custody_compatibility.is_none()
            && entry.fork_arguments.is_none()
            && entry.fork_run_key.is_none()
            && entry.fork_accepted_act.is_none()
            && entry.merge_intent.is_none()
            && entry.merge_preparation.is_none()
            && entry.merge_result.is_none()
            && entry.merge_aliases.is_empty()
            && !entry.prepared
            && !entry.lineage_required
            && !entry.merge_key_tombstone
            && resolution_barrier_valid(entry)
            && entry.waiting_for.is_none()
            && matches!(
                entry.state,
                EntryState::Pending
                    | EntryState::Sent
                    | EntryState::Uncertain
                    | EntryState::HostedPending
                    | EntryState::Confirmed
            )
            && entry.answer.as_deref().is_none_or(|a| {
                matches!(
                    a,
                    "receipt" | "refused" | "already_applied" | "hosted_pending"
                )
            })
            && (entry.state != EntryState::Confirmed
                || entry
                    .answer
                    .as_deref()
                    .is_some_and(|a| matches!(a, "receipt" | "refused" | "already_applied")))
            && entry.kernel_v2_custody.as_ref().is_some_and(|c| {
                c.original.is_none()
                    && c.engine == "native-kernel-v2"
                    && c.binding.valid()
                    && c.contract_digest.len() == 64
                    && c.contract_digest.bytes().all(|b| b.is_ascii_hexdigit())
            })
            && crate::mcp::kernel_v2::writes::replay::ReplayProposal::from_original(
                operation.source_tool(),
                native.clone(),
                entry.idempotency_key.clone(),
                &identity,
            )
            .is_ok_and(|p| p.request_fingerprint() == self.request_fingerprint)
    }
}

/// Immutable capability issued only after the original entry's file and
/// directory sync succeeded. It contains no deserialized Caller authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableAppend {
    id: String,
    seq: u64,
    original: OriginalAppend,
    args: Value,
    binding: WorkingBinding,
}
impl DurableAppend {
    pub(crate) fn operation(&self) -> &str {
        self.original.source_tool()
    }
    pub(crate) fn catalog_operation(&self) -> &str {
        self.original.operation()
    }
    pub(crate) fn record_operation(&self) -> Option<RecordOperation> {
        self.original.record_operation()
    }
    pub(crate) fn proposal_identity(
        &self,
    ) -> crate::mcp::kernel_v2::writes::replay::ProposalIdentity {
        self.original.proposal_identity()
    }
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.seq
    }
    pub(crate) fn actor(&self) -> &str {
        &self.original.actor
    }
    pub(crate) fn fingerprint(&self) -> &str {
        &self.original.request_fingerprint
    }
    pub(crate) fn arguments(&self) -> &Value {
        self.original
            .native_arguments
            .as_ref()
            .unwrap_or(&self.args)
    }
    pub(crate) fn wire_arguments(&self) -> &Value {
        &self.args
    }
    pub(crate) fn references_created_record(&self, id: &str) -> bool {
        let args = self.arguments();
        self.record_operation().map_or_else(
            || args["id"].as_str() == Some(id),
            |operation| operation.targets(args).iter().any(|target| target == id),
        ) || args["home_id"].as_str() == Some(id)
    }

    pub(crate) fn primary_target(&self) -> Option<&str> {
        if let Some(operation) = self.record_operation() {
            operation.primary_target(self.arguments())
        } else {
            self.arguments()["id"].as_str()
        }
    }
    pub(crate) fn annotations(&self) -> crate::store::EventAnnotations {
        self.original.annotations.replay()
    }
    pub(crate) fn binding(&self) -> &WorkingBinding {
        &self.binding
    }
}

/// The gate serializes proposal/verdict durability with W commit/publication.
/// It is asynchronous: no std mutex is held across SQLite awaits.
pub(crate) struct JournalFence {
    _guard: OwnedMutexGuard<()>,
    // The fence is the complete authority lease, not just an async lock.
    // Retained W custody must keep the directory owner alive after handles drop.
    _journal: Arc<Journal>,
    _exclusive: Arc<File>,
    view: WorkingJournalView,
}
#[derive(Clone)]
pub(crate) struct WorkingJournalView {
    revision: String,
    proposals: Vec<DurableAppend>,
    has_hosted_verdict: bool,
    requires_reconciliation: bool,
    outcomes: std::collections::BTreeMap<String, WorkingOutcome>,
    revision_pieces: Vec<Vec<u8>>,
    resolutions: std::collections::BTreeMap<String, WorkingResolution>,
}
/// Read-only facts from the sole original journal at this fence's revision.
/// They confer no ticket/verdict authority and W cannot write them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkingCanonicalAnswer {
    Pending,
    Accepted,
    Refused,
    Unsupported,
}
#[derive(Clone, Debug)]
pub(crate) struct WorkingOutcome {
    answer: WorkingCanonicalAnswer,
    uncertain: bool,
    never_attempted: bool,
}
impl WorkingOutcome {
    pub(crate) fn answer(&self) -> WorkingCanonicalAnswer {
        self.answer
    }
    pub(crate) fn uncertain(&self) -> bool {
        self.uncertain
    }
    pub(crate) fn never_attempted(&self) -> bool {
        self.never_attempted
    }
}
impl JournalFence {
    pub(crate) fn view(&self) -> &WorkingJournalView {
        &self.view
    }
}
impl WorkingJournalView {
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }
    pub(crate) fn proposals(&self) -> &[DurableAppend] {
        &self.proposals
    }
    pub(crate) fn has_hosted_verdict(&self) -> bool {
        self.has_hosted_verdict
    }
    pub(crate) fn requires_reconciliation(&self) -> bool {
        self.requires_reconciliation
    }
    pub(crate) fn outcome(&self, id: &str) -> Option<&WorkingOutcome> {
        self.outcomes.get(id)
    }
    pub(crate) fn resolution(&self, id: &str) -> Option<&WorkingResolution> {
        self.resolutions.get(id)
    }
    pub(crate) fn has_resolution(&self) -> bool {
        !self.resolutions.is_empty()
    }
    pub(crate) fn resolutions(&self) -> impl Iterator<Item = (&str, &WorkingResolution)> {
        self.resolutions
            .iter()
            .map(|(id, resolution)| (id.as_str(), resolution))
    }
    pub(crate) fn prefix_revision(&self, count: usize) -> Result<String> {
        let pieces = self
            .revision_pieces
            .get(..count)
            .ok_or_else(|| Error::engine("working original prefix exceeds retained journal"))?;
        let mut digest = Sha256::new();
        digest.update(b"[");
        for (index, piece) in pieces.iter().enumerate() {
            if index != 0 {
                digest.update(b",");
            }
            digest.update(piece);
        }
        digest.update(b"]");
        Ok(hex::encode(digest.finalize()))
    }
}
#[derive(Clone)]
pub(crate) struct WorkingJournal {
    journal: Arc<Journal>,
    serial: Arc<AsyncMutex<()>>,
    binding: WorkingBinding,
    _exclusive: Arc<File>,
    root: PathBuf,
    version: u32,
    installed_admission: Option<Arc<crate::node::gate::WriteGate>>,
    location_scope: Option<(std::path::PathBuf, String)>,
    refusal_drafts: bool,
}
impl WorkingJournal {
    pub(crate) fn with_refusal_drafts(mut self) -> Result<Self> {
        if self.binding.install_id.is_none() || self.version != INSTALLED_WORKING_VERSION {
            return Err(Error::engine(
                "draft recovery requires enrolled working custody",
            ));
        }
        if self
            .journal
            .enrolled_qualification()
            .and_then(tokio::sync::OnceCell::get)
            .is_none()
        {
            return Err(Error::engine(
                "draft recovery requires verified journal continuity",
            ));
        }
        self.refusal_drafts = true;
        Ok(self)
    }

    pub(crate) fn refusal_drafts(&self) -> bool {
        self.refusal_drafts
    }

    /// Read-only admission barrier from the sole journal, not a wake hint.
    pub(crate) fn has_resolution(&self) -> bool {
        self.journal.has_working_resolution()
    }

    pub(crate) fn open(root: &Path, binding: WorkingBinding) -> Result<Self> {
        binding.validate()?;
        let path = root.join("working-manager-journal");
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                check_owned(&meta, 0o700)?;
                if !meta.is_dir() {
                    return Err(Error::engine("working journal root is not a directory"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&path)?;
                File::open(root)?.sync_all()?;
            }
            Err(error) => return Err(error.into()),
        }
        let exclusive = File::open(&path)?;
        fs2::FileExt::try_lock_exclusive(&exclusive)
            .map_err(|_| Error::engine("working journal already has an owner"))?;
        let scope = CustodyBinding {
            account_id: binding.account_id.clone(),
            database_id: binding.database_id.clone(),
            origin_database_id: binding.origin_database_id.clone(),
            history_lineage: binding.history_lineage.clone(),
            resource_origin: binding.resource_origin.clone(),
            install_id: binding.install_id.clone(),
        };
        let journal = Journal::open_bound(
            &path,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(scope),
        )?;
        if journal.unreadable != 0
            || journal
                .entries
                .lock()
                .expect("journal entries")
                .values()
                .any(|entry| entry.version != WORKING_VERSION || !entry.is_working())
        {
            return Err(Error::engine(
                "working journal has unreadable authority; recovery required",
            ));
        }
        Ok(Self {
            journal: Arc::new(journal),
            serial: Arc::new(AsyncMutex::new(())),
            binding,
            _exclusive: Arc::new(exclusive),
            root: path,
            version: WORKING_VERSION,
            installed_admission: None,
            location_scope: None,
            refusal_drafts: false,
        })
    }

    /// Installed facade over the existing scoped gate's sole journal. The
    /// directory lock survives detached ownership and prevents another working
    /// node owner from adopting the scope while an old transaction is retained.
    /// Legacy entries are preserved and remain ordering barriers in this slice.
    fn scoped_entry_allowed(entry: &Entry) -> bool {
        // Ordinary receipts retired by their own queue are history, never
        // working proposals. The owner still proves the accepted base covers
        // its canonical floor before constructing W. Other evidence is a barrier.
        if entry.version == V2_EVIDENCE_VERSION {
            return entry.valid_v6()
                && entry.state == EntryState::Confirmed
                && entry.answer.as_deref() == Some("receipt")
                && !entry.in_flight
                && entry.arguments.is_none()
                && entry.envelope.is_none();
        }
        (installed_working_version(entry.version) && entry.is_working())
            || (matches!(entry.version, 1..=4)
                && matches!(entry.state, EntryState::Confirmed | EntryState::NotSent)
                && !entry.in_flight
                && (entry.state != EntryState::NotSent || !entry.maybe_applied))
    }
    pub(crate) fn binding(&self) -> &WorkingBinding {
        &self.binding
    }
    pub(in crate::node) fn from_scoped(
        journal: Arc<Journal>,
        binding: WorkingBinding,
    ) -> Result<Self> {
        binding.validate()?;
        let expected = CustodyBinding {
            account_id: binding.account_id.clone(),
            database_id: binding.database_id.clone(),
            origin_database_id: binding.origin_database_id.clone(),
            history_lineage: binding.history_lineage.clone(),
            resource_origin: binding.resource_origin.clone(),
            install_id: binding.install_id.clone(),
        };
        if journal.custody_binding.as_ref() != Some(&expected)
            || journal.unreadable != 0
            || journal
                .entries
                .lock()
                .expect("journal entries")
                .values()
                .any(|entry| !Self::scoped_entry_allowed(entry))
        {
            return Err(Error::engine("existing scoped custody must settle before working append enrollment; originals retained"));
        }
        let root = journal
            .directory
            .parent()
            .ok_or_else(|| Error::engine("missing scoped journal owner"))?
            .to_path_buf();
        let exclusive = File::open(&root)?;
        fs2::FileExt::try_lock_exclusive(&exclusive)
            .map_err(|_| Error::engine("working scope still has an owner"))?;
        Ok(Self {
            serial: journal.working_serial.clone(),
            journal,
            binding,
            _exclusive: Arc::new(exclusive),
            root,
            version: INSTALLED_WORKING_VERSION,
            installed_admission: None,
            location_scope: None,
            refusal_drafts: false,
        })
    }

    pub(in crate::node) fn with_installed_admission(
        mut self,
        gate: Arc<crate::node::gate::WriteGate>,
    ) -> Result<Self> {
        if self.version != INSTALLED_WORKING_VERSION || !Arc::ptr_eq(&self.journal, &gate.journal) {
            return Err(Error::engine(
                "installed admission must own this exact custody journal",
            ));
        }
        // No retained installed original may replay during owner startup
        // under a different compiled contract. Reuse the exact queue rule;
        // this never grants description-only compatibility or queries hosted.
        if self
            .journal
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|entry| {
                installed_working_version(entry.version) && !gate.working_contract_current(entry)
            })
        {
            return Err(Error::engine(
                "retained working operation contract changed; original retained; startup replay refused",
            ));
        }
        self.installed_admission = Some(gate);
        Ok(self)
    }

    /// The private accepted owner pins restart coordinates before admitting
    /// any original. Missing provenance on nonempty journals is never adopted.
    pub(crate) fn with_location_scope(
        mut self,
        root: std::path::PathBuf,
        area: String,
    ) -> Result<Self> {
        if uuid::Uuid::parse_str(&area).is_err() {
            return Err(Error::engine("working area must be generated"));
        }
        self.location_scope = Some((root, area));
        Ok(self)
    }
    pub(crate) fn location_scope(&self) -> Option<&(std::path::PathBuf, String)> {
        self.location_scope.as_ref()
    }
    pub(crate) fn requires_location(&self) -> bool {
        self.installed_admission.is_some()
    }
    pub(crate) fn anchor_bytes(&self) -> Result<Vec<u8>> {
        use std::os::unix::fs::MetadataExt;
        let path = self.root.join("pinned-base.json");
        let meta = fs::symlink_metadata(&path)?;
        check_owned(&meta, 0o600)?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > 65536 {
            return Err(Error::engine("invalid working base anchor"));
        }
        Ok(fs::read(path)?)
    }
    pub(crate) fn location(&self) -> Result<Option<crate::fork::working_v2::WorkingLocation>> {
        use std::os::unix::fs::MetadataExt;
        let path = self.root.join("working-location.json");
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        check_owned(&meta, 0o600)?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > 65536 {
            return Err(Error::engine("invalid working location file"));
        }
        let location: crate::fork::working_v2::WorkingLocation =
            serde_json::from_slice(&fs::read(path)?)?;
        location.validate()?;
        if location.original_anchor_sha256 != hex::encode(Sha256::digest(self.anchor_bytes()?)) {
            return Err(Error::engine("retained working location anchor mismatch"));
        }
        Ok(Some(location))
    }
    pub(crate) fn bind_location(
        &self,
        location: &crate::fork::working_v2::WorkingLocation,
    ) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        location.validate()?;
        if location.original_anchor_sha256 != hex::encode(Sha256::digest(self.anchor_bytes()?)) {
            return Err(Error::engine("working location anchor mismatch"));
        }
        if let Some(old) = self.location()? {
            if old != *location {
                return Err(Error::engine("working location cannot be replaced"));
            }
            File::open(&self.root)?.sync_all()?;
            return Ok(());
        }
        let bytes = serde_json::to_vec(location)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.root.join("working-location.json"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn bind_base(
        &self,
        capability: &crate::fork::working_v2::WorkingReadBinding,
    ) -> Result<()> {
        self.bind_base_bytes(&capability.anchor_bytes()?)
    }
    // Filesystem persistence only. Runtime callers enter through the opaque
    // accepted-owner capability above; tests can exercise refusal without
    // inventing one. Bytes here never construct or grant a read capability.
    fn bind_base_bytes(&self, expected: &[u8]) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if expected.len() > 65536 {
            return Err(Error::engine("working base provenance is too large"));
        }
        let path = self.root.join("pinned-base.json");
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                check_owned(&meta, 0o600)?;
                if !meta.is_file()
                    || meta.nlink() != 1
                    || meta.len() > 65536
                    || fs::read(&path)? != expected
                {
                    return Err(Error::engine(
                        "AwaitingQualifiedUndo: pinned accepted base changed or invalid",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self
                    .journal
                    .entries
                    .lock()
                    .expect("journal entries")
                    .values()
                    .any(|entry| {
                        entry.version == self.version
                            || (self.version == INSTALLED_WORKING_VERSION
                                && installed_working_version(entry.version))
                    })
                {
                    return Err(Error::engine(
                        "working journal missing pinned accepted-base provenance",
                    ));
                }
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(expected)?;
                file.sync_all()?;
            }
            Err(error) => return Err(error.into()),
        }
        // Also establish directory durability after a prior interrupted initial
        // fsync. No proposals are admitted before this acknowledged sync.
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    /// The caller supplies a proposal from the agreed original-identity
    /// provider. This adapter copies it exactly; it never normalizes requests
    /// or derives the request fingerprint. This free-actor adapter exists only
    /// for format fixtures; runtime admission uses the sealed manager value.
    #[cfg(test)]
    pub(crate) async fn persist_original(
        &self,
        actor: String,
        proposal: &crate::mcp::kernel_v2::writes::replay::ReplayProposal,
        identity: FirstPartyIdentity,
        contract_digest: String,
    ) -> Result<DurableAppend> {
        let _serial = self.serial.lock().await;
        self.persist_captured(
            actor,
            proposal,
            identity,
            contract_digest,
            Default::default(),
            None,
        )
    }
    /// Called only on an owned blocking job. The sealed admission owns actual
    /// native principal/provenance; no runtime free-actor/fingerprint ingress.
    /// The async revision gate still serializes durability with W publication.
    pub(crate) fn persist_admitted_blocking(
        &self,
        admitted: &crate::fork::working_v2::manager::AdmittedAppend,
        contract_digest: String,
    ) -> Result<DurableAppend> {
        let _serial = self.serial.blocking_lock();
        if self.journal.has_working_resolution() {
            return Err(Error::engine(
                "original resolution pauses admission; payload retained",
            ));
        }
        if admitted.binding() != &self.binding {
            return Err(Error::engine("working admission namespace changed"));
        }
        self.persist_captured(
            admitted.actor().to_owned(),
            admitted.proposal(),
            Self::admitted_identity(admitted)?,
            contract_digest,
            admitted.annotations(),
            admitted.wire_arguments().cloned(),
        )
    }
    /// Extend an already captured owner turn through fsync without unlocking
    /// or recursively acquiring its serial fence. Run on the owned blocking
    /// worker; no canonical network operation is performed here.
    pub(crate) fn persist_admitted_fenced_blocking(
        &self,
        fence: JournalFence,
        admitted: &crate::fork::working_v2::manager::AdmittedAppend,
        contract_digest: String,
    ) -> Result<(DurableAppend, JournalFence)> {
        if !Arc::ptr_eq(&fence._journal, &self.journal) || admitted.binding() != &self.binding {
            return Err(Error::engine("working admission fence changed owner"));
        }
        let ticket = self.persist_captured(
            admitted.actor().to_owned(),
            admitted.proposal(),
            Self::admitted_identity(admitted)?,
            contract_digest,
            admitted.annotations(),
            admitted.wire_arguments().cloned(),
        )?;
        let updated = self.capture_owned(fence._guard)?;
        Ok((ticket, updated))
    }
    fn admitted_identity(
        admitted: &crate::fork::working_v2::manager::AdmittedAppend,
    ) -> Result<FirstPartyIdentity> {
        let proposal = admitted.proposal();
        if let Some(operation) = admitted.record_operation() {
            if proposal.tool() != operation.source_tool()
                || proposal.identity().app.is_some()
                || proposal.identity().mint_context.as_deref()
                    != (operation == RecordOperation::Create).then_some("first-party")
            {
                return Err(Error::engine("unsupported original record identity"));
            }
            return Ok(FirstPartyIdentity::Record(RecordIdentity {
                operation,
                mint_context: proposal.identity().mint_context.clone(),
            }));
        }
        match (
            proposal.tool(),
            proposal.identity().app.as_ref(),
            proposal.identity().mint_context.as_deref(),
        ) {
            ("update_record", None, None) => Ok(FirstPartyIdentity::FirstParty),
            ("create_record", None, Some("first-party")) => {
                Ok(FirstPartyIdentity::FirstPartyCreate {
                    context: "first-party".into(),
                })
            }
            _ => Err(Error::engine("unsupported original working identity")),
        }
    }
    fn persist_captured(
        &self,
        actor: String,
        proposal: &crate::mcp::kernel_v2::writes::replay::ReplayProposal,
        identity: FirstPartyIdentity,
        contract_digest: String,
        annotations: crate::store::EventAnnotations,
        wire_arguments: Option<Value>,
    ) -> Result<DurableAppend> {
        if proposal.tool() == "create_record" && self.version != INSTALLED_WORKING_VERSION {
            return Err(Error::engine("final create requires the installed scoped journal; private v5 remains append-only"));
        }
        // The v7 runtime facade always owns the SAME gate admission turn as
        // typed merge insertion. Format-only fixtures may omit the gate.
        #[cfg(not(test))]
        if self.version == INSTALLED_WORKING_VERSION && self.installed_admission.is_none() {
            return Err(Error::engine("installed custody admission owner missing"));
        }
        if !self.refusal_drafts && self.journal.has_working_resolution() {
            return Err(Error::engine(
                "original resolution pauses admission; payload retained",
            ));
        }
        let record = match &identity {
            FirstPartyIdentity::Record(identity) => Some(identity.operation),
            _ => None,
        };
        if record.is_some() && self.version != INSTALLED_WORKING_VERSION {
            return Err(Error::engine(
                "record family requires installed scoped custody",
            ));
        }
        let wire = wire_arguments.unwrap_or_else(|| proposal.args().clone());
        let executor = record.map_or("records_write", RecordOperation::executor);
        let operation = match record {
            Some(record) => record.catalog_operation(),
            None => proposal.tool(),
        };
        let _admission = self
            .installed_admission
            .as_ref()
            .map(|gate| {
                if record.is_some() {
                    gate.working_record_admission(executor, operation, &wire, &contract_digest)
                } else {
                    gate.working_admission(operation, &wire, &contract_digest)
                }
            })
            .transpose()?;
        if proposal.identity().app.is_some()
            || proposal.identity().mint_context.as_deref()
                != (proposal.tool() == "create_record").then_some("first-party")
        {
            return Err(Error::engine(
                "working journal accepts observed first-party identity only",
            ));
        }
        if let Some(record) = record {
            if proposal.tool() != record.source_tool() {
                return Err(Error::engine("record source operation changed"));
            }
            let mut source = proposal.args().clone();
            if record == RecordOperation::Create {
                if let Some(object) = source.as_object_mut() {
                    object.remove("id");
                    object.remove("id_nonce");
                }
            }
            record.validate(&source)?;
        } else {
            crate::fork::validate_working_shape_kernel_v2(
                proposal.tool(),
                proposal.args(),
                1024 * 1024,
            )
            .map_err(|error| Error::engine(error.to_string()))?;
        }
        let key = proposal
            .idempotency_key()
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(|| Error::engine("working proposal requires its original key"))?;
        if proposal
            .args()
            .get("idempotency_key")
            .and_then(Value::as_str)
            != Some(key)
        {
            return Err(Error::engine(
                "working proposal key disagrees with original arguments",
            ));
        }
        let original = OriginalAppend {
            actor,
            request_fingerprint: proposal.request_fingerprint().to_owned(),
            identity,
            native_arguments: record.map(|_| proposal.args().clone()),
            annotations: OriginalAnnotations::capture(annotations),
        };
        if !original.valid() && record.is_none() {
            return Err(Error::engine("invalid original proposal identity"));
        }
        let mut entries = self.journal.entries.lock().expect("journal entries");
        if let Some(entry) = entries.values().find(|entry| {
            entry
                .working_original
                .as_ref()
                .is_some_and(|old| old.source_tool() == proposal.tool())
                && entry
                    .working_original
                    .as_ref()
                    .is_some_and(|old| old.actor == original.actor)
                && entry.idempotency_key.as_deref() == Some(key)
        }) {
            if entry.working_resolution.is_some() {
                return Err(Error::conflict(
                    "original has retained resolution; inspect its recovery disposition",
                ));
            }
            // Retry decoration belongs to this invocation, not request
            // identity. Keep the FIRST original's annotation bytes unchanged;
            // a new run/client may retrieve its own exact pending proposal.
            if !entry.working_original.as_ref().is_some_and(|old| {
                old.actor == original.actor
                    && old.request_fingerprint == original.request_fingerprint
                    && old.identity == original.identity
                    && old.native_arguments == original.native_arguments
            }) || entry.arguments.as_ref() != Some(&wire)
            {
                return Err(Error::conflict(
                    "working proposal key is reserved for different original bytes",
                ));
            }
            return self.ticket(entry);
        }
        if self.version == INSTALLED_WORKING_VERSION {
            if entries.values().any(|entry| {
                entry.ordinary_v2()
                    && entry.native_operation() == proposal.tool()
                    && entry.idempotency_key.as_deref() == Some(key)
            }) {
                return Err(Error::conflict("key already belongs to ordinary v2 custody; it cannot become a second working original"));
            }
            if entries
                .values()
                .any(|entry| !Self::scoped_entry_allowed(entry))
            {
                return Err(Error::conflict(
                    "another original custody entry requires ordered reconciliation; nothing saved",
                ));
            }
        }
        let new = NewEntry {
            executor: executor.into(),
            operation: operation.into(),
            tool: executor.into(),
            run_key: None,
            client_info: None,
            app_identity: None,
            idempotency_key: Some(key.into()),
            key_origin: Some(KeyOrigin::Caller),
            arguments: wire,
            parent_key: None,
            title: None,
            record_id: record
                .and_then(|op| op.primary_target(proposal.args()))
                .or_else(|| proposal.args()["id"].as_str())
                .map(str::to_owned),
            record_ids: record
                .map(|op| {
                    op.targets(proposal.args())
                        .into_iter()
                        .filter(|id| Some(id.as_str()) != op.primary_target(proposal.args()))
                        .collect()
                })
                .unwrap_or_default(),
            envelope: Some(json!({})),
            intent_digest: None,
        };
        let mut entry = self
            .journal
            .make_entry(new, None, None, Some(contract_digest))?;
        entry.version = if record.is_some() {
            INSTALLED_RECORD_VERSION
        } else if proposal.tool() == "create_record" {
            INSTALLED_CREATE_VERSION
        } else {
            self.version
        };
        entry.state = EntryState::Pending;
        entry.working_original = Some(original);
        if !entry.is_working() {
            return Err(Error::engine("invalid working proposal format"));
        }
        self.journal.write(&entry)?;
        let ticket = self.ticket(&entry)?;
        entries.insert(entry.id.clone(), entry);
        Ok(ticket)
    }
    fn ticket(&self, entry: &Entry) -> Result<DurableAppend> {
        if !entry.is_working() {
            return Err(Error::engine("not a durable working proposal"));
        }
        Ok(DurableAppend {
            id: entry.id.clone(),
            seq: entry.seq,
            original: entry.working_original.clone().expect("validated original"),
            args: entry.arguments.clone().expect("retained original"),
            binding: self.binding.clone(),
        })
    }
    pub(crate) async fn capture(&self) -> Result<JournalFence> {
        let guard = self.serial.clone().lock_owned().await;
        self.capture_owned(guard)
    }
    fn capture_owned(&self, guard: OwnedMutexGuard<()>) -> Result<JournalFence> {
        let entries = self.journal.entries.lock().expect("journal entries");
        if self.version == INSTALLED_WORKING_VERSION
            && entries
                .values()
                .any(|entry| !Self::scoped_entry_allowed(entry))
        {
            return Err(Error::engine("another original custody entry requires ordered reconciliation; working view retained"));
        }
        let mut retained: Vec<_> = entries
            .values()
            .filter(|entry| {
                entry.version == self.version
                    || (self.version == INSTALLED_WORKING_VERSION
                        && installed_working_version(entry.version))
            })
            .collect();
        retained.sort_by_key(|entry| entry.seq);
        let mut proposals = Vec::new();
        let mut has_hosted_verdict = false;
        let mut requires_reconciliation = false;
        let mut outcomes = std::collections::BTreeMap::new();
        let continuity_verified = self
            .journal
            .enrolled_qualification()
            .and_then(tokio::sync::OnceCell::get)
            .is_some();
        for entry in &retained {
            proposals.push(self.ticket(entry)?);
            let verdict = entry.answer.is_some()
                && (self.version == WORKING_VERSION
                    || entry.answer.as_deref() != Some("hosted_pending"));
            has_hosted_verdict |= verdict;
            requires_reconciliation |= entry.working_resolution.is_some()
                || verdict
                || (self.version == WORKING_VERSION && entry.state != EntryState::Pending);
            let answer = match (entry.state, entry.answer.as_deref()) {
                (EntryState::Confirmed, Some("receipt" | "already_applied")) => {
                    WorkingCanonicalAnswer::Accepted
                }
                (EntryState::Confirmed, Some("refused")) => WorkingCanonicalAnswer::Refused,
                (_, None) => WorkingCanonicalAnswer::Pending,
                _ => WorkingCanonicalAnswer::Unsupported,
            };
            outcomes.insert(
                entry.id.clone(),
                WorkingOutcome {
                    answer,
                    never_attempted: continuity_verified
                        && entry.attempts == 0
                        && !entry.in_flight
                        && !entry.maybe_applied
                        && entry.state == EntryState::Pending
                        && entry.answer.is_none(),
                    uncertain: entry.maybe_applied
                        || matches!(
                            entry.state,
                            EntryState::Uncertain | EntryState::HostedPending
                        ),
                },
            );
        }
        // This is a journal revision digest, NOT an engine request fingerprint.
        let revision_bytes = if self.version == WORKING_VERSION {
            serde_json::to_vec(&retained)?
        } else {
            // Transport attempts/maintenance update status, not the admitted
            // proposal or canonical verdict. Passive bookkeeping cannot break
            // exact retries or invalidate an installed working publication.
            let authority: Vec<_> = retained
                .iter()
                .map(|entry| {
                    (
                        &entry.id,
                        entry.seq,
                        &entry.working_original,
                        &entry.arguments,
                        &entry.idempotency_key,
                        &entry.kernel_v2_custody,
                        entry
                            .answer
                            .as_ref()
                            .filter(|answer| answer.as_str() != "hosted_pending"),
                        entry.reply.as_ref().filter(|_| {
                            entry
                                .answer
                                .as_deref()
                                .is_some_and(|answer| answer != "hosted_pending")
                        }),
                    )
                })
                .collect();
            serde_json::to_vec(&authority)?
        };
        let revision = hex::encode(Sha256::digest(revision_bytes));
        let revision_pieces = retained
            .iter()
            .map(|entry| {
                if self.version == WORKING_VERSION {
                    return serde_json::to_vec(entry);
                }
                let authority = (
                    &entry.id,
                    entry.seq,
                    &entry.working_original,
                    &entry.arguments,
                    &entry.idempotency_key,
                    &entry.kernel_v2_custody,
                    entry
                        .answer
                        .as_ref()
                        .filter(|answer| answer.as_str() != "hosted_pending"),
                    entry.reply.as_ref().filter(|_| {
                        entry
                            .answer
                            .as_deref()
                            .is_some_and(|answer| answer != "hosted_pending")
                    }),
                );
                if let Some(resolution) = &entry.working_resolution {
                    serde_json::to_vec(&(
                        "native.working-resolution-revision.v1",
                        authority,
                        resolution,
                    ))
                } else {
                    serde_json::to_vec(&authority)
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let revision = if retained
            .iter()
            .any(|entry| entry.working_resolution.is_some())
        {
            let mut bytes = Vec::from(b"[".as_slice());
            for (index, piece) in revision_pieces.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                bytes.extend(piece);
            }
            bytes.push(b']');
            hex::encode(Sha256::digest(bytes))
        } else {
            revision
        };
        Ok(JournalFence {
            _guard: guard,
            _journal: self.journal.clone(),
            _exclusive: self._exclusive.clone(),
            view: WorkingJournalView {
                revision,
                proposals,
                has_hosted_verdict,
                requires_reconciliation,
                outcomes,
                revision_pieces,
                resolutions: retained
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .working_resolution
                            .clone()
                            .map(|r| (entry.id.clone(), r))
                    })
                    .collect(),
            },
        })
    }
}

#[cfg(test)]
impl WorkingJournal {
    pub(crate) async fn fixture_resolution_requested(
        &self,
        id: &str,
    ) -> crate::kernel::original_settlement::Original {
        let _turn = self.serial.lock().await;
        let entry = self.journal.request_working_resolution(id).unwrap();
        settlement_original(&entry).unwrap()
    }
    /// Real settlement answer for working-fold tests. HTTP ingress tests use
    /// the sealed authenticated producer instead of this fixture seam.
    pub(crate) async fn fixture_resolution_verified(&self, id: &str, answer: Value) {
        let _turn = self.serial.lock().await;
        let entry = self.journal.get(id).unwrap();
        let original = settlement_original(&entry).unwrap();
        validate_settlement_for_entry(&entry, &original, &answer).unwrap();
        self.journal
            .update_checked(
                id,
                |entry| {
                    entry.working_resolution = Some(WorkingResolution::Verified {
                        schema: "native.node-original-resolution.v1".into(),
                        expected_binding_sha256: original.expected_binding_sha256.clone(),
                        answer,
                    });
                },
                |_, after| {
                    if !resolution_barrier_valid(after) {
                        return Err(Error::engine("fixture resolution invalid"));
                    }
                    Ok(())
                },
                true,
            )
            .unwrap();
    }
    pub(crate) fn retained_count_for_test(&self) -> usize {
        self.journal.entries.lock().unwrap().len()
    }
    pub(crate) fn fail_fsync_for_test(&self) {
        self.journal
            .fail_after
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }
    pub(crate) async fn fixture_transport_uncertain(&self, id: &str) {
        let _serial = self.serial.lock().await;
        self.journal.begin_queue_send(id).unwrap();
        self.journal
            .update(id, |entry| {
                entry.in_flight = false;
                entry.maybe_applied = true;
                entry.state = EntryState::Uncertain;
            })
            .unwrap();
    }
    pub(crate) fn fixture_entry_bytes(&self, id: &str) -> Vec<u8> {
        std::fs::read(self.journal.path(id)).unwrap()
    }
    /// Format-7 codec/owner fixture only, never an installed admission path.
    pub(crate) fn fixture_installed(root: &Path, binding: WorkingBinding) -> Result<Self> {
        let mut journal = Self::open(root, binding)?;
        if !journal
            .journal
            .entries
            .lock()
            .expect("fixture journal")
            .is_empty()
        {
            return Err(Error::engine("fixture requires a new empty journal"));
        }
        journal.version = INSTALLED_WORKING_VERSION;
        journal.serial = journal.journal.working_serial.clone();
        Ok(journal)
    }
    /// Working-copy fixtures isolate replay and publication from the signed
    /// hosted continuity protocol covered by the node ingress tests.
    pub(crate) fn qualify_enrolled_fixture(&self) {
        self.journal
            .enrolled_qualification()
            .unwrap()
            .set(())
            .unwrap();
    }

    /// Format/order fixture only: actual provider projection and fingerprint,
    /// never runtime admission or a locally applied/hosted acceptance claim.
    pub(crate) async fn fixture_record_original(
        &self,
        actor: &str,
        operation: RecordOperation,
        wire: Value,
        contract: String,
    ) -> Result<DurableAppend> {
        if operation == RecordOperation::Create {
            return Err(Error::engine(
                "create fixtures require real original mint capture",
            ));
        }
        let _serial = self.serial.lock().await;
        let (tool, native) =
            crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()?
                .working_native_arguments(
                    operation.executor(),
                    operation.catalog_operation(),
                    &wire,
                )?;
        let proposal = crate::mcp::kernel_v2::writes::replay::ReplayProposal::from_original(
            &tool,
            native,
            wire["idempotency_key"].as_str().map(str::to_owned),
            &Default::default(),
        )?;
        self.persist_captured(
            actor.into(),
            &proposal,
            FirstPartyIdentity::Record(RecordIdentity {
                operation,
                mint_context: None,
            }),
            contract,
            Default::default(),
            Some(wire),
        )
    }
    pub(crate) async fn fixture_accepted_verdict(&self, id: &str, receipt: serde_json::Value) {
        let _serial = self.serial.lock().await;
        let reply = serde_json::to_string(&receipt).unwrap();
        self.journal
            .update_checked(
                id,
                |entry| {
                    entry.answer = Some("receipt".into());
                    entry.state = EntryState::Confirmed;
                    entry.reply = Some(reply.clone());
                    entry.in_flight = false;
                },
                |_, _| Ok(()),
                true,
            )
            .unwrap();
    }
    // Fixture canonical outcome only. Runtime verdict authority remains sealed
    // to the existing verified queue response producer.
    pub(crate) async fn fixture_refused_verdict(&self, id: &str) {
        let _serial = self.serial.lock().await;
        self.journal
            .update(id, |entry| {
                entry.answer = Some("refused".into());
                entry.state = EntryState::Confirmed;
            })
            .unwrap();
    }
}

#[cfg(test)]
pub(crate) fn fixture_enrollment_before_active(
    control: &crate::fork::working_v2::manager::WorkingControl,
    completed: Option<crate::standby::AcceptedKernelDelta>,
) {
    crate::node::failover::enrollment_before_active_for_test(control, completed);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> WorkingBinding {
        WorkingBinding {
            account_id: "account".into(),
            database_id: "route".into(),
            origin_database_id: "origin".into(),
            history_lineage: "genesis".into(),
            resource_origin: "https://fixture.test".into(),
            install_id: None,
        }
    }
    use crate::mcp::kernel_v2::writes::replay::{ProposalIdentity, ReplayProposal};
    // Provider-constructed journal fixture; not authenticated ingress evidence.
    fn proposal(key: &str) -> ReplayProposal {
        ReplayProposal::from_original("update_record",
            json!({"id":"70110000-0000-4000-8000-000000000001","body_append":"retained payload","reason":"journal fixture","idempotency_key":key}),
            Some(key.into()), &ProposalIdentity::default()).unwrap()
    }
    #[test]
    fn enrolled_journal_requires_qualification_and_refuses_a_restored_counter() {
        let directory = tempfile::tempdir().unwrap();
        let install = "b".repeat(64);
        let scope = WorkingBinding {
            install_id: Some(install.clone()),
            ..binding()
        };
        let journal = WorkingJournal::fixture_installed(directory.path(), scope.clone()).unwrap();
        let root = journal.root.clone();
        let counter_path = root.join("installed-journal-sequence.json");
        let persist = |journal: &WorkingJournal, key: &str| {
            journal.persist_captured(
                "actor".into(),
                &proposal(key),
                FirstPartyIdentity::FirstParty,
                "4eb0ca37e1d1caa6d8981b65f4f7ed5f26ab6f929c9de0d2304d57635798cc3a".into(),
                Default::default(),
                None,
            )
        };

        let refused = persist(&journal, "first-original").err().unwrap();
        assert!(refused
            .to_string()
            .contains("continuity has not been verified"));
        assert!(!counter_path.exists());

        journal
            .journal
            .enrolled_qualification()
            .unwrap()
            .set(())
            .unwrap();
        let ticket = persist(&journal, "first-original").unwrap();
        let retained = journal.fixture_entry_bytes(ticket.id());
        let custody = journal.journal.custody_binding.clone();
        drop(journal);

        let reopen = || Journal::open_bound(&root, Duration::ZERO, Duration::ZERO, custody.clone());
        let restarted = WorkingJournal::from_scoped(Arc::new(reopen().unwrap()), scope).unwrap();
        let refused = persist(&restarted, "second-original").err().unwrap();
        assert!(refused
            .to_string()
            .contains("continuity has not been verified"));
        assert_eq!(restarted.fixture_entry_bytes(ticket.id()), retained);
        let (high_water, observed, _) = restarted
            .journal
            .enrolled_original_sequences(&install)
            .unwrap();
        assert_eq!(high_water, 1);
        assert_eq!(observed.keys().copied().collect::<Vec<_>>(), vec![1]);
        drop(restarted);

        let mut counter: Value = serde_json::from_slice(&fs::read(&counter_path).unwrap()).unwrap();
        counter["high_water"] = json!(0);
        crate::node::oauth::atomic_private_write(
            &counter_path,
            &serde_json::to_vec(&counter).unwrap(),
        )
        .unwrap();
        let restored = reopen().err().unwrap();
        assert!(restored
            .to_string()
            .contains("sequence counter was restored"));
    }

    #[tokio::test]
    async fn working_resolution_strict_predecessor_barrier_retains_original_and_blocks_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let scope = binding();
        let journal = WorkingJournal::fixture_installed(root.path(), scope).unwrap();
        let ticket = journal
            .persist_captured(
                "actor".into(),
                &proposal("resolution-key"),
                FirstPartyIdentity::FirstParty,
                "4eb0ca37e1d1caa6d8981b65f4f7ed5f26ab6f929c9de0d2304d57635798cc3a".into(),
                Default::default(),
                None,
            )
            .unwrap();
        let before = journal.fixture_entry_bytes(ticket.id());
        let before_revision = journal
            .capture()
            .await
            .unwrap()
            .view()
            .revision()
            .to_owned();
        let original = journal.fixture_resolution_requested(ticket.id()).await;
        let after = journal.fixture_entry_bytes(ticket.id());
        let old: Value = serde_json::from_slice(&before).unwrap();
        let value: Value = serde_json::from_slice(&after).unwrap();
        for field in [
            "version",
            "arguments",
            "working_original",
            "idempotency_key",
            "answer",
            "reply",
            "maybe_applied",
            "in_flight",
        ] {
            assert_eq!(old.get(field), value.get(field));
        }
        assert_eq!(value["compatibility_block"], "original_resolution");
        assert_eq!(
            value["working_resolution"]["expected_binding_sha256"],
            original.expected_binding_sha256
        );
        assert_ne!(
            journal.capture().await.unwrap().view().revision(),
            before_revision
        );
        assert!(journal.journal.begin_queue_send(ticket.id()).is_err());
        assert!(journal
            .journal
            .update(ticket.id(), |entry| entry.compatibility_block = None)
            .is_err());
        assert!(journal
            .journal
            .update(ticket.id(), |entry| entry.working_resolution = None)
            .is_err());
        assert!(journal
            .journal
            .operator_decision(
                ticket.id(),
                None,
                "not a canonical decision",
                crate::node::owner_uid(),
                None
            )
            .is_err());
        assert_eq!(journal.fixture_entry_bytes(ticket.id()), after);
        // Exact predecessor enum (c9) rejects this new variant. Exercise that
        // decoder through the real preserved-file/queue-loader seam; no old
        // executable run is claimed.
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum BeforeResolution {
            Incompatible,
            EvidenceMissing,
            LegacyDigestDrift,
        }
        fn predecessor(path: &Path) -> Result<Entry> {
            let bytes = fs::read(path)?;
            let raw: Value = serde_json::from_slice(&bytes)?;
            if let Some(block) = raw.get("compatibility_block").filter(|v| !v.is_null()) {
                let _: BeforeResolution = serde_json::from_value(block.clone())?;
            }
            read_entry(path)
        }
        let directory = journal.root.clone();
        let binding = journal.journal.custody_binding.clone();
        let path = journal.journal.path(ticket.id());
        drop(journal);
        let older = Journal::open_bound_with_reader(
            &directory,
            Duration::ZERO,
            Duration::ZERO,
            binding.clone(),
            predecessor,
        )
        .unwrap();
        assert_eq!(older.status()["unreadable_files"], 1);
        assert!(older.next_pending(false).is_none());
        assert!(older.has_opaque_custody());
        older.prune();
        assert_eq!(fs::read(&path).unwrap(), after);
        drop(older);
        let current =
            Journal::open_bound(&directory, Duration::ZERO, Duration::ZERO, binding.clone())
                .unwrap();
        assert!(current
            .get(ticket.id())
            .unwrap()
            .working_resolution
            .is_some());
        drop(current);
        let mut foreign = value;
        foreign["kernel_v2_custody"]["binding"]["account_id"] = json!("different-account");
        let foreign = serde_json::to_vec(&foreign).unwrap();
        fs::write(&path, &foreign).unwrap();
        let invalid =
            Journal::open_bound(&directory, Duration::ZERO, Duration::ZERO, binding).unwrap();
        assert!(invalid.get(ticket.id()).is_none());
        invalid.prune();
        assert_eq!(fs::read(path).unwrap(), foreign);
    }

    #[tokio::test]
    async fn working_v9_record_projection_restart_keys_and_older_readers_preserve_originals() {
        use crate::mcp::kernel_v2::writes::replay::{ProposalIdentity, ReplayProposal};
        let root = tempfile::tempdir().unwrap();
        let scope = binding();
        let journal = WorkingJournal::fixture_installed(root.path(), scope.clone()).unwrap();
        let wire = json!({"source_id":"11111111-1111-4111-8111-111111111111","target_id":"22222222-2222-4222-8222-222222222222","relationship":"references","idempotency_key":"family-native-key"});
        let contracts =
            crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap();
        let (tool, native) = contracts
            .working_native_arguments("records_write", "manage_links.add", &wire)
            .unwrap();
        assert_eq!(native["action"], "add");
        assert!(wire.get("action").is_none());
        let proposal = ReplayProposal::from_original(
            &tool,
            native.clone(),
            Some("family-native-key".into()),
            &ProposalIdentity::default(),
        )
        .unwrap();
        let identity = FirstPartyIdentity::Record(RecordIdentity {
            operation: RecordOperation::LinkAdd,
            mint_context: None,
        });
        let ticket = journal
            .persist_captured(
                "actor".into(),
                &proposal,
                identity.clone(),
                "a".repeat(64),
                Default::default(),
                Some(wire.clone()),
            )
            .unwrap();
        let path = journal.journal.path(ticket.id());
        let bytes = fs::read(&path).unwrap();
        let entry = journal.journal.get(ticket.id()).unwrap();
        assert_eq!(entry.version, INSTALLED_RECORD_VERSION);
        super::super::tests::assert_declared_entry(&entry, "production");
        assert_eq!(entry.arguments, Some(wire.clone()));
        assert_eq!(ticket.arguments(), &native);
        assert_eq!(ticket.operation(), "manage_links");
        assert_eq!(ticket.catalog_operation(), "manage_links.add");
        assert_eq!(
            entry.record_ids,
            vec!["22222222-2222-4222-8222-222222222222"]
        );
        assert!(journal
            .journal
            .update(ticket.id(), |entry| entry.version =
                INSTALLED_WORKING_VERSION)
            .is_err());
        assert!(journal
            .journal
            .operator_decision(
                ticket.id(),
                Some("not_applied"),
                "retain original",
                owner_uid(),
                None
            )
            .is_err());
        journal.journal.prune();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let (remove_tool, remove_native) = contracts
            .working_native_arguments("records_write", "manage_links.remove", &wire)
            .unwrap();
        let remove = ReplayProposal::from_original(
            &remove_tool,
            remove_native,
            Some("family-native-key".into()),
            &ProposalIdentity::default(),
        )
        .unwrap();
        assert!(journal
            .persist_captured(
                "actor".into(),
                &remove,
                FirstPartyIdentity::Record(RecordIdentity {
                    operation: RecordOperation::LinkRemove,
                    mint_context: None
                }),
                "a".repeat(64),
                Default::default(),
                Some(wire.clone())
            )
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(journal.bind_base_bytes(b"cannot adopt new base").is_err());
        let directory = journal.root.clone();
        let custody = journal.journal.custody_binding.clone();
        drop(journal);
        fn before_record(path: &Path) -> Result<Entry> {
            let value: Value = serde_json::from_slice(&fs::read(path)?)?;
            if value["version"]
                .as_u64()
                .is_some_and(|v| v >= u64::from(INSTALLED_RECORD_VERSION))
            {
                return Err(Error::engine("unsupported newer custody"));
            }
            read_entry(path)
        }
        let older = Journal::open_bound_with_reader(
            &directory,
            Duration::ZERO,
            Duration::ZERO,
            custody.clone(),
            before_record,
        )
        .unwrap();
        assert_eq!(older.status()["unreadable_files"], 1);
        assert!(older.next_pending(false).is_none());
        older.prune();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(older);
        let reopened = WorkingJournal::from_scoped(
            Arc::new(
                Journal::open_bound(&directory, Duration::ZERO, Duration::ZERO, custody.clone())
                    .unwrap(),
            ),
            scope.clone(),
        )
        .unwrap();
        assert_eq!(
            reopened.capture().await.unwrap().view().proposals()[0],
            ticket
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(reopened);
        let mut malformed: Value = serde_json::from_slice(&bytes).unwrap();
        malformed["working_original"]["native_arguments"]["action"] = json!("remove");
        let invalid = serde_json::to_vec(&malformed).unwrap();
        fs::write(&path, &invalid).unwrap();
        let raw = Journal::open_bound(&directory, Duration::ZERO, Duration::ZERO, custody).unwrap();
        assert_eq!(raw.status()["unreadable_files"], 1);
        assert!(raw.get(ticket.id()).is_none());
        raw.prune();
        assert_eq!(fs::read(path).unwrap(), invalid);
    }

    #[tokio::test]
    async fn installed_working_v8_create_original_proof_retry_and_rollback_reader_preservation() {
        let root = tempfile::tempdir().unwrap();
        let scope = binding();
        let raw = Arc::new(
            Journal::open_bound(
                root.path(),
                Duration::ZERO,
                Duration::ZERO,
                Some(CustodyBinding {
                    account_id: scope.account_id.clone(),
                    database_id: scope.database_id.clone(),
                    origin_database_id: scope.origin_database_id.clone(),
                    history_lineage: scope.history_lineage.clone(),
                    resource_origin: scope.resource_origin.clone(),
                    install_id: scope.install_id.clone(),
                }),
            )
            .unwrap(),
        );
        let shared = WorkingJournal::from_scoped(raw.clone(), scope.clone()).unwrap();
        let (id, nonce) = crate::record_id::mint(
            &crate::record_id::qualified_principal("actor"),
            "first-party",
            [47; 32],
        );
        let args = json!({"type":"Document","kind":"note","name":"Durable final note","body":"retained create content","home_id":"70110000-0000-4000-8000-000000000001","reason":"codec fixture","idempotency_key":"format8-create","id":id,"id_nonce":nonce});
        let proposal = ReplayProposal::from_original(
            "create_record",
            args.clone(),
            Some("format8-create".into()),
            &ProposalIdentity {
                app: None,
                mint_context: Some("first-party".into()),
            },
        )
        .unwrap();
        let identity = FirstPartyIdentity::FirstPartyCreate {
            context: "first-party".into(),
        };
        let private_root = tempfile::tempdir().unwrap();
        let private = WorkingJournal::open(private_root.path(), scope.clone()).unwrap();
        assert!(private
            .persist_original("actor".into(), &proposal, identity.clone(), "b".repeat(64))
            .await
            .is_err());
        assert!(
            private
                .capture()
                .await
                .unwrap()
                .view()
                .proposals()
                .is_empty(),
            "private v5 cannot acquire create custody"
        );
        let ticket = shared
            .persist_original("actor".into(), &proposal, identity.clone(), "b".repeat(64))
            .await
            .unwrap();
        super::super::tests::assert_declared_entry(&raw.get(ticket.id()).unwrap(), "production");
        let path = raw.path(ticket.id());
        let before = fs::read(&path).unwrap();
        let anchor = shared.root.join("pinned-base.json");
        assert!(!anchor.exists());
        let refusal = shared
            .bind_base_bytes(b"test-only proposed fresh base")
            .unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("missing pinned accepted-base provenance"),
            "{refusal}"
        );
        assert!(
            !anchor.exists(),
            "retained create8 must never adopt a new base"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "base refusal retains every original byte"
        );
        let create_entry = read_entry(&path).unwrap();
        assert_eq!(create_entry.version, INSTALLED_CREATE_VERSION);
        let create_request =
            crate::node::gate::WriteGate::fixture_request_for(&create_entry).unwrap();
        assert_eq!(create_request["params"]["arguments"]["format"], "json");
        assert_eq!(create_request["params"]["arguments"]["arguments"], args);
        let append_root = tempfile::tempdir().unwrap();
        let append_journal =
            WorkingJournal::fixture_installed(append_root.path(), scope.clone()).unwrap();
        let append_proposal = self::proposal("format7-wire-control");
        let append_ticket = append_journal
            .persist_original(
                "actor".into(),
                &append_proposal,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        let append_entry = read_entry(&append_journal.journal.path(append_ticket.id())).unwrap();
        assert_eq!(append_entry.version, INSTALLED_WORKING_VERSION);
        let append_request =
            crate::node::gate::WriteGate::fixture_request_for(&append_entry).unwrap();
        assert!(append_request["params"]["arguments"]
            .get("format")
            .is_none());
        assert_eq!(
            append_request["params"]["arguments"]["arguments"],
            append_entry.arguments.unwrap()
        );
        assert_eq!(ticket.operation(), "create_record");
        assert_eq!(
            shared
                .persist_original("actor".into(), &proposal, identity, "b".repeat(64))
                .await
                .unwrap(),
            ticket
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(read_before_v6(&path).is_err());
        assert!(raw
            .operator_decision(
                ticket.id(),
                Some("not_applied"),
                "cannot invent canonical refusal",
                owner_uid(),
                None
            )
            .is_err());
        assert!(raw
            .update(ticket.id(), |entry| entry.version =
                INSTALLED_WORKING_VERSION)
            .is_err());
        raw.prune();
        assert_eq!(fs::read(&path).unwrap(), before);
        let entry = read_entry(&path).unwrap();
        assert!(entry.installed_working());
        assert!(!entry.ordinary_v2());
        assert_eq!(shared.capture().await.unwrap().view().proposals().len(), 1);
    }

    #[tokio::test]
    async fn installed_working_v7_shared_original_attempt_fence_and_verdict_guard() {
        let root = tempfile::tempdir().unwrap();
        let scope = binding();
        let raw = Arc::new(
            Journal::open_bound(
                root.path(),
                Duration::ZERO,
                Duration::ZERO,
                Some(CustodyBinding {
                    account_id: scope.account_id.clone(),
                    database_id: scope.database_id.clone(),
                    origin_database_id: scope.origin_database_id.clone(),
                    history_lineage: scope.history_lineage.clone(),
                    resource_origin: scope.resource_origin.clone(),
                    install_id: scope.install_id.clone(),
                }),
            )
            .unwrap(),
        );
        let shared = WorkingJournal::from_scoped(raw.clone(), scope.clone()).unwrap();
        let original = proposal("installed-format-original");
        let ticket = shared
            .persist_original(
                "actor".into(),
                &original,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        super::super::tests::assert_declared_entry(&raw.get(ticket.id()).unwrap(), "production");
        let path = raw.path(ticket.id());
        let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["version"], INSTALLED_WORKING_VERSION);
        let revision = shared.capture().await.unwrap().view().revision().to_owned();
        raw.begin_queue_send(ticket.id()).unwrap();
        raw.update(ticket.id(), |entry| {
            entry.in_flight = false;
            entry.maybe_applied = true;
            entry.state = EntryState::Uncertain;
        })
        .unwrap();
        let after = shared.capture().await.unwrap();
        assert_eq!(after.view().revision(), revision);
        assert!(
            !after.view().requires_reconciliation(),
            "transport uncertainty is not an invented canonical verdict"
        );
        drop(after);
        let unchanged = fs::read(&path).unwrap();
        assert!(raw
            .update(ticket.id(), |entry| {
                entry.answer = Some("receipt".into());
                entry.reply = Some("fabricated".into());
                entry.state = EntryState::Confirmed;
            })
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), unchanged);
        assert!(raw
            .update(ticket.id(), |entry| entry
                .working_original
                .as_mut()
                .unwrap()
                .annotations
                .intent = Some("rewrite".into()))
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), unchanged);
        raw.prune();
        assert_eq!(
            fs::read(&path).unwrap(),
            unchanged,
            "no receipt/content retirement shortcut"
        );
        drop(shared);
        drop(raw);
        let reader = Arc::new(
            Journal::open_bound(
                root.path(),
                Duration::ZERO,
                Duration::ZERO,
                Some(CustodyBinding {
                    account_id: scope.account_id.clone(),
                    database_id: scope.database_id.clone(),
                    origin_database_id: scope.origin_database_id.clone(),
                    history_lineage: scope.history_lineage.clone(),
                    resource_origin: scope.resource_origin.clone(),
                    install_id: scope.install_id.clone(),
                }),
            )
            .unwrap(),
        );
        let recovered = WorkingJournal::from_scoped(reader.clone(), scope).unwrap();
        assert_eq!(
            recovered.capture().await.unwrap().view().proposals()[0].arguments(),
            original.args()
        );
        assert!(
            reader.oldest_pending().is_some(),
            "same-key uncertain installed originals remain replayable by the real queue"
        );
    }
    #[tokio::test]
    async fn installed_working_v7_preserves_old_working_v6_and_separates_evidence_v6() {
        let root = tempfile::tempdir().unwrap();
        let scope = binding();
        let custody = CustodyBinding {
            account_id: scope.account_id.clone(),
            database_id: scope.database_id.clone(),
            origin_database_id: scope.origin_database_id.clone(),
            history_lineage: scope.history_lineage.clone(),
            resource_origin: scope.resource_origin.clone(),
            install_id: scope.install_id.clone(),
        };
        let raw = Arc::new(
            Journal::open_bound(
                root.path(),
                Duration::ZERO,
                Duration::ZERO,
                Some(custody.clone()),
            )
            .unwrap(),
        );
        let shared = WorkingJournal::from_scoped(raw.clone(), scope.clone()).unwrap();
        let original = proposal("retired-working-format-six");
        let ticket = shared
            .persist_original(
                "actor".into(),
                &original,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        let mut old = raw.get(ticket.id()).unwrap();
        assert_eq!(old.version, INSTALLED_WORKING_VERSION);
        assert!(old.installed_working());
        assert!(!old.ordinary_v2());
        // Exact real predecessor shape: provider-created immutable original,
        // no ordinary contract evidence, and an interrupted transport attempt.
        old.version = V2_EVIDENCE_VERSION;
        old.state = EntryState::Sent;
        old.in_flight = true;
        old.maybe_applied = true;
        assert!(old.kernel_v2_custody.as_ref().unwrap().original.is_none());
        assert!(!old.is_working());
        assert!(!old.valid_v6());
        let path = raw.path(&old.id);
        let bytes = serde_json::to_vec(&old).unwrap();
        fs::write(&path, &bytes).unwrap();
        drop(shared);
        drop(raw);
        let reader = Arc::new(
            Journal::open_bound(
                root.path(),
                Duration::ZERO,
                Duration::ZERO,
                Some(custody.clone()),
            )
            .unwrap(),
        );
        assert_eq!(reader.status()["unreadable_files"], 1);
        assert!(reader.get(&old.id).is_none());
        assert!(reader.oldest_pending().is_none());
        assert!(reader.next_pending(false).is_none());
        assert!(reader.has_open_body_custody(original.args()["id"].as_str().unwrap(), false));
        for outcome in [None, Some("not_applied")] {
            assert!(reader
                .operator_decision(
                    &old.id,
                    outcome,
                    "do not reinterpret retired working custody",
                    0,
                    None
                )
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        reader.prune();
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "startup must not recover Sent, erase uncertainty or prune opaque originals"
        );
        assert!(WorkingJournal::from_scoped(reader, scope.clone()).is_err());

        // Genuine upstream format 6 stays on its own validator and queue;
        // it is neither a working ticket nor a candidate for conversion.
        let ordinary_root = tempfile::tempdir().unwrap();
        let ordinary = Arc::new(
            Journal::open_bound(
                ordinary_root.path(),
                Duration::ZERO,
                Duration::ZERO,
                Some(custody.clone()),
            )
            .unwrap(),
        );
        let contract = crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()
            .unwrap()
            .holding_contract("records_write", "update_record")
            .unwrap()
            .for_custody()
            .unwrap();
        let digest = contract.description["contract_digest"]
            .as_str()
            .unwrap()
            .to_owned();
        let entry = ordinary
            .begin_kernel_v2(
                NewEntry {
                    executor: "records_write".into(),
                    operation: "update_record".into(),
                    tool: "records_write".into(),
                    run_key: None,
                    client_info: None,
                    app_identity: None,
                    idempotency_key: original.idempotency_key().map(str::to_owned),
                    key_origin: Some(KeyOrigin::Caller),
                    arguments: original.args().clone(),
                    parent_key: None,
                    title: None,
                    record_id: original.args()["id"].as_str().map(str::to_owned),
                    record_ids: vec![],
                    envelope: Some(json!({})),
                    intent_digest: None,
                },
                digest,
                OriginalContract {
                    rule: SOURCE_DESCRIPTION_RULE,
                    contract,
                },
            )
            .unwrap();
        assert_eq!(entry.version, V2_EVIDENCE_VERSION);
        assert!(entry.valid_v6());
        assert!(entry.ordinary_v2());
        assert!(!entry.is_working());
        ordinary
            .hold(
                &entry.id,
                HoldReason::HostedUnreachable,
                "held".into(),
                false,
            )
            .unwrap();
        assert!(WorkingJournal::from_scoped(ordinary.clone(), scope).is_err());
        let ordinary_path = ordinary.path(&entry.id);
        let ordinary_bytes = fs::read(&ordinary_path).unwrap();
        drop(ordinary);
        let reopened = Journal::open_bound(
            ordinary_root.path(),
            Duration::ZERO,
            Duration::ZERO,
            Some(custody),
        )
        .unwrap();
        let loaded = reopened.get(&entry.id).unwrap();
        assert!(loaded.valid_v6());
        assert!(loaded.ordinary_v2());
        assert!(!loaded.installed_working());
        assert!(reopened.next_pending(false).is_some());
        reopened.prune();
        assert_eq!(fs::read(&ordinary_path).unwrap(), ordinary_bytes);
        assert!(
            reopened.working_terminal("actor", &original).is_err(),
            "pending ordinary key cannot become a second working original"
        );
        reopened
            .settle(&entry.id, EntryState::Confirmed, Some("receipt"), None)
            .unwrap();
        let receipt_bytes = fs::read(&ordinary_path).unwrap();
        assert!(
            reopened.working_terminal("actor", &original).is_err(),
            "retired ordinary content cannot establish a different original by key alone"
        );
        let retained = Arc::new(reopened);
        let terminal_history = WorkingJournal::from_scoped(retained.clone(), binding()).unwrap();
        assert!(terminal_history
            .persist_original(
                "actor".into(),
                &original,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64)
            )
            .await
            .is_err());
        assert_eq!(fs::read(&ordinary_path).unwrap(), receipt_bytes);
        assert_eq!(
            retained.entries.lock().unwrap().len(),
            1,
            "insertion preserves ordinary key ownership after an earlier admission check"
        );
        let fresh = proposal("fresh-after-ordinary-receipt");
        let admitted = terminal_history
            .persist_original(
                "actor".into(),
                &fresh,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        assert_eq!(
            retained.get(admitted.id()).unwrap().version,
            INSTALLED_WORKING_VERSION
        );
        assert_eq!(
            fs::read(&ordinary_path).unwrap(),
            receipt_bytes,
            "ordinary terminal evidence is not converted or rewritten"
        );
    }

    #[tokio::test]
    async fn working_manager_journal_fsync_ticket_restart_retention_and_immutability() {
        let root = tempfile::tempdir().unwrap();
        let journal = WorkingJournal::open(root.path(), binding()).unwrap();
        assert!(
            WorkingJournal::open(root.path(), binding()).is_err(),
            "one durable authority owner"
        );
        journal
            .journal
            .fail_after
            .store(0, std::sync::atomic::Ordering::SeqCst);
        assert!(journal
            .persist_original(
                "actor".into(),
                &proposal("failed"),
                FirstPartyIdentity::FirstParty,
                "b".repeat(64)
            )
            .await
            .is_err());
        assert!(journal.capture().await.unwrap().view.proposals.is_empty());
        let original = proposal("durable");
        let ticket = journal
            .persist_original(
                "actor".into(),
                &original,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        let repeated = journal
            .persist_original(
                "actor".into(),
                &original,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        super::super::tests::assert_declared_entry(
            &journal.journal.get(ticket.id()).unwrap(),
            "production",
        );
        assert_eq!(ticket.id(), repeated.id());
        let mut changed_args = original.args().clone();
        changed_args["body_append"] = json!("changed bytes");
        let different = ReplayProposal::from_original(
            "update_record",
            changed_args,
            original.idempotency_key().map(str::to_owned),
            &ProposalIdentity::default(),
        )
        .unwrap();
        let conflict = journal
            .persist_original(
                "actor".into(),
                &different,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap_err();
        assert!(conflict
            .to_string()
            .contains("reserved for different original bytes"));
        let saved = fs::read(journal.journal.path(ticket.id())).unwrap();
        for change in [0, 1, 2, 3] {
            assert!(journal
                .journal
                .update(ticket.id(), |entry| match change {
                    0 => entry.version = 3,
                    1 => entry.arguments = None,
                    2 => entry.working_original = None,
                    _ =>
                        entry.working_original.as_mut().unwrap().annotations.intent =
                            Some("rewritten decoration".into()),
                })
                .is_err());
            assert_eq!(fs::read(journal.journal.path(ticket.id())).unwrap(), saved);
        }
        // Even a hosted terminal outcome must keep payload until a separate
        // accepted-materialization authority permits future retirement.
        journal
            .journal
            .update(ticket.id(), |entry| {
                entry.answer = Some("refused".into());
                entry.state = EntryState::Confirmed;
                entry.received_unix_ms = 0;
            })
            .unwrap();
        journal.journal.prune();
        assert!(journal.journal.path(ticket.id()).exists());
        drop(journal);
        let recovered = WorkingJournal::open(root.path(), binding()).unwrap();
        let fence = recovered.capture().await.unwrap();
        assert!(fence.view.has_hosted_verdict);
        assert_eq!(fence.view.proposals.len(), 1);
        assert_eq!(fence.view.proposals[0].arguments(), original.args());
        assert_eq!(
            fence.view.proposals[0].fingerprint(),
            original.request_fingerprint()
        );
        drop(recovered);
        assert!(
            WorkingJournal::open(root.path(), binding()).is_err(),
            "retained fence owns directory authority after outer handle drop"
        );
        drop(fence);
        let mut wrong = binding();
        wrong.history_lineage = "replacement".into();
        assert!(WorkingJournal::open(root.path(), wrong).is_err());
    }
    #[tokio::test]
    async fn working_manager_journal_carried_identity_refusal_preserves_original() {
        let root = tempfile::tempdir().unwrap();
        let journal = WorkingJournal::open(root.path(), binding()).unwrap();
        let original = proposal("identity-original");
        let ticket = journal
            .persist_original(
                "actor".into(),
                &original,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        let saved = fs::read(journal.journal.path(ticket.id())).unwrap();
        let revision = journal.capture().await.unwrap().view.revision.clone();
        for identity in [
            ProposalIdentity {
                app: Some(json!({"app_id":"carried-app"})),
                mint_context: None,
            },
            ProposalIdentity {
                app: None,
                mint_context: Some("carried-context".into()),
            },
        ] {
            for key in ["identity-original", "unreserved-key"] {
                let mut args = original.args().clone();
                args["idempotency_key"] = json!(key);
                let carried = ReplayProposal::from_original(
                    "update_record",
                    args,
                    Some(key.into()),
                    &identity,
                )
                .unwrap();
                let error = journal
                    .persist_original(
                        "actor".into(),
                        &carried,
                        FirstPartyIdentity::FirstParty,
                        "b".repeat(64),
                    )
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("first-party identity only"));
                assert_eq!(fs::read(journal.journal.path(ticket.id())).unwrap(), saved);
                let fence = journal.capture().await.unwrap();
                assert_eq!(fence.view.revision, revision);
                assert_eq!(fence.view.proposals.len(), 1);
                assert_eq!(fence.view.proposals[0].arguments(), original.args());
            }
        }
        let null = ReplayProposal::from_original(
            "update_record",
            original.args().clone(),
            original.idempotency_key().map(str::to_owned),
            &ProposalIdentity {
                app: Some(Value::Null),
                mint_context: None,
            },
        )
        .unwrap();
        assert_eq!(null.request_fingerprint(), original.request_fingerprint());
        let repeated = journal
            .persist_original(
                "actor".into(),
                &null,
                FirstPartyIdentity::FirstParty,
                "b".repeat(64),
            )
            .await
            .unwrap();
        assert_eq!(repeated.id(), ticket.id());
        assert_eq!(fs::read(journal.journal.path(ticket.id())).unwrap(), saved);
    }
    #[tokio::test]
    async fn working_manager_journal_provider_fingerprint_tamper_is_preserved_and_refused() {
        let original = proposal("fingerprint-original");
        let mut changed_args = original.args().clone();
        changed_args["body_append"] = json!("different fingerprint payload");
        let changed = ReplayProposal::from_original(
            "update_record",
            changed_args,
            original.idempotency_key().map(str::to_owned),
            &ProposalIdentity::default(),
        )
        .unwrap();
        for bad_fingerprint in [changed.request_fingerprint().to_owned(), "a".repeat(64)] {
            let root = tempfile::tempdir().unwrap();
            let journal = WorkingJournal::open(root.path(), binding()).unwrap();
            let ticket = journal
                .persist_original(
                    "actor".into(),
                    &original,
                    FirstPartyIdentity::FirstParty,
                    "b".repeat(64),
                )
                .await
                .unwrap();
            drop(journal);
            let recovered = WorkingJournal::open(root.path(), binding()).unwrap();
            {
                let fence = recovered.capture().await.unwrap();
                assert_eq!(fence.view.proposals.len(), 1);
                assert_eq!(
                    fence.view.proposals[0].fingerprint(),
                    original.request_fingerprint()
                );
            }
            let path = recovered.journal.path(ticket.id());
            let mut tampered: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            tampered["working_original"]["request_fingerprint"] = json!(bad_fingerprint);
            let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
            fs::write(&path, &tampered_bytes).unwrap();
            drop(recovered);
            assert!(WorkingJournal::open(root.path(), binding()).is_err());
            assert_eq!(
                fs::read(&path).unwrap(),
                tampered_bytes,
                "incoherent authority is preserved, never repaired or removed"
            );
            assert_eq!(tampered["arguments"], *original.args());
        }
    }
}
