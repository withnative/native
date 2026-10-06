//! Gated public rule admission/disable/call/inspect host (task 81c1d95, S2a).
//!
//! The only public path to rule snapshots: admission derives SQL read-sets
//! and output labels on the host, validates through the trusted engine seam
//! off the writer transaction, and appends sealed snapshots. Requests carry
//! scope, immutable revision, opaque settings, and ExpectedSeq only — never
//! read-sets, evidence, receipts, or engine-build pins. No evaluator, no SQL
//! execution, no hosted/v1 schema. K6a impact inspection stays with the
//! existing dependency APIs (S2b).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::authorization::Capability;
use crate::error::Error;

// Full authoring model usable without receipt construction:
// `RuleAdmissionReceipt::issue` stays `pub(crate)`, and no request accepts
// evidence or a receipt — the missing surface is the boundary.
use crate::query::rule_install as ri;
pub use crate::query::rule_install::{
    DefinitionPin, EngineValidationEvidence, ParameterDecl, ParameterSource, RuleCardinality,
    RuleExample, RuleInputDecl, RuleRevision, RuleValidationError, RuleValidationRequest,
    RuleValidator,
};
pub use crate::query::rule_shape::{
    BindingContractVersion, CompletionFact, RequiredWhen, RuleInputContract, ScalarArgument,
    ScalarField, ScalarSource, ScalarType,
};

const TARGET_HIDDEN: &str = crate::dependency::TARGET_HIDDEN;

/// Admission request: scope, immutable revision, opaque engine settings, and
/// the seq precondition. Unknown fields refuse at deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleAdmissionRequest {
    pub scope_home: String,
    pub revision: RuleRevision,
    pub settings: serde_json::Value,
    pub expected_seq: Option<i64>,
}

/// One input's pinned dependencies for inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationInputView {
    pub name: String,
    pub relations: Vec<String>,
    pub parameter_slots: Vec<usize>,
}

/// Verified installation metadata for inspection: active or disabled, even
/// when currently incompatible. Carries the stored immutable revision and
/// opaque settings so a Manage author can correct/re-enable without keeping
/// an external copy (registry only reads them; receipt construction stays
/// private), plus full read-sets, catalog/profile pins, definition pins, and
/// last-verified engine metadata for upgrade-impact inspection. Actor follows
/// the kernel history rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationView {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub revision: RuleRevision,
    pub settings: serde_json::Value,
    pub revision_digest: String,
    pub settings_digest: String,
    pub readset_digest: String,
    pub language: String,
    pub active: bool,
    pub event_seq: i64,
    pub actor: Option<String>,
    pub inputs: Vec<InstallationInputView>,
    pub readsets: BTreeMap<String, native_query_contract::rule_contract::RuleInputReadset>,
    pub catalog_revision: u32,
    pub profile_id: String,
    pub profile_revision: u32,
    pub definition_pins: Vec<DefinitionPin>,
    pub policy_version: String,
    pub engine_id: String,
    pub engine_version: String,
    pub bundle_sha256: Option<String>,
}

/// Inert pre-invocation recipe: what a future evaluator needs, without SQL
/// execution or clause evaluation. Carries read-only last-verified metadata
/// (policy, engine id/version/bundle) from the stored receipt so the engine
/// can decide lazy revalidation; the registry never compares builds or
/// policies. The gate MUST run at actual invocation; this recipe is never
/// trusted invocation input on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInvocationRecipe {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub revision: RuleRevision,
    pub settings: serde_json::Value,
    pub input_order: Vec<String>,
    pub revision_digest: String,
    pub settings_digest: String,
    pub readset_digest: String,
    pub language: String,
    pub policy_version: String,
    pub engine_id: String,
    pub engine_version: String,
    pub bundle_sha256: Option<String>,
    pub catalog_revision: u32,
    pub profile_id: String,
    pub profile_revision: u32,
    pub event_seq: i64,
}

/// Public error: the typed engine validation failure is preserved (only
/// `EngineUnavailable` retries); host refusals keep the typed host error —
/// including `Conflict` for ExpectedSeq mismatches — so no string matching
/// is needed to recover codes. Validator panic maps to nonretryable engine
/// fault; cancelled scheduling is unavailable. Neither appends anything.
#[derive(Debug)]
pub enum RuleRegistryError {
    Validation(RuleValidationError),
    Refused(Error),
}

impl RuleRegistryError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Validation(inner) => inner.is_retryable(),
            Self::Refused(_) => false,
        }
    }
}

impl std::fmt::Display for RuleRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(inner) => write!(f, "rule validation failed: {inner:?}"),
            Self::Refused(inner) => write!(f, "rule registry refused: {inner}"),
        }
    }
}

impl std::error::Error for RuleRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // RuleValidationError carries codes, not an Error impl.
            Self::Validation(_) => None,
            Self::Refused(inner) => Some(inner),
        }
    }
}

impl From<RuleValidationError> for RuleRegistryError {
    fn from(inner: RuleValidationError) -> Self {
        Self::Validation(inner)
    }
}

impl From<RuleRegistryError> for Error {
    fn from(err: RuleRegistryError) -> Self {
        match err {
            RuleRegistryError::Validation(inner) => {
                Error::engine(format!("rule validation failed: {inner:?}"))
            }
            RuleRegistryError::Refused(inner) => inner,
        }
    }
}

/// Host errors keep their type (notably `Conflict` for ExpectedSeq): `?`
/// converts without re-wrapping everything as `Engine`.
impl From<Error> for RuleRegistryError {
    fn from(inner: Error) -> Self {
        Self::Refused(inner)
    }
}

impl From<sqlx::Error> for RuleRegistryError {
    fn from(inner: sqlx::Error) -> Self {
        Self::Refused(Error::from(inner))
    }
}

impl From<native_query_contract::QueryError> for RuleRegistryError {
    fn from(inner: native_query_contract::QueryError) -> Self {
        Self::Refused(Error::from(inner))
    }
}

fn refused(detail: impl Into<String>) -> RuleRegistryError {
    RuleRegistryError::Refused(Error::engine(detail))
}

fn conflict(detail: impl Into<String>) -> RuleRegistryError {
    RuleRegistryError::Refused(Error::conflict(detail))
}

/// First read-only authority/presence proof, before any SQL or engine
/// diagnostics: uniform missing/hidden target for a bad scope, unknown
/// principal, or missing capability.
async fn prove_manage(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    scope_home: &str,
) -> std::result::Result<(), RuleRegistryError> {
    use crate::dependency::{principal_exists, scope_exists};
    if !scope_exists(conn, scope_home).await? {
        return Err(refused(TARGET_HIDDEN));
    }
    if !principal_exists(conn, actor).await? {
        return Err(refused(TARGET_HIDDEN));
    }
    let allows = crate::kernel::kernel_effective_capability_on(conn, actor, scope_home)
        .await
        .map(|c| c.allows(Capability::Manage))
        .unwrap_or(false);
    if !allows {
        return Err(refused(TARGET_HIDDEN));
    }
    Ok(())
}

async fn prove_view(
    conn: &mut sqlx::SqliteConnection,
    viewer: &str,
    scope_home: &str,
) -> std::result::Result<(), RuleRegistryError> {
    use crate::dependency::{principal_exists, scope_exists};
    if !scope_exists(conn, scope_home).await? {
        return Err(refused(TARGET_HIDDEN));
    }
    if !principal_exists(conn, viewer).await? {
        return Err(refused(TARGET_HIDDEN));
    }
    let allows = crate::kernel::kernel_effective_capability_on(conn, viewer, scope_home)
        .await
        .map(|c| c.allows(Capability::View))
        .unwrap_or(false);
    if !allows {
        return Err(refused(TARGET_HIDDEN));
    }
    Ok(())
}

/// Host-derived per-input evidence: read-sets plus output labels, keyed by
/// input name in declaration order.
type DerivedInputs = (
    BTreeMap<String, native_query_contract::rule_contract::RuleInputReadset>,
    BTreeMap<String, Vec<String>>,
);

/// Host derivation: read-sets solely from the authoritative extractor,
/// output labels solely from the validated prepare path. Unique labels are
/// enforced here (the prepare helper returns duplicates as-is) before any
/// required-field or DAG check runs.
fn derive_inputs(revision: &RuleRevision) -> std::result::Result<DerivedInputs, RuleRegistryError> {
    let mut readsets = BTreeMap::new();
    let mut labels = BTreeMap::new();
    for input in &revision.inputs {
        let readset = crate::query::sql::extract_rule_input_dependencies(&input.sql)
            .map_err(|e| refused(format!("rule input '{}' is inadmissible: {e}", input.name)))?;
        let columns = crate::query::sql::validated_output_columns(&input.sql).map_err(|e| {
            refused(format!(
                "rule input '{}' labels unreadable: {e}",
                input.name
            ))
        })?;
        let unique: BTreeSet<&str> = columns.iter().map(String::as_str).collect();
        if unique.len() != columns.len() {
            return Err(refused(format!(
                "rule input '{}' output labels must be unique",
                input.name
            )));
        }
        readsets.insert(input.name.clone(), readset);
        labels.insert(input.name.clone(), columns);
    }
    Ok((readsets, labels))
}

/// Run the trusted validator off the Tokio runtime and before any writer
/// transaction. The blocking closure owns immutable revision/settings/digest
/// copies plus the `Arc` adapter; the borrowed request is rebuilt inside.
async fn validate_off_runtime(
    validator: &Arc<dyn RuleValidator>,
    revision: RuleRevision,
    settings: serde_json::Value,
    revision_digest: String,
    settings_digest: String,
) -> std::result::Result<EngineValidationEvidence, RuleRegistryError> {
    let validator = Arc::clone(validator);
    let outcome = tokio::task::spawn_blocking(move || {
        let request = RuleValidationRequest {
            revision: &revision,
            settings: &settings,
            revision_digest: &revision_digest,
            settings_digest: &settings_digest,
        };
        validator.validate(request)
    })
    .await
    .map_err(|error| {
        RuleRegistryError::Validation(if error.is_panic() {
            RuleValidationError::EngineFault {
                message: "rule validator panicked; report this engine defect".to_owned(),
            }
        } else {
            RuleValidationError::EngineUnavailable {
                message: "rule validator worker is unavailable".to_owned(),
            }
        })
    })?;
    outcome.map_err(RuleRegistryError::Validation)
}

/// Register (or replace, or re-enable) one installation: full admission.
/// Shape, digests, host derivation, DAG/order, eligibility, engine
/// validation, then — inside one writer transaction — authority, ExpectedSeq,
/// current catalog/eligibility, effective definition pins, and digest
/// rechecks before the receipt is minted and appended. Refusals roll back
/// with nothing appended. Authoring defects need a corrected revision or
/// settings, never a retry of the same bytes.
pub async fn register_rule(
    db: &crate::db::Db,
    actor_principal_id: &str,
    validator: &Arc<dyn RuleValidator>,
    request: &RuleAdmissionRequest,
) -> std::result::Result<InstallationView, RuleRegistryError> {
    use crate::meta::rule_installation as inst;
    // Code-owned admission catalog/profile captured BEFORE extraction: the
    // writer rechecks the derived read-sets against a fresh live catalog with
    // an explicit equality seam (no TOCTOU relabeling).
    let admission = crate::query::sql::current_catalog_snapshot();
    // Read-only authority first, on the read pool: no SQL or engine
    // diagnostics leak past it, and hot admission never serializes on the
    // sole writer pool.
    {
        let mut read = db.pool().begin().await?;
        prove_manage(&mut read, actor_principal_id, &request.scope_home).await?;
        read.rollback().await?;
    }
    ri::validate_revision_shape(&request.revision)?;
    let revision_digest = ri::revision_digest(&request.revision)?;
    let settings_digest = ri::settings_digest(&request.settings)?;
    let (readsets, labels) = derive_inputs(&request.revision)?;
    let order = ri::validate_parameter_dag(&request.revision, &readsets, &labels)?;
    // Pure rule-side eligibility before engine work (best-effort/transient
    // refusal even if ever admitted).
    {
        let snapshot = crate::query::sql::current_catalog_snapshot();
        for readset in readsets.values() {
            for pinned in &readset.relations {
                let live =
                    native_query_contract::rule_contract::find_relation(&snapshot, &pinned.name)
                        .ok_or_else(|| {
                            refused(format!(
                                "rule input observes unaudited relation '{}'",
                                pinned.name
                            ))
                        })?;
                native_query_contract::rule_contract::check_rule_eligibility(live)?;
            }
        }
    }
    let evidence = validate_off_runtime(
        validator,
        request.revision.clone(),
        request.settings.clone(),
        revision_digest.clone(),
        settings_digest.clone(),
    )
    .await?;
    ri::evidence_binds_request(
        &evidence,
        &request.revision,
        &revision_digest,
        &settings_digest,
    )?;
    ri::validate_evidence_shape(&evidence)?;
    ri::ensure_non_fixture_evidence(&evidence)?;
    // Writer transaction: every precondition rechecked, no SQL preparation
    // and no validator inside.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let stored = async {
        prove_manage(&mut tx, actor_principal_id, &request.scope_home).await?;
        // Fresh live catalog with an explicit equality seam against the
        // pre-extraction admission snapshot: a concurrent catalog move refuses
        // instead of relabeling earlier read-sets with new pins.
        let live = crate::query::sql::current_catalog_snapshot();
        native_query_contract::rule_contract::check_catalog_pin(
            &live,
            admission.revision,
            &admission.profile_id,
            admission.profile_revision,
        )?;
        // Recompute revision/settings digests and re-confirm the evidence
        // bindings in-transaction before anything is minted or appended.
        let revision_digest = ri::revision_digest(&request.revision)?;
        let settings_digest = ri::settings_digest(&request.settings)?;
        ri::evidence_binds_request(
            &evidence,
            &request.revision,
            &revision_digest,
            &settings_digest,
        )?;
        ri::ensure_non_fixture_evidence(&evidence)?;
        // ExpectedSeq projection integrity read before the receipt is minted
        // (the sealed setter enforces the precondition again at append).
        let current = inst::read_installation_in(
            &mut tx,
            &request.scope_home,
            &request.revision.namespace,
            &request.revision.name,
        )
        .await?;
        match (&current, request.expected_seq) {
            (None, None) => {}
            (None, Some(_)) | (Some(_), None) => {
                return Err(conflict(
                    "stale rule admission: ExpectedSeq must match the current snapshot",
                ));
            }
            (Some(stored), Some(expected)) if expected != stored.event_seq => {
                return Err(conflict(
                    "stale rule admission: the snapshot moved under this writer",
                ));
            }
            (Some(_), Some(_)) => {}
        }
        let snapshot = live;
        for readset in readsets.values() {
            for pinned in &readset.relations {
                native_query_contract::rule_contract::check_relation_pin(&snapshot, pinned)?;
                let live =
                    native_query_contract::rule_contract::find_relation(&snapshot, &pinned.name)
                        .ok_or_else(|| refused("rule input relation vanished mid-admission"))?;
                native_query_contract::rule_contract::check_rule_eligibility(live)?;
            }
        }
        // Exact effective definition pins at this scope for every declared pin.
        for pin in &request.revision.definition_pins {
            match crate::kernel::resolve_effective_adoption_verified(
                &mut tx,
                &pin.family,
                &request.scope_home,
            )
            .await?
            {
                Some(crate::kernel::ScopedAdoption::Adopted(effective))
                    if effective.version == pin.version && effective.digest == pin.digest => {}
                _ => {
                    return Err(refused(format!(
                        "rule definition pin '{}' is not effectively adopted at this scope",
                        pin.family
                    )));
                }
            }
        }
        // Receipt minted only after every recheck above: evidence already
        // bound to the host digests/language, fixture refused.
        let receipt = {
            let pairs: Vec<(
                &str,
                &native_query_contract::rule_contract::RuleInputReadset,
            )> = readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
            let digest = ri::readset_digest(
                snapshot.revision,
                &snapshot.profile_id,
                snapshot.profile_revision,
                &pairs,
            );
            ri::RuleAdmissionReceipt::issue(evidence.clone(), digest)
        };
        let _ = order;
        let (stored, _) = inst::set_installation_in(
            &mut tx,
            &request.scope_home,
            &request.revision,
            &request.settings,
            snapshot.revision,
            &snapshot.profile_id,
            snapshot.profile_revision,
            &readsets,
            &receipt,
            true,
            request.expected_seq,
            Some(actor_principal_id),
            &mut crate::act::ActAllocation::new(),
        )
        .await?;
        // Redacted public view built inside the SAME writer tx before commit
        // (register_consumer_at precedent): no fallible step runs after the
        // append, so refusals truly append nothing, with no extra pool hop.
        // Re-enable is this same fresh admission against today's catalog —
        // stale stored pins never block it; only prior integrity plus seq do.
        let actor =
            crate::dependency::disclose_actor(&mut tx, actor_principal_id, &stored.actor).await?;
        Ok(to_view(&stored, actor))
    }
    .await;
    match stored {
        Ok(view) => {
            tx.commit().await?;
            Ok(view)
        }
        Err(err) => {
            tx.rollback().await?;
            Err(err)
        }
    }
}

fn to_view(
    stored: &crate::meta::rule_installation::StoredInstallation,
    actor: Option<String>,
) -> InstallationView {
    InstallationView {
        scope_home: stored.scope_home.clone(),
        namespace: stored.namespace.clone(),
        name: stored.name.clone(),
        revision: stored.revision.clone(),
        settings: stored.settings.clone(),
        revision_digest: stored.revision_digest.clone(),
        settings_digest: stored.settings_digest.clone(),
        readset_digest: stored.readset_digest.clone(),
        language: stored.revision.language.clone(),
        active: stored.active,
        event_seq: stored.event_seq,
        actor,
        inputs: stored
            .readsets
            .iter()
            .map(|(name, readset)| InstallationInputView {
                name: name.clone(),
                relations: readset.relations.iter().map(|r| r.name.clone()).collect(),
                parameter_slots: readset.parameter_slots.clone(),
            })
            .collect(),
        readsets: stored.readsets.clone(),
        catalog_revision: stored.catalog_revision,
        profile_id: stored.profile_id.clone(),
        profile_revision: stored.profile_revision,
        definition_pins: stored.revision.definition_pins.clone(),
        policy_version: stored.receipt.policy_version.clone(),
        engine_id: stored.receipt.engine_id.clone(),
        engine_version: stored.receipt.engine_version.clone(),
        bundle_sha256: stored.receipt.bundle_sha256.clone(),
    }
}

/// Disable one installation: scope/namespace/name/seq only. Manage plus
/// seq/integrity rechecked; the current revision, settings, read-sets,
/// receipt, and pins are preserved and only `active` flips — no current
/// catalog check and no engine validation, so an incompatible installation
/// always remains removable. No public bare re-enable flip: re-enable is
/// admission through [`register_rule`].
pub async fn disable_rule(
    db: &crate::db::Db,
    actor_principal_id: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
    expected_seq: Option<i64>,
) -> std::result::Result<InstallationView, RuleRegistryError> {
    use crate::meta::rule_installation as inst;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let view = async {
        prove_manage(&mut tx, actor_principal_id, scope_home).await?;
        let current = inst::read_installation_in(&mut tx, scope_home, namespace, name)
            .await?
            .ok_or_else(|| refused(TARGET_HIDDEN))?;
        let Some(expected) = expected_seq else {
            return Err(conflict(
                "stale rule disable: disables must name the current event seq",
            ));
        };
        if expected != current.event_seq {
            return Err(conflict(
                "stale rule disable: the snapshot moved under this writer",
            ));
        }
        let mut alloc = crate::act::ActAllocation::new();
        let (stored, _) = inst::set_installation_in(
            &mut tx,
            scope_home,
            &current.revision,
            &current.settings,
            current.catalog_revision,
            &current.profile_id,
            current.profile_revision,
            &current.readsets,
            &current.receipt,
            false,
            Some(current.event_seq),
            Some(actor_principal_id),
            &mut alloc,
        )
        .await?;
        let actor =
            crate::dependency::disclose_actor(&mut tx, actor_principal_id, &stored.actor).await?;
        Ok(to_view(&stored, actor))
    }
    .await;
    match view {
        Ok(view) => {
            tx.commit().await?;
            Ok(view)
        }
        Err(err) => {
            tx.rollback().await?;
            Err(err)
        }
    }
}

/// View-authorized keyed inspection: verified stored snapshot with redacted
/// actor, active or disabled, even when currently incompatible. How an author
/// inspects upgrade/retirement needs without a successful invocation. No
/// caller catalog, no catalog mutation.
pub async fn inspect_rule(
    db: &crate::db::Db,
    viewer_principal_id: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> std::result::Result<InstallationView, RuleRegistryError> {
    use crate::meta::rule_installation as inst;
    // ONE explicit read-pool snapshot for auth, read, and redaction;
    // explicit rollback after. No writer lock held.
    let mut read = db.pool().begin().await?;
    let view = async {
        prove_view(&mut read, viewer_principal_id, scope_home).await?;
        let stored = inst::read_installation_in(&mut read, scope_home, namespace, name)
            .await?
            .ok_or_else(|| refused(TARGET_HIDDEN))?;
        let actor =
            crate::dependency::disclose_actor(&mut read, viewer_principal_id, &stored.actor)
                .await?;
        Ok(to_view(&stored, actor))
    }
    .await;
    read.rollback().await?;
    view
}

/// Read-only pre-invocation gate: authority View/presence first (uniform
/// hidden/missing), then the verified latest installation, active status,
/// strict receipt guard, language equality only against the host-configured
/// engine language (never engine build or policy equality), current
/// global/profile/relation/column compatibility plus rule eligibility, and
/// the exact effective v2 pins through the existing verified resolver.
/// Returns the inert recipe — revision, settings, re-derived input order,
/// digests, and validation metadata — with no SQL execution, no clause
/// evaluation, and no durable capability. The order derives solely from the
/// pure immutable graph (no SQL preparation of any kind).
pub async fn prepare_rule_call(
    db: &crate::db::Db,
    caller_principal_id: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
    engine_language: &str,
) -> std::result::Result<RuleInvocationRecipe, RuleRegistryError> {
    use crate::meta::rule_installation as inst;
    let mut read = db.pool().begin().await?;
    let recipe = async {
        prove_view(&mut read, caller_principal_id, scope_home).await?;
        let stored = inst::read_installation_in(&mut read, scope_home, namespace, name)
            .await?
            .ok_or_else(|| refused(TARGET_HIDDEN))?;
        if !stored.active {
            return Err(refused("rule installation is not active"));
        }
        ri::verify_receipt_usable(&stored.receipt)?;
        if stored.revision.language != engine_language {
            return Err(refused(format!(
                "rule language '{}' does not match the configured engine language",
                stored.revision.language
            )));
        }
        let snapshot = crate::query::sql::current_catalog_snapshot();
        native_query_contract::rule_contract::check_catalog_pin(
            &snapshot,
            stored.catalog_revision,
            &stored.profile_id,
            stored.profile_revision,
        )?;
        for readset in stored.readsets.values() {
            for pinned in &readset.relations {
                native_query_contract::rule_contract::check_relation_pin(&snapshot, pinned)?;
                let live =
                    native_query_contract::rule_contract::find_relation(&snapshot, &pinned.name)
                        .ok_or_else(|| refused("rule input relation vanished mid-call"))?;
                native_query_contract::rule_contract::check_rule_eligibility(live)?;
            }
        }
        for pin in &stored.revision.definition_pins {
            match crate::kernel::resolve_effective_adoption_verified(
                &mut read,
                &pin.family,
                scope_home,
            )
            .await?
            {
                Some(crate::kernel::ScopedAdoption::Adopted(effective))
                    if effective.version == pin.version && effective.digest == pin.digest => {}
                _ => {
                    return Err(refused(format!(
                        "rule definition pin '{}' is not effectively adopted at this scope",
                        pin.family
                    )));
                }
            }
        }
        // Order re-derived from the immutable verified graph alone — no SQL
        // preparation, no labels, no historical compilation at call time.
        let order = ri::derive_input_order(&stored.revision)?;
        Ok(RuleInvocationRecipe {
            scope_home: stored.scope_home.clone(),
            namespace: stored.namespace.clone(),
            name: stored.name.clone(),
            revision: stored.revision.clone(),
            settings: stored.settings.clone(),
            input_order: order,
            revision_digest: stored.revision_digest.clone(),
            settings_digest: stored.settings_digest.clone(),
            readset_digest: stored.readset_digest.clone(),
            language: stored.revision.language.clone(),
            policy_version: stored.receipt.policy_version.clone(),
            engine_id: stored.receipt.engine_id.clone(),
            engine_version: stored.receipt.engine_version.clone(),
            bundle_sha256: stored.receipt.bundle_sha256.clone(),
            catalog_revision: stored.catalog_revision,
            profile_id: stored.profile_id.clone(),
            profile_revision: stored.profile_revision,
            event_seq: stored.event_seq,
        })
    }
    .await;
    read.rollback().await?;
    recipe
}
