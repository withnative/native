//! Install-scoped abandonment receipts for new authenticated node custody.
//!
//! A receipt here records that the internal abandon command committed. The
//! original write's globally keyed receipt remains under its ordinary
//! operation name. Existing readers can project both using the same format.

use super::*;

#[cfg(feature = "mcp-executor-prototype")]
pub mod custody;

const ABANDON: &str = "native.node.abandon-original.v1";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Status,
    Abandon,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: RequestAction,
    pub original: Original,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestAction {
    Write,
    Status,
    Abandon,
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) struct WriteAdmission {
    guard: std::sync::Arc<dyn RouteGuard>,
    install: String,
    custody: custody::Scope,
    sequence: u64,
    original: Original,
}

/// Execute only a qualified current original, with the install fence checked
/// by the same writer that commits the globally deduplicated effect.
#[cfg(feature = "mcp-executor-prototype")]
pub async fn write(
    db: &Db,
    route: &AuthenticatedRoute<'_>,
    install: &str,
    sequence: u64,
    original: Original,
) -> Result<Value> {
    if sequence == 0
        || !digest(install)
        || (
            original.account_id.as_str(),
            original.principal_id.as_str(),
            original.database_id.as_str(),
            original.origin_database_id.as_str(),
        ) != (route.account, route.principal, route.database, route.origin)
    {
        return Err(Error::auth("invalid installed original authority"));
    }
    let caller = crate::mcp::registry::Caller::authenticated(route.account);
    crate::mcp::kernel_v2::writes::execute_installed(
        db,
        caller,
        WriteAdmission {
            guard: route.guard.clone(),
            install: install.into(),
            custody: custody::Scope::new(route, install)?,
            sequence,
            original,
        },
    )
    .await
}

#[cfg(feature = "mcp-executor-prototype")]
impl WriteAdmission {
    pub(crate) fn original(&self) -> &Original {
        &self.original
    }

    pub(crate) async fn recheck(&self, tx: &mut SqliteConnection, actor: &str) -> Result<()> {
        self.guard.recheck().await?;
        let original = &self.original;
        if actor != original.principal_id
            || fences::origin_on(tx).await? != original.origin_database_id
        {
            return Err(Error::auth("installed original authority changed"));
        }
        let (binding, _) = recompute_binding(original)?;
        if binding != original.expected_binding_sha256 {
            return Err(invalid());
        }
        if crate::mcp::executor_prototype::original_settlement_contract(
            original.journal_variant,
            &original.operation,
            original.arguments["action"].as_str(),
            &original.catalog_executor,
            &original.catalog_operation,
            Some(&original.retained_contract_digest),
        )?
        .as_deref()
            != Some(original.retained_contract_digest.as_str())
        {
            return Err(invalid());
        }
        self.custody
            .require_observed_on(tx, self.sequence, &binding)
            .await?;
        require_not_abandoned(tx, actor, &self.install, original).await
    }
}

/// The route supplies the install from verified enrollment. It never takes
/// this coordinate from the submitted original.
pub async fn settle(
    db: &Db,
    route: &AuthenticatedRoute<'_>,
    install: &str,
    action: Action,
    original: Original,
) -> Result<Value> {
    if !digest(install) {
        return Err(Error::auth("invalid installed original authority"));
    }
    let request = super::Request {
        schema: "native.original-settlement.request.v1".into(),
        action: "settle_original".into(),
        purpose: "held_refusal_resolution".into(),
        abandon_if_unapplied: true,
        original,
    };
    super::settle_owned(
        db,
        route,
        request,
        super::SettlementMode::Installed {
            install: install.into(),
            action,
        },
    )
    .await
}

fn key(install: &str, original_namespace: &str) -> String {
    sha(
        "native.node.original-key.v1\0",
        &json!([install, original_namespace]),
    )
}

/// Check a reply's binding before recording it. Local settlement still
/// requires inclusion of the exact canonical event in an authorized copy.
pub(crate) fn validate_answer(original: &Original, install: &str, answer: &Value) -> Result<()> {
    if answer["schema"] != "native.installed-original-settlement.answer.v1"
        || answer["install_id"] != install
        || answer["original_binding_sha256"] != original.expected_binding_sha256
        || answer["namespace_sha256"] != namespace(original)
    {
        return Err(invalid());
    }
    let native: NativeFenceReference = match answer["verdict"].as_str() {
        Some("accepted") => {
            let receipt = &answer["receipt"];
            let identity = &receipt["identity"];
            let native: NativeFenceReference = serde_json::from_value(receipt["native"].clone())?;
            if answer["binding_verified"] != true
                || identity["principal_id"] != original.principal_id
                || identity["operation"] != original.operation
                || identity["operation_key"] != original.operation_key.trim()
                || identity["canonical_event_id"] != native.canonical_event_id
                || !identity["receipt_sha256"].as_str().is_some_and(digest)
            {
                return Err(invalid());
            }
            native
        }
        Some("unapplied_terminal")
            if answer["terminal"] == true && answer["scope"] == "install_idempotency_namespace" =>
        {
            serde_json::from_value(answer["native"].clone())?
        }
        _ => return Err(invalid()),
    };
    if native.origin_database_id != original.origin_database_id
        || native.local_seq <= 0
        || native.act <= 0
        || native.genesis_event_id.is_empty()
        || native.canonical_event_id.is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Abandonment {
    install_id: String,
    namespace_sha256: String,
    original_binding_sha256: String,
}

impl Abandonment {
    fn at(install: &str, original: &Original, binding: &str) -> Self {
        Self {
            install_id: install.into(),
            namespace_sha256: namespace(original),
            original_binding_sha256: binding.into(),
        }
    }

    fn key(&self) -> String {
        key(&self.install_id, &self.namespace_sha256)
    }
}

async fn lookup(
    tx: &mut SqliteConnection,
    actor: &str,
    scoped_key: &str,
) -> Result<Option<(Abandonment, NativeFenceReference)>> {
    match lookup_outcome_on(tx, actor, ABANDON, scoped_key).await? {
        KeyedOutcome::Accepted {
            request,
            receipt,
            native,
        } => {
            if receipt != "{\"abandoned\":true}" {
                return Err(invalid());
            }
            let fact: Abandonment = serde_json::from_str(&request)?;
            if fact.key() != scoped_key
                || !digest(&fact.install_id)
                || !digest(&fact.namespace_sha256)
                || !digest(&fact.original_binding_sha256)
            {
                return Err(invalid());
            }
            Ok(Some((fact, native)))
        }
        KeyedOutcome::Absent => Ok(None),
        KeyedOutcome::Terminal { .. } => Err(invalid()),
    }
}

fn terminal(expected: &Abandonment, fact: &Abandonment, native: NativeFenceReference) -> Value {
    if expected.original_binding_sha256 != fact.original_binding_sha256 {
        return json!({
            "schema":"native.installed-original-settlement.answer.v1",
            "verdict":"mismatch",
            "install_id":expected.install_id,
            "reason":"install_abandoned_other_original",
            "terminal":false
        });
    }
    json!({
        "schema":"native.installed-original-settlement.answer.v1",
        "verdict":"unapplied_terminal",
        "scope":"install_idempotency_namespace",
        "install_id":fact.install_id,
        "namespace_sha256":fact.namespace_sha256,
        "original_binding_sha256":fact.original_binding_sha256,
        "native":native,
        "terminal":true
    })
}

pub(crate) async fn prove_terminal_inclusion(
    snapshot: &mut super::outcome_profile::VerifiedOutcomeSnapshot<'_>,
    actor: &str,
    install: &str,
    original_binding: &str,
    answer: &Value,
) -> Result<Option<NativeFenceReference>> {
    use super::outcome_profile::OutcomeLookup;
    let namespace = answer["namespace_sha256"]
        .as_str()
        .filter(|value| digest(value))
        .ok_or_else(invalid)?;
    if answer["install_id"] != install || answer["original_binding_sha256"] != original_binding {
        return Err(invalid());
    }
    match snapshot
        .lookup(actor, ABANDON, &key(install, namespace))
        .await
        .map_err(|error| Error::engine(error.code()))?
    {
        OutcomeLookup::Typed(KeyedOutcome::Accepted {
            request,
            receipt,
            native,
        }) => {
            let fact: Abandonment = serde_json::from_str(request)?;
            if receipt != "{\"abandoned\":true}"
                || fact.install_id != install
                || fact.namespace_sha256 != namespace
                || fact.original_binding_sha256 != original_binding
                || serde_json::to_value(native)? != answer["native"]
            {
                return Err(invalid());
            }
            Ok(Some(native.clone()))
        }
        OutcomeLookup::Typed(KeyedOutcome::Absent) | OutcomeLookup::Legacy(None) => Ok(None),
        _ => Err(invalid()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn decide_on(
    db: &Db,
    tx: &mut SqliteConnection,
    route: &AuthenticatedRoute<'_>,
    install: &str,
    action: Action,
    original: &Original,
    binding: &str,
    global: KeyedOutcome,
) -> Result<Value> {
    let expected = Abandonment::at(install, original, binding);
    let scoped_key = expected.key();
    if let Some((fact, native)) = lookup(tx, route.principal, &scoped_key).await? {
        return Ok(terminal(&expected, &fact, native));
    }
    match global {
        KeyedOutcome::Accepted {
            request,
            receipt,
            native,
        } => {
            let mut result = accepted_answer(
                route,
                original,
                binding,
                &original.retained_provider_fingerprint,
                request,
                receipt,
                native,
            );
            result["schema"] = json!("native.installed-original-settlement.answer.v1");
            result["install_id"] = json!(install);
            return Ok(result);
        }
        // Preserve the existing pilot fence. It cannot certify abandonment
        // by the independently admitted install.
        KeyedOutcome::Terminal { .. } => return Ok(status_required("prior_global_fence")),
        KeyedOutcome::Absent => {}
    }
    if matches!(action, Action::Status) {
        return Ok(json!({
            "schema":"native.installed-original-settlement.answer.v1",
            "verdict":"absent",
            "install_id":install,
            "namespace_sha256":expected.namespace_sha256,
            "original_binding_sha256":binding,
            "terminal":false
        }));
    }
    receipts::record_on(
        db,
        tx,
        &mut crate::act::ActAllocation::new(),
        receipts::Outcome {
            principal: route.principal,
            operation: ABANDON,
            key: &scoped_key,
            request: &serde_json::to_string(&expected)?,
            receipt: "{\"abandoned\":true}",
        },
    )
    .await?;
    let (fact, native) = lookup(tx, route.principal, &scoped_key)
        .await?
        .ok_or_else(invalid)?;
    Ok(terminal(&expected, &fact, native))
}
/// Called inside the write transaction before global receipt lookup or any
/// domain side effect. Exact retries from the abandoning install stay fenced.
#[cfg(feature = "mcp-executor-prototype")]
async fn require_not_abandoned(
    tx: &mut SqliteConnection,
    actor: &str,
    install: &str,
    original: &Original,
) -> Result<()> {
    if lookup(tx, actor, &key(install, &namespace(original)))
        .await?
        .is_some()
    {
        return Err(Error::conflict("original abandoned by this install"));
    }
    Ok(())
}
