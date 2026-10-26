//! Native installed-app authority. Custody is evidence, never current consent.
//! Activation is a host preparation operation, not a tool or lazy launch side effect.
use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "v2-kernel-probe")]
mod admission;
mod consent;
pub(crate) mod declarations;
use declarations::activation_supported;
mod management;
mod preview;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use admission::{
    admit_account_app_as, admit_data_as, admit_dispatched_on, dispatched_identity,
};
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use consent::install_for_user_as;
pub(crate) use consent::ACTIONS_DDL;
pub(crate) use consent::OUTCOMES_DDL;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use consent::{
    admit_app_on, admit_install_on, adopt_as, bundle_source_on, launch_source_on,
    prepare_source_as, preview_as, AdoptRequest, AppSourceAdmission,
};
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use consent::{finish_app_action_in, start_app_action_in, start_declared_app_action_in};
pub use consent::{install_as, InstallOutcome, InstallRequest};
pub(crate) use management::ManagementOutcome;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use management::{inspect_as, list_as};

const RETAINED_SOURCE_UNVERIFIED: &str = "retained_source_unverified_on_v2";

pub(crate) const ACTIVATED: &str = "kernel.app_installs_activated.v1";
pub(crate) const REMOVED: &str = "kernel.app_install_removed.v1";
pub(crate) const PREFIX: &str = "kernel:app-installs:";
const ACTIVATION_ID: &str = "kernel:app-installs:activation";
pub(crate) const INSTALLS_DDL: &str = "CREATE TABLE kernel_app_installs (
 principal TEXT NOT NULL REFERENCES kernel_principals(principal_id), package TEXT NOT NULL,
 row_json TEXT NOT NULL CHECK(json_valid(row_json)), source_body TEXT,
 generation TEXT NOT NULL, status TEXT NOT NULL, executable INTEGER NOT NULL,
 refusal TEXT, previous_generation TEXT, event_seq INTEGER NOT NULL,
 PRIMARY KEY(principal,package))";
pub(crate) const SOURCES_DDL: &str = "CREATE TABLE kernel_app_package_sources (
 package TEXT NOT NULL, version TEXT NOT NULL, digest TEXT NOT NULL,
 artifact_id TEXT NOT NULL, source_revision TEXT NOT NULL, declaration_digest TEXT NOT NULL,
 pin_json TEXT NOT NULL CHECK(json_valid(pin_json)), source_body TEXT NOT NULL,
 event_seq INTEGER NOT NULL,
 PRIMARY KEY(package,version,digest,artifact_id,source_revision,declaration_digest))";

pub(crate) const IMPORT_CLOSED_INDEX: &str = "CREATE INDEX idx_kernel_import_closed ON content_events(type,seq) WHERE type IN ('kernel.hosted_membership.v1','kernel.app_installs_activated.v1')";

pub(crate) const REVOCATIONS_DDL: &str = "CREATE TABLE kernel_app_consent_revocations (
 principal TEXT PRIMARY KEY, event_seq INTEGER NOT NULL)";

/// A trusted host's verification of a selected, frozen app closure set. This
/// proof cannot be deserialized from MCP arguments. The source head alone is
/// an attempted import and does not certify completion.
pub struct VerifiedFrozenApps {
    evidence: Activation,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Activation {
    format: u32,
    source_head: Value,
    report_sha256: String,
    capsules: BTreeMap<String, i64>,
}
impl VerifiedFrozenApps {
    /// # Safety
    /// The host must have frozen the canonical source, completed and verified
    /// the selected app closures, and resolved every review/refusal affecting
    /// them. Supply the exact source-head JSON, verified report SHA-256 and
    /// capsule event sequences from that run. Stop/drain importers and exclude
    /// their write credentials/handles from the promoted serving generation.
    /// No caller or app input may supply this proof.
    pub unsafe fn from_verified_import_unchecked(
        source_head: Value,
        report_sha256: String,
        capsules: BTreeMap<String, i64>,
    ) -> Self {
        Self {
            evidence: Activation {
                // Version 2 admits the two existing frozen Slack pins. Version
                // 1 replay keeps its original four-pin activation decision.
                format: 2,
                source_head,
                report_sha256,
                capsules,
            },
        }
    }
    /// Contract-based admission for new cutovers. Formats 1–3 retain their
    /// historical package/version decisions during replay.
    /// # Safety
    /// The same frozen-source and exclusive-importer requirements as
    /// `from_verified_import_unchecked` apply.
    pub unsafe fn from_verified_contract_import_unchecked(
        source_head: Value,
        report_sha256: String,
        capsules: BTreeMap<String, i64>,
    ) -> Self {
        let mut proof = Self::from_verified_import_unchecked(source_head, report_sha256, capsules);
        proof.evidence.format = 4;
        proof
    }
    /// Declarative SQL/effect activation. Earlier formats keep their decisions.
    /// # Safety
    /// The frozen-source and exclusive-importer requirements above apply.
    pub unsafe fn from_verified_declarative_import_unchecked(
        source_head: Value,
        report_sha256: String,
        capsules: BTreeMap<String, i64>,
    ) -> Self {
        let mut proof = Self::from_verified_import_unchecked(source_head, report_sha256, capsules);
        proof.evidence.format = 5;
        proof
    }
    /// v1 parity operator format. Earlier activation formats keep their
    /// original replay decisions; format 3 also retains verified shell-auto
    /// adoptions, which v1 admits through its authored-app adoption producer.
    /// # Safety
    /// The same frozen source, complete verification and exclusive importer
    /// requirements as `from_verified_import_unchecked` apply.
    pub unsafe fn from_verified_v1_parity_import_unchecked(
        source_head: Value,
        report_sha256: String,
        capsules: BTreeMap<String, i64>,
    ) -> Self {
        let mut proof = Self::from_verified_import_unchecked(source_head, report_sha256, capsules);
        proof.evidence.format = 3;
        proof
    }
}

fn invalid(message: &str) -> Error {
    Error::engine(format!("native app activation: {message}"))
}

async fn require_activated_on(conn: &mut SqliteConnection) -> Result<()> {
    let active: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type=?)")
            .bind(ACTIVATED)
            .fetch_one(conn)
            .await?;
    if !active {
        return Err(Error::engine(
            "manage_alpha_tabs: frozen apps are not activated on this v2 database",
        ));
    }
    Ok(())
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid("missing install evidence"))
}
// Historical replay only: never extend these pins for new app releases.
fn legacy_supported(format: u32, package: &str, version: &str) -> bool {
    matches!(
        (package, version),
        ("agent.docs", "0.8.2" | "0.9.0" | "0.9.1")
            | ("agent.spaces", "0.7.0")
            | ("agent.whiteboard", "0.2.0")
    ) || (matches!(format, 2 | 3)
        && matches!(
            (package, version),
            ("agent.slack-workspace-v2", "0.4.1" | "0.5.7")
        ))
}
pub(crate) const NOT_YET_AVAILABLE: &str = "app_not_yet_available_on_v2";
const UNSUPPORTED_WITNESS: &str = "app_adoption_witness_not_yet_available_on_v2";

fn adoption_witness_supported(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some(
            "alpha_tab.adopted"
                | "alpha_tab.updated"
                | "alpha_tab.installed"
                | "alpha_tab.restored"
                | "alpha_tab.adopted.v2"
        )
    )
}

fn contract_supported(declaration: &Value) -> bool {
    crate::mcp::tools::alpha_tabs::is_app_v2_declaration(declaration)
        && crate::alpha_tab_sessions::validate_declaration_contract(declaration).is_ok()
        && declaration.as_object().is_some_and(|object| {
            object
                .keys()
                .all(|key| matches!(key.as_str(), "contract" | "needs" | "effects"))
        })
}

fn verified_adoption(adoption: &str) -> bool {
    matches!(adoption, "shell_adopt.v1" | "shell_auto.v1")
}

fn aggregate(principal: &str, package: &str) -> String {
    format!(
        "{PREFIX}{}",
        Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            &serde_json::to_vec(&(principal, package)).expect("string tuple")
        )
    )
}

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(&IMPORT_CLOSED_INDEX.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name IN ('kernel_app_installs','kernel_app_consent_revocations') AND type='table'").fetch_one(&mut *conn).await?;
    let sources: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='kernel_app_package_sources' AND type='table')").fetch_one(&mut *conn).await?;
    let outcomes: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='kernel_app_install_outcomes' AND type='table')").fetch_one(&mut *conn).await?;
    if count == 2 && sources && outcomes {
        return consent::ensure_actions_schema(conn).await;
    }
    if count != 0 && count != 2 {
        return Err(invalid("partial install projection schema"));
    }
    if count == 0 {
        sqlx::query(INSTALLS_DDL).execute(&mut *conn).await?;
        sqlx::query(REVOCATIONS_DDL).execute(&mut *conn).await?;
    }
    if !sources {
        sqlx::query(SOURCES_DDL).execute(&mut *conn).await?;
    }
    if !outcomes {
        sqlx::query(OUTCOMES_DDL).execute(&mut *conn).await?;
    }
    let events = crate::conformance::rebuild::read_events_of_types(
        conn,
        &[
            ACTIVATED,
            REMOVED,
            consent::RECORDED,
            consent::ADOPTED,
            hosted_identity::offboarding::EVENT,
        ],
    )
    .await?;
    for event in &events {
        if count == 2 {
            if event.event_type == ACTIVATED {
                let evidence: Activation = event_payload(event)?;
                for install in verify(conn, &evidence, event.local_seq).await? {
                    project_source(conn, &install, event.local_seq).await?;
                }
            }
            if !outcomes && event.event_type == consent::RECORDED {
                consent::recover_outcome(conn, event).await?;
            }
            if !outcomes && event.event_type == consent::ADOPTED {
                consent::recover_adopted_outcome(conn, event).await?;
            }
            if !outcomes && event.event_type == REMOVED {
                recover_removal_outcome(conn, event).await?;
            }
            continue;
        }
        match event.event_type.as_str() {
            ACTIVATED | REMOVED | consent::RECORDED | consent::ADOPTED => {
                project(conn, event).await?
            }
            hosted_identity::offboarding::EVENT => revoke_offboarded(conn, event).await?,
            _ => (),
        }
    }
    consent::ensure_actions_schema(conn).await
}

/// Idempotent only for exactly the same verified evidence. Later source custody
/// never refreshes native consent and cannot reverse a removal or offboarding.
pub async fn activate_as(db: &Db, host: &str, proof: VerifiedFrozenApps) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    ensure_schema(&mut tx).await?;
    activate_on(db, &mut tx, host, &proof).await?;
    db.commit_kernel_content(tx).await?;
    Ok(())
}

pub(crate) async fn activate_on(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    host: &str,
    proof: &VerifiedFrozenApps,
) -> Result<()> {
    let prior: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1",
    )
    .bind(ACTIVATED)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(prior) = prior {
        if serde_json::from_str::<Activation>(&prior)? != proof.evidence {
            return Err(Error::conflict("native app activation evidence changed"));
        }
        return Ok(());
    }
    // Live admission uses the shared carrier resolver. Replay verifies the
    // retained outcome without consulting a source's later type or policy.
    for install in verify(tx, &proof.evidence, i64::MAX).await? {
        if install.body.is_some() {
            let artifact = string(&install.row, "artifact_id")?;
            let record = read_record_unchecked_on(tx, host, artifact)
                .await?
                .ok_or_else(|| invalid("app artifact missing"))?;
            if hq::tombstoned_on(tx, artifact).await? || !is_artifact_on(tx, &record).await? {
                return Err(invalid("app source is not a live Document/artifact"));
            }
        }
    }
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: ACTIVATION_ID.into(),
            event_type: ACTIVATED.into(),
            payload: serde_json::to_value(&proof.evidence)?,
            actor: Some(host.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    Ok(())
}

/// Read-only operator preflight. Uses the same verifier as activation/replay;
/// returns counts only, never source, account IDs, declarations or read SQL.
/// `catalog_members` is a freshly fenced hosted owner/member roster.
pub async fn inspect_frozen_activation_on(
    conn: &mut SqliteConnection,
    proof: &VerifiedFrozenApps,
    catalog_members: &BTreeSet<String>,
) -> Result<Value> {
    let prior: Option<String> =
        sqlx::query_scalar("SELECT payload FROM content_events WHERE type=? ORDER BY seq LIMIT 1")
            .bind(ACTIVATED)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some(prior) = &prior {
        if serde_json::from_str::<Activation>(prior)? != proof.evidence {
            return Err(invalid("activation evidence changed"));
        }
    }
    // Count the complete stale-capsule class before refusing the batch. These
    // diagnostics carry no imported IDs, declarations or application content.
    let mut stale = 0usize;
    for (bearer, seq) in &proof.evidence.capsules {
        let (_, state) = app_state::evidence_at(conn, bearer, *seq, i64::MAX).await?;
        if state.custody.as_ref().is_none_or(|f| {
            f.format != 1
                || f.content_frontier != proof.evidence.source_head["seq"].as_i64().unwrap_or(-1)
                || f.control_frontier
                    != proof.evidence.source_head["control_seq"]
                        .as_i64()
                        .unwrap_or(-1)
                || !f.missing_source_events.is_empty()
                || !f.missing_control_events.is_empty()
        }) {
            stale += 1;
        }
    }
    if stale > 0 {
        return Err(invalid(&format!(
            "incomplete or stale capsule; class=stale_capsule count={stale}"
        )));
    }
    let mut counts = BTreeMap::<(String, String), (usize, BTreeMap<String, usize>)>::new();
    // verify() keeps unmapped accounts as forensic custody. The operator must
    // instead refuse any otherwise active adopted install without an identity.
    for (bearer, seq) in &proof.evidence.capsules {
        let (_, state) = app_state::evidence_at(conn, bearer, *seq, i64::MAX).await?;
        for row in &state.alpha_tab_installs {
            // Excluded apps carry no executable authority and must not make
            // identity preflight block activation of the supported installs.
            if proof.evidence.format >= 4
                && !row["consented_declaration"]
                    .as_str()
                    .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                    .is_some_and(|declaration| {
                        activation_supported(proof.evidence.format, &declaration)
                    })
            {
                continue;
            }
            if proof.evidence.format >= 4
                && state
                    .control_events
                    .get(row["event_id"].as_str().unwrap_or_default())
                    .is_some_and(|event| !adoption_witness_supported(event["type"].as_str()))
            {
                continue;
            }
            if row["status"] == "installed"
                && matches!(
                    row["adoption"].as_str(),
                    Some("shell_adopt.v1" | "shell_auto.v1")
                )
            {
                let binding = string(row, "account_id")?;
                let principal: Option<String> = sqlx::query_scalar(
                    "SELECT principal_id FROM kernel_principals WHERE kind='account' AND auth_binding=?"
                ).bind(binding).fetch_optional(&mut *conn).await?;
                let principal = principal
                    .ok_or_else(|| invalid("adopting member unmapped in hosted identity"))?;
                let revoked: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM kernel_app_consent_revocations WHERE principal=?)",
                )
                .bind(&principal)
                .fetch_one(&mut *conn)
                .await?;
                if revoked
                    || !hosted_identity::account_admitted_before(conn, &principal, i64::MAX).await?
                {
                    return Err(invalid("adopting member offboarded or not admitted"));
                }
                let mut mapped = false;
                for account in catalog_members {
                    mapped |= hosted_identity::catalog_account_matches_on(
                        conn, account, binding, &principal,
                    )
                    .await?;
                }
                if !mapped {
                    return Err(invalid(
                        "adopting member unmapped in current hosted catalog",
                    ));
                }
            }
        }
    }
    for install in verify(conn, &proof.evidence, i64::MAX).await? {
        if install.body.is_some() {
            let artifact = string(&install.row, "artifact_id")?;
            let host: String = sqlx::query_scalar(
                "SELECT principal_id FROM kernel_principals WHERE auth_binding=?",
            )
            .bind(HOST_IMPORT_BINDING)
            .fetch_one(&mut *conn)
            .await?;
            let record = read_record_unchecked_on(conn, &host, artifact)
                .await?
                .ok_or_else(|| invalid("app source is not a live Document/artifact"))?;
            if hq::tombstoned_on(conn, artifact).await? || !is_artifact_on(conn, &record).await? {
                return Err(invalid("app source is not a live Document/artifact"));
            }
        }
        let entry = counts
            .entry((
                string(&install.row, "package")?.into(),
                string(&install.row, "version")?.into(),
            ))
            .or_default();
        if install.body.is_some() {
            entry.0 += 1;
        } else {
            let reason = match install.row["status"].as_str() {
                Some("disabled") => "inactive_on_v1",
                Some("removed") => "removed_on_v1",
                _ if !matches!(
                    install.row["adoption"].as_str(),
                    Some("shell_adopt.v1" | "shell_auto.v1")
                ) =>
                {
                    "unadopted_on_v1"
                }
                _ => install
                    .refusal
                    .as_deref()
                    .filter(|_| proof.evidence.format >= 4)
                    .unwrap_or("source_deleted_or_unsupported_on_v2"),
            };
            *entry.1.entry(reason.into()).or_default() += 1;
        }
    }
    Ok(
        json!({"already_active":prior.is_some(), "packages":counts.into_iter().map(|((package,version),(eligible,excluded))|
        json!({"package":package,"version":version,"eligible":eligible,"excluded":excluded.values().sum::<usize>(),"exclusion_reasons":excluded})).collect::<Vec<_>>()}),
    )
}

struct CapturedInstall {
    principal: String,
    row: Value,
    body: Option<String>,
    refusal: Option<String>,
}

async fn verify(
    conn: &mut SqliteConnection,
    p: &Activation,
    before: i64,
) -> Result<Vec<CapturedInstall>> {
    verify_sources(conn, p, before, false).await
}

// Source admission may verify retained Class 2 evidence from format 4 without
// changing its activation or granting executable consent.
async fn verify_sources(
    conn: &mut SqliteConnection,
    p: &Activation,
    before: i64,
    retained_declarative: bool,
) -> Result<Vec<CapturedInstall>> {
    if !matches!(p.format, 1..=5)
        || p.report_sha256.len() != 64
        || !p
            .report_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid("unsupported verifier or report digest"));
    }
    let roster: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type=? AND seq<?)",
    )
    .bind(hosted_identity::ROSTER_EVENT)
    .bind(before)
    .fetch_one(&mut *conn)
    .await?;
    if !roster {
        return Err(invalid("hosted identity activation required"));
    }
    let head: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE type='kernel.import_source_head.v1' AND seq<? ORDER BY seq DESC LIMIT 1").bind(before).fetch_optional(&mut *conn).await?;
    if head
        .map(|s| serde_json::from_str::<Value>(&s))
        .transpose()?
        .as_ref()
        != Some(&p.source_head)
    {
        return Err(invalid("frozen source head changed"));
    }
    let mut installs = Vec::new();
    let mut identities = BTreeSet::new();
    for (bearer, capsule_seq) in &p.capsules {
        let state = async {
            if *capsule_seq >= before {
                return Err(invalid("capsule is not preceding evidence"));
            }
            let (origin, state) =
                app_state::evidence_at(conn, bearer, *capsule_seq, before).await?;
            if p.source_head["origin"] != origin {
                return Err(invalid("capsule identity changed"));
            }
            let f = state
                .custody
                .as_ref()
                .ok_or_else(|| invalid("capsule frontier missing"))?;
            if f.format != 1
                || f.content_frontier != p.source_head["seq"].as_i64().unwrap_or(-1)
                || f.control_frontier != p.source_head["control_seq"].as_i64().unwrap_or(-1)
                || !f.missing_source_events.is_empty()
                || !f.missing_control_events.is_empty()
            {
                return Err(invalid("incomplete or stale capsule"));
            }
            Ok(state)
        }
        .await;
        let state = match state {
            Ok(state) => state,
            Err(_) if retained_declarative => continue,
            Err(error) => return Err(error),
        };
        let context = InstallEvidence {
            p,
            before,
            retained_declarative,
            bearer,
            state: &state,
        };
        for row in &state.alpha_tab_installs {
            match verify_install_row(conn, &context, row.clone(), &mut identities).await {
                Ok(Some(install)) => installs.push(install),
                Ok(None) => {}
                Err(_) if retained_declarative => installs.push(CapturedInstall {
                    principal: String::new(),
                    row: row.clone(),
                    body: None,
                    refusal: Some(RETAINED_SOURCE_UNVERIFIED.into()),
                }),
                Err(error) => return Err(error),
            }
        }
    }
    Ok(installs)
}

struct InstallEvidence<'a> {
    p: &'a Activation,
    before: i64,
    retained_declarative: bool,
    bearer: &'a str,
    state: &'a app_state::RetainedAppState,
}

async fn verify_install_row(
    conn: &mut SqliteConnection,
    context: &InstallEvidence<'_>,
    row: Value,
    identities: &mut BTreeSet<(String, String)>,
) -> Result<Option<CapturedInstall>> {
    let &InstallEvidence {
        p,
        before,
        retained_declarative,
        bearer,
        state,
    } = context;
    if row["artifact_id"] != bearer {
        return Err(invalid("install bearer mismatch"));
    }
    let account = string(&row, "account_id")?;
    let principal: Option<String> = sqlx::query_scalar("SELECT p.principal_id FROM kernel_principals p WHERE p.kind='account' AND p.auth_binding=? AND EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=p.principal_id AND e.type='kernel.principal_created.v1' AND e.seq<?)").bind(account).bind(before).fetch_optional(&mut *conn).await?;
    // Unmapped foreign accounts remain forensic custody, not native authority.
    let Some(principal) = principal else {
        return Ok(None);
    };
    let package = string(&row, "package")?;
    if !identities.insert((principal.clone(), package.to_owned())) {
        return Err(invalid("duplicate install identity"));
    }
    let version = string(&row, "version")?;
    string(&row, "event_id")?;
    let status = string(&row, "status")?;
    if !matches!(status, "installed" | "removed" | "disabled") {
        return Err(invalid("invalid install status"));
    }
    // Unsupported declarations are per-install exclusions, including
    // unadopted or malformed legacy declarations. They grant no source
    // or consent authority and never abort activation of other apps.
    if p.format >= 4
        && !row["consented_declaration"]
            .as_str()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .is_some_and(|declaration| {
                activation_supported(p.format, &declaration)
                    || (retained_declarative && declarations::declarative(&declaration).is_ok())
            })
    {
        return Ok(Some(CapturedInstall {
            principal,
            row,
            body: None,
            refusal: Some(NOT_YET_AVAILABLE.into()),
        }));
    }
    let mut refusal = Some("unsupported_on_v2".to_owned());
    let mut body = None;
    if !state.source_deleted
        && status == "installed"
        && (row["adoption"] == "shell_adopt.v1"
            || (p.format >= 3 && row["adoption"] == "shell_auto.v1"))
        && (p.format >= 4 || legacy_supported(p.format, package, version))
    {
        let declaration: Value = serde_json::from_str(string(&row, "consented_declaration")?)?;
        if p.format < 4 && !contract_supported(&declaration) {
            return Err(invalid("unsupported app contract"));
        }
        let event = state
            .source_events
            .get(string(&row, "consented_source_revision")?)
            .ok_or_else(|| invalid("pinned source missing"))?;
        if event["record_id"] != bearer
            || !matches!(
                event["type"].as_str(),
                Some("record.created" | "record.updated" | "record.body.updated")
            )
        {
            return Err(invalid("pinned source does not belong to artifact"));
        }
        let payload: Value = serde_json::from_str(string(event, "payload")?)?;
        let source = string(&payload, "body")?.to_owned();
        let digest = crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration)?;
        if row["declaration_digest"] != digest
            || row["digest"]
                != crate::mcp::tools::alpha_tabs::alpha_tab_digest(
                    &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&source),
                    &digest,
                    "native.html.v1",
                )
        {
            return Err(invalid("source or declaration digest mismatch"));
        }
        let control = state
            .control_events
            .get(string(&row, "event_id")?)
            .ok_or_else(|| invalid("install control witness missing"))?;
        let evidence: Value = serde_json::from_str(string(control, "payload")?)?;
        if p.format >= 4 && !adoption_witness_supported(control["type"].as_str()) {
            // A future transition type grants no executable authority.
            // Still reject any contradictory retained pin fields.
            for key in [
                "account_id",
                "package",
                "version",
                "digest",
                "artifact_id",
                "consented_source_revision",
                "declaration_digest",
                "adoption",
            ] {
                if evidence.get(key).is_some_and(|value| value != &row[key]) {
                    return Err(invalid("install control witness mismatch"));
                }
            }
            if evidence
                .get("consented_declaration")
                .is_some_and(|value| value != &declaration)
                || control["actor"] != account
            {
                return Err(invalid("adoption ownership mismatch"));
            }
            return Ok(Some(CapturedInstall {
                principal,
                row,
                body: None,
                refusal: Some(UNSUPPORTED_WITNESS.into()),
            }));
        }
        if !matches!(
            control["type"].as_str(),
            Some("alpha_tab.adopted" | "alpha_tab.updated")
        ) {
            if p.format < 4 {
                return Err(invalid("unsupported adoption witness"));
            }
            // v1 stored (not new-append) validation preserves legacy
            // installed/restored shell_adopt bases. See predecessor.rs
            // :388–407 and control::validate_stored_control_event.
            let event: crate::control::ControlEventRow = serde_json::from_value(control.clone())
                .map_err(|_| invalid("invalid stored adoption witness"))?;
            crate::control::validate_stored_control_event(&event)?;
        }

        for key in [
            "account_id",
            "package",
            "version",
            "digest",
            "artifact_id",
            "consented_source_revision",
            "declaration_digest",
            "adoption",
        ] {
            if evidence[key] != row[key] {
                return Err(invalid("install control witness mismatch"));
            }
        }
        // Stored legacy state events bind account/package through the
        // canonical aggregate; v1 does not require their import actor
        // to be the account. Direct adoption/update retain their fence.
        let legacy_state = p.format >= 4
            && matches!(
                control["type"].as_str(),
                Some("alpha_tab.installed" | "alpha_tab.restored")
            );
        if evidence["consented_declaration"] != declaration
            || (!legacy_state && control["actor"] != account)
        {
            return Err(invalid("adoption ownership mismatch"));
        }
        body = Some(source);
        refusal = None;
    }
    Ok(Some(CapturedInstall {
        principal,
        row,
        body,
        refusal,
    }))
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND payload IS ? AND actor IS ? AND act IS ?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type).bind(&event.payload).bind(&event.actor).bind(event.act).fetch_one(&mut *conn).await?;
    if !logged {
        return Err(invalid("event is not a retained outcome"));
    }
    app_state::refuse_entity_collision(conn, &event.record_id).await?;
    match event.event_type.as_str() {
        consent::ACTION_STARTED => consent::project_action_started(conn, event).await?,
        consent::ACTION_RECORDED => consent::project_action_recorded(conn, event).await?,
        consent::RECORDED => consent::project_recorded(conn, event).await?,
        consent::ADOPTED => consent::project_adopted(conn, event).await?,
        ACTIVATED => {
            hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
            let p: Activation = event_payload(event)?;
            if event.record_id != ACTIVATION_ID {
                return Err(invalid("activation aggregate mismatch"));
            }
            let prior: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type=? AND seq<?)",
            )
            .bind(ACTIVATED)
            .bind(event.local_seq)
            .fetch_one(&mut *conn)
            .await?;
            if prior {
                return Err(invalid("duplicate activation"));
            }
            let installs = verify(conn, &p, event.local_seq).await?;
            for install in installs {
                project_source(conn, &install, event.local_seq).await?;
                let offboarded: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM kernel_app_consent_revocations WHERE principal=?)",
                )
                .bind(&install.principal)
                .fetch_one(&mut *conn)
                .await?;
                let admitted = hosted_identity::account_admitted_before(
                    conn,
                    &install.principal,
                    event.local_seq,
                )
                .await?;
                let revoked = offboarded || !admitted;
                let generation = string(&install.row, "event_id")?;
                let package = string(&install.row, "package")?;
                let status = if revoked {
                    "removed"
                } else {
                    string(&install.row, "status")?
                };
                sqlx::query("INSERT INTO kernel_app_installs(principal,package,row_json,source_body,generation,status,executable,refusal,previous_generation,event_seq) VALUES(?,?,?,?,?,?,?,?,NULL,?)")
                    .bind(&install.principal).bind(package).bind(serde_json::to_string(&install.row)?).bind(&install.body).bind(generation).bind(status)
                    .bind(!revoked && install.refusal.is_none()).bind(if offboarded { Some("offboarded") } else if !admitted { Some("membership_not_admitted") } else { install.refusal.as_deref() }).bind(event.local_seq).execute(&mut *conn).await?;
            }
        }
        REMOVED => {
            let p: Removal = event_payload(event)?;
            let principal = event
                .actor
                .as_deref()
                .ok_or_else(|| invalid("removal actor missing"))?;
            if event.record_id != aggregate(principal, &p.package) {
                return Err(invalid("removal aggregate mismatch"));
            }
            if let Some(intent) = &p.intent {
                validate_removal_intent(intent)?;
                if !hosted_identity::account_admitted_before(conn, principal, event.local_seq)
                    .await?
                {
                    return Err(Error::engine("database membership not found"));
                }
            }
            let changed = sqlx::query("UPDATE kernel_app_installs SET previous_generation=generation,generation=?,status='removed',executable=0,refusal='removed',event_seq=? WHERE principal=? AND package=? AND generation=? AND status!='removed'")
                .bind(&event.id).bind(event.local_seq).bind(principal).bind(&p.package).bind(&p.previous_generation).execute(&mut *conn).await?.rows_affected();
            if changed != 1 {
                return Err(Error::conflict("native app removal predecessor changed"));
            }
            recover_removal_outcome(conn, event).await?;
        }
        _ => return Err(invalid("unsupported event")),
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Removal {
    package: String,
    previous_generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent: Option<RemovalIntent>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovalIntent {
    key: String,
    reason: String,
}

fn validate_removal_intent(intent: &RemovalIntent) -> Result<()> {
    if intent.key.trim().is_empty() || intent.reason.trim().is_empty() || intent.reason.len() > 1024
    {
        return Err(Error::engine("manage_alpha_tabs: invalid removal intent"));
    }
    Ok(())
}

fn removal_request_json(p: &Removal, reason: &str) -> Result<String> {
    Ok(serde_json::to_string(&(
        &p.package,
        &p.previous_generation,
        reason,
    ))?)
}

async fn recover_removal_outcome(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Removal = event_payload(event)?;
    if let Some(intent) = &p.intent {
        validate_removal_intent(intent)?;
        consent::project_outcome(
            conn,
            event,
            &intent.key,
            "remove",
            &removal_request_json(&p, &intent.reason)?,
        )
        .await?;
    }
    Ok(())
}

/// Removal does not require continued visibility of the source artifact.
pub async fn remove_as(db: &Db, principal: &str, package: &str, expected: &str) -> Result<String> {
    remove_with_intent(db, principal, package, expected, None)
        .await
        .map(|outcome| outcome.outcome.generation)
}

pub(crate) async fn remove_for_user_as(
    db: &Db,
    principal: &str,
    package: &str,
    expected: &str,
    reason: String,
    key: Option<String>,
) -> Result<ManagementOutcome> {
    let intent = RemovalIntent {
        key: key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("alpha-tab-removed:{principal}:{package}:{expected}")),
        reason,
    };
    validate_removal_intent(&intent)?;
    remove_with_intent(db, principal, package, expected, Some(intent)).await
}

async fn remove_with_intent(
    db: &Db,
    principal: &str,
    package: &str,
    expected: &str,
    intent: Option<RemovalIntent>,
) -> Result<ManagementOutcome> {
    let mut tx = begin_write(db.write_pool()).await?;
    if !hosted_identity::admitted(&mut tx, principal).await? {
        return Err(Error::engine("database membership not found"));
    }
    let payload = Removal {
        package: package.into(),
        previous_generation: expected.into(),
        intent,
    };
    if let Some(intent) = &payload.intent {
        if !hosted_identity::account_admitted_before(&mut tx, principal, i64::MAX).await? {
            return Err(Error::engine("database membership not found"));
        }
        let old: Option<(String, String, String)> = sqlx::query_as(
            "SELECT operation,request_json,event_id FROM kernel_app_install_outcomes WHERE principal=? AND operation_key=?",
        ).bind(principal).bind(&intent.key).fetch_optional(&mut *tx).await?;
        if let Some((operation, request, generation)) = old {
            if operation != "remove" || request != removal_request_json(&payload, &intent.reason)? {
                return Err(Error::conflict(
                    "idempotency_key reused for different app intent",
                ));
            }
            let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal=? AND package=? AND generation=? AND status='removed')")
                .bind(principal).bind(package).bind(&generation).fetch_one(&mut *tx).await?;
            if !current {
                return Err(Error::conflict("native app installation changed"));
            }
            return management::outcome_on(&mut tx, principal, package, generation, false).await;
        }
    }
    let row: Option<(String,String,Option<String>)> = sqlx::query_as("SELECT generation,status,previous_generation FROM kernel_app_installs WHERE principal=? AND package=?").bind(principal).bind(package).fetch_optional(&mut *tx).await?;
    let Some((generation, status, previous)) = row else {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    };
    if status == "removed" && previous.as_deref() == Some(expected) {
        if payload.intent.is_some() {
            return Err(Error::conflict(
                "native app removal already accepted with another intent",
            ));
        }
        return management::outcome_on(&mut tx, principal, package, generation, false).await;
    }
    if generation != expected {
        return Err(Error::conflict("native app installation changed"));
    }
    if status == "removed" {
        return management::outcome_on(&mut tx, principal, package, generation, false).await;
    }
    let outcome = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: aggregate(principal, package),
            event_type: REMOVED.into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(principal.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    let result = management::outcome_on(&mut tx, principal, package, outcome.id, true).await?;
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

pub(crate) async fn revoke_offboarded(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Value = event_payload(event)?;
    if let Some(principal) = p["target_principal"].as_str() {
        sqlx::query("INSERT INTO kernel_app_consent_revocations(principal,event_seq) VALUES(?,?) ON CONFLICT(principal) DO UPDATE SET event_seq=excluded.event_seq WHERE excluded.event_seq>kernel_app_consent_revocations.event_seq").bind(principal).bind(event.local_seq).execute(&mut *conn).await?;
        sqlx::query("UPDATE kernel_app_installs SET status='removed',executable=0,refusal='offboarded',generation=?,event_seq=? WHERE principal=?").bind(&event.id).bind(event.local_seq).bind(principal).execute(conn).await?;
    }
    Ok(())
}

// Frozen package authority belongs to the verified activation, independently
// of any account's continued consent. Runtime transitions never update it.
async fn project_source(
    conn: &mut SqliteConnection,
    install: &CapturedInstall,
    seq: i64,
) -> Result<()> {
    let Some(body) = &install.body else {
        return Ok(());
    };
    let pin = source_pin(&install.row, body)?.to_string();
    let row = &install.row;
    let package = string(row, "package")?;
    let version = string(row, "version")?;
    let digest = string(row, "digest")?;
    let artifact = string(row, "artifact_id")?;
    let revision = string(row, "consented_source_revision")?;
    let declaration_digest = string(row, "declaration_digest")?;
    sqlx::query("INSERT INTO kernel_app_package_sources VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(package,version,digest,artifact_id,source_revision,declaration_digest) DO NOTHING")
        .bind(package).bind(version).bind(digest).bind(artifact).bind(revision).bind(declaration_digest).bind(&pin).bind(body).bind(seq).execute(&mut *conn).await?;
    let stored:(String,String,i64)=sqlx::query_as("SELECT pin_json,source_body,event_seq FROM kernel_app_package_sources WHERE package=? AND version=? AND digest=? AND artifact_id=? AND source_revision=? AND declaration_digest=?")
        .bind(package).bind(version).bind(digest).bind(artifact).bind(revision).bind(declaration_digest).fetch_one(conn).await?;
    if stored != (pin, body.clone(), seq) {
        return Err(invalid("frozen package source changed"));
    }
    Ok(())
}

fn source_pin(row: &Value, body: &str) -> Result<Value> {
    let package = string(row, "package")?;
    let version = string(row, "version")?;
    let digest = string(row, "digest")?;
    let artifact = string(row, "artifact_id")?;
    let revision = string(row, "consented_source_revision")?;
    let declaration_digest = string(row, "declaration_digest")?;
    // Consent rows retain their original JSON TEXT. The shared source pin
    // canonicalizes only declaration JSON, so equivalent consent spellings
    // cannot make another account's otherwise identical source ambiguous.
    let declaration: Value = serde_json::from_str(string(row, "consented_declaration")?)?;
    Ok(json!({
        "format":1,
        "package":package, "version":version, "digest":digest,
        "artifact_id":artifact,
        "source_revision":revision,
        "consented_declaration":String::from_utf8(crate::canonical_json::canonical_json(&declaration)).map_err(|_| invalid("canonical declaration encoding"))?,
        "declaration_digest":declaration_digest,
        "runtime":"native.html.v1",
        "bundle_sha256":crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(body)
    }))
}

/// Read-only evidence admission for the member consent path. Reuses the
/// strict adoption/source verifier at the retained activation frontier; no
/// activation event, source projection, or executable install is changed.
async fn retained_sources_on(
    conn: &mut SqliteConnection,
    artifact: Option<&str>,
) -> Result<Vec<(Value, String, i64)>> {
    let activation: Option<(String, i64)> = sqlx::query_as(
        "SELECT payload,seq FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1",
    )
    .bind(ACTIVATED)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((raw, seq)) = activation else {
        return Ok(vec![]);
    };
    let mut evidence: Activation = match serde_json::from_str(&raw) {
        Ok(evidence) => evidence,
        Err(_) => return Ok(vec![]),
    };
    if evidence.format != 4 {
        return Ok(vec![]);
    }
    if let Some(id) = artifact {
        evidence.capsules.retain(|bearer, _| bearer == id);
    }
    let mut sources = Vec::new();
    let verified = match verify_sources(conn, &evidence, seq, true).await {
        Ok(verified) => verified,
        // Invalid retained activation evidence grants no source authority.
        // Member list/prepare flows must remain usable for other source pins.
        Err(_) => return Ok(sources),
    };
    for install in verified {
        let declaration: Value = match install.row["consented_declaration"]
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
        {
            Some(value) => value,
            None => continue,
        };
        if declarations::declarative(&declaration).is_err() {
            continue;
        }
        if let Some(body) = install.body.filter(|_| install.refusal.is_none()) {
            if let Ok(pin) = source_pin(&install.row, &body) {
                sources.push((pin, body, seq));
            }
        }
    }
    Ok(sources)
}

/// Exact frozen pins available for a new personal consent in this database.
/// Revoking another account's install neither removes nor grants this access.
/// Body bytes are reserved for the separately admitted preview/delivery lane.
pub async fn frozen_sources_as(db: &Db, principal: &str) -> Result<Vec<Value>> {
    let mut snapshot = db.write_pool().begin().await?;
    let pins = frozen_sources_on(&mut snapshot, principal, None).await?;
    snapshot.rollback().await?;
    Ok(pins)
}

async fn frozen_sources_on(
    conn: &mut SqliteConnection,
    principal: &str,
    retained: Option<&[(Value, String, i64)]>,
) -> Result<Vec<Value>> {
    if !hosted_identity::account_admitted_before(conn, principal, i64::MAX).await? {
        return Err(Error::engine("database membership not found"));
    }
    require_activated_on(conn).await?;
    let pins: Vec<String> = sqlx::query_scalar(
        "SELECT pin_json FROM kernel_app_package_sources ORDER BY package,version,digest,artifact_id,source_revision,declaration_digest",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut pins = pins;
    let owned;
    let retained = match retained {
        Some(retained) => retained,
        None => {
            owned = retained_sources_on(conn, None).await?;
            &owned
        }
    };
    for (pin, _, _) in retained {
        let raw = pin.to_string();
        if !pins.contains(&raw) {
            pins.push(raw);
        }
    }
    let mut visible = Vec::new();
    for raw in pins {
        let pin: Value = serde_json::from_str(&raw)?;
        let artifact = string(&pin, "artifact_id")?;
        if let Some(record) = read_record_on(conn, principal, artifact).await? {
            if is_artifact_on(conn, &record).await? {
                let runtime: Option<String> = sqlx::query_scalar(
                    "SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'",
                )
                .bind(artifact)
                .fetch_optional(&mut *conn)
                .await?
                .flatten();
                if runtime.as_deref() == Some("native.html.v1") {
                    visible.push(pin);
                }
            }
        }
    }
    Ok(visible)
}

async fn is_artifact_on(conn: &mut SqliteConnection, record: &KernelRecordView) -> Result<bool> {
    if record.archived {
        return Ok(false);
    }
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM main.kernel_records WHERE id=?")
            .bind(&record.id)
            .fetch_one(conn)
            .await?;
    Ok(crate::v2_standard::v1_compat::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|p| p.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    ) == (Some("Document"), Some("artifact")))
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod frozen_messaging_tests {
    use super::*;

    #[test]
    fn activation_format_never_upgrades_an_earlier_retained_install() {
        for version in ["0.4.1", "0.5.7"] {
            assert!(!legacy_supported(1, "agent.slack-workspace-v2", version));
            assert!(legacy_supported(2, "agent.slack-workspace-v2", version));
        }
        assert!(!legacy_supported(2, "agent.slack-workspace-v2", "0.5.13"));
        assert!(!legacy_supported(2, "agent.slack-workspace", "0.5.7"));
        for format in [1, 2] {
            assert!(legacy_supported(format, "agent.docs", "0.8.2"));
            assert!(legacy_supported(format, "agent.docs", "0.9.0"));
            assert!(legacy_supported(format, "agent.docs", "0.9.1"));
            assert!(legacy_supported(format, "agent.spaces", "0.7.0"));
            assert!(legacy_supported(format, "agent.whiteboard", "0.2.0"));
        }
    }
}
