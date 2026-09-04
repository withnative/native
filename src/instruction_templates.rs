//! Engine-owned provisioning for portable workspace/member instruction state.
//!
//! The records remain ordinary event-sourced content. Their bindings,
//! programmes, template provenance, member contexts, and obligations are
//! canonical control events projected synchronously in the same write
//! transaction.

use chrono::DateTime;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::authorization::{AllowEntry, Capability};
use crate::control::{
    append_control_event_in, member_obligation_aggregate_id, programme_source_aggregate_id,
    ControlEventPayload, InstructionBindingStatePayload, MemberContextProvisionedPayload,
    MemberObligationStatePayload, NewControlEvent, OnboardingProgrammeSourcePayload,
    OnboardingProgrammeStatePayload, SeededInstructionSourceAppliedPayload,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::schema::ROOT_RECORD_ID;
pub(crate) use crate::schema::{
    INSTRUCTIONS_FOLDER_ID, MEMBER_CRITERIA_ID, MEMBER_GUIDANCE_ID, OWNER_CRITERIA_ID,
    OWNER_GUIDANCE_ID, WORKSPACE_INSTRUCTIONS_ID,
};
use crate::store::{append_engine_provisioned_in, append_in, now_iso, AppendSpec};

pub(crate) const DATABASE_SCOPE_ID: &str = "native:database";
pub(crate) const OWNER_PROGRAMME_ID: &str = "native:onboarding-owner-first-run";
pub(crate) const MEMBER_PROGRAMME_ID: &str = "native:onboarding-member-joined";

pub(crate) const WORKSPACE_BINDING_ID: &str = "native:binding-workspace-agent-instructions";

const WORKSPACE_BODY: &str = "# Workspace agent instructions\n\nAdd guidance that should be considered by agents working in this database. These instructions are presented with their workspace provenance; they do not change permissions.";
const PERSONAL_BODY: &str = "# My agent instructions\n\nAdd guidance and preferences that should be considered when an agent is assisting you in this database.";
const OWNER_GUIDANCE_BODY: &str = "# Owner orientation\n\nBegin with the route the owner selects: set up a practical workflow, compare Native with another tool, or explain Native conceptually. Give enough of the product model for the choice to be meaningful. A comparison or conceptual explanation must not force concrete work or an artifact. On the practical route, anchor on the outcome the owner wants and choose one small, high-value workflow achievable now. Reuse Bootstrap's exact run key and declare a clear aim through the separate `set_intent` call. Record only bounded progress metadata with `manage_onboarding`; never put preview text or learned context in control-event evidence. Record `route_selected` with only the chosen stable route ID, then record `value_delivered` only after the owner confirms the assistance was useful.\n\nWhen practical work produces a useful durable result, propose an ordinary workspace record by default. Show its exact draft and placement, explain the relevant visibility, and obtain explicit consent before writing. Do not infer personal, organisational, or external-system facts. Shared records remain subject to ordinary inspect, edit, delete, policy, and portable-export controls.\n\nOnly when the owner intentionally chooses private agent context, offer one private `Starting context` note under the caller's `My agent context` root. Show the exact draft before any content write and include exactly: current aim, useful learned context, work or decision made, next step, and material uncertainty and source attribution. Explain the current policy status and ordinary inspect, edit, delete, and portable-export controls. Record `artifact_previewed` only after explicit consent to write, then create it if absent or inspect and update the sole existing ordinary Document/note, and record `artifact_written`. Extraction is a separate visibility-disclosed action. An interrupted session remains pending; explicit deferral is non-terminal.";
const OWNER_CRITERIA_BODY: &str = "# Owner orientation completion\n\nComplete orientation only after useful route-appropriate assistance, any relevant visibility explanation, and the owner's explicit confirmation of completion. Comparison and conceptual routes do not require an artifact. On the practical route, writing is optional: if a workspace record is written, it must be the exact consented draft at the disclosed placement; if private agent context is chosen, the exact Starting context draft and the owner's explicit choice whether to write it are required, and any written note must be the consented draft under My agent context. Decline or defer only after explicit owner intent. Interruption, silence, or a closed session leaves the obligation pending.";
const MEMBER_GUIDANCE_BODY: &str = "# Member orientation\n\nBegin with the route the member selects: set up a practical workflow, compare Native with another tool, or explain Native conceptually. Give enough of the product model for the choice to be meaningful. A comparison or conceptual explanation must not force concrete work or an artifact. On the practical route, anchor on the outcome the member wants and choose one small, high-value workflow achievable now. Do not conduct an owner interview or ask the member to define the workspace or organisation. Reuse Bootstrap's exact run key and declare a clear aim through the separate `set_intent` call. Record only bounded progress metadata with `manage_onboarding`; never put preview text or learned context in control-event evidence. Record `route_selected` with only the chosen stable route ID, then record `value_delivered` only after the member confirms the assistance was useful.\n\nWhen practical work produces a useful durable result, propose an ordinary workspace record by default. Show its exact draft and placement, explain the relevant visibility, and obtain explicit consent before writing. Do not infer personal, organisational, or external-system facts. Shared records remain subject to ordinary inspect, edit, delete, policy, and portable-export controls.\n\nOnly when the member intentionally chooses private agent context, offer one private `Starting context` note under the caller's `My agent context` root. Show the exact draft before any content write and include exactly: current aim, useful learned context, work or decision made, next step, and material uncertainty and source attribution. Explain the current policy status and ordinary inspect, edit, delete, and portable-export controls. Record `artifact_previewed` only after explicit consent to write, then create it if absent or inspect and update the sole existing ordinary Document/note, and record `artifact_written`. Extraction is a separate visibility-disclosed action. An interrupted session remains pending; explicit deferral is non-terminal.";
const MEMBER_CRITERIA_BODY: &str = "# Member orientation completion\n\nComplete orientation only after useful route-appropriate assistance, any relevant visibility explanation, and the member's explicit confirmation of completion. Comparison and conceptual routes do not require an artifact. On the practical route, writing is optional: if a workspace record is written, it must be the exact consented draft at the disclosed placement; if private agent context is chosen, the exact Starting context draft and the member's explicit choice whether to write it are required, and any written note must be the consented draft under My agent context. Decline or defer only after explicit member intent. Interruption, silence, or a closed session leaves the obligation pending.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustedMembershipRole {
    Owner,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustedMembershipSource {
    Personal,
    Direct,
    Invitation,
}

/// Immutable catalog facts carried across the hosting/portable boundary.
/// Workbench's mutable first-seen/onboarding fields are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedMembershipArrival {
    pub(crate) role: TrustedMembershipRole,
    pub(crate) source: TrustedMembershipSource,
    pub(crate) created_at: String,
}

impl TrustedMembershipArrival {
    pub(crate) fn validate(&self) -> Result<()> {
        DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|_| Error::engine("trusted membership created_at must be RFC3339"))?;
        if self.source == TrustedMembershipSource::Personal
            && self.role != TrustedMembershipRole::Owner
        {
            return Err(Error::engine(
                "trusted personal membership must carry owner role",
            ));
        }
        Ok(())
    }
}

/// The authority under which a portable member is being provisioned.
///
/// Hosted callers carry a catalog membership whose role controls shared
/// instruction administration. A standalone caller instead possesses the
/// database file and has explicitly selected this canonical account, so that
/// selected account is the local authority even after a hosted-era migration.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MemberProvisioningAuthority<'a> {
    Hosted(&'a TrustedMembershipArrival),
    Standalone,
}

impl<'a> MemberProvisioningAuthority<'a> {
    fn arrival(self) -> Option<&'a TrustedMembershipArrival> {
        match self {
            Self::Hosted(arrival) => Some(arrival),
            Self::Standalone => None,
        }
    }
}

#[derive(Clone, Copy)]
struct ProgrammeSeed {
    id: &'static str,
    trigger_key: &'static str,
    position: i64,
}

const PROGRAMMES: [ProgrammeSeed; 2] = [
    ProgrammeSeed {
        id: OWNER_PROGRAMME_ID,
        trigger_key: "on_owner_first_run",
        position: 100,
    },
    ProgrammeSeed {
        id: MEMBER_PROGRAMME_ID,
        trigger_key: "on_member_joined",
        position: 200,
    },
];

fn programme_payload(
    seed: ProgrammeSeed,
    cutoff: Option<&str>,
    at: &str,
) -> OnboardingProgrammeStatePayload {
    OnboardingProgrammeStatePayload {
        id: seed.id.into(),
        trigger_key: seed.trigger_key.into(),
        generation: 1,
        position: seed.position,
        enabled: true,
        created_by: "engine:seed".into(),
        legacy_baseline_before: cutoff.map(str::to_owned),
        created_at: at.into(),
        updated_at: at.into(),
    }
}

async fn ensure_programmes_in(tx: &mut Transaction<'static, Sqlite>) -> Result<()> {
    let existing: Vec<(String, Option<String>)> = sqlx::query(
        "SELECT id,legacy_baseline_before FROM onboarding_programmes
          WHERE id IN (?,?) ORDER BY id",
    )
    .bind(OWNER_PROGRAMME_ID)
    .bind(MEMBER_PROGRAMME_ID)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|row| Ok((row.try_get("id")?, row.try_get("legacy_baseline_before")?)))
    .collect::<std::result::Result<_, sqlx::Error>>()?;
    if existing.len() == PROGRAMMES.len() {
        return Ok(());
    }
    if !existing.is_empty() {
        return Err(Error::engine(
            "portable onboarding programme seed is partial",
        ));
    }
    let at = now_iso();
    for seed in PROGRAMMES {
        let payload = programme_payload(seed, None, &at);
        append_control_event_in(
            tx,
            NewControlEvent::engine_provisioned(
                format!("seed:v1:programme:{}", seed.id),
                seed.id,
                "seed fresh portable onboarding programme",
                ControlEventPayload::OnboardingProgrammeCreated(payload),
            )?,
        )
        .await?;
    }
    Ok(())
}

pub(crate) fn instruction_body_digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

#[derive(Debug)]
pub(crate) struct SeededInstructionTemplate {
    pub(crate) key: &'static str,
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) body: &'static str,
}

static TEMPLATE_REGISTRY: [SeededInstructionTemplate; 6] = [
    SeededInstructionTemplate {
        key: "workspace-agent-instructions",
        version: 1,
        name: "Workspace agent instructions",
        body: WORKSPACE_BODY,
    },
    SeededInstructionTemplate {
        key: "owner-onboarding-guidance",
        version: 2,
        name: "Owner onboarding guidance",
        body: OWNER_GUIDANCE_BODY,
    },
    SeededInstructionTemplate {
        key: "owner-onboarding-completion",
        version: 2,
        name: "Owner onboarding completion",
        body: OWNER_CRITERIA_BODY,
    },
    SeededInstructionTemplate {
        key: "member-onboarding-guidance",
        version: 2,
        name: "Member onboarding guidance",
        body: MEMBER_GUIDANCE_BODY,
    },
    SeededInstructionTemplate {
        key: "member-onboarding-completion",
        version: 2,
        name: "Member onboarding completion",
        body: MEMBER_CRITERIA_BODY,
    },
    SeededInstructionTemplate {
        key: "personal-agent-instructions",
        version: 1,
        name: "My agent instructions",
        body: PERSONAL_BODY,
    },
];

pub(crate) fn instruction_template(key: &str) -> Option<&'static SeededInstructionTemplate> {
    TEMPLATE_REGISTRY
        .iter()
        .find(|template| template.key == key)
}

struct Template<'a> {
    id: &'a str,
    key: &'a str,
    version: i64,
    name: &'a str,
    body: &'a str,
    home_id: &'a str,
    owner_id: Option<&'a str>,
}

async fn apply_template_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    template: Template<'_>,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT type,kind,name,body,home_id,owner_id,deleted_at FROM records WHERE id=?",
    )
    .bind(template.id)
    .fetch_optional(&mut **tx)
    .await?;
    let provenance = sqlx::query(
        "SELECT template_key,template_version,last_applied_digest
           FROM seeded_instruction_sources WHERE source_record_id=?",
    )
    .bind(template.id)
    .fetch_optional(&mut **tx)
    .await?;

    let mut applied_body = false;
    match (row, provenance.as_ref()) {
        (None, None) => {
            append_engine_provisioned_in(
                db,
                tx,
                AppendSpec {
                    record_id: template.id.into(),
                    event_type: "record.created".into(),
                    payload: json!({
                        "type": "Document",
                        "kind": "note",
                        "name": template.name,
                        "body": template.body,
                        "home_id": template.home_id,
                        "owner_id": template.owner_id,
                        "persistence": "enduring"
                    }),
                    actor: Some("engine:provisioning".into()),
                },
            )
            .await?;
            applied_body = true;
        }
        (None, Some(_)) => {
            return Err(Error::engine(format!(
                "seeded instruction source '{}' is missing its content record",
                template.id
            )))
        }
        (Some(row), None) => {
            // Adopting a record that already carries a reserved id. Refusing
            // here is the same lockout the reserved folder had: this runs on
            // connect, so the mismatch being reported is also what stops anyone
            // from repairing it. `type` cannot be changed by any event and the
            // projector refuses a tombstoned row, so those two stay refusals.
            if row.try_get::<String, _>("type")? != "Document"
                || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
            {
                return Err(Error::engine(format!(
                    "reserved seeded instruction record '{}' already exists with incompatible content",
                    template.id
                )));
            }

            let body = row.try_get::<Option<String>, _>("body")?;
            let mut restored = serde_json::Map::new();
            if row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("note") {
                restored.insert("kind".into(), json!("note"));
            }
            if row.try_get::<String, _>("name")? != template.name {
                restored.insert("name".into(), json!(template.name));
            }
            if row.try_get::<Option<String>, _>("home_id")?.as_deref() != Some(template.home_id) {
                restored.insert("home_id".into(), json!(template.home_id));
            }
            if row.try_get::<Option<String>, _>("owner_id")?.as_deref() != template.owner_id {
                restored.insert("owner_id".into(), json!(template.owner_id));
            }
            // The body is deliberately left alone. These documents exist to be
            // written in, and the provenance branch below already treats a body
            // that has diverged from `last_applied_digest` as the author's and
            // declines to overwrite it. Restoring it here would delete guidance
            // somebody wrote, which is a far worse failure than a stale name.
            if !restored.is_empty() {
                let drifted = restored
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                restored.insert(
                    "reason".into(),
                    json!(format!(
                        "engine provisioning restored reserved seeded instruction \
                         record fields ({drifted}) to their seeded values"
                    )),
                );
                append_in(
                    db,
                    tx,
                    AppendSpec {
                        record_id: template.id.into(),
                        event_type: "record.updated".into(),
                        payload: serde_json::Value::Object(restored),
                        actor: Some("engine:provisioning".into()),
                    },
                )
                .await?;
            }
            // Claim the template body was applied only when it actually is the
            // template body. Provenance is recorded either way, since there is
            // none yet — and recording the template digest against a body the
            // author has changed is what later makes the upgrade branch leave
            // that body alone.
            applied_body = body.as_deref() == Some(template.body);
        }
        (Some(row), Some(provenance)) => {
            let key: String = provenance.try_get("template_key")?;
            let version: i64 = provenance.try_get("template_version")?;
            if key != template.key {
                return Err(Error::engine(format!(
                    "seeded instruction source '{}' has incompatible template provenance",
                    template.id
                )));
            }
            if version > template.version {
                return Err(Error::engine(format!(
                    "seeded instruction source '{}' has future template version {version}",
                    template.id
                )));
            }
            if version < template.version {
                let current_body = row
                    .try_get::<Option<String>, _>("body")?
                    .unwrap_or_default();
                let last_digest: String = provenance.try_get("last_applied_digest")?;
                if instruction_body_digest(&current_body) == last_digest {
                    append_in(
                        db,
                        tx,
                        AppendSpec {
                            record_id: template.id.into(),
                            event_type: "record.updated".into(),
                            payload: json!({ "body": template.body }),
                            actor: Some("engine:provisioning".into()),
                        },
                    )
                    .await?;
                    applied_body = true;
                }
            }
        }
    }

    if provenance.is_none() || applied_body {
        let at = now_iso();
        append_control_event_in(
            tx,
            NewControlEvent::engine_provisioned(
                format!("seed:v1:template:{}:v{}", template.id, template.version),
                template.id,
                "record product-provided instruction template provenance",
                ControlEventPayload::SeededInstructionSourceApplied(
                    SeededInstructionSourceAppliedPayload {
                        source_record_id: template.id.into(),
                        template_key: template.key.into(),
                        template_version: template.version,
                        last_applied_digest: instruction_body_digest(template.body),
                        last_applied_at: at,
                        operation: None,
                        expected_body_digest: None,
                    },
                ),
            )?,
        )
        .await?;
    }
    Ok(())
}

async fn create_folder_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    id: &str,
    name: &str,
    home_id: &str,
    owner_id: Option<&str>,
) -> Result<bool> {
    let row =
        sqlx::query("SELECT type,kind,name,home_id,owner_id,deleted_at FROM records WHERE id=?")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(row) = row {
        // Drift here used to be fatal, and fatal at the worst possible moment:
        // provisioning runs on connect, so one mismatched field refused every
        // session — including the calls that would have repaired it. The folder's
        // identity is its ID and its placement is a product decision, so the
        // seeded values are authoritative and are restored rather than asserted.
        //
        // `record.updated` can carry kind, name, home_id and owner_id. It cannot
        // change `type`, and the projector refuses a tombstoned row, so those two
        // stay refusals: there is no event that repairs them, and a silent
        // half-reconciliation would be worse than saying so.
        if row.try_get::<String, _>("type")? != "Collection"
            || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
        {
            return Err(Error::engine(format!(
                "reserved instruction folder '{id}' already exists with incompatible content"
            )));
        }

        let mut restored = serde_json::Map::new();
        if row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("folder") {
            restored.insert("kind".into(), json!("folder"));
        }
        if row.try_get::<String, _>("name")? != name {
            restored.insert("name".into(), json!(name));
        }
        if row.try_get::<Option<String>, _>("home_id")?.as_deref() != Some(home_id) {
            restored.insert("home_id".into(), json!(home_id));
        }
        if row.try_get::<Option<String>, _>("owner_id")?.as_deref() != owner_id {
            restored.insert("owner_id".into(), json!(owner_id));
        }
        if !restored.is_empty() {
            let drifted = restored
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            restored.insert(
                "reason".into(),
                json!(format!(
                    "engine provisioning restored reserved instruction folder \
                     fields ({drifted}) to their seeded values"
                )),
            );
            // Ordinary admission: engine-provisioning admission accepts only
            // `record.created`, because its job is to authorize reserved
            // `native:` ids at mint time. The record already exists here.
            append_in(
                db,
                tx,
                AppendSpec {
                    record_id: id.into(),
                    event_type: "record.updated".into(),
                    payload: serde_json::Value::Object(restored),
                    actor: Some("engine:provisioning".into()),
                },
            )
            .await?;
        }
        // Reconciling is not creating: the caller uses this flag to gate the
        // one-time policy and binding setup, which must not run again here.
        return Ok(false);
    }
    append_engine_provisioned_in(
        db,
        tx,
        AppendSpec {
            record_id: id.into(),
            event_type: "record.created".into(),
            payload: json!({
                "type": "Collection",
                "kind": "folder",
                "name": name,
                "home_id": home_id,
                "owner_id": owner_id,
                "persistence": "enduring"
            }),
            actor: Some("engine:provisioning".into()),
        },
    )
    .await?;
    Ok(true)
}

async fn ensure_global_defaults_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    policy_actor: &str,
    trusted_owner_account_id: Option<&str>,
) -> Result<()> {
    let folder_created = create_folder_in(
        db,
        tx,
        INSTRUCTIONS_FOLDER_ID,
        "Agent instructions",
        ROOT_RECORD_ID,
        None,
    )
    .await?;
    for template in [
        Template {
            id: WORKSPACE_INSTRUCTIONS_ID,
            key: "workspace-agent-instructions",
            version: 1,
            name: "Workspace agent instructions",
            body: WORKSPACE_BODY,
            home_id: INSTRUCTIONS_FOLDER_ID,
            owner_id: None,
        },
        Template {
            id: OWNER_GUIDANCE_ID,
            key: "owner-onboarding-guidance",
            version: 2,
            name: "Owner onboarding guidance",
            body: OWNER_GUIDANCE_BODY,
            home_id: INSTRUCTIONS_FOLDER_ID,
            owner_id: None,
        },
        Template {
            id: OWNER_CRITERIA_ID,
            key: "owner-onboarding-completion",
            version: 2,
            name: "Owner onboarding completion",
            body: OWNER_CRITERIA_BODY,
            home_id: INSTRUCTIONS_FOLDER_ID,
            owner_id: None,
        },
        Template {
            id: MEMBER_GUIDANCE_ID,
            key: "member-onboarding-guidance",
            version: 2,
            name: "Member onboarding guidance",
            body: MEMBER_GUIDANCE_BODY,
            home_id: INSTRUCTIONS_FOLDER_ID,
            owner_id: None,
        },
        Template {
            id: MEMBER_CRITERIA_ID,
            key: "member-onboarding-completion",
            version: 2,
            name: "Member onboarding completion",
            body: MEMBER_CRITERIA_BODY,
            home_id: INSTRUCTIONS_FOLDER_ID,
            owner_id: None,
        },
    ] {
        apply_template_in(db, tx, template).await?;
    }
    if folder_created {
        let mut entries = vec![AllowEntry::members(Capability::View)];
        if let Some(owner) = trusted_owner_account_id {
            entries.push(AllowEntry::account(owner, Capability::Manage));
        }
        crate::authorization::replace_explicit_policy_on(
            tx,
            policy_actor,
            INSTRUCTIONS_FOLDER_ID,
            entries,
        )
        .await?;
    } else if let Some(owner) = trusted_owner_account_id {
        let rows = sqlx::query(
            "SELECT subject_kind,subject_id,capability FROM policy_entries
              WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id,effect",
        )
        .bind(INSTRUCTIONS_FOLDER_ID)
        .fetch_all(&mut **tx)
        .await?;
        let owner_has_manage = rows.iter().any(|row| {
            row.get::<String, _>("subject_kind") == "account"
                && row.get::<String, _>("subject_id") == owner
                && row.get::<String, _>("capability") == "manage"
        });
        if !owner_has_manage {
            let mut owners = rows
                .iter()
                .filter(|row| {
                    row.get::<String, _>("subject_kind") == "account"
                        && row.get::<String, _>("capability") == "manage"
                })
                .map(|row| row.get::<String, _>("subject_id"))
                .collect::<Vec<_>>();
            owners.push(owner.into());
            owners.sort();
            owners.dedup();
            let mut entries = vec![AllowEntry::members(Capability::View)];
            entries.extend(
                owners
                    .into_iter()
                    .map(|account| AllowEntry::account(account, Capability::Manage)),
            );
            crate::authorization::replace_explicit_policy_on(
                tx,
                policy_actor,
                INSTRUCTIONS_FOLDER_ID,
                entries,
            )
            .await?;
        }
    }

    if folder_created {
        let at = now_iso();
        append_control_event_in(
            tx,
            NewControlEvent::engine_provisioned(
                "seed:v1:binding:workspace-agent-instructions",
                WORKSPACE_BINDING_ID,
                "bind product-provided workspace agent instructions",
                ControlEventPayload::InstructionBindingCreated(InstructionBindingStatePayload {
                    id: WORKSPACE_BINDING_ID.into(),
                    scope_kind: "database".into(),
                    scope_id: DATABASE_SCOPE_ID.into(),
                    source_record_id: WORKSPACE_INSTRUCTIONS_ID.into(),
                    position: 100,
                    enabled: true,
                    created_by: "engine:seed".into(),
                    created_at: at.clone(),
                    updated_at: at,
                }),
            )?,
        )
        .await?;
    } else {
        let binding: Option<String> =
            sqlx::query_scalar("SELECT source_record_id FROM instruction_bindings WHERE id=?")
                .bind(WORKSPACE_BINDING_ID)
                .fetch_optional(&mut **tx)
                .await?;
        if binding.as_deref() != Some(WORKSPACE_INSTRUCTIONS_ID) {
            return Err(Error::engine(
                "workspace instruction seed has missing or incompatible binding",
            ));
        }
    }

    for (programme, source, role, position) in [
        (OWNER_PROGRAMME_ID, OWNER_GUIDANCE_ID, "guidance", 100),
        (
            OWNER_PROGRAMME_ID,
            OWNER_CRITERIA_ID,
            "completion_criteria",
            200,
        ),
        (MEMBER_PROGRAMME_ID, MEMBER_GUIDANCE_ID, "guidance", 100),
        (
            MEMBER_PROGRAMME_ID,
            MEMBER_CRITERIA_ID,
            "completion_criteria",
            200,
        ),
    ] {
        if folder_created {
            append_control_event_in(
                tx,
                NewControlEvent::engine_provisioned(
                    format!("seed:v1:programme-source:{programme}:{source}"),
                    programme_source_aggregate_id(programme, source),
                    "attach product-provided onboarding programme source",
                    ControlEventPayload::OnboardingProgrammeSourceAdded(
                        OnboardingProgrammeSourcePayload {
                            programme_id: programme.into(),
                            source_record_id: source.into(),
                            source_role: role.into(),
                            position,
                        },
                    ),
                )?,
            )
            .await?;
        } else {
            let actual: Option<(String, i64)> = sqlx::query(
                "SELECT source_role,position FROM onboarding_programme_sources
                  WHERE programme_id=? AND source_record_id=?",
            )
            .bind(programme)
            .bind(source)
            .fetch_optional(&mut **tx)
            .await?
            .map(|row| {
                Ok::<(String, i64), sqlx::Error>((
                    row.try_get("source_role")?,
                    row.try_get("position")?,
                ))
            })
            .transpose()?;
            if actual
                .as_ref()
                .map(|(actual_role, actual_position)| (actual_role.as_str(), *actual_position))
                != Some((role, position))
            {
                return Err(Error::engine(
                    "onboarding programme seed has missing or incompatible source",
                ));
            }
        }
    }
    Ok(())
}

async fn existing_context_root(
    tx: &mut Transaction<'static, Sqlite>,
    account_id: &str,
    person_record_id: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT person_record_id,root_record_id FROM member_contexts WHERE account_id=?",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        None => Ok(None),
        Some(row) => {
            let actual_person: String = row.try_get("person_record_id")?;
            if actual_person != person_record_id {
                return Err(Error::engine(
                    "portable member context points to a different person identity",
                ));
            }
            Ok(Some(row.try_get("root_record_id")?))
        }
    }
}

async fn provision_private_context_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    account_id: &str,
    person_record_id: &str,
) -> Result<()> {
    if existing_context_root(tx, account_id, person_record_id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let root_id = Uuid::new_v4().to_string();
    let document_id = Uuid::new_v4().to_string();
    create_folder_in(
        db,
        tx,
        &root_id,
        "My agent context",
        ROOT_RECORD_ID,
        Some(person_record_id),
    )
    .await?;
    apply_template_in(
        db,
        tx,
        Template {
            id: &document_id,
            key: "personal-agent-instructions",
            version: 1,
            name: "My agent instructions",
            body: PERSONAL_BODY,
            home_id: &root_id,
            owner_id: Some(person_record_id),
        },
    )
    .await?;
    crate::authorization::replace_explicit_policy_on(
        tx,
        account_id,
        &root_id,
        vec![AllowEntry::account(account_id, Capability::Manage)],
    )
    .await?;
    let at = now_iso();
    append_control_event_in(
        tx,
        NewControlEvent::engine_provisioned(
            format!("provision:v1:member-context:{account_id}"),
            account_id,
            "provision private portable member context",
            ControlEventPayload::MemberContextProvisioned(MemberContextProvisionedPayload {
                account_id: account_id.into(),
                person_record_id: person_record_id.into(),
                root_record_id: root_id,
                created_at: at.clone(),
            }),
        )?,
    )
    .await?;
    let binding_id = format!("native:binding-personal:{account_id}");
    append_control_event_in(
        tx,
        NewControlEvent::engine_provisioned(
            format!("provision:v1:personal-binding:{account_id}"),
            binding_id.clone(),
            "bind private member agent instructions",
            ControlEventPayload::InstructionBindingCreated(InstructionBindingStatePayload {
                id: binding_id,
                scope_kind: "account".into(),
                scope_id: account_id.into(),
                source_record_id: document_id,
                position: 100,
                enabled: true,
                created_by: account_id.into(),
                created_at: at.clone(),
                updated_at: at,
            }),
        )?,
    )
    .await?;
    Ok(())
}

async fn ensure_arrival_obligation_in(
    tx: &mut Transaction<'static, Sqlite>,
    account_id: &str,
    arrival: Option<&TrustedMembershipArrival>,
) -> Result<()> {
    if let Some(arrival) = arrival {
        arrival.validate()?;
    }
    let programme_id = match arrival {
        None => OWNER_PROGRAMME_ID,
        Some(value) if value.role == TrustedMembershipRole::Owner => OWNER_PROGRAMME_ID,
        Some(_) => MEMBER_PROGRAMME_ID,
    };
    let already_has_state: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM member_obligations WHERE account_id=? AND programme_id=?)",
    )
    .bind(account_id)
    .bind(programme_id)
    .fetch_one(&mut **tx)
    .await?;
    if already_has_state {
        return Ok(());
    }
    let programme = sqlx::query(
        "SELECT generation,legacy_baseline_before FROM onboarding_programmes
          WHERE id=? AND enabled=1",
    )
    .bind(programme_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("applicable onboarding programme is missing or disabled"))?;
    let generation: i64 = programme.try_get("generation")?;
    let cutoff: Option<String> = programme.try_get("legacy_baseline_before")?;
    let baselined = match (cutoff.as_deref(), arrival) {
        (Some(_), None) => true,
        (Some(cutoff), Some(arrival)) => {
            DateTime::parse_from_rfc3339(&arrival.created_at)
                .map_err(|_| Error::engine("trusted membership created_at must be RFC3339"))?
                <= DateTime::parse_from_rfc3339(cutoff)
                    .map_err(|_| Error::engine("programme rollout cutoff must be RFC3339"))?
        }
        (None, _) => false,
    };
    let at = now_iso();
    let state = if baselined { "completed" } else { "pending" };
    let payload = MemberObligationStatePayload {
        account_id: account_id.into(),
        programme_id: programme_id.into(),
        generation,
        state: state.into(),
        created_at: at.clone(),
        updated_at: at,
    };
    let (key_kind, reason, payload) = if baselined {
        (
            "baseline",
            "grandfather membership established before portable onboarding activation",
            ControlEventPayload::MemberObligationRolloutBaselined(payload),
        )
    } else {
        (
            "activate",
            "activate portable onboarding for first applicable member arrival",
            ControlEventPayload::MemberObligationActivated(payload),
        )
    };
    append_control_event_in(
        tx,
        NewControlEvent::engine_provisioned(
            format!("provision:v1:{key_kind}:{account_id}:{programme_id}:{generation}"),
            member_obligation_aggregate_id(account_id, programme_id, generation),
            reason,
            payload,
        )?,
    )
    .await?;
    Ok(())
}

/// Compose all member-specific and database-default provisioning into the
/// caller's identity transaction. Repeated calls are read-mostly no-ops; a
/// partial committed shape is treated as corruption because this function's
/// first write is all-or-nothing.
pub(crate) async fn provision_member_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    account_id: &str,
    person_record_id: &str,
    authority: MemberProvisioningAuthority<'_>,
) -> Result<bool> {
    let arrival = authority.arrival();
    let before: (i64, i64, i64) = (
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(&mut **tx)
            .await?,
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM policy_events")
            .fetch_one(&mut **tx)
            .await?,
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM control_events")
            .fetch_one(&mut **tx)
            .await?,
    );
    if let Some(arrival) = arrival {
        arrival.validate()?;
    }
    ensure_programmes_in(tx).await?;
    let trusted_owner = match authority {
        MemberProvisioningAuthority::Hosted(arrival)
            if arrival.role == TrustedMembershipRole::Owner =>
        {
            Some(account_id)
        }
        MemberProvisioningAuthority::Hosted(_) => None,
        // In stdio mode, file possession plus explicit account selection is the
        // authority boundary. On a multi-account file only the selected account
        // is elevated; an ambiguous unselected open fails before provisioning.
        MemberProvisioningAuthority::Standalone => Some(account_id),
    };
    ensure_global_defaults_in(db, tx, account_id, trusted_owner).await?;
    provision_private_context_in(db, tx, account_id, person_record_id).await?;
    ensure_arrival_obligation_in(tx, account_id, arrival).await?;
    crate::instructions::validate_account_stack_in(tx, "member provisioning", Some(account_id))
        .await?;
    let after: (i64, i64, i64) = (
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(&mut **tx)
            .await?,
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM policy_events")
            .fetch_one(&mut **tx)
            .await?,
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM control_events")
            .fetch_one(&mut **tx)
            .await?,
    );
    Ok(before != after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratified_onboarding_corpus_is_digest_pinned() {
        assert_eq!(
            instruction_body_digest(OWNER_GUIDANCE_BODY),
            "352768499a487cfa648cad742e3db898d92983eb71b621679f79d0f96ccd136b"
        );
        assert_eq!(
            instruction_body_digest(OWNER_CRITERIA_BODY),
            "e418caad78e957e5908ef0dfcca753f052d9dd80fe1ae6307047c972d9267569"
        );
        assert_eq!(
            instruction_body_digest(MEMBER_GUIDANCE_BODY),
            "d5dae1587a480bb51d782e9e84ea12c2fd6c1bb70f41a4f30253d1e09823a1ac"
        );
        assert_eq!(
            instruction_body_digest(MEMBER_CRITERIA_BODY),
            "386c459c81c6c5d829cd163258523f5251e7059ef1be753271bcfb1af71d0526"
        );
        assert!(OWNER_GUIDANCE_BODY.contains("concrete work"));
        assert!(MEMBER_GUIDANCE_BODY.contains("Do not conduct an owner interview"));
        for body in [OWNER_GUIDANCE_BODY, MEMBER_GUIDANCE_BODY] {
            assert!(body.contains("explicit consent"));
            assert!(body.contains("Do not infer"));
            assert!(body.contains("non-terminal"));
            assert!(body.to_lowercase().contains("shared"));
            assert!(body.contains("Starting context"));
            assert!(body.contains("preview text"));
            assert!(body.contains("workspace record by default"));
            assert!(body.contains("must not force concrete work or an artifact"));
            assert!(body.contains("`route_selected`"));
            assert!(body.contains("`value_delivered`"));
        }
    }
}
