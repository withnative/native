//! Read-only configuration preserved by the sealed W8 import. Mutations remain
//! unavailable; a successful list never claims delivery or editing authority.
use super::*;
use crate::authorization::Capability;
use sqlx::SqliteConnection;

const INSTRUCTIONS_READ_ONLY: &str = "Changing instruction bindings and seeded defaults isn't available on this workspace yet. You can read the current instructions and open their source records. Names for the original defaults aren't available.";
const ONBOARDING_READ_ONLY: &str = "Changing onboarding programmes isn't available on this workspace yet. Imported programmes are read-only; automatic delivery is disabled. Names for the original defaults aren't available.";

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    Workspace,
    Member,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Instructions {
    List { scope: Option<Scope> },
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Onboarding {
    ListProgrammes,
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    for (tool, selectors, message) in [
        ("manage_instructions", &["list"][..], INSTRUCTIONS_READ_ONLY),
        (
            "manage_onboarding",
            &["list_programmes"][..],
            ONBOARDING_READ_ONLY,
        ),
    ] {
        registry.register_engine_handler_for_selector_values(
            tool,
            EngineKind::KernelV2,
            "action",
            selectors,
            move |engine, caller, args| async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                match (tool, args["action"].as_str()) {
                    ("manage_instructions", Some("list")) => {
                        let Instructions::List { scope } = parse(tool, args)?;
                        instructions(&db, &actor, &caller, scope).await
                    }
                    ("manage_onboarding", Some("list_programmes")) => {
                        let Onboarding::ListProgrammes = parse(tool, args)?;
                        onboarding(&db, &actor, &caller).await
                    }
                    _ => Err::<Value, Error>(Error::engine(message)),
                }
            },
        )?;
    }
    Ok(())
}

async fn owner_on(conn: &mut SqliteConnection, actor: &str, caller: &Caller) -> Result<bool> {
    // Host owner footing is explicit. Standalone accounts need actual kernel
    // root Manage, not is_host_owner()'s historical no-host default.
    Ok(caller.counter_footing().is_owner()
        || (caller.hosting_database().is_none()
            && !caller.is_member_copy()
            && kernel::kernel_effective_capability_on(conn, actor, crate::events::KERNEL_ROOT_ID)
                .await?
                .allows(Capability::Manage)))
}

async fn instructions(
    db: &Db,
    actor: &str,
    caller: &Caller,
    scope: Option<Scope>,
) -> Result<Value> {
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let owner = owner_on(&mut tx, actor, caller).await?;
    let rows:Vec<(String,String,String,i64,bool)>=sqlx::query_as("SELECT id,scope_kind,source_record_id,position,enabled FROM main.kernel_instruction_bindings WHERE (scope_kind='database' AND scope_id='native:database' AND ?) OR (scope_kind='account' AND account_principal=? AND ?) ORDER BY CASE scope_kind WHEN 'database' THEN 0 ELSE 1 END,position,id")
        .bind(!matches!(scope,Some(Scope::Member))).bind(actor).bind(!matches!(scope,Some(Scope::Workspace))).fetch_all(&mut *tx).await?;
    let mut bindings = vec![];
    for (id, scope, source, position, enabled) in rows {
        let record = kernel::read_record_on(&mut tx, actor, &source).await?;
        let Some(record) = record else {
            if scope == "database" && !owner {
                continue;
            }
            if scope == "database" && owner {
                return Err(Error::auth(format!(
                    "manage_instructions: workspace instruction source {source} is not readable. Workspace ownership does not override a record's private access policy. Ask the record owner to grant you access."
                )));
            }
            return Err(Error::auth(
                "manage_instructions: an instruction source is not readable",
            ));
        };
        let primary: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM main.kernel_records WHERE id=?")
                .bind(&source)
                .fetch_one(&mut *tx)
                .await?;
        let (typ, _) = v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|p| p.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        );
        if scope == "database" && !owner && typ != Some("Document") {
            continue;
        }
        bindings.push(json!({"id":id,"scope":if scope=="database" {"workspace"}else{"member"},"source_record_id":source,"position":position,"enabled":enabled,
            "source_title":record.fields.get("title").and_then(Value::as_str).unwrap_or(""),"source_updated_at":kernel::record_metadata::updated_at_on(&mut tx,&source).await?,
            "seed":{"template_key":null,"template_version":null,"last_applied_digest":null}}));
    }
    Ok(
        json!({"bindings":bindings,"limit_bytes":crate::instructions::MAX_RESOLVED_INSTRUCTION_BYTES,"mutations_available":false,"unavailable_message":INSTRUCTIONS_READ_ONLY,"template_provenance":"unavailable_in_imported_projection"}),
    )
}

#[derive(Deserialize)]
struct Programme {
    id: String,
    trigger_key: String,
    generation: i64,
    position: i64,
    enabled: Value,
    legacy_baseline_before: Option<String>,
}
#[derive(Deserialize)]
struct ProgrammeSource {
    programme_id: String,
    source_record_id: String,
    source_role: String,
    position: i64,
}
#[derive(Deserialize)]
struct Obligation {
    programme_id: String,
    state: String,
}
async fn decoded_rows<T: serde::de::DeserializeOwned>(
    conn: &mut SqliteConnection,
    section: &str,
) -> Result<Vec<T>> {
    kernel::v1_state::rows_on(conn, section)
        .await?
        .into_iter()
        .map(|v| {
            serde_json::from_value(v).map_err(|_| {
                Error::engine("manage_onboarding: imported programme state is invalid")
            })
        })
        .collect()
}
async fn onboarding(db: &Db, actor: &str, caller: &Caller) -> Result<Value> {
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    if !owner_on(&mut tx, actor, caller).await? {
        return Err(Error::auth(
            "manage_onboarding: database owner host role required",
        ));
    }
    let mut programmes: Vec<Programme> = decoded_rows(&mut tx, "onboarding_programmes").await?;
    programmes.sort_by(|a, b| (&a.position, &a.id).cmp(&(&b.position, &b.id)));
    let sources: Vec<ProgrammeSource> =
        decoded_rows(&mut tx, "onboarding_programme_sources").await?;
    let obligations: Vec<Obligation> = decoded_rows(&mut tx, "member_obligations").await?;
    let mut result = vec![];
    for programme in programmes {
        let enabled = match programme.enabled {
            Value::Bool(v) => v,
            Value::Number(n) if n.as_i64() == Some(0) => false,
            Value::Number(n) if n.as_i64() == Some(1) => true,
            _ => {
                return Err(Error::engine(
                    "manage_onboarding: imported programme state is invalid",
                ))
            }
        };
        let mut selected: Vec<_> = sources
            .iter()
            .filter(|s| s.programme_id == programme.id)
            .collect();
        selected.sort_by(|a, b| {
            (&a.position, &a.source_record_id).cmp(&(&b.position, &b.source_record_id))
        });
        let mut entries = vec![];
        for source in selected {
            let id = &source.source_record_id;
            let Some(record) = kernel::read_record_on(&mut tx, actor, id).await? else {
                return Err(Error::auth(
                    "manage_onboarding: a programme instruction source is not readable",
                ));
            };
            entries.push(json!({"source_record_id":id,"source_title":record.fields.get("title").and_then(Value::as_str).unwrap_or(""),"source_role":source.source_role,"position":source.position,"source_updated_at":kernel::record_metadata::updated_at_on(&mut tx,id).await?,"seed":{"template_key":null,"template_version":null,"last_applied_digest":null,"last_applied_at":null}}));
        }
        result.push(json!({"id":programme.id,"trigger_key":programme.trigger_key,"generation":programme.generation,"position":programme.position,"enabled":enabled,"legacy_baseline_before":programme.legacy_baseline_before,"pending_count":obligations.iter().filter(|o|o.programme_id==programme.id && o.state=="pending").count(),"sources":entries}));
    }
    Ok(
        json!({"programmes":result,"mutations_available":false,"unavailable_message":ONBOARDING_READ_ONLY,"template_provenance":"unavailable_in_imported_projection","delivery_enabled":false}),
    )
}
