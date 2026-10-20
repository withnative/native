//! S1: owner-locked persona profiles, registration, retirement and discovery.
use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, require_nonblank_reason, require_record_in};
use crate::authorization::{AllowEntry, Capability};
use crate::db::Db;
use crate::store::{append_in, AppendSpec};
use crate::{Error, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum Args {
    RegisterPersona {
        name: Option<String>,
        body: Option<String>,
        record_id: Option<String>,
        home_id: Option<String>,
        facets: Option<std::collections::BTreeMap<String, Value>>,
        reason: String,
        idempotency_key: Option<String>,
    },
    RetirePersona {
        persona_id: String,
        reason: String,
        idempotency_key: Option<String>,
    },
    List,
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn validate_kernel_arguments(args: &Value) -> Result<()> {
    parse_args::<Args>("manage_participants", args.clone()).map(|_| ())
}

async fn owner(conn: &mut sqlx::SqliteConnection, caller: &Caller) -> Result<(String, String)> {
    let people: Vec<(String,String)> = sqlx::query_as("SELECT r.id,p.identifier FROM records r
        JOIN bindings a ON a.record_id=r.id AND a.system='account' AND a.is_canonical=1 AND a.identifier=?
        JOIN bindings p ON p.record_id=r.id AND p.system='native-principal' AND p.is_canonical=1
        WHERE r.type='Entity' AND r.kind='person' AND r.deleted_at IS NULL")
        .bind(caller.credential()).fetch_all(conn).await?;
    match people.as_slice() {
        [(id, principal)] => Ok((id.clone(), principal.clone())),
        _ => Err(Error::engine(
            "manage_participants requires one canonical owner Person and principal",
        )),
    }
}

/// Replay renderer for a keyed `register_persona` (keyed-replay contract,
/// `keyed_replay`): the persona id is the record the registration event
/// landed on, whether the command created the profile or adopted an existing
/// one.
fn replay_registration(replay: &super::keyed_replay::KeyedReplay) -> Result<Value> {
    let id = replay
        .content()
        .iter()
        .find(|event| event.event_type == "persona.registered.v1")
        .map(|event| event.record_id.clone())
        .ok_or_else(|| Error::engine("manage_participants: idempotent receipt is incomplete"))?;
    super::echo_act(
        json!({"id":id,"persona_id":id,"participant_address":format!("persona:{id}"),"state":"active"}),
        replay.act(),
    )
}

/// Check the persona's facet values against the caller's current schema.
/// Runs after the keyed replay lookup: a vocabulary value deprecated since a
/// committed first call must not turn its retry into a validation failure.
async fn assert_register_facets_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    facet_writes: &mut [super::lifecycle::FacetWrite],
) -> Result<()> {
    let schema = crate::query::cascade::schema_config_rows_for_principal_on(
        tx,
        Some(super::principal(caller)),
    )
    .await?;
    super::lifecycle::assert_facet_value_predicates_in(
        tx,
        &schema,
        "register_persona",
        "Entity",
        Some("persona"),
        None,
        facet_writes,
    )
    .await
}

async fn manage_participants(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    // The exact dispatched arguments: a keyed lookup recomputes their digest.
    let provenance_arguments = arguments.clone();
    let args: Args = parse_args("manage_participants", arguments)?;
    let mut tx = if matches!(&args, Args::List) {
        db.write_pool().begin().await?
    } else {
        crate::db::begin_write(db.write_pool()).await?
    };
    let (owner_id, owner_principal) = owner(&mut tx, &caller).await?;
    let mut act = crate::act::ActAllocation::new();
    let result = match args {
        Args::RegisterPersona {
            name,
            body,
            record_id,
            home_id,
            facets,
            reason,
            idempotency_key,
        } => {
            require_nonblank_reason("register_persona", &reason)?;
            let keyed = super::keyed_replay::idempotency_key(
                "manage_participants",
                idempotency_key.as_deref(),
            )?
            .is_some();
            for (field, value) in [
                ("name", name.as_deref()),
                ("body", body.as_deref()),
                ("record_id", record_id.as_deref()),
                ("home_id", home_id.as_deref()),
            ] {
                if value.is_some_and(|value| value.trim().is_empty()) {
                    return Err(Error::engine(format!(
                        "register_persona: {field} must not be blank"
                    )));
                }
            }
            let mut facet_writes = Vec::new();
            for (key, value) in facets.iter().flatten() {
                if let Some(write) =
                    super::lifecycle::parse_facet_entry("register_persona", key, value, false)?
                {
                    facet_writes.push(write);
                }
            }
            let id = if let Some(id) = record_id {
                require_record_in(
                    &mut tx,
                    &caller,
                    "register_persona",
                    &id,
                    Capability::Manage,
                )
                .await?;
                // Keyed replay: after the Manage check, before the facet
                // vocabulary check (a value deprecated since the first call
                // must not break a retry) and the unregistered check the
                // first registration's own effect would now trip.
                if keyed {
                    if let Some(replay) = super::keyed_replay::keyed_replay_in(
                        &mut tx,
                        &caller,
                        "manage_participants",
                        &provenance_arguments,
                    )
                    .await?
                    {
                        let receipt = replay_registration(&replay)?;
                        tx.rollback().await?;
                        replay.settle();
                        return Ok(receipt);
                    }
                }
                assert_register_facets_in(&mut tx, &caller, &mut facet_writes).await?;
                crate::persona::require_unregistered(&mut tx, &id, "register_persona").await?;
                let row = sqlx::query(
                    "SELECT type,kind,owner_id FROM records WHERE id=? AND deleted_at IS NULL",
                )
                .bind(&id)
                .fetch_one(&mut *tx)
                .await?;
                if row.try_get::<String, _>("type")? != "Entity"
                    || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("persona")
                    || row.try_get::<Option<String>, _>("owner_id")?.as_deref() != Some(&owner_id)
                {
                    return Err(Error::engine(
                        "register_persona requires the caller's owned Entity/persona profile",
                    ));
                }
                if name.is_some() || body.is_some() || home_id.is_some() {
                    return Err(Error::engine(
                        "register_persona: edit an existing profile with update_record",
                    ));
                }
                let entries =
                    crate::authorization::effective_policy_entries_on(&mut tx, &id).await?;
                if entries.iter().any(|entry| {
                    entry.subject
                        != crate::authorization::PolicySubject::Account(caller.credential().into())
                }) {
                    return Err(Error::engine("register_persona: existing profile must already be owner-only; make its policy owner-only before registering"));
                }
                id
            } else {
                let name = name
                    .filter(|n| !n.trim().is_empty())
                    .ok_or_else(|| Error::engine("register_persona requires a nonblank name"))?;
                let home = home_id.unwrap_or_else(|| crate::schema::UNFILED_RECORD_ID.into());
                require_record_in(
                    &mut tx,
                    &caller,
                    "register_persona",
                    &home,
                    Capability::Edit,
                )
                .await?;
                // Keyed replay: after the home-edit check, before the facet
                // vocabulary check (see above) and before a fresh persona id
                // is minted.
                if keyed {
                    if let Some(replay) = super::keyed_replay::keyed_replay_in(
                        &mut tx,
                        &caller,
                        "manage_participants",
                        &provenance_arguments,
                    )
                    .await?
                    {
                        let receipt = replay_registration(&replay)?;
                        tx.rollback().await?;
                        replay.settle();
                        return Ok(receipt);
                    }
                }
                assert_register_facets_in(&mut tx, &caller, &mut facet_writes).await?;
                let id = uuid::Uuid::new_v4().to_string();
                append_in(&db,&mut tx,AppendSpec { record_id:id.clone(),event_type:"record.created".into(),payload:json!({"type":"Entity","kind":"persona","name":name,"body":body,"home_id":home,"owner_id":owner_id,"reason":reason}),actor:Some(caller.actor().into()) },&mut act).await?;
                id
            };
            for write in &facet_writes {
                append_in(
                    &db,
                    &mut tx,
                    super::lifecycle::facet_set_spec(&id, write, caller.actor()),
                    &mut act,
                )
                .await?;
            }
            // Install the private boundary before locking identity, atomically.
            crate::authorization::replace_explicit_policy_on(
                &mut tx,
                caller.actor(),
                &id,
                vec![AllowEntry::account(caller.credential(), Capability::Manage)],
                &mut act,
            )
            .await?;
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: id.clone(),
                    event_type: "persona.registered.v1".into(),
                    payload: json!({"owner_person_id":owner_id,"owner_principal":owner_principal}),
                    actor: Some(caller.actor().into()),
                },
                &mut act,
            )
            .await?;
            json!({"id":id,"persona_id":id,"participant_address":format!("persona:{id}"),"state":"active"})
        }
        Args::RetirePersona {
            persona_id,
            reason,
            idempotency_key,
        } => {
            require_nonblank_reason("retire_persona", &reason)?;
            let keyed = super::keyed_replay::idempotency_key(
                "manage_participants",
                idempotency_key.as_deref(),
            )?
            .is_some();
            require_record_in(
                &mut tx,
                &caller,
                "retire_persona",
                &persona_id,
                Capability::Manage,
            )
            .await?;
            // Keyed replay: after the Manage check, before the active-state
            // check the first retirement's own effect would now fail.
            if keyed {
                if let Some(replay) = super::keyed_replay::keyed_replay_in(
                    &mut tx,
                    &caller,
                    "manage_participants",
                    &provenance_arguments,
                )
                .await?
                {
                    if replay.content().len() != 1 {
                        return Err(Error::engine(
                            "manage_participants: idempotent receipt is incomplete",
                        ));
                    }
                    let receipt = super::echo_act(
                        json!({"id":persona_id,"persona_id":persona_id,"state":"retired"}),
                        replay.act(),
                    )?;
                    tx.rollback().await?;
                    replay.settle();
                    return Ok(receipt);
                }
            }
            let valid: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM personas WHERE persona_id=? AND owner_person_id=? AND owner_principal=? AND state='active')")
                .bind(&persona_id).bind(&owner_id).bind(&owner_principal).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(Error::engine("persona does not exist or is not active"));
            }
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: persona_id.clone(),
                    event_type: "persona.retired.v1".into(),
                    payload: json!({"reason":reason}),
                    actor: Some(caller.actor().into()),
                },
                &mut act,
            )
            .await?;
            json!({"id":persona_id,"persona_id":persona_id,"state":"retired"})
        }
        Args::List => {
            let rows=sqlx::query("SELECT p.persona_id,p.state,r.name FROM personas p JOIN records r ON r.id=p.persona_id WHERE p.owner_person_id=? AND p.owner_principal=? AND r.deleted_at IS NULL ORDER BY p.persona_id")
                .bind(&owner_id).bind(&owner_principal).fetch_all(&mut *tx).await?;
            let mut participants = Vec::new();
            for row in rows {
                let id: String = row.try_get("persona_id")?;
                if !super::can_record_in(&mut tx, &caller, &id, Capability::View).await? {
                    continue;
                }
                participants.push(json!({"kind":"persona","persona_id":row.try_get::<String,_>("persona_id")?,"participant_address":format!("persona:{}",row.try_get::<String,_>("persona_id")?),"display_name":row.try_get::<String,_>("name")?,"state":row.try_get::<String,_>("state")?}));
            }
            tx.rollback().await?;
            return Ok(json!({"participants":participants}));
        }
    };
    super::keyed_replay::anchor_noop_in(&mut tx).await?;
    db.commit_content(tx).await?;
    super::echo_act(result, act.get())
}

pub fn register_participant_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(ToolKind::ManageParticipants,
        "Register, retire or list owner-only Entity/persona profiles. No grants; retirement preserves history.",
        json!({"type":"object","oneOf":[
            {"type":"object","properties":{
                "action":{"const":"register_persona"},
                "facets":{"type":"object","additionalProperties":true},"name":{"type":"string","pattern":"\\S"},"body":{"type":"string","pattern":"\\S"},"home_id":{"type":"string","pattern":"\\S"},"record_id":{"type":"string","pattern":"\\S"},"reason":{"type":"string","pattern":"\\S"},
                "idempotency_key":super::keyed_replay::idempotency_key_schema()
            },"required":["action","reason"],"additionalProperties":false,"not":{"anyOf":[{"required":["record_id","body"]},{"required":["record_id","home_id"]}]},"oneOf":[
                {"required":["name"]},
                {"required":["record_id"]}
            ]},
            {"type":"object","properties":{"action":{"const":"retire_persona"},"persona_id":{"type":"string","pattern":"\\S"},"reason":{"type":"string","pattern":"\\S"},"idempotency_key":super::keyed_replay::idempotency_key_schema()},"required":["action","persona_id","reason"],"additionalProperties":false},
            {"type":"object","properties":{"action":{"const":"list"}},"required":["action"],"additionalProperties":false}
        ]}),|db, caller, arguments| {
            super::keyed_replay::with_race_replay(move || {
                Box::pin(manage_participants(db.clone(), caller.clone(), arguments.clone()))
            })
        })
}

#[cfg(test)]
#[path = "participants_tests.rs"]
pub(crate) mod tests;
