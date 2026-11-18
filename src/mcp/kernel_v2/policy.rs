//! V1 policy-list shape over the kernel's own authority and policy snapshot.
use super::*;
use crate::authorization::Capability;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    action: String,
    record_id: String,
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let mut schema = registry
        .get("manage_record_policy")
        .ok_or_else(|| Error::engine("missing policy descriptor"))?
        .input_schema
        .clone();
    for branch in schema["oneOf"]
        .as_array_mut()
        .ok_or_else(|| Error::engine("missing policy action schema"))?
    {
        let action = branch["properties"]["action"]["const"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !matches!(action.as_str(), "list" | "inspect" | "set_many") {
            branch["properties"]["if_content_seq"] = json!({"type":"integer","minimum":1,"description":"Optional exact content event sequence for this target."});
        }
        if action == "restore_inheritance" {
            branch["properties"]["if_inherited_policy_revision"] =
                json!({"type":"string","minLength":1});
        }
        if action == "set_many" {
            branch["properties"]["items"]["items"]["properties"]["if_content_seq"] =
                json!({"type":"integer","minimum":1});
            branch["properties"]["items"]["items"]["properties"]["if_policy_revision"] =
                json!({"type":"string","minLength":1});
        }
    }
    fn person_guards(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if let Some(properties) =
                    object.get_mut("properties").and_then(Value::as_object_mut)
                {
                    if properties.contains_key("person_record_id") {
                        properties.insert(
                            "if_account_id".into(),
                            json!({"type":"string","minLength":1}),
                        );
                    }
                }
                for child in object.values_mut() {
                    person_guards(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    person_guards(child);
                }
            }
            _ => {}
        }
    }
    person_guards(&mut schema);
    registry.set_kernel_v2_schema("manage_record_policy", schema)?;
    registry.register_engine_handler_for_selector_values(
        "manage_record_policy",
        EngineKind::KernelV2,
        "action",
        &[
            "inspect",
            "list",
            "grant",
            "revoke",
            "replace",
            "restore_inheritance",
            "set_many",
            "set_members_baseline",
        ],
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            let read = matches!(args["action"].as_str(), Some("list" | "inspect"));
            let value = if args["action"] == "list" {
                list(&db, &actor, &caller, args).await?
            } else if args["action"] == "inspect" {
                inspect(&db, &actor, &caller, args).await?
            } else {
                mutate(&db, &actor, &caller, args).await?
            };
            if read {
                if let Some(app) = caller.host_asserted_app() {
                    kernel::app_installs::admit_account_app_as(&db, caller.credential(), app)
                        .await?;
                }
            }
            Ok(value)
        },
    )
}
fn missing() -> Error {
    Error::engine("manage_record_policy: record does not exist")
}
async fn list(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let args: Args = parse("manage_record_policy", args)?;
    if args.action != "list" {
        return Err(Error::engine("policy list action required"));
    }
    let root_operator = caller.counter_footing().is_owner()
        && ["native:root", crate::events::KERNEL_ROOT_ID].contains(&args.record_id.as_str());
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    // Authorize before decoding or describing a policy: malformed descriptions
    // are repair information for administrators, never a View-only oracle.
    let target = if args.record_id == "native:root" {
        crate::events::KERNEL_ROOT_ID
    } else {
        args.record_id.as_str()
    };
    let capability = kernel::kernel_effective_capability_on(&mut tx, actor, target)
        .await
        .map_err(|e| match e {
            Error::Engine(s) if s == kernel::HIDDEN_OR_MISSING => missing(),
            e => e,
        })?;
    let authorized = capability.allows(Capability::Manage) || root_operator;
    if !authorized {
        return Err(missing());
    }
    if kernel::is_message_record(&mut tx, target).await? {
        return Err(Error::engine(
            "manage_record_policy: Message access uses its sealed audience; a home policy listing does not describe Message access and isn't available on v2 yet",
        ));
    }
    let snapshot = kernel::policy_read::snapshot_on(&mut tx, actor, target, root_operator).await?;
    if kernel::is_message_record(&mut tx, &snapshot.target).await? {
        return Err(Error::engine(
            "manage_record_policy: Message access uses its sealed audience; a home policy listing does not describe Message access and isn't available on v2 yet",
        ));
    }
    let mut entries = Vec::new();
    for entry in snapshot.entries {
        let subject = if entry.kind == "members" {
            json!({"kind":"members"})
        } else {
            let identity = identity_read::principal_identity_on(&mut tx,actor,&entry.subject).await?
                .ok_or_else(|| Error::engine("policy contains a non-portable subject; its complete listing is not yet available on v2"))?;
            let person = if let Some(id) = identity.person_id {
                kernel::read_record_on(&mut tx,actor,&id).await?.map(|record| {
                    json!({"record_id":id,"name":record.fields.get("title").or_else(||record.fields.get("name"))})
                })
            } else {
                None
            };
            json!({"kind":"account","account_id":identity.account_id,"person":person})
        };
        entries.push(json!({"subject":subject,"capability":entry.capability}));
    }
    entries.sort_by_key(|e| {
        (
            e["subject"]["kind"].as_str().unwrap_or_default().to_owned(),
            e["subject"]["account_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    });
    tx.rollback().await?;
    let target =
        if args.record_id == "native:root" && snapshot.target == crate::events::KERNEL_ROOT_ID {
            "native:root".into()
        } else {
            snapshot.target
        };
    Ok(
        json!({"record_id":args.record_id,"authorization_target_id":target,"mode":snapshot.mode,
        "anchor_id":snapshot.anchor,"caller_capability":snapshot.capability.as_policy_str().unwrap_or("none"),
        "policy_administration_authorized":authorized,"entries":entries,"policy_revision":snapshot.revision}),
    )
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputCapability {
    View,
    Edit,
    Manage,
}
impl From<InputCapability> for Capability {
    fn from(value: InputCapability) -> Self {
        match value {
            InputCapability::View => Self::View,
            InputCapability::Edit => Self::Edit,
            InputCapability::Manage => Self::Manage,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum Subject {
    Members,
    Account {
        account_id: String,
    },
    Person {
        person_record_id: String,
        if_account_id: Option<String>,
    },
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementEntry {
    subject: Subject,
    capability: InputCapability,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetItem {
    record_id: String,
    subject: Subject,
    capability: Option<InputCapability>,
    if_policy_revision: Option<String>,
    if_content_seq: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum MutationArgs {
    Grant {
        record_id: String,
        subject: Subject,
        capability: InputCapability,
        if_policy_revision: Option<String>,
        if_content_seq: Option<i64>,
        reason: String,
    },
    Revoke {
        record_id: String,
        subject: Subject,
        if_policy_revision: Option<String>,
        if_content_seq: Option<i64>,
        reason: String,
    },
    SetMembersBaseline {
        record_id: String,
        capability: Option<InputCapability>,
        if_policy_revision: Option<String>,
        if_content_seq: Option<i64>,
        reason: String,
    },
    Replace {
        record_id: String,
        entries: Vec<ReplacementEntry>,
        if_policy_revision: String,
        if_content_seq: Option<i64>,
        reason: String,
    },
    RestoreInheritance {
        record_id: String,
        if_policy_revision: String,
        if_content_seq: Option<i64>,
        if_inherited_policy_revision: Option<String>,
        reason: String,
    },
    SetMany {
        items: Vec<SetItem>,
        reason: String,
    },
}

use native_policy_kernel::{
    AllowEntry, PolicyMode, PolicyMutation, PolicySnapshot, PolicySubject, PolicyTransition,
};
use std::collections::{BTreeMap, BTreeSet};

fn shared(snapshot: &kernel::policy_read::Snapshot) -> Result<PolicySnapshot> {
    Ok(PolicySnapshot {
        mode: if snapshot.mode == "explicit" {
            PolicyMode::Explicit
        } else {
            PolicyMode::Inherit
        },
        anchor_id: snapshot.anchor.clone(),
        revision: snapshot.revision.clone(),
        entries: snapshot
            .entries
            .iter()
            .map(|entry| {
                Ok(AllowEntry {
                    subject: if entry.kind == "members" {
                        PolicySubject::Members
                    } else {
                        PolicySubject::Account(entry.subject.clone())
                    },
                    capability: Capability::from_policy_str(&entry.capability)
                        .ok_or_else(|| Error::engine("invalid stored policy capability"))?,
                })
            })
            .collect::<Result<_>>()?,
    })
}
fn state(snapshot: &PolicySnapshot) -> Value {
    json!({"mode":snapshot.mode,"anchor_id":snapshot.anchor_id})
}
fn after_virtual(before: &PolicySnapshot, transition: &PolicyTransition) -> PolicySnapshot {
    PolicySnapshot {
        mode: transition.after_mode(),
        anchor_id: transition.after_anchor_id().into(),
        revision: before.revision.clone(),
        entries: transition
            .after_normalized()
            .iter()
            .map(|entry| AllowEntry {
                subject: if entry.subject_kind == "members" {
                    PolicySubject::Members
                } else {
                    PolicySubject::Account(entry.subject_id.clone())
                },
                capability: Capability::from_policy_str(&entry.capability)
                    .expect("shared planner emits valid capabilities"),
            })
            .collect(),
    }
}
fn assert_revision(actual: &str, expected: Option<&str>) -> Result<()> {
    if let Some(expected) = expected {
        if expected.trim().is_empty() || actual != expected {
            return Err(Error::conflict(
                "policy revision conflict; list the policy and retry",
            ));
        }
    }
    Ok(())
}
async fn account_on(conn: &mut sqlx::SqliteConnection, account: &str) -> Result<String> {
    sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(account)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| Error::engine("policy subject account is not bound"))
}
async fn subject_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    subject: Subject,
) -> Result<PolicySubject> {
    match subject {
        Subject::Members => Ok(PolicySubject::Members),
        Subject::Account { account_id } => {
            Ok(PolicySubject::Account(account_on(conn, &account_id).await?))
        }
        Subject::Person {
            person_record_id,
            if_account_id,
        } => {
            kernel::read_record_on(conn, actor, &person_record_id)
                .await?
                .ok_or_else(missing)?;
            // The existing kernel identity association is canonical. Neither
            // labels nor caller-supplied bindings can provision an account.
            let account:Option<String>=sqlx::query_scalar("SELECT p.auth_binding FROM kernel_message_people m JOIN kernel_principals p ON p.principal_id=m.principal_id WHERE m.person_id=? AND p.kind='account'")
                .bind(&person_record_id).fetch_optional(&mut *conn).await?;
            let account = account
                .ok_or_else(|| Error::engine("policy Person has no canonical account identity"))?;
            if if_account_id
                .as_ref()
                .is_some_and(|expected| expected != &account)
            {
                return Err(Error::conflict("policy Person account binding changed"));
            }
            Ok(PolicySubject::Account(account_on(conn, &account).await?))
        }
    }
}

async fn authorized_snapshot(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    caller: &Caller,
    requested: &str,
) -> Result<kernel::policy_read::Snapshot> {
    let target = if requested == "native:root" {
        crate::events::KERNEL_ROOT_ID
    } else {
        requested
    };
    let root_operator =
        caller.counter_footing().is_owner() && target == crate::events::KERNEL_ROOT_ID;
    let capability = kernel::kernel_effective_capability_on(conn, actor, target)
        .await
        .map_err(|_| missing())?;
    if !capability.allows(Capability::Manage) && !root_operator {
        return Err(missing());
    }
    if kernel::is_message_record(conn, target).await? {
        return Err(Error::engine("Message access uses its sealed audience"));
    }
    let snapshot = kernel::policy_read::snapshot_on(conn, actor, target, root_operator).await?;
    if snapshot.target != target {
        return Err(Error::engine(
            "policy mutations must explicitly target the terminal authorization bearer",
        ));
    }
    if kernel::is_message_record(conn, &snapshot.target).await? {
        return Err(Error::engine("Message access uses its sealed audience"));
    }
    Ok(snapshot)
}
async fn content_guard(
    conn: &mut sqlx::SqliteConnection,
    target: &str,
    expected: Option<i64>,
) -> Result<()> {
    if let Some(expected) = expected {
        let actual: i64 =
            sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=?")
                .bind(target)
                .fetch_one(conn)
                .await?;
        if expected < 1 || actual != expected {
            return Err(Error::conflict("policy content revision conflict"));
        }
    }
    Ok(())
}
struct Planned {
    requested: String,
    target: String,
    before: PolicySnapshot,
    transition: PolicyTransition,
}
async fn reject_ancestry(
    conn: &mut sqlx::SqliteConnection,
    targets: &BTreeSet<String>,
) -> Result<()> {
    if targets.len() < 2 {
        return Ok(());
    }
    for target in targets {
        let mut home = kernel::policy_mutations::physical_home_on(conn, target).await?;
        let mut seen = BTreeSet::new();
        for _ in 0..=100 {
            if !seen.insert(home.clone()) {
                return Err(Error::engine("invalid policy home ancestry"));
            }
            if home != *target && targets.contains(&home) {
                return Err(Error::engine(
                    "set_many policy targets cannot have an ancestor/descendant relationship",
                ));
            }
            let logical = kernel::v1_state::lifecycle_bearer_on(conn, &home, None).await?;
            let logical = if logical == "native:root" {
                crate::events::KERNEL_ROOT_ID
            } else {
                logical.as_str()
            };
            if logical != target && targets.contains(logical) {
                return Err(Error::engine(
                    "set_many policy targets cannot have an ancestor/descendant relationship",
                ));
            }
            let parent: Option<String> =
                sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id=?")
                    .bind(&home)
                    .fetch_one(&mut *conn)
                    .await?;
            let Some(parent) = parent else { break };
            home = parent;
            if seen.len() > 100 {
                return Err(Error::engine("policy home ancestry exceeds depth limit"));
            }
        }
    }
    Ok(())
}

async fn mutate(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let request_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&args)?));
    let parsed: MutationArgs = parse("manage_record_policy", args)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let (reason, planned, batch) = match parsed {
        MutationArgs::SetMany { items, reason } => {
            crate::mcp::tools::require_nonblank_reason("manage_record_policy", &reason)?;
            if items.is_empty() || items.len() > 100 {
                return Err(Error::engine("set_many requires between 1 and 100 items"));
            }
            let mut seen = BTreeSet::new();
            let mut virtuals = BTreeMap::<String, PolicySnapshot>::new();
            let mut planned = Vec::new();
            let mut targets = BTreeSet::new();
            for item in items {
                let snapshot = authorized_snapshot(&mut tx, actor, caller, &item.record_id).await?;
                content_guard(&mut tx, &snapshot.target, item.if_content_seq).await?;
                assert_revision(&snapshot.revision, item.if_policy_revision.as_deref())?;
                let subject = subject_on(&mut tx, actor, item.subject).await?;
                let subject_key = match &subject {
                    PolicySubject::Members => String::new(),
                    PolicySubject::Account(id) => id.clone(),
                };
                if !seen.insert((snapshot.target.clone(), subject_key)) {
                    return Err(Error::engine(
                        "set_many duplicate resolved record and subject",
                    ));
                }
                let before = virtuals
                    .get(&snapshot.target)
                    .cloned()
                    .unwrap_or(shared(&snapshot)?);
                let transition = native_policy_kernel::plan_policy_transition(
                    &snapshot.target,
                    snapshot.target == crate::events::KERNEL_ROOT_ID,
                    &before,
                    PolicyMutation::Set {
                        subject,
                        capability: item.capability.map(Into::into),
                    },
                )
                .map_err(|e| Error::engine(e.to_string()))?;
                virtuals.insert(snapshot.target.clone(), after_virtual(&before, &transition));
                targets.insert(snapshot.target.clone());
                planned.push(Planned {
                    requested: item.record_id,
                    target: snapshot.target,
                    before,
                    transition,
                });
            }
            reject_ancestry(&mut tx, &targets).await?;
            (reason, planned, true)
        }
        parsed => {
            let (record_id, expected, content, reason, kind) = match parsed {
                MutationArgs::Grant {
                    record_id,
                    subject,
                    capability,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                } => (
                    record_id,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                    (0, Some(subject), Some(capability), None, None),
                ),
                MutationArgs::Revoke {
                    record_id,
                    subject,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                } => (
                    record_id,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                    (1, Some(subject), None, None, None),
                ),
                MutationArgs::SetMembersBaseline {
                    record_id,
                    capability,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                } => (
                    record_id,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                    (2, None, capability, None, None),
                ),
                MutationArgs::Replace {
                    record_id,
                    entries,
                    if_policy_revision,
                    if_content_seq,
                    reason,
                } => (
                    record_id,
                    Some(if_policy_revision),
                    if_content_seq,
                    reason,
                    (3, None, None, Some(entries), None),
                ),
                MutationArgs::RestoreInheritance {
                    record_id,
                    if_policy_revision,
                    if_content_seq,
                    if_inherited_policy_revision,
                    reason,
                } => (
                    record_id,
                    Some(if_policy_revision),
                    if_content_seq,
                    reason,
                    (4, None, None, None, if_inherited_policy_revision),
                ),
                MutationArgs::SetMany { .. } => unreachable!(),
            };
            crate::mcp::tools::require_nonblank_reason("manage_record_policy", &reason)?;
            let snapshot = authorized_snapshot(&mut tx, actor, caller, &record_id).await?;
            assert_revision(&snapshot.revision, expected.as_deref())?;
            content_guard(&mut tx, &snapshot.target, content).await?;
            let before = shared(&snapshot)?;
            let mutation = match kind {
                (0, Some(subject), Some(capability), _, _) => PolicyMutation::Grant {
                    subject: subject_on(&mut tx, actor, subject).await?,
                    capability: capability.into(),
                },
                (1, Some(subject), _, _, _) => PolicyMutation::Revoke {
                    subject: subject_on(&mut tx, actor, subject).await?,
                },
                (2, _, capability, _, _) => PolicyMutation::SetMembersBaseline {
                    capability: capability.map(Into::into),
                },
                (3, _, _, Some(entries), _) => {
                    let mut resolved = Vec::new();
                    for entry in entries {
                        resolved.push(AllowEntry {
                            subject: subject_on(&mut tx, actor, entry.subject).await?,
                            capability: entry.capability.into(),
                        });
                    }
                    PolicyMutation::Replace { entries: resolved }
                }
                (4, _, _, _, expected) => {
                    native_policy_kernel::validate_inheritance_restoration(
                        &snapshot.target,
                        snapshot.target == crate::events::KERNEL_ROOT_ID,
                        &before,
                    )
                    .map_err(|e| Error::engine(e.to_string()))?;
                    let inherited =
                        kernel::policy_mutations::inherited_on(&mut tx, actor, &snapshot.target)
                            .await?;
                    assert_revision(&inherited.revision, expected.as_deref())?;
                    PolicyMutation::RestoreInheritance {
                        inherited: shared(&inherited)?,
                    }
                }
                _ => unreachable!(),
            };
            let transition = native_policy_kernel::plan_policy_transition(
                &snapshot.target,
                snapshot.target == crate::events::KERNEL_ROOT_ID,
                &before,
                mutation,
            )
            .map_err(|e| Error::engine(e.to_string()))?;
            (
                reason,
                vec![Planned {
                    requested: record_id,
                    target: snapshot.target,
                    before,
                    transition,
                }],
                false,
            )
        }
    };
    let admitted_targets = planned.iter().map(|item| item.target.clone()).collect();
    kernel::policy_mutations::scope_admission(actor, admitted_targets, async move {
    let mut acts = crate::act::ActAllocation::new();
    let changed = planned
        .iter()
        .any(|item| !matches!(item.transition, PolicyTransition::NoChange { .. }));
    let pending = if changed {
        kernel::app_installs::start_app_action_in(
            db,
            &mut tx,
            actor,
            "manage_record_policy",
            request_digest,
            Some(reason.clone()),
            &mut acts,
        )
        .await?
    } else {
        None
    };
    let mut outcomes = Vec::new();
    let mut changed_count = 0;
    for (index, item) in planned.into_iter().enumerate() {
        let (event, boundary) = match item.transition {
            PolicyTransition::NoChange { .. } => (None, false),
            PolicyTransition::ReplaceExplicit {
                entries,
                boundary_created,
                ..
            } => {
                changed_count += 1;
                (
                    Some(
                        kernel::policy_mutations::apply_in(
                            db,
                            &mut tx,
                            &mut acts,
                            actor,
                            &item.target,
                            Some(entries),
                            &reason,
                        )
                        .await?,
                    ),
                    boundary_created,
                )
            }
            PolicyTransition::RestoreInheritance { .. } => {
                changed_count += 1;
                (
                    Some(
                        kernel::policy_mutations::apply_in(
                            db,
                            &mut tx,
                            &mut acts,
                            actor,
                            &item.target,
                            None,
                            &reason,
                        )
                        .await?,
                    ),
                    false,
                )
            }
        };
        // The original admission authorizes this policy receipt, even when
        // the change removes the actor's grant. No content is disclosed here.
        let after = kernel::policy_read::inherited_on(&mut tx, actor, &item.target).await?;
        let after = shared(&after)?;
        let mut outcome = json!({"record_id":item.requested,"authorization_target_id":item.target,"changed":event.is_some(),"boundary_created":boundary,
            "before":state(&item.before),"after":state(&after),"policy_revision":after.revision});
        if let Some(event) = event {
            outcome["event"] = json!({"id":event.id});
        }
        if batch {
            outcome["index"] = json!(index);
        }
        outcomes.push(outcome);
    }
    let mut response = if batch {
        json!({"ok":true,"item_count":outcomes.len(),"changed_count":changed_count,"outcomes":outcomes})
    } else {
        outcomes.remove(0)
    };
    response["act"] = json!(acts.get());
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        response["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(response)
    }).await
}

async fn inspect(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let args: Args = parse("manage_record_policy", args)?;
    let target = if args.record_id == "native:root" {
        crate::events::KERNEL_ROOT_ID
    } else {
        args.record_id.as_str()
    };
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let capability = kernel::kernel_effective_capability_on(&mut tx, actor, target).await?;
    let root_operator =
        caller.counter_footing().is_owner() && target == crate::events::KERNEL_ROOT_ID;
    if !capability.allows(Capability::View) && !root_operator {
        return Err(missing());
    }
    let terminal = if target == crate::events::KERNEL_ROOT_ID {
        target.to_owned()
    } else {
        kernel::comments_v2::derived_terminal_on(&mut tx, target)
            .await?
            .ok_or_else(missing)?
    };
    Ok(
        json!({"record_id":args.record_id,"authorization_target_id":terminal,"caller_capability":capability.as_policy_str().unwrap_or("none"),
        "policy_administration_authorized":capability.allows(Capability::Manage)||root_operator}),
    )
}
