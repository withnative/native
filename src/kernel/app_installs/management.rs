//! Account-private management reads with the existing shell response shapes.
use super::*;

pub(crate) struct ManagementOutcome {
    pub outcome: InstallOutcome,
    pub install: Value,
}

pub(super) async fn outcome_on(
    conn: &mut SqliteConnection,
    principal: &str,
    package: &str,
    generation: String,
    changed: bool,
) -> Result<ManagementOutcome> {
    let install = entry_on(conn, principal, package)
        .await?
        .ok_or_else(|| invalid("install projection missing after accepted outcome"))?;
    if install["event_id"] != generation {
        return Err(invalid(
            "accepted install generation does not match projection",
        ));
    }
    Ok(ManagementOutcome {
        outcome: InstallOutcome {
            generation,
            changed,
        },
        install,
    })
}

async fn account_on(conn: &mut SqliteConnection, principal: &str) -> Result<String> {
    if !hosted_identity::account_admitted_before(conn, principal, i64::MAX).await? {
        return Err(Error::engine("database membership not found"));
    }
    require_activated_on(conn).await?;
    sqlx::query_scalar(
        "SELECT auth_binding FROM kernel_principals WHERE principal_id=? AND kind='account'",
    )
    .bind(principal)
    .fetch_one(conn)
    .await
    .map_err(Into::into)
}

async fn source_matches(
    conn: &mut SqliteConnection,
    row: &Value,
    declaration: &Value,
    retained: Option<&[(Value, String, i64)]>,
) -> Result<bool> {
    let fields: Option<Vec<&str>> = [
        "package",
        "version",
        "digest",
        "artifact_id",
        "consented_source_revision",
        "declaration_digest",
    ]
    .iter()
    .map(|key| row[*key].as_str())
    .collect();
    let Some(fields) = fields else {
        return Ok(false);
    };
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(fields[3])
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
    if runtime.as_deref() != Some("native.html.v1") {
        return Ok(false);
    }
    let pin: Option<String> = sqlx::query_scalar("SELECT pin_json FROM kernel_app_package_sources WHERE package=? AND version=? AND digest=? AND artifact_id=? AND source_revision=? AND declaration_digest=?")
        .bind(fields[0]).bind(fields[1]).bind(fields[2]).bind(fields[3]).bind(fields[4]).bind(fields[5])
        .fetch_optional(&mut *conn).await?;
    let pin = if let Some(pin) = pin {
        pin
    } else {
        let owned;
        let retained = match retained {
            Some(retained) => retained,
            None => {
                owned = retained_sources_on(conn, Some(fields[3])).await?;
                &owned
            }
        };
        let Some((pin, _, _)) = retained.iter().find(|(pin, _, _)| {
            pin["package"] == fields[0]
                && pin["version"] == fields[1]
                && pin["digest"] == fields[2]
                && pin["source_revision"] == fields[4]
                && pin["declaration_digest"] == fields[5]
        }) else {
            return Ok(false);
        };
        pin.to_string()
    };
    let pin: Value = serde_json::from_str(&pin)?;
    let pinned_declaration: Value = serde_json::from_str(string(&pin, "consented_declaration")?)?;
    Ok(pinned_declaration == *declaration && pin["runtime"] == "native.html.v1")
}

pub(super) async fn entry_on(
    conn: &mut SqliteConnection,
    principal: &str,
    package: &str,
) -> Result<Option<Value>> {
    entry_with_retained_on(conn, principal, package, None).await
}

async fn entry_with_retained_on(
    conn: &mut SqliteConnection,
    principal: &str,
    package: &str,
    retained: Option<&[(Value, String, i64)]>,
) -> Result<Option<Value>> {
    let stored: Option<(String, String, String, bool, Option<String>, i64)> = sqlx::query_as(
        "SELECT row_json,generation,status,executable,refusal,event_seq FROM kernel_app_installs WHERE principal=? AND package=?",
    ).bind(principal).bind(package).fetch_optional(&mut *conn).await?;
    let Some((raw, generation, status, executable, refusal, seq)) = stored else {
        return Ok(None);
    };
    let row: Value = serde_json::from_str(&raw)?;
    let declaration = row["consented_declaration"]
        .as_str()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .unwrap_or(Value::Null);
    let mut provenance = match &row["adoption_provenance"] {
        Value::String(raw) => serde_json::from_str::<Value>(raw).ok(),
        Value::Object(_) => Some(row["adoption_provenance"].clone()),
        _ => None,
    }
    .filter(Value::is_object);
    if let Some(object) = provenance.as_mut().and_then(Value::as_object_mut) {
        object.remove("launch_id");
        object.remove("authored_run_key");
    }
    let adoption = row["adoption"].as_str().unwrap_or("caller_asserted");
    let target_reason = if status == "removed" {
        Some("removed")
    } else if status == "disabled" {
        Some("disabled")
    } else {
        match read_record_on(conn, principal, string(&row, "artifact_id")?).await? {
            // Remembered consent does not grant visibility of a hidden
            // source's present existence, type or archival state.
            None => Some("unauthorized"),
            Some(record) if record.archived => Some("archived"),
            Some(record) if !is_artifact_on(conn, &record).await? => Some("wrong_record_type"),
            Some(_) => None,
        }
    };
    let epoch: i64 = sqlx::query_scalar(
        "SELECT event_seq FROM kernel_app_consent_revocations WHERE principal=?",
    )
    .bind(principal)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or(0);
    let source_valid = if target_reason.is_none() {
        source_matches(conn, &row, &declaration, retained).await?
    } else {
        false
    };
    let ready = target_reason.is_none()
        && status == "installed"
        && executable
        && verified_adoption(adoption)
        && refusal.is_none()
        && source_valid
        && row["consent_revocation_seq"].as_i64().unwrap_or(0) == epoch;
    let readopt = source_valid
        && refusal.as_deref() == Some(NOT_YET_AVAILABLE)
        && declarations::declarative(&declaration).is_ok();
    let reason = target_reason.unwrap_or_else(|| {
        if ready {
            "launch_request_required"
        } else if readopt {
            "readopt_required_on_v2"
        } else if adoption == "caller_asserted" && source_valid {
            "digest_unverified"
        } else {
            match refusal.as_deref() {
                Some(NOT_YET_AVAILABLE)
                    if verified_adoption(adoption)
                        && declarations::declarative(&declaration).is_ok() =>
                {
                    RETAINED_SOURCE_UNVERIFIED
                }
                Some(NOT_YET_AVAILABLE) => NOT_YET_AVAILABLE,
                Some(UNSUPPORTED_WITNESS) => UNSUPPORTED_WITNESS,
                _ => "unsupported_on_v2",
            }
        }
    });
    let mut launch_binding = json!({"digest_version":"alpha-tab-digest.v1","verdict":"refused","reason":reason,"receipt":null});
    if source_valid {
        launch_binding["delivery"] = json!("reusable.v1");
    }
    let basis = match &provenance {
        Some(value) if value["carried_from_event_id"].is_string() => Some("carried"),
        Some(_) => Some("direct"),
        None if adoption == "caller_asserted" => Some("requires_adoption"),
        None => None,
    };
    Ok(Some(json!({
        "package":package,"version":row["version"],"digest":row["digest"],
        "artifact_id":row["artifact_id"],"consented_source_revision":row["consented_source_revision"],
        "declaration_digest":row["declaration_digest"],"consented_declaration":declaration,
        "adoption":adoption,"adoption_basis":basis,"adoption_provenance":provenance,
        "request":row["request"],"status":status,"event_id":generation,"event_seq":seq,
        "target_resolves":target_reason.is_none(),"target_skip_reason":target_reason,
        "resolves":false,"skip_reason":reason,"digest_binding":"stored-not-enforced",
        "launch_binding":launch_binding,
    })))
}

async fn effective_order(conn: &mut SqliteConnection, principal: &str) -> Result<Vec<String>> {
    let eligible: Vec<String> = sqlx::query_scalar("SELECT package FROM kernel_app_installs WHERE principal=? AND status='installed' ORDER BY package")
        .bind(principal).fetch_all(&mut *conn).await?;
    let retained = app_state::account_order_on(conn, principal).await?;
    let saved: Vec<String> = match retained.as_ref().and_then(|row| row["tab_order"].as_str()) {
        Some(raw) => serde_json::from_str(raw)?,
        None => vec![],
    };
    let mut ordered = Vec::new();
    for package in saved.into_iter().chain(eligible.iter().cloned()) {
        if eligible.contains(&package) && !ordered.contains(&package) {
            ordered.push(package);
        }
    }
    Ok(ordered)
}

pub(crate) async fn list_as(
    db: &Db,
    principal: &str,
    view: Option<String>,
    include_removed: Option<bool>,
) -> Result<Value> {
    let view = view.as_deref().unwrap_or("full");
    if !matches!(view, "full" | "summary") {
        return Err(Error::engine("manage_alpha_tabs: invalid list view"));
    }
    let include_removed = include_removed.unwrap_or(view == "full");
    let mut tx = db.write_pool().begin().await?;
    let account = account_on(&mut tx, principal).await?;
    let packages: Vec<String> = sqlx::query_scalar(
        "SELECT package FROM kernel_app_installs WHERE principal=? ORDER BY package",
    )
    .bind(principal)
    .fetch_all(&mut *tx)
    .await?;
    // Derive certificates once inside this pinned, read-only list transaction.
    // Only immutable retained source evidence is shared; each entry still
    // checks this member's live visibility, consent and revocation state.
    let retained = retained_sources_on(&mut tx, None).await?;
    let mut installs = Vec::new();
    let mut removed_hidden = 0;
    for package in packages {
        let entry = entry_with_retained_on(&mut tx, principal, &package, Some(&retained))
            .await?
            .ok_or_else(|| invalid("install projection missing"))?;
        if !include_removed && entry["status"] == "removed" {
            removed_hidden += 1;
            continue;
        }
        if view == "summary" {
            let name = if entry["target_resolves"] == true {
                read_record_on(&mut tx, principal, string(&entry, "artifact_id")?)
                    .await?
                    .and_then(|record| record.fields.get("name").cloned())
                    .unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            installs.push(json!({"package":entry["package"],"name":name,"version":entry["version"],
                "status":entry["status"],"artifact_id":entry["artifact_id"],"event_id":entry["event_id"],
                "adoption_basis":entry["adoption_basis"],"request":entry["request"],
                "target_resolves":entry["target_resolves"],"target_skip_reason":entry["target_skip_reason"]}));
        } else {
            installs.push(entry);
        }
    }
    let order = effective_order(&mut tx, principal).await?;
    let sources = if view == "full" {
        let mut sources = Vec::new();
        for pin in frozen_sources_on(&mut tx, principal, Some(&retained)).await? {
            let declaration: Value = serde_json::from_str(string(&pin, "consented_declaration")?)?;
            sources.push(json!({"package":pin["package"],"version":pin["version"],"digest":pin["digest"],
                "artifact_id":pin["artifact_id"],"source_revision":pin["source_revision"],
                "declaration":declaration,"declaration_digest":pin["declaration_digest"],
                "bundle_sha256":pin["bundle_sha256"],"runtime":pin["runtime"],"requires_adoption":true}));
        }
        Some(sources)
    } else {
        None
    };
    tx.rollback().await?;
    let mut result = json!({"account_id":account,"installs":installs,"tab_order":order});
    if view == "summary" {
        result["view"] = json!("summary");
        result["removed_hidden"] = json!(removed_hidden);
    }
    if let Some(sources) = sources {
        result["frozen_sources"] = json!(sources);
    }
    Ok(result)
}

pub(crate) async fn inspect_as(db: &Db, principal: &str, package: &str) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    account_on(&mut tx, principal).await?;
    let entry = entry_on(&mut tx, principal, package).await?;
    let order = effective_order(&mut tx, principal).await?;
    tx.rollback().await?;
    Ok(match entry {
        Some(entry) => {
            json!({"package":package,"installed":true,"install":entry,"tab_order":order})
        }
        None => json!({"package":package,"installed":false,"tab_order":order}),
    })
}
