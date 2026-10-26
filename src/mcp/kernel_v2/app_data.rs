//! Declared app reads through the ordinary caller-scoped kernel SQL surface.
use super::*;
use crate::kernel::app_installs::{self as installs, AppSourceAdmission};
use crate::mcp::tools::alpha_tabs::LiveReadSubscribe;
use crate::need_subscriptions::GateSnapshot;
use crate::need_subscriptions::{params_digest, ConnectionToken, SubscriptionId, SurfaceBinding};
use crate::realtime::v2::{AppDataEvaluation, AppDataGate, AppDataNeeds, AppDataRequest};
use crate::realtime::RealtimeHub;
use futures::future::BoxFuture;
use std::sync::Arc;

const SNAPSHOT: &str = "native.app.snapshot.v2";

#[derive(Debug, Default)]
pub struct NativeAppDataNeeds;

fn invalid(code: &str) -> Error {
    Error::engine(format!("manage_alpha_tabs: live read refused [{code}]"))
}

fn pin_string(source: &AppSourceAdmission, key: &str) -> Result<String> {
    source.pin[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("source_pin_changed"))
}

async fn gate(
    conn: &mut sqlx::SqliteConnection,
    source: &AppSourceAdmission,
) -> Result<AppDataGate> {
    // Policy definitions live in meta; placement, bearer links, deletion,
    // Message state and home-policy/roster events
    // live in content. Keep this internal epoch out of viewer revision digests.
    // Drop/rejoin and revoke/regrant cannot restore an old subscription gate.
    let authorization_epoch = if declaration(source)?.get("contract").is_none() {
        authorization_epoch_on(conn).await?
    } else {
        // The native contract's declared frame has no data; preserve its
        // existing gate. Its app-host requests recheck their own live scopes.
        String::new()
    };

    Ok(AppDataGate {
        principal: source.principal.clone(),
        authorization_epoch,
        // These states are established afresh by admit_data_as, including
        // account_admitted_before, source View and the revocation comparison.
        consent_status: "installed".into(),
        executable: true,
        revocation_epoch: u64::try_from(source.revocation_epoch)
            .map_err(|_| invalid("revocation_epoch_invalid"))?,
        install_generation: u64::try_from(source.install_event_seq)
            .map_err(|_| invalid("install_generation_invalid"))?,
        surface: GateSnapshot {
            install_event_id: source.generation.clone(),
            status: "installed".into(),
            adoption: "shell_adopt.v1".into(),
            declaration_digest: pin_string(source, "declaration_digest")?,
            bundle_sha256: pin_string(source, "bundle_sha256")?,
            source_event_id: pin_string(source, "source_revision")?,
            source_revision: pin_string(source, "source_revision")?,
            runtime: Some("native.html.v1".into()),
        },
    })
}

// Conservative, monotone fence for live SQL visibility and member identity.
// Include native link revisions, Direct destinations, carrier binding/type
// changes, and the realtime authority families; body-only edits stay out.
async fn authorization_epoch_on(conn: &mut sqlx::SqliteConnection) -> Result<String> {
    let epochs: (i64, i64) = sqlx::query_as("SELECT (SELECT coalesce(max(seq),0) FROM main.meta_events),(SELECT coalesce(max(seq),0) FROM main.content_events WHERE type LIKE 'kernel.home_%' OR type LIKE 'kernel.record_rehomed.%' OR type LIKE 'kernel.principal_%' OR type LIKE 'kernel.hosted_%' OR type LIKE 'kernel.import_%' OR type IN ('kernel.archive_changed.v1','kernel.record_deleted.v1','kernel.message_state.v1') OR type LIKE 'kernel.generic_link_%' OR type LIKE 'kernel.link_added.%' OR type LIKE 'kernel.link_removed.%' OR type IN ('kernel.root_admin_bootstrapped.v1','kernel.record_rebound.v1','kernel.identity_binding_added.v1','kernel.attachment_bound.v1','kernel.message_destination_set.v1') OR (type IN ('kernel.record_revised.v1','kernel.record_revised.v2') AND (json_type(payload,'$.fields.v1_type') IS NOT NULL OR json_type(payload,'$.fields.v1_kind') IS NOT NULL)))")
        .fetch_one(conn).await?;
    Ok(crate::canonical_json::digest_json(&json!(epochs)))
}

fn declaration(source: &AppSourceAdmission) -> Result<Value> {
    serde_json::from_str(pin_string(source, "consented_declaration")?.as_str()).map_err(Into::into)
}

fn validate_request(source: &AppSourceAdmission, request: &AppDataRequest) -> Result<()> {
    let declared = declaration(source)?;
    if declared.get("contract").is_some() {
        if request.need.is_some() {
            return Err(invalid("undeclared_need"));
        }
    } else {
        let parsed = installs::declarations::declarative(&declared)?;
        if let Some(key) = &request.need {
            if let Some(need) = parsed.sql.iter().find(|need| need.key == *key) {
                crate::mcp::tools::alpha_tabs::bind_sql_params(need, Some(&request.params))
                    .map_err(invalid)?;
            } else if parsed.needs.contains(key) {
                crate::mcp::tools::alpha_tabs::parse_declared_read(key, Some(&request.params))
                    .map_err(invalid)?;
            } else {
                return Err(invalid("undeclared_need"));
            }
        }
    }
    if request.need.is_none()
        && request
            .params
            .as_object()
            .is_none_or(|params| !params.is_empty())
    {
        return Err(invalid("invalid_params"));
    }
    Ok(())
}

async fn search_on_snapshot(db: &Db, actor: &str, query: String, limit: i64) -> Result<Value> {
    let actor_owned = actor.to_owned();
    super::sql::in_snapshot(db,actor,move |conn| Box::pin(async move {
        let (hits,truncated)=kernel::search_v2::search_scoped_on(conn,&actor_owned,&query,limit,false,None).await?;
        let mut rendered=Vec::new();
        for hit in &hits {
            let home_id=crate::v1_import::placement_on(conn,&actor_owned,&hit.id).await?
                .filter(|p|p.kernel_home_id==hit.home_id).and_then(|p|p.home_id);
            rendered.push(json!({"id":hit.id,"type":hit.record_type,"kind":hit.kind,"name":hit.name,"home_id":home_id,"score":hit.score,"snippet":hit.snippet}));
        }
        let limit_reached=truncated||hits.len() as i64==limit;
        let mut payload=json!({"query":query,"scope":null,"hits":rendered,"total":hits.len(),"returned":hits.len(),"limit":limit,"limit_reached":limit_reached,"thin":false});
        if limit_reached {payload["guidance"]=json!("This list may be incomplete. Use query_record with a filter step for a narrow, exhaustive answer.");}
        Ok(payload)
    })).await
}

async fn source_and_gate(
    db: &Db,
    actor: &str,
    request: &AppDataRequest,
) -> Result<(AppSourceAdmission, AppDataGate)> {
    let owned_actor = actor.to_owned();
    let request = request.clone();
    super::sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move {
            let source = installs::admit_install_on(
                conn,
                &owned_actor,
                &request.package,
                &request.expected_install_event_id,
            )
            .await?;
            validate_request(&source, &request)?;
            let gate = gate(conn, &source).await?;
            Ok((source, gate))
        })
    })
    .await
}

async fn evaluate_declared(
    db: &Db,
    caller: &Caller,
    request: &AppDataRequest,
) -> Result<AppDataEvaluation> {
    use crate::kernel::app_installs::declarations;
    use crate::mcp::tools::alpha_tabs as alpha;
    let actor = super::principal(db, caller).await?;
    let initial = installs::admit_data_as(
        db,
        caller,
        &request.package,
        &request.expected_install_event_id,
    )
    .await?;
    let declared = declaration(&initial)?;
    let legacy = declared.get("contract").is_none();
    let parsed = if legacy {
        Some(declarations::declarative(&declared)?)
    } else {
        None
    };
    if !legacy && request.need.is_some() {
        return Err(invalid("undeclared_need"));
    }
    if request.need.is_none() && request.params.as_object().is_none_or(|p| !p.is_empty()) {
        return Err(invalid("invalid_params"));
    }
    let selected: Vec<_> = parsed
        .as_ref()
        .map(|p| {
            p.sql
                .iter()
                .filter(|need| match request.need.as_deref() {
                    Some(key) => need.key == key,
                    None => need.params.is_empty(),
                })
                .collect()
        })
        .unwrap_or_default();
    // v1's snapshot read has no implicit empty frame for declarative apps.
    // Keyed/parameterized reads (including search) remain independently usable.
    if legacy && request.need.is_none() && selected.is_empty() {
        return Err(invalid("undeclared_need"));
    }
    let statements: Vec<_> = selected.iter().map(|need| need.sql.as_str()).collect();
    super::sql::with_query_read_session(db, &actor, &statements, async {
        let (source, gate) = source_and_gate(db, &actor, request).await?;
        let pin = json!({"package":source.package,"version":source.version,"digest":source.pin["digest"],
            "artifact_id":source.pin["artifact_id"],"source_revision":source.pin["source_revision"],
            "declaration_digest":source.pin["declaration_digest"]});
        let mut input_sql = serde_json::Map::new();
        let mut sql_digest = serde_json::Map::new();
        let mut time_dependent = false;
        let mut as_of_ms: Option<i64> = None;
        for need in &selected {
            let params = if request.need.is_some() { Some(&request.params) } else { None };
            let parameters = alpha::bind_sql_params(need, params).map_err(invalid)?;
            let raw = super::sql::query_sql(db, &actor, json!({"sql":need.sql,"parameters":parameters})).await
                .map_err(|error| Error::engine(format!("manage_alpha_tabs: sql need '{}' failed: {error} [sql_need_failed]",need.key)))?;
            let result = alpha::project_snapshot_need(need, &raw)?;
            time_dependent |= result.time_dependent;
            as_of_ms = match (as_of_ms,result.now_ms_ms) { (Some(a),Some(b)) => Some(a.max(b)), (a,b) => a.or(b) };
            input_sql.insert(need.key.clone(), result.input);
            sql_digest.insert(need.key.clone(), result.digest);
        }
        let rows = json!([]);
        let rows_sha256 = crate::canonical_json::digest_json(&rows);
        let revision_digest = crate::canonical_json::digest_json(&json!({"rows":rows,"sql":sql_digest,"pin":pin,"install_event_id":source.generation}));
        let mut response = json!({"package":request.package,"install_event_id":source.generation,"pin":pin,
            "source":{"event_id":source.pin["source_revision"],"bundle_sha256":source.pin["bundle_sha256"],"runtime":"native.html.v1"},
            "live_reads":true,"effects_wired":false,"revision":{"revision_digest":revision_digest,"rows_sha256":rows_sha256}});
        if let Some(key) = &request.need {
            let result = if let Some(result) = input_sql.remove(key) { result } else {
                if key != alpha::RECORDS_SEARCH_NEED || !parsed.as_ref().is_some_and(|p| p.needs.contains(key)) {
                    return Err(invalid("undeclared_need"));
                }
                let alpha::DeclaredRead::Search {query, limit} = alpha::parse_declared_read(key, Some(&request.params)).map_err(invalid)? else { return Err(invalid("undeclared_need")); };
                search_on_snapshot(db, &actor, query, limit).await?
            };
            response.as_object_mut().unwrap().remove("revision");
            if let Some(need) = selected.iter().find(|need| need.key==*key) {
                if let Some(digest) = sql_digest.get(key).and_then(|digest| alpha::sql_keyed_revision_for_pin(&pin,need,digest)) {
                    response["revision"]=json!({"revision_digest":digest});
                }
            }
            response["need"] = json!(key);
            response["params"] = request.params.clone();
            response["result"] = result;
        } else {
            let mut input = json!({"version":"native.artifact-input.v1","mode":"live","sample_preview":false,
                "records":rows,"records_sha256":rows_sha256,"inputs":{}});
            if !input_sql.is_empty() { input["sql"] = Value::Object(input_sql); }
            response["need"] = json!(if legacy { alpha::ATTENTION_QUERY_NEED } else { SNAPSHOT });
            response["declared_needs"] = declared["needs"].clone();
            response["input_digest"] = json!(alpha::alpha_tab_sample_input_digest(&input));
            response["input"] = input;
            response["rows_sha256"] = json!(rows_sha256);
            response["as_of_ms"] = json!(as_of_ms);
            response["time_dependent"] = json!(time_dependent);
            response["window"] = json!({"bounded_window":true});
        }
        Ok(AppDataEvaluation {result:response,gate,time_dependent})
    }).await
}

impl AppDataNeeds for NativeAppDataNeeds {
    fn evaluate<'a>(
        &'a self,
        db: &'a Db,
        caller: &'a Caller,
        request: &'a AppDataRequest,
    ) -> BoxFuture<'a, Result<AppDataEvaluation>> {
        Box::pin(evaluate_declared(db, caller, request))
    }
    fn revalidate<'a>(
        &'a self,
        db: &'a Db,
        caller: &'a Caller,
        request: &'a AppDataRequest,
    ) -> BoxFuture<'a, Result<AppDataGate>> {
        Box::pin(async move {
            let actor = super::principal(db, caller).await?;
            let (_, gate) = source_and_gate(db, &actor, request).await?;
            Ok(gate)
        })
    }
}

/// The shell coalesces concurrent page reads into this v1 envelope. Item
/// errors stay local, while losing install/visibility authority refuses the
/// whole delivery. SQL and search share one caller-owned read snapshot.
pub(super) async fn batch_read(
    db: &Db,
    caller: &Caller,
    package: String,
    generation: String,
    reads: Vec<crate::mcp::tools::alpha_tabs::LiveReadItem>,
) -> Result<Value> {
    use crate::mcp::tools::alpha_tabs as alpha;
    if reads.is_empty() || reads.len() > alpha::LIVE_READ_BATCH_MAX {
        return Err(invalid("invalid_params"));
    }
    let actor = super::principal(db, caller).await?;
    let source = installs::admit_data_as(db, caller, &package, &generation).await?;
    let declared = declaration(&source)?;
    let parsed = if declared.get("contract").is_none() {
        Some(installs::declarations::declarative(&declared)?)
    } else {
        None
    };
    // A malformed statement is an item refusal, not a batch setup failure.
    // The ordinary query guard repeats full validation when that item runs.
    let statements: Vec<_> = parsed
        .as_ref()
        .into_iter()
        .flat_map(|p| p.sql.iter())
        .filter(|need| {
            reads.iter().any(|item| {
                item.need == need.key
                    || (item.need == alpha::ATTENTION_QUERY_NEED && need.params.is_empty())
            })
        })
        .map(|need| need.sql.as_str())
        .filter(|sql| crate::query::sql::public_reads_ad_hoc(sql).is_ok())
        .collect();
    let request = AppDataRequest {
        package: package.clone(),
        expected_install_event_id: generation.clone(),
        need: None,
        params: json!({}),
    };
    let (mut response, held) = super::sql::with_query_read_session(db, &actor, &statements, async {
        let (source, held) = source_and_gate(db, &actor, &request).await?;
        let mut results = Vec::with_capacity(reads.len());
        for item in reads {
            let snapshot = item.need == alpha::ATTENTION_QUERY_NEED;
            let evaluated = if snapshot && item.params.is_some() {
                Err(invalid("invalid_params"))
            } else {
                evaluate_declared(db, caller, &AppDataRequest {
                    need: if snapshot { None } else { Some(item.need.clone()) },
                    params:item.params.unwrap_or_else(||json!({})),
                    ..request.clone()
                }).await
            };
            let body = match evaluated {
                Ok(evaluated) => {
                    if evaluated.gate != held { return Err(invalid("admission_gate_changed")); }
                    Ok(evaluated.result)
                }
                Err(error) => {
                    let (_, current) = source_and_gate(db, &actor, &request).await?;
                    if current != held { return Err(invalid("admission_gate_changed")); }
                    Err(error)
                }
            };
            results.push(alpha::live_read_item_result(&item.need, body));
        }
        Ok((json!({"package":package,"install_event_id":generation,
            "pin":{"package":source.package,"version":source.version,"digest":source.pin["digest"],"artifact_id":source.pin["artifact_id"],"source_revision":source.pin["source_revision"],"declaration_digest":source.pin["declaration_digest"]},
            "source":{"event_id":source.pin["source_revision"],"bundle_sha256":source.pin["bundle_sha256"],"runtime":"native.html.v1"},
            "results":results,"live_reads":true,"effects_wired":false}), held))
    }).await?;
    // Once the session ends, recheck current authority rather than returning
    // captured rows after a concurrent revoke/regrant or policy change.
    let (_, fresh) = source_and_gate(db, &actor, &request).await?;
    if held != fresh {
        return Err(invalid("admission_gate_changed"));
    }
    // Keep the same public envelope as v1; internal gates never leave here.
    response.sort_all_objects();
    Ok(response)
}

/// Registration and its admission pin belong to W6c's existing registry.
/// Cancellation before the tool response is ready releases both pending and
/// newly active entries; no second subscription authority is introduced.
struct Pending {
    hub: Arc<RealtimeHub>,
    token: ConnectionToken,
    id: SubscriptionId,
    keep: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.keep {
            self.hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .unsubscribe(&self.token, &self.id);
        }
    }
}

fn revision(result: &Value) -> Result<&str> {
    result["revision"]["revision_digest"]
        .as_str()
        .filter(|digest| !digest.is_empty())
        .ok_or_else(|| invalid("revision_missing"))
}

pub(super) async fn live_read(
    db: &Db,
    caller: &Caller,
    request: AppDataRequest,
    subscribe: Option<LiveReadSubscribe>,
    if_revision: Option<String>,
) -> Result<Value> {
    if request.need.is_some() && (subscribe.is_some() || if_revision.is_some()) {
        return Err(invalid("invalid_params"));
    }
    let hub = RealtimeHub::for_database(db)
        .filter(|hub| hub.has_app_data_needs())
        .ok_or_else(|| invalid("evaluator_unavailable"))?;
    let mut pending = None;
    let mut refused = None;
    if let Some(subscribe) = subscribe {
        if let Some(token) = ConnectionToken::from_hex(subscribe.stream.trim()) {
            let registered = hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .subscribe_pending(
                    &token,
                    caller.credential(),
                    hub.database_identity(),
                    SurfaceBinding::alpha_tab(&request.package, &request.expected_install_event_id),
                    SNAPSHOT,
                    &params_digest(Some(&request.params)),
                );
            match registered {
                Ok(id) => {
                    pending = Some(Pending {
                        hub: hub.clone(),
                        token,
                        id,
                        keep: false,
                    })
                }
                Err(reason) => refused = Some(reason.as_code().to_owned()),
            }
        } else {
            refused = Some("stream_unknown".into());
        }
    }
    let mut evaluated = if let Some(pending) = &pending {
        hub.admit_app_data_subscription(caller, &pending.token, &pending.id, &request)
            .await?
    } else {
        let evaluated = hub.evaluate_app_data(caller, &request).await?;
        if evaluated.gate != hub.revalidate_app_data(caller, &request).await? {
            return Err(invalid("admission_gate_changed"));
        }
        evaluated
    };
    let mut subscription = None;
    if let Some(pending) = &mut pending {
        let dirty = {
            let mut registry = hub.need_registry().lock().expect("need registry poisoned");
            let activated = registry.activate_with_probe_safety(
                &pending.token,
                &pending.id,
                revision(&evaluated.result)?,
                evaluated.time_dependent,
                None,
                false,
            );
            if activated == Some(true) {
                registry.clear_dirty_for_catchup(&pending.token, &pending.id);
            }
            activated
        };
        match dirty {
            Some(dirty) => {
                if dirty {
                    // The hub compares to the immutable admission pin; a
                    // changed gate closes rather than refreshing that pin.
                    evaluated = hub
                        .check_app_data_subscription(caller, &pending.token, &pending.id)
                        .await?;
                    let still_active = hub
                        .need_registry()
                        .lock()
                        .expect("need registry poisoned")
                        .activate_with_probe_safety(
                            &pending.token,
                            &pending.id,
                            revision(&evaluated.result)?,
                            evaluated.time_dependent,
                            None,
                            false,
                        );
                    if still_active.is_none() {
                        return Err(invalid("stream_unknown"));
                    }
                    let mut registry = hub.need_registry().lock().expect("need registry poisoned");
                    if still_active == Some(true) {
                        // A write during the immediate rerun belongs to the
                        // scheduler; the rerun cannot consume that wake.
                        registry.enqueue_dirty_with_trigger(
                            &pending.token,
                            &pending.id,
                            true,
                            crate::need_metrics::Trigger::Subscribe,
                        );
                    }
                    registry.finish_catchup(&pending.token, &pending.id);
                }
                subscription = Some(json!({"id":pending.id.as_str(),
                    "time_dependent":evaluated.time_dependent}));
            }
            None => refused = Some("stream_unknown".into()),
        }
    }
    let mut result = if if_revision
        .as_deref()
        .is_some_and(|held| evaluated.result["revision"]["revision_digest"].as_str() == Some(held))
    {
        json!({"package":evaluated.result["package"],
            "install_event_id":evaluated.result["install_event_id"],
            "pin":evaluated.result["pin"],"revision":evaluated.result["revision"],
            "unchanged":true})
    } else {
        evaluated.result
    };
    if let Some(subscription) = subscription {
        result["subscription"] = subscription;
        if let Some(pending) = &mut pending {
            pending.keep = true;
        }
    }
    if let Some(refused) = refused {
        result["subscribe_refused"] = json!(refused);
    }
    Ok(result)
}

pub(super) fn unsubscribe(db: &Db, caller: &Caller, stream: &str, subscription: &str) -> Value {
    if let (Some(hub), Some(token)) = (
        RealtimeHub::for_database(db),
        ConnectionToken::from_hex(stream.trim()),
    ) {
        let mut registry = hub.need_registry().lock().expect("need registry poisoned");
        if registry
            .connection_footing(&token)
            .is_some_and(|(account, _)| account == caller.credential())
        {
            registry.unsubscribe(&token, &SubscriptionId::from_wire(subscription));
        }
    }
    json!({"subscription":subscription,"unsubscribed":true})
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn declarative_sql_epoch_fences_native_links_destinations_carriers_and_identity() {
        let mut conn = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE meta_events(seq INTEGER PRIMARY KEY); CREATE TABLE content_events(seq INTEGER PRIMARY KEY,type TEXT,payload TEXT)").execute(&mut conn).await.unwrap();
        let mut previous = authorization_epoch_on(&mut conn).await.unwrap();
        for event in [
            "kernel.link_added.v1",
            "kernel.link_added.v2",
            "kernel.link_removed.v1",
            "kernel.link_removed.v2",
            "kernel.message_destination_set.v1",
            "kernel.record_rebound.v1",
            "kernel.identity_binding_added.v1",
            "kernel.attachment_bound.v1",
            "kernel.root_admin_bootstrapped.v1",
            "kernel.generic_link_removed.v1",
            "kernel.import_home_policy.v1",
        ] {
            sqlx::query("INSERT INTO content_events(type,payload) VALUES(?,'{}')")
                .bind(event)
                .execute(&mut conn)
                .await
                .unwrap();
            let current = authorization_epoch_on(&mut conn).await.unwrap();
            assert_ne!(current, previous, "{event}");
            previous = current;
        }
        sqlx::query("INSERT INTO content_events(type,payload) VALUES('kernel.record_revised.v2','{\"fields\":{\"v1_kind\":\"attachment\"}}')").execute(&mut conn).await.unwrap();
        let current = authorization_epoch_on(&mut conn).await.unwrap();
        assert_ne!(current, previous);
        previous = current;
        sqlx::query("INSERT INTO content_events(type,payload) VALUES('kernel.record_revised.v2','{\"fields\":{\"title\":\"Unrelated title\"}}')").execute(&mut conn).await.unwrap();
        assert_eq!(authorization_epoch_on(&mut conn).await.unwrap(), previous);
        sqlx::query("INSERT INTO meta_events VALUES(1)")
            .execute(&mut conn)
            .await
            .unwrap();
        assert_ne!(authorization_epoch_on(&mut conn).await.unwrap(), previous);
    }
}
