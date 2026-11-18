//! Read adapter over an admitted NKM2 file. Captured readers retain a lifecycle
//! lease gate, so retirement refuses old snapshots before purge can run.
use super::*;
use crate::member_copy_kernel_v2::profile::AdmittedMemberFile;
use serde_json::{json, Value};
mod basics;

#[derive(Clone)]
pub(crate) struct NativeReader {
    file: Arc<Mutex<AdmittedMemberFile>>,
    lifecycle: Arc<Mutex<MemberCopyLifecycle>>,
    leases: Arc<MemberCopyLeaseGate>,
    admitted: AdmittedGeneration,
}

impl MemberCopyServing {
    pub(crate) fn native_reader(&self) -> Option<NativeReader> {
        let active = self.active.as_ref()?;
        Some(NativeReader {
            file: active.native.clone()?,
            lifecycle: self.lifecycle.clone(),
            leases: self.leases.clone(),
            admitted: active.admitted.clone(),
        })
    }

    pub(crate) fn native_vault_snapshot(
        &self,
    ) -> Result<Option<crate::markdown_vault::SourceSnapshot>> {
        self.native_reader()
            .map(|reader| {
                reader.vault_snapshot(
                    self.origin_database_id().unwrap_or_default(),
                    &self.account_token().unwrap_or_default(),
                )
            })
            .transpose()
    }
}

fn unavailable(surface: &str) -> Error {
    Error::unavailable_offline(surface, "not_held")
}
fn marker(surface: &str) -> Value {
    json!({"unavailable_offline":{"surface":surface,"retry":"when_online"}})
}

impl NativeReader {
    fn lease(&self) -> Result<MemberCopyLease> {
        let lease = self.leases.acquire()?;
        let state = self
            .lifecycle
            .lock()
            .map_err(|_| Error::copy_unavailable())?;
        if !matches!(state.read_decision(), ReadDecision::Allow) {
            return Err(Error::copy_unavailable());
        }
        Ok(lease)
    }

    fn rows(file: &AdmittedMemberFile, relation: &str) -> Result<Vec<Value>> {
        file.objects(relation).map_err(|_| unavailable(relation))
    }

    fn get(file: &AdmittedMemberFile, args: &Value) -> Result<Value> {
        let rows = Self::rows(file, "records")?;
        let links = Self::rows(file, "links")?;
        let facets = Self::rows(file, "facet_values")?;
        let metadata = Self::rows(file, "member_record_metadata")?;
        let schema = basics::schema_rows(file)?;
        let ids: Vec<&str> = if let Some(ids) = args["ids"].as_array() {
            ids.iter().filter_map(Value::as_str).collect()
        } else {
            ["id", "record_id"]
                .iter()
                .find_map(|key| args[*key].as_str())
                .into_iter()
                .collect()
        };
        if ids.is_empty() || ids.len() > 100 {
            return Err(Error::engine("get_record requires 1–100 references"));
        }
        let mut records = Vec::new();
        for reference in ids {
            let matching: Vec<_> = rows
                .iter()
                .filter(|r| {
                    r["id"].as_str().is_some_and(|id| {
                        id == reference || (reference.len() >= 7 && id.starts_with(reference))
                    })
                })
                .collect();
            let [record] = matching.as_slice() else {
                records.push(json!({"id":reference,"status":if matching.is_empty(){"not_found"}else{"ambiguous"}}));
                continue;
            };
            let mut value = (**record).clone();
            let id = value["id"].clone();
            value["status"] = json!("found");
            value["archived"] = json!(value["archived"] == 1);
            value["body_digest"] = json!(crate::mcp::tools::lifecycle::body_digest(
                value["body"].as_str()
            ));
            let meta = metadata
                .iter()
                .find(|row| row["record_id"] == id)
                .ok_or_else(Error::copy_unavailable)?;
            crate::mcp::tools::lifecycle::apply_record_path_with_reference(
                &mut value,
                id.as_str().unwrap_or_default(),
                meta["display_reference"].as_str().map(str::to_owned),
            )?;
            value["owner_id"] = meta["owner_id"].clone();
            value["custody_boundary"] = json!(meta["custody_boundary"] == 1);
            let (path, complete) = basics::path(&rows, id.as_str().unwrap_or_default());
            value["containment_path_visible"] = json!(complete);
            value["path"] = json!(path);
            value["bears_shape"] = json!(crate::query::cascade::bears_shape_from_rows(
                &schema,
                id.as_str().unwrap_or_default()
            ));
            value["facets"] = json!(facets
                .iter()
                .filter(|r| r["record_id"] == id)
                .collect::<Vec<_>>());
            let outgoing: Vec<_> = links
                .iter()
                .filter(|r| r["source_id"] == id)
                .cloned()
                .collect();
            let incoming: Vec<_> = links
                .iter()
                .filter(|r| r["target_id"] == id)
                .cloned()
                .collect();
            value["links_out_count"] = json!(outgoing.len());
            value["links_out"] = json!(outgoing);
            value["links_in_count"] = json!(incoming.len());
            value["links_in"] = json!(incoming);
            for key in [
                "history_summary",
                "contribution",
                "citation_resolution",
                "message_audience",
                "message_mentions",
            ] {
                value[key] = marker(key);
            }
            if args["include_interpretation"] == true {
                value["interpretation"] = marker("interpretation");
            }
            records.push(value);
        }
        Ok(json!({"records":records}))
    }

    fn gate(&self) -> MemberCopyGate {
        MemberCopyGate::with_leases(
            self.lifecycle.clone(),
            self.admitted.scope_ref.clone(),
            self.admitted.ordinal,
            self.admitted.schema_incomplete_for.clone(),
            self.leases.clone(),
        )
        .with_generation_id(self.admitted.generation_id.clone())
    }
    async fn session_read(
        &self,
        registry: &ToolRegistry,
        kind: Option<crate::mcp::interactions::ToolKind>,
        tool: String,
        args: Value,
    ) -> Result<Value> {
        let gate = self.gate();
        gate.admit(kind, &tool, &args)?;
        let lease = self.lease()?;
        let source = self
            .file
            .lock()
            .map_err(|_| Error::copy_unavailable())?
            .borrow_member_read(lease)?;
        let mut session = source.open().await?;
        let context = crate::domain_transaction::request::member_correlation_context(
            crate::mcp::Caller::member_copy(session.principal()),
            &args,
        )?;
        let echo_context = tool == "bootstrap"
            || args.get("run_key").is_some()
            || args.get("parent_key").is_some();
        let mut caller = context.caller;
        let mut args = args;
        crate::domain_transaction::request::strip_run_context(&mut args);
        caller.set_member_schema_incomplete_for(self.admitted.schema_incomplete_for.clone());
        let result = match tool.as_str() {
            "bootstrap" => {
                let result = crate::mcp::tools::orientation::native_member_bootstrap(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await;
                match result {
                    Ok(mut value) => {
                        let policy = crate::mcp::interactions::ResolvedToolExposure::new(
                            registry.exposure_profile(),
                        );
                        match registry.exposure_summary(&policy, false).await {
                            Ok(exposure) => {
                                crate::mcp::tools::orientation::attach_member_bootstrap_exposure(
                                    &mut value, exposure,
                                )
                                .map(|()| value)
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            "query_record" => {
                crate::mcp::tools::querying::native_member_query_record(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "open_collection" => {
                crate::mcp::tools::artifacts::native_member_open_collection(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "get_record" => {
                crate::mcp::tools::lifecycle::native_member_get_record(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "resolve_many" => {
                crate::mcp::tools::resolution::native_member_resolve_many(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "scan" => {
                crate::mcp::tools::querying::native_member_scan(&mut session, &caller, args.clone())
                    .await
            }
            "get_dashboard" => {
                crate::mcp::tools::orientation::native_member_get_dashboard(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "search" => {
                crate::mcp::tools::querying::native_member_search(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "get_structure" => {
                crate::mcp::tools::orientation::native_member_get_structure(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "describe_schema" => {
                crate::mcp::tools::orientation::native_member_describe_schema(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "suggest_facet_values" => {
                crate::mcp::tools::facets::native_member_suggest_facet_values(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "resolve_facets" => {
                crate::mcp::tools::facets::native_member_resolve_facets(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "preview_record_shape" => {
                crate::mcp::tools::record_shape::native_member_preview_record_shape(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "manage_links" => {
                crate::mcp::tools::links::native_member_manage_links(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            "render_record" => {
                crate::mcp::tools::lifecycle::native_member_render_record(
                    &mut session,
                    &caller,
                    args.clone(),
                )
                .await
            }
            _ => Err(unavailable(&tool)),
        }
        .and_then(|mut value| {
            gate.decorate_value(&tool, &args, &mut value)?;
            if echo_context {
                value = crate::domain_transaction::request::attach_run_context(value, context.echo);
            }
            if tool == "bootstrap" {
                crate::mcp::tools::orientation::enforce_member_bootstrap_total(&value)?;
            }
            Ok(value)
        });
        let close = session.close().await;
        match result {
            Ok(value) => {
                close?;
                Ok(value)
            }
            Err(error) => {
                let _ = close;
                Err(error)
            }
        }
    }

    pub(crate) fn read(&self, registry: &ToolRegistry, name: &str, args: &Value) -> Result<Value> {
        let tool = registry
            .get(name)
            .ok_or_else(|| Error::engine("unknown member tool"))?;
        let scope = tool.kind.map(|k| k.member_scope());
        if matches!(
            scope,
            Some(crate::mcp::member_scope::MemberScope::WriteRefused)
        ) || scope
            .and_then(|s| s.refused_write_actions())
            .is_some_and(|actions| {
                args["action"]
                    .as_str()
                    .is_some_and(|action| actions.contains(&action))
            })
        {
            return Err(Error::standby_read_only());
        }
        let _lease = self.lease()?;
        if let Some(scope) = scope {
            use crate::mcp::member_scope::MemberScope;
            match scope {
                MemberScope::UnavailableOffline => return Err(unavailable(name)),
                MemberScope::Served { refused_args, .. }
                | MemberScope::ServedPartial { refused_args, .. }
                | MemberScope::SchemaGated { refused_args, .. } => {
                    if refused_args.iter().any(|argument| {
                        args.get(argument.name())
                            .is_some_and(|value| !value.is_null())
                    }) {
                        return Err(unavailable(name));
                    }
                }
                MemberScope::WriteRefused => return Err(Error::standby_read_only()),
            }
        }
        let file = self.file.lock().map_err(|_| Error::copy_unavailable())?;
        let mut result = match name {
            "ping" => json!({"ok":true}),
            "engine_info" => {
                json!({"engine":"native-kernel-v2","read_only":true,"storage_policy":marker("storage_policy")})
            }
            "standby_status" => serde_json::to_value(crate::holding::HoldingDisclosureV2::member(
                self.admitted.scope_ref.clone(),
                self.admitted.ordinal,
            ))?,
            "read_guide" => crate::mcp::guides::read_guide_value(args.clone())?,
            "quickstart" => crate::mcp::tools::quickstart::quickstart_value(args.clone())?,
            "get_record" => Self::get(&file, args)?,
            "query_sql" => file.query(args.clone())?,
            "read_attachment" | "manage_attachments" => {
                use crate::mcp::tools::attachments::member_attachment_request;
                let request = member_attachment_request(name, args.clone())?;
                let port=crate::member_copy_kernel_v2::profile::executor::NativeStatementExecutor::attachment_reader(&file)?;
                crate::member_copy_kernel_v2::profile::attachments::dispatch(&port, request)?
            }

            _ => return Err(unavailable(name)),
        };
        result["standby_context"] =
            serde_json::to_value(crate::holding::HoldingDisclosureV2::member(
                self.admitted.scope_ref.clone(),
                self.admitted.ordinal,
            ))?;
        Ok(result)
    }

    fn vault_snapshot(
        &self,
        origin: &str,
        account: &str,
    ) -> Result<crate::markdown_vault::SourceSnapshot> {
        use crate::markdown_vault::{SourceLink, SourceRecord, SourceSnapshot};
        let _lease = self.lease()?;
        let file = self.file.lock().map_err(|_| Error::copy_unavailable())?;
        let mut snapshot = SourceSnapshot {
            origin: origin.into(),
            account: account.into(),
            generation: self.admitted.generation_id.clone(),
            freshness: json!({"source":"member_copy","content_act":"not_held","author_history":"not_held"}),
            ..Default::default()
        };
        for row in Self::rows(&file, "records")? {
            let mut record = SourceRecord {
                id: row["id"]
                    .as_str()
                    .ok_or_else(Error::copy_unavailable)?
                    .into(),
                record_type: row["type"].as_str().unwrap_or("Record").into(),
                kind: row["kind"].as_str().map(str::to_owned),
                name: row["name"].as_str().map(str::to_owned),
                body: row["body"].as_str().map(str::to_owned),
                home_id: row["home_id"].as_str().map(str::to_owned),
                archived: row["archived"] == 1,
                ..Default::default()
            };
            for key in [
                "summary",
                "lifecycle",
                "maturity",
                "created_at",
                "updated_at",
                "last_activity_at",
            ] {
                if !row[key].is_null() {
                    record.metadata.insert(key.into(), row[key].clone());
                }
            }
            if row["is_current"] == 0 || row["successor_count"].as_i64().unwrap_or(0) > 0 {
                record.metadata.insert("superseded".into(), json!(true));
            }
            snapshot.records.insert(record.id.clone(), record);
        }
        // Match the native vault's format-only virtual-root projection, using
        // only the already admitted descriptor. This never inserts a record
        // into the member file or creates canonical source authority.
        let context = Self::rows(&file, "member_context")?;
        let [context] = context.as_slice() else {
            return Err(Error::copy_unavailable());
        };
        let root = crate::member_copy_kernel_v2::profile::virtual_root::MemberVirtualRoot::decode(
            context["virtual_root"]
                .as_str()
                .ok_or_else(Error::copy_unavailable)?,
        )
        .map_err(|_| Error::copy_unavailable())?
        .ok_or_else(Error::copy_unavailable)?;
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("last_activity_at".into(), json!(root.last_activity_at));
        metadata.insert("custody_boundary".into(), json!(root.custody_boundary));
        snapshot.records.insert(
            root.id.clone(),
            SourceRecord {
                id: root.id.clone(),
                record_type: root.record_type,
                kind: Some(root.kind),
                name: Some(root.name),
                home_id: root.home_id,
                archived: root.archived,
                metadata,
                ..Default::default()
            },
        );
        // Placement aliases denote the selected root in the renderer format.
        // Keep every other source-selected parent unchanged; no policy-home
        // ancestry, hidden folder or directory is reconstructed here.
        for record in snapshot.records.values_mut() {
            if record.home_id.as_deref().is_some_and(
                crate::member_copy_kernel_v2::profile::virtual_root::MemberVirtualRoot::is_alias,
            ) {
                record.home_id = Some(root.id.clone());
            }
        }
        for row in Self::rows(&file, "member_record_metadata")? {
            if let Some(record) = row["record_id"]
                .as_str()
                .and_then(|id| snapshot.records.get_mut(id))
            {
                record
                    .metadata
                    .insert("owner_id".into(), row["owner_id"].clone());
                record.metadata.insert(
                    "custody_boundary".into(),
                    json!(row["custody_boundary"] == 1),
                );
            }
        }
        for row in Self::rows(&file, "facet_values")? {
            if let Some(record) = row["record_id"]
                .as_str()
                .and_then(|id| snapshot.records.get_mut(id))
            {
                if let Some(key) = row["key"].as_str() {
                    record.facets.insert(key.into(), row["value"].clone());
                }
            }
        }
        for row in Self::rows(&file, "links")? {
            snapshot
                .links
                .push(serde_json::from_value::<SourceLink>(row)?);
        }
        for row in Self::rows(&file, "comment_anchors")? {
            if let Some(record) = row["annotation_id"]
                .as_str()
                .and_then(|id| snapshot.records.get_mut(id))
            {
                if let Some(selectors) = row["selectors"].as_str() {
                    record.anchors.push(serde_json::from_str(selectors)?);
                }
            }
        }
        Ok(snapshot)
    }
}

impl crate::mcp::NoHeldToolCall for NativeReader {
    fn refuse(&self, _name: &str, _arguments: &Value) -> Error {
        Error::copy_unavailable()
    }
    fn call(&self, registry: &ToolRegistry, name: &str, args: &Value) -> Result<Value> {
        let context = crate::domain_transaction::request::member_correlation_context(
            crate::mcp::Caller::member_copy(
                self.file
                    .lock()
                    .map_err(|_| Error::copy_unavailable())?
                    .principal_id()
                    .to_owned(),
            ),
            args,
        )?;
        let explicit = args.get("run_key").is_some() || args.get("parent_key").is_some();
        let mut args = args.clone();
        crate::domain_transaction::request::strip_run_context(&mut args);
        let value = self.read(registry, name, &args)?;
        Ok(if explicit {
            crate::domain_transaction::request::attach_run_context(value, context.echo)
        } else {
            value
        })
    }
    fn call_async<'a>(
        &'a self,
        registry: &'a ToolRegistry,
        name: &'a str,
        args: &'a Value,
    ) -> futures::future::BoxFuture<'a, Result<Value>> {
        if matches!(
            name,
            "bootstrap"
                | "query_record"
                | "open_collection"
                | "get_record"
                | "resolve_many"
                | "render_record"
                | "manage_links"
                | "preview_record_shape"
                | "resolve_facets"
                | "suggest_facet_values"
                | "describe_schema"
                | "get_structure"
                | "search"
                | "scan"
                | "get_dashboard"
        ) {
            Box::pin(self.session_read(
                registry,
                registry.get(name).and_then(|tool| tool.kind),
                name.to_owned(),
                args.clone(),
            ))
        } else {
            Box::pin(futures::future::ready(self.call(registry, name, args)))
        }
    }
}
