//! Small source seams absent from the logical kernel staging: use existing
//! instruction authority, schema visibility/exact-id gate and facet discovery.
use super::*;

// Resolve nothing here: scan only bodies already selected into this exact
// member cut. The shared read fold later resolves against admitted visibility.
pub(super) fn mentions(destination: &mut Connection) -> Result<()> {
    let tx = storage(destination.transaction())?;
    {
        let mut statement =
            storage(tx.prepare("SELECT id,body FROM records WHERE body IS NOT NULL"))?;
        let mut rows = storage(statement.query([]))?;
        while let Some(row) = storage(rows.next())? {
            let id: String = storage(row.get(0))?;
            let body: String = storage(row.get(1))?;
            for occurrence in crate::mentions::scan_body(&body) {
                storage(tx.execute(
                    "INSERT INTO member_mentions VALUES (?,?,?,?,?,?)",
                    rusqlite::params![
                        id,
                        occurrence.authored_reference,
                        occurrence.lookup_key,
                        occurrence.form.as_str(),
                        occurrence.span_start as i64,
                        occurrence.span_end as i64
                    ],
                ))?;
            }
        }
    }
    storage(tx.commit())
}

pub(super) async fn record_metadata(
    source: &mut sqlx::SqliteConnection,
    destination: &mut Connection,
    principal: &str,
    shape_ids: &BTreeSet<String>,
) -> Result<()> {
    // Retain the old id order and first-row lookup behavior even for duplicate
    // ids. Defer type/kind conversion failures to the old lookup position, after
    // the source authority/identity helpers have run for that record.
    let mut first = None::<(String, Result<(String, Option<String>)>)>;
    let records: Vec<_> = storage(
        storage(destination.prepare("SELECT id,type,kind FROM records ORDER BY id,rowid"))?
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let fields = match &first {
                    Some((previous, fields)) if previous == &id => fields.clone(),
                    _ => {
                        let fields: rusqlite::Result<(String, Option<String>)> =
                            (|| Ok((row.get(1)?, row.get(2)?)))();
                        let fields = storage(fields);
                        first = Some((id.clone(), fields.clone()));
                        fields
                    }
                };
                Ok((id, fields))
            }),
    )?
    .collect::<std::result::Result<_, _>>()
    .map_err(|_| Refusal::Storage)?;
    let visible: std::collections::HashSet<_> = records.iter().map(|(id, _)| id.clone()).collect();
    let mut owners = std::collections::BTreeMap::<String, Option<String>>::new();
    let mut writes = MetadataWrites {
        destination,
        active: false,
    };
    // This fresh read cache cannot inherit logical TEMP labels or a caller's
    // pinned/capability scope. It ends before mentions, blobs and final fences.
    crate::kernel::read_cache::scope_member_metadata(async {
        for (id, fields) in records {
            let raw: Option<String> = storage(
                sqlx::query_scalar("SELECT owner_id FROM main.kernel_records WHERE id=?")
                    .bind(&id)
                    .fetch_optional(&mut *source)
                    .await,
            )?
            .flatten();
            let owner = if let Some(raw) = raw {
                if visible.contains(&raw) {
                    Some(raw)
                } else if let Some(owner) = owners.get(&raw) {
                    owner.clone()
                } else {
                    let owner = crate::mcp::kernel_v2::member_visible_person_on(
                        source,
                        principal,
                        Some(&raw),
                    )
                    .await
                    .map_err(|_| Refusal::Authorization)?
                    .filter(|id| visible.contains(id));
                    owners.insert(raw, owner.clone());
                    owner
                }
            } else {
                None
            };
            let boundary = crate::mcp::kernel_v2::custody_boundary_on(source, &id)
                .await
                .map_err(|_| Refusal::Storage)?;
            let containment_path_visible =
                crate::mcp::kernel_v2::native_containment_path_visible_on(source, principal, &id)
                    .await
                    .map_err(|_| Refusal::Authorization)?;
            let display_reference = crate::mcp::kernel_v2::member_display_reference_on(source, &id)
                .await
                .map_err(|_| Refusal::Storage)?;
            let native_comment = crate::kernel::comments_v2::is_comment_on(source, &id)
                .await
                .map_err(|_| Refusal::Storage)?;
            let bears_shape = shape_ids.contains(&id);
            let comment_context = if native_comment {
                let bearers = crate::kernel::comments_v2::bearer_on(source, &id)
                    .await
                    .map_err(|_| Refusal::Authorization)?;
                let [bearer] = bearers.as_slice() else {
                    return Err(Refusal::Content);
                };
                let position = crate::kernel::comments_v2::position_on(source, bearer)
                    .await
                    .map_err(|_| Refusal::Content)?;
                let (position, root_id) = match position {
                    crate::kernel::comments_v2::Position::Root => ("root", id.as_str()),
                    crate::kernel::comments_v2::Position::Reply => ("reply", bearer.as_str()),
                };
                Some(storage(serde_json::to_string(
                    &serde_json::json!({"position":position,"root_id":root_id}),
                ))?)
            } else {
                None
            };
            let native_identity = if id == crate::events::KERNEL_ROOT_ID {
                serde_json::json!({"virtual_root":true})
            } else {
                let record = crate::kernel::read_record_on(source, principal, &id)
                    .await
                    .map_err(|_| Refusal::Authorization)?
                    .ok_or(Refusal::Authorization)?;
                let created_at: String = storage(
                    sqlx::query_scalar("SELECT created_at FROM main.kernel_records WHERE id=?")
                        .bind(&id)
                        .fetch_one(&mut *source)
                        .await,
                )?;
                crate::mcp::kernel_v2::native_record_identity(&record, &created_at)
            };
            let native_identity = storage(serde_json::to_string(&native_identity))?;
            let (typ, kind) = fields?;
            let blob_metadata = if typ == "Document" && kind.as_deref() == Some("attachment") {
                let metadata = crate::kernel::blobs::metadata_optional(source, principal, &id)
                    .await
                    .map_err(|_| Refusal::Authorization)?;
                metadata
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(|_| Refusal::Content)?
            } else {
                None
            };
            writes.insert(rusqlite::params![
                id,
                owner,
                boundary,
                display_reference,
                native_comment,
                bears_shape,
                blob_metadata,
                native_identity,
                comment_context,
                containment_path_visible
            ])?;
        }
        Ok(())
    })
    .await?;
    writes.commit()
}

// A rusqlite Transaction/Statement borrows &Connection and cannot cross the
// source awaits in this Send future. Keep an exclusive mutable borrow instead;
// check the cached statement out only for each synchronous insert. Begin at the
// first write so source refusals before it retain their original ordering.
struct MetadataWrites<'a> {
    destination: &'a mut Connection,
    active: bool,
}
impl MetadataWrites<'_> {
    fn insert(&mut self, params: impl rusqlite::Params) -> Result<()> {
        if !self.active {
            storage(self.destination.execute_batch("BEGIN DEFERRED"))?;
            self.active = true;
        }
        storage(
            storage(self.destination.prepare_cached(
                "INSERT INTO member_record_metadata VALUES (?,?,?,?,?,?,?,?,?,?)",
            ))?
            .execute(params),
        )?;
        Ok(())
    }
    fn commit(mut self) -> Result<()> {
        if self.active {
            storage(self.destination.execute_batch("COMMIT"))?;
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for MetadataWrites<'_> {
    fn drop(&mut self) {
        if self.active {
            // Errors and cancellation discard the exclusively owned fresh file
            // in produce_in. Never reuse/publish it, even if rollback fails.
            let _ = self.destination.execute_batch("ROLLBACK");
        }
    }
}

pub(super) struct SelectedMemberContext {
    pub instructions: serde_json::Value,
    pub instruction_source_ids: std::collections::BTreeSet<String>,
    pub principal: serde_json::Value,
    pub virtual_root: Option<super::virtual_root::MemberVirtualRoot>,
    pub source_context: Option<super::source_context::MemberSourceContext>,
}

pub(super) async fn populate(
    source: &mut sqlx::SqliteConnection,
    destination: &mut Connection,
    schema: Vec<crate::query::cascade::SchemaConfigRow>,
    selected: SelectedMemberContext,
) -> Result<Vec<String>> {
    let SelectedMemberContext {
        instructions,
        instruction_source_ids,
        principal,
        virtual_root,
        source_context,
    } = selected;
    let visible: std::collections::HashSet<String> = storage(
        storage(destination.prepare("SELECT id FROM records"))?.query_map([], |r| r.get(0)),
    )?
    .collect::<std::result::Result<_, _>>()
    .map_err(|_| Refusal::Storage)?;
    if !instruction_source_ids.iter().all(|id| visible.contains(id)) {
        return Err(Refusal::Content);
    }
    // The shared resolver has already applied binding authority and source
    // visibility. Entries must also close over this exact staged snapshot.
    for entry in instructions["entries"].as_array().ok_or(Refusal::Content)? {
        let id = entry["source"]["record_id"]
            .as_str()
            .ok_or(Refusal::Content)?;
        let body: Option<String> =
            storage(
                destination.query_row("SELECT body FROM records WHERE id=?", [id], |r| r.get(0)),
            )?;
        if !visible.contains(id) || entry["content"].as_str() != body.as_deref() {
            return Err(Refusal::Content);
        }
    }
    storage(sqlx::query("CREATE TEMP TABLE schema_config (id TEXT,layer TEXT,name TEXT,data TEXT,applies_to_collection_id TEXT,version_lineage TEXT,created_at TEXT,created_at_ms INTEGER)").execute(&mut *source).await)?;
    let mut gate = crate::member_copy_producer::SchemaGate::default();
    for row in schema {
        let data = storage(serde_json::to_string(&row.data))?;
        if crate::member_copy_producer::exact_id_gate_withholds(&data, &visible) {
            gate.record(row.applies_to_collection_id.as_deref());
            continue;
        }
        let millis = chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map_err(|_| Refusal::Content)?
            .timestamp_millis();
        storage(destination.execute(
            "INSERT INTO schema_config VALUES (?,?,?,?,?,?,?,?)",
            rusqlite::params![
                row.id,
                row.layer,
                row.name,
                data,
                row.applies_to_collection_id,
                row.version_lineage,
                row.created_at,
                millis
            ],
        ))?;
        storage(
            sqlx::query("INSERT INTO temp.schema_config VALUES (?,?,?,?,?,?,?,?)")
                .bind(row.id)
                .bind(row.layer)
                .bind(row.name)
                .bind(data)
                .bind(row.applies_to_collection_id)
                .bind(row.version_lineage)
                .bind(row.created_at)
                .bind(millis)
                .execute(&mut *source)
                .await,
        )?;
    }
    let incomplete = gate.into_incomplete_for();
    super::source_context::MemberSourceContext::validate_held(&source_context, destination)?;
    storage(destination.execute(
        "INSERT INTO member_context VALUES (?,?,?,?,?,?)",
        rusqlite::params![
            storage(serde_json::to_string(&instructions))?,
            storage(serde_json::to_string(&incomplete))?,
            storage(serde_json::to_string(&principal))?,
            storage(serde_json::to_string(&instruction_source_ids))?,
            storage(serde_json::to_string(&virtual_root))?,
            storage(serde_json::to_string(&source_context))?,
        ],
    ))?;
    storage(sqlx::query("CREATE TEMP TABLE _query_sql_facet_keys (scope_id TEXT,type TEXT,kind TEXT,key TEXT,record_count INTEGER,declared INTEGER,value_type TEXT,vocab_ref TEXT,required INTEGER)").execute(&mut *source).await)?;
    crate::query::sql::populate_facet_keys_on(
        source,
        std::time::Instant::now()
            + std::time::Duration::from_millis(crate::query::sql_contract::QUERY_DEADLINE_MS),
    )
    .await
    .map_err(|_| Refusal::Storage)?;
    for row in storage(sqlx::query("SELECT scope_id,type,kind,key,record_count,declared,value_type,vocab_ref,required FROM temp._query_sql_facet_keys ORDER BY scope_id,type,kind,key").fetch_all(&mut *source).await)? {
        let values = (0..9).map(|index| cell(&row,index)).collect::<Result<Vec<_>>>()?;
        storage(destination.execute("INSERT INTO facet_keys VALUES (?,?,?,?,?,?,?,?,?)", rusqlite::params_from_iter(values)))?;
    }
    Ok(incomplete)
}
