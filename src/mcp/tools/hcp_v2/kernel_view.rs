//! Ordinary editable kernel views, kept separate from trusted HCP state.
use super::{
    setup,
    store::{Store, WriteTx},
};
use crate::{
    kernel,
    store::{append_in, AppendSpec},
    Error, Result,
};
use serde_json::{json, Value};

pub(super) async fn private_revision(
    store: &Store<'_>,
    tx: &mut WriteTx,
    id: &str,
    entry: bool,
) -> Result<Option<String>> {
    private_revision_on(tx, store.account(), id, entry).await
}
pub(super) async fn private_revision_on(
    tx: &mut sqlx::SqliteConnection,
    principal: &str,
    id: &str,
    entry: bool,
) -> Result<Option<String>> {
    let Some(record) = kernel::read_record_on(tx, principal, id).await? else {
        return Ok(None);
    };
    let family = if entry {
        setup::KERNEL_ENTRY_FAMILY
    } else {
        setup::KERNEL_SUGGESTION_FAMILY
    };
    let kind = if entry { "hcp_entry" } else { "suggestion" };
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if record.archived
        || record.family.as_deref() != Some(family)
        || record.kind.as_deref() != Some(kind)
        || owner.as_deref() != Some(principal)
    {
        return Ok(None);
    }
    let snapshot = kernel::policy_read::snapshot_on(tx, principal, id, false).await?;
    // A suggestion inherits the entry's exact private policy home. An entry
    // must retain its own private anchor, not inherit a newly moved placement.
    let sole = snapshot.entries.len() == 1
        && snapshot.entries[0].kind == "account"
        && snapshot.entries[0].subject == principal
        && snapshot.entries[0].capability == "manage";
    if !sole || (entry && snapshot.mode != "explicit") {
        return Ok(None);
    }
    Ok(Some(snapshot.revision))
}
async fn event(
    store: &Store<'_>,
    tx: &mut WriteTx,
    acts: &mut crate::act::ActAllocation,
    id: &str,
    ty: &str,
    payload: Value,
) -> Result<()> {
    append_in(
        store.db,
        tx,
        AppendSpec {
            record_id: id.into(),
            event_type: ty.into(),
            payload,
            actor: Some(store.account().into()),
        },
        acts,
    )
    .await?;
    Ok(())
}
pub(super) async fn create(store: &Store<'_>, args: Value) -> Result<Value> {
    let mut tx = store.begin().await?;
    let mut acts = crate::act::ActAllocation::new();
    let id = create_in(store, &mut tx, &mut acts, &args).await?;
    store.commit(tx).await?;
    Ok(json!({"id":id}))
}
async fn create_in(
    store: &Store<'_>,
    tx: &mut WriteTx,
    acts: &mut crate::act::ActAllocation,
    args: &Value,
) -> Result<String> {
    let entry = args["type"] == "Resolution";
    let family = if entry {
        setup::KERNEL_ENTRY_FAMILY
    } else {
        setup::KERNEL_SUGGESTION_FAMILY
    };
    let kind = if entry { "hcp_entry" } else { "suggestion" };
    let target = args["links"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|l| l["target_id"].as_str());
    let home = if let Some(target) = target {
        if private_revision(store, tx, target, true).await?.is_none() {
            return Err(Error::engine("HCP suggestion target is no longer private"));
        }
        kernel::read_record_on(tx, store.account(), target)
            .await?
            .unwrap()
            .home_id
    } else {
        crate::events::KERNEL_ROOT_ID.into()
    };
    let mut fields = json!({"title":args["name"]});
    if let Some(life) = args.get("lifecycle") {
        fields["lifecycle"] = life.clone();
    }
    let raw = fields.to_string();
    let id = kernel::create_input_admitted_in(
        store.db,
        tx,
        acts,
        store.account(),
        family,
        kind,
        kernel::FieldInput::Raw(&raw),
        &home,
        None,
        !entry,
        args["id"].as_str(),
        None,
        None,
    )
    .await?;
    if entry {
        kernel::account_only_record_in(store.db, tx, acts, store.account(), &id).await?;
    }
    if let Some(body) = args.get("body") {
        event(
            store,
            tx,
            acts,
            &id,
            "kernel.body_set.v1",
            json!({"body":body}),
        )
        .await?;
    }
    crate::mcp::kernel_v2::writes::facets(
        store.db,
        tx,
        acts,
        store.account(),
        &id,
        args.get("facets"),
        "HCP view",
    )
    .await?;
    if let Some(target) = target {
        kernel::generic_links::add_generic_link_in(
            store.db,
            tx,
            acts,
            store.account(),
            &id,
            target,
            "part_of",
            None,
        )
        .await?;
    }
    Ok(id)
}
pub(super) async fn update(store: &Store<'_>, mut args: Value) -> Result<Value> {
    // Shared view code supplies an empty v1 source declaration. The kernel
    // update contract has no sources argument; preserve every actual write
    // and CAS field, and refuse rather than discard a nonempty declaration.
    if let Some(sources) = args.as_object_mut().and_then(|args| args.remove("sources")) {
        if sources.as_array().is_none_or(|sources| !sources.is_empty()) {
            return Err(Error::engine(
                "kernel HCP view updates require an empty source declaration",
            ));
        }
    }
    let mut tx = store.begin().await?;
    let mut acts = crate::act::ActAllocation::new();
    let id = args["id"]
        .as_str()
        .ok_or_else(|| Error::engine("missing HCP view id"))?;
    if private_revision(store, &mut tx, id, true).await?.is_none() {
        return Err(Error::engine("HCP view is no longer private"));
    }
    let result =
        crate::mcp::kernel_v2::writes::update(store.db, &mut tx, &mut acts, store.account(), &args)
            .await?;
    store.commit(tx).await?;
    Ok(result)
}

pub(super) async fn sync_suggestions(store: &Store<'_>) -> Result<()> {
    let mut tx = store.begin().await?;
    let mut acts = crate::act::ActAllocation::new();
    let fold = store.fold_all_in(&mut tx).await?;
    for entry in fold
        .entries
        .values()
        .map(|f| f.current())
        .filter(|e| e.status() == "conflicted" && e.declaration_type() == "model-inferred")
    {
        let target = super::store::record_id_of(entry.id()).unwrap();
        if private_revision(store, &mut tx, &target, true)
            .await?
            .is_none()
        {
            continue;
        }
        let held = kernel::read_record_on(&mut tx, store.account(), &target)
            .await?
            .unwrap();
        let body = entry.view_body();
        if held.body.as_deref() != Some(&body) {
            continue;
        }
        let mut open = false;
        for mapping in fold.suggestions.values().filter(|p| {
            p.entry_id == entry.id()
                && p.version == entry.version()
                && !fold.resolutions.contains_key(&p.suggestion_id)
        }) {
            if private_revision(store, &mut tx, &mapping.suggestion_id, false)
                .await?
                .is_some()
            {
                let record =
                    kernel::read_record_on(&mut tx, store.account(), &mapping.suggestion_id)
                        .await?
                        .unwrap();
                let targets:Vec<String>=sqlx::query_scalar("SELECT target_id FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1").bind(&mapping.suggestion_id).fetch_all(&mut *tx).await?;
                if record.fields["lifecycle"] == "open"
                    && record.body.as_deref() == Some(&body)
                    && targets == [target.clone()]
                {
                    open = true;
                }
            }
        }
        if open {
            continue;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let digest = super::store::sha256_hex(&body);
        create_in(store,&mut tx,&mut acts,&json!({"id":id,"type":"Annotation","kind":"suggestion","name":"Confirm or reject this inferred preference","lifecycle":"open","body":body,"links":[{"target_id":target,"relationship":"part_of"}],"facets":{"proposal.precondition":"digest","anchor.base_digest":digest}})).await?;
        let created:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='kernel.record_created.v1' ORDER BY seq LIMIT 1").bind(&id).fetch_one(&mut *tx).await?;
        store
            .append(
                &mut tx,
                &mut acts,
                format!("hcp-suggestion:{}:{id}", store.account()),
                "Bind private suggestion to HCP inference version".into(),
                crate::control::ControlEventPayload::HcpEntrySuggestion(
                    crate::control::HcpEntrySuggestionPayload {
                        account_id: store.account().into(),
                        entry_id: entry.id().into(),
                        version: entry.version(),
                        client: super::store::payload_of(&super::client::ClientIdentity::native()),
                        suggestion_id: id,
                        created_event_id: created,
                        body_digest: digest,
                    },
                ),
            )
            .await?;
    }
    for mapping in fold.suggestions.values() {
        let live = fold.entries.get(&mapping.entry_id).is_some_and(|f| {
            f.current().version() == mapping.version
                && f.current().status() == "conflicted"
                && super::store::sha256_hex(&f.current().view_body()) == mapping.body_digest
        });
        if (!live || fold.resolutions.contains_key(&mapping.suggestion_id))
            && private_revision(store, &mut tx, &mapping.suggestion_id, false)
                .await?
                .is_some()
        {
            let record = kernel::read_record_on(&mut tx, store.account(), &mapping.suggestion_id)
                .await?
                .unwrap();
            if record.fields["lifecycle"] == "open" {
                event(
                    store,
                    &mut tx,
                    &mut acts,
                    &mapping.suggestion_id,
                    "kernel.archive_changed.v1",
                    json!({"archived":true}),
                )
                .await?;
            }
        }
    }
    store.commit(tx).await
}

#[cfg(test)]
mod tests {
    use super::super::{client::ClientIdentity, ops, PseudonymKey};
    use super::*;
    use crate::mcp::registry::Caller;

    #[tokio::test]
    async fn kernel_hcp_tools_opt_in_roundtrip_private_edit_and_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("tools.db").display());
        let (db, admin) = kernel::create_v2_database(&url, "account", "Admin", "test:hcp-kernel")
            .await
            .unwrap();
        assert!(setup::not_configured_kernel(&db).await.unwrap().is_some());
        for (family, bytes) in [
            (setup::KERNEL_ENTRY_FAMILY, setup::KERNEL_ENTRY_DEFINITION),
            (
                setup::KERNEL_SUGGESTION_FAMILY,
                setup::KERNEL_SUGGESTION_DEFINITION,
            ),
        ] {
            let pin = kernel::install_definition_as(&db, &admin, family, 1, bytes.as_bytes())
                .await
                .unwrap();
            kernel::adopt_definition_as(&db, &admin, family, Some(&pin))
                .await
                .unwrap();
        }
        assert!(setup::not_configured_kernel(&db).await.unwrap().is_none());
        let other = kernel::create_principal(&db, "account", "Other", "test:other", &admin)
            .await
            .unwrap();
        let caller =
            Caller::authenticated("test:other").with_oauth_client_id(Some("client-a".into()));
        let store = Store::new_kernel(
            &db,
            &caller,
            ClientIdentity::of(&caller).unwrap(),
            PseudonymKey::from_secret(&[42; 32]).unwrap(),
        )
        .await
        .unwrap();
        let added=ops::add(&store,&json!({"category":"general_preferences","preference":"Be concise","sourceContext":"fixture","declarationType":"user-declared"})).await.unwrap_or_else(|_|panic!("add failed"));
        let urn = added["id"].as_str().unwrap();
        let id = super::super::store::record_id_of(urn).unwrap();
        assert!(kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .is_none());
        let original = kernel::read_record_as(&db, &other, &id)
            .await
            .unwrap()
            .unwrap();
        let mut body: Value = serde_json::from_str(original.body.as_deref().unwrap()).unwrap();
        body["claim"]["subject"]["preference"] = json!("Use plain language");
        let mut tx = store.begin().await.unwrap();
        event(
            &store,
            &mut tx,
            &mut crate::act::ActAllocation::new(),
            &id,
            "kernel.body_set.v1",
            json!({"body":body.to_string()}),
        )
        .await
        .unwrap();
        store.commit(tx).await.unwrap();
        let second_caller = caller.clone().with_oauth_client_id(Some("client-b".into()));
        let second = Store::new_kernel(
            &db,
            &second_caller,
            ClientIdentity::of(&second_caller).unwrap(),
            PseudonymKey::from_secret(&[42; 32]).unwrap(),
        )
        .await
        .unwrap();
        assert!(ops::get(
            &second,
            &json!({"entryId":urn,"purpose":"undisclosed direct get"})
        )
        .await
        .is_err());
        assert_eq!(
            store.fold_all().await.unwrap().entries[urn]
                .current()
                .version(),
            1,
            "disclosure must precede reconciliation"
        );
        let got = ops::get(&store, &json!({"entryId":urn,"purpose":"fixture"}))
            .await
            .unwrap_or_else(|_| panic!("get failed"));
        assert_eq!(got["entry"]["record"]["version"], 2);
        assert_eq!(
            got["entry"]["claim"]["subject"]["preference"],
            "Use plain language"
        );
        let discovered=ops::search(&second,&json!({"query":"plain","categories":["general_preferences"],"purpose":"discover edited preference"})).await.unwrap_or_else(|_|panic!("second-client search failed"));
        assert_eq!(discovered["entries"].as_array().unwrap().len(), 1);
        assert!(ops::get(
            &second,
            &json!({"entryId":urn,"purpose":"previously disclosed"})
        )
        .await
        .is_ok());
        let disclosed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_hcp_disclosures WHERE principal_id=? AND client_id='client-b' AND entry_id=?)").bind(&other).bind(urn).fetch_one(db.pool()).await.unwrap();
        assert!(
            disclosed,
            "search acknowledges only after disclosure commits"
        );
        ops::update(
            &store,
            &json!({"entryId":urn,"updatedPreference":"Be brief","reason":"fixture"}),
        )
        .await
        .unwrap_or_else(|_| panic!("update failed"));
        let update_a =
            json!({"entryId":urn,"updatedPreference":"Be brief A","reason":"concurrent A"});
        let update_b =
            json!({"entryId":urn,"updatedPreference":"Be brief B","reason":"concurrent B"});
        let (a, b) = tokio::join!(
            ops::update(&store, &update_a),
            ops::update(&store, &update_b)
        );
        assert!(a.is_ok() && b.is_ok());
        let fold = store.fold_all().await.unwrap();
        assert_eq!(
            fold.entries[urn].versions.len(),
            5,
            "serialized writers cannot reuse a version"
        );
        assert!(fold.rejected.is_empty());
        let found = ops::search(
            &store,
            &json!({"query":"brief","categories":["general_preferences"],"purpose":"fixture"}),
        )
        .await
        .unwrap_or_else(|_| panic!("search failed"));
        assert_eq!(found["entries"].as_array().unwrap().len(), 1);
        ops::delete(&store, &json!({"entryId":urn,"reason":"fixture"}))
            .await
            .unwrap_or_else(|_| panic!("delete failed"));
        assert!(
            ops::get(&store, &json!({"entryId":urn,"purpose":"fixture"}))
                .await
                .is_err()
        );
        for principal in [&admin, &other] {
            let mut snapshot = db.pool().begin().await.unwrap();
            let reads =
                std::collections::BTreeSet::from([("content_events".into(), "type".into())]);
            crate::mcp::kernel_v2::sql::install(&mut snapshot, principal, &reads)
                .await
                .unwrap();
            let leaked:i64=sqlx::query_scalar("SELECT count(*) FROM temp.content_events WHERE type GLOB 'kernel.hcp_*' OR type GLOB 'hcp.*'").fetch_one(&mut *snapshot).await.unwrap();
            assert_eq!(
                leaked, 0,
                "raw HCP events are excluded even for administrators"
            );
            snapshot.rollback().await.unwrap();
        }
        let mut hcp_registry = crate::mcp::registry::ToolRegistry::new();
        super::super::register_hcp_v2_tools(
            &mut hcp_registry,
            PseudonymKey::from_secret(&[42; 32]).unwrap(),
        )
        .unwrap();
        assert!(hcp_registry.get(super::super::AUDIT_TOOL).is_none());
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    }
}
