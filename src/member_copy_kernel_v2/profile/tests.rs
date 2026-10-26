use super::*;
use crate::mcp::{
    registry::{EngineHandle, ToolRegistry},
    Caller,
};
use crate::{
    events::KERNEL_ROOT_ID,
    holding::*,
    kernel,
    member_copy_transport::{test_consumer, CredentialSelection},
    replica_generation::*,
    standby_snapshot::*,
};
use serde_json::{json, Value as Json};
const OWNER: &str = "acct_00000000000000000000000000000001";
const OTHER: &str = "acct_00000000000000000000000000000003";
const MEMBER: &str = "acct_00000000000000000000000000000002";
fn manifest(cut: &NativeMemberCut) -> ReplicaGenerationManifest {
    ReplicaGenerationManifest {
        contract: REPLICA_GENERATION_CONTRACT.into(),
        version: REPLICA_GENERATION_VERSION,
        origin_database_id: cut.origin_database_id.clone(),
        hosted_route_database_id: "route-test".into(),
        captured_at: "2026-10-22T00:00:00Z".into(),
        snapshot_completed_at: "2026-10-22T00:00:01Z".into(),
        producer: StandbySnapshotEngineIdentity {
            name: "native-ce".into(),
            source_sha: "a".repeat(40),
            schema_version: 1,
            ddl_sha256: "b".repeat(64),
        },
        consumer: test_consumer(),
        bytes: StandbySnapshotBytes {
            media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
            size_bytes: 1024,
            sha256: "c".repeat(64),
        },
        materialization: StandbyGenerationMaterialization::Snapshot,
        scope: ReplicaScope::Member {
            scope_ref: "scope-one".into(),
        },
        ordering: ReplicaOrdering::Scoped { ordinal: 1 },
        holding: HoldingDisclosureV2::member("scope-one".into(), 1),
        profile: ReplicaProfile::MemberReadKernelV2 {
            engine: crate::standby::kernel_v2::ENGINE.into(),
            member_schema_digest: schema_digest(),
            identity: cut.profile_identity(),
        },
        content_digest: "e".repeat(64),
        own_writes: ReplicaOwnWrites::not_computed(),
        frontier: None,
        schema_incomplete_for: vec![],
    }
}
fn context(account: &str, manifest: &ReplicaGenerationManifest) -> MemberCopyContext {
    MemberCopyContext::new(
        account.into(),
        "https://example.invalid".into(),
        "route-test".into(),
        manifest.origin_database_id.clone(),
        test_consumer(),
        "scope-one".into(),
        CredentialSelection::for_test(b"synthetic credential"),
    )
}
async fn produce(db: &crate::Db, account: &str, directory: &Path) -> ProducedMemberFile {
    let mut conn = db.pool().acquire().await.unwrap();
    conn.close_on_drop();
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    let generation = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    let origin = crate::standby::kernel_v2::origin(&mut conn, &generation)
        .await
        .unwrap();
    let cut = super::super::tests::ready(capture_in(&mut conn, &origin, account).await.unwrap());
    let declaration = manifest(&cut);
    let result = produce_in(&mut conn, cut, directory, declaration)
        .await
        .unwrap();
    let staged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        staged, 0,
        "physical source helpers must not see logical TEMP views"
    );
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    result
}
async fn fixture(activate: bool) -> (tempfile::TempDir, crate::Db, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    let member = kernel::create_principal(&db, "account", "Member", MEMBER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "edit")],
    )
    .await
    .unwrap();
    let other = kernel::create_principal(&db, "account", "Other", OTHER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "edit"), (&other, "view")],
    )
    .await
    .unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &owner, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let documents = crate::v2_standard::document4_package();
    let document_identity = kernel::install_package_as(&db, &owner, &documents)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &documents,
        Some(&document_identity),
        &documents.declared_reads,
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (id, principal) in [
        ("person:owner", owner.clone()),
        ("person:member", member.clone()),
        ("person:other", other.clone()),
    ] {
        kernel::import_record_as(
            &db,
            &host,
            id,
            KERNEL_ROOT_ID,
            Some(&owner),
            &kernel::ImportRecordState {
                message_principal: Some(principal),
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: package.definitions[0].family.clone(),
                        version: package.definitions[0].version,
                        digest: package.definitions[0].digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        "Entity",
                        "person",
                        Some(id),
                        None,
                        None,
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    if activate {
        super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    }
    (dir, db, owner, member)
}
#[tokio::test]
async fn native_profile_matches_live_current_relations_for_each_member() {
    let (dir, db, owner, member) = fixture(false).await;
    // Ordinary shared and private homes, plus owner-floor and hidden-home
    // placement, use kernel production primitives without projection edits.
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&owner, "manage")]), &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(&db, &owner, &private, &[(&owner, "manage")])
        .await
        .unwrap();
    for package in [
        crate::v2_standard::document4_package(),
        crate::v2_standard::v1_compat::package(),
    ] {
        let identity = package.identity().unwrap();
        kernel::adopt_package_at(
            &db,
            &owner,
            &private,
            &package,
            Some(&identity),
            &package.declared_reads,
        )
        .await
        .unwrap();
    }
    let shared = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Shared","body":"shared body","home_id":KERNEL_ROOT_ID})).await["id"].as_str().unwrap().to_owned();
    let secret = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Secret","body":"private body","home_id":private})).await["id"].as_str().unwrap().to_owned();
    let comment = call(&db, OWNER, "create_record", json!({"type":"Annotation","kind":"comment","body":"synthetic private comment","links":[{"target_id":secret,"relationship":"part_of"}],"reason":"Synthetic member-copy derived proof"})).await["id"].as_str().unwrap().to_owned();
    let mut attachment_ids = vec![];
    for bearer in [&shared, &secret] {
        let result = call(&db, OWNER, "attach_text", json!({"record_id":bearer,"text":format!("attachment for {bearer}"),"filename":"proof.txt","mime":"text/plain"})).await;
        attachment_ids.push(result["attachment_id"].as_str().unwrap().to_owned());
    }
    // Other members' Directs remain hidden even from a root manager. This
    // tests both directions rather than assuming owner always sees everything.
    let mut direct_ids = vec![];
    for (account, person) in [(OWNER, "person:owner"), (MEMBER, "person:member")] {
        let result = call(&db, account,"manage_messages",json!({"action":"send","id":uuid::Uuid::new_v4().to_string(),"body":format!("synthetic direct {account}"),"addressed_to":["person:other"],"origin":{"type":"direct","participant_ids":[person,"person:other"]},"expectation":"reply","idempotency_key":format!("direct-{account}"),"reason":"Synthetic member-copy visibility proof"})).await;
        direct_ids.push(result["id"].as_str().unwrap().to_owned());
    }
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    // A stale shared home cannot make a hidden bearer's derived row visible.
    for (id, home, owner_id, typ, kind) in [
        (
            "derived-hidden",
            KERNEL_ROOT_ID,
            owner.as_str(),
            "Annotation",
            "highlight",
        ),
        (
            "owned-hidden-home",
            private.as_str(),
            member.as_str(),
            "Document",
            "note",
        ),
    ] {
        kernel::import_record_as(
            &db,
            &host,
            id,
            home,
            Some(owner_id),
            &kernel::ImportRecordState {
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: package.definitions[0].family.clone(),
                        version: package.definitions[0].version,
                        digest: package.definitions[0].digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        typ,
                        kind,
                        Some(id),
                        None,
                        None,
                    ),
                }),
                body: Some("synthetic derived body".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    kernel::import_generic_link_as(
        &db,
        &host,
        &kernel::GenericLink {
            link_id: uuid::Uuid::new_v4().to_string(),
            source_id: "derived-hidden".into(),
            target_id: secret.clone(),
            relationship: "part_of".into(),
            note: None,
            created_at: "2026-10-22T00:00:00Z".into(),
            actor: None,
        },
    )
    .await
    .unwrap();
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    for account in [OWNER, MEMBER, OTHER] {
        let produced = produce(&db, account, dir.path()).await;
        assert_eq!(
            produced.manifest().producer.name,
            crate::standby::kernel_v2::ENGINE
        );
        assert_eq!(produced.manifest().producer.schema_version, 0);
        let admitted = AdmittedMemberFile::open(
            produced.builder._file.path(),
            dir.path(),
            &context(account, produced.manifest()),
            produced.manifest(),
        )
        .unwrap();
        if account == MEMBER {
            let bytes = std::fs::read(produced.builder._file.path()).unwrap();
            assert!(!bytes
                .windows(private.len())
                .any(|w| w == private.as_bytes()));
            assert!(!bytes
                .windows(b"private body".len())
                .any(|w| w == b"private body"));
            let hidden = format!("synthetic direct {OWNER}");
            assert!(!bytes.windows(hidden.len()).any(|w| w == hidden.as_bytes()));
        }
        let copied = admitted.relation("records").unwrap();
        let ids: BTreeSet<_> = copied
            .iter()
            .map(|r| match &r[0] {
                Value::Text(id) => id.clone(),
                _ => panic!("id"),
            })
            .collect();
        assert!(ids.contains(&shared));
        assert_eq!(ids.contains(&secret), account == OWNER);
        assert_eq!(ids.contains("derived-hidden"), account == OWNER);
        assert_eq!(ids.contains(&comment), account == OWNER);
        assert_eq!(
            ids.contains(&direct_ids[0]),
            account == OWNER || account == OTHER
        );
        assert_eq!(
            ids.contains(&direct_ids[1]),
            account == MEMBER || account == OTHER
        );
        let attachments = admitted.relation("member_attachments").unwrap();
        assert_eq!(attachments.len(), if account == OWNER { 2 } else { 1 });
        assert!(attachments
            .iter()
            .any(|r| r[0] == Value::Text(attachment_ids[0].clone())));
        // Also compare to public live query_sql, not just its staging helper.
        let online = call(
            &db,
            account,
            "query_sql",
            json!({"sql":"SELECT id,home_id FROM records ORDER BY id"}),
        )
        .await;
        let mut offline: Vec<_> = copied.iter().map(|row| { let Value::Text(id)=&row[0] else {panic!("id")};
            let columns=tables().into_iter().find(|(n,_)|n=="records").unwrap().1;
            let home=&row[columns.iter().position(|c|c=="home_id").unwrap()];
            json!({"id":id,"home_id":match home { Value::Text(s)=>Json::String(s.clone()), Value::Null=>Json::Null,_=>panic!("home") }})
        }).collect();
        offline.sort_by_key(|row| row["id"].as_str().unwrap().to_owned());
        assert_eq!(online["rows"], Json::Array(offline));
        let actor = kernel::resolve_principal_by_binding(&db, account)
            .await
            .unwrap()
            .unwrap()
            .0;
        let mut conn = db.pool().acquire().await.unwrap();
        conn.close_on_drop();
        sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
        let reads = tables()
            .into_iter()
            .filter(|(n, _)| n != "member_attachments")
            .flat_map(|(n, c)| c.into_iter().map(move |c| (n.clone(), c)))
            .collect();
        crate::mcp::kernel_v2::sql::install(&mut conn, &actor, &reads)
            .await
            .unwrap();
        for (name, columns) in tables()
            .into_iter()
            .filter(|(n, _)| n != "member_attachments")
        {
            let rows = sqlx::query(&format!("SELECT {} FROM temp.{name}", quoted(&columns)))
                .fetch_all(&mut *conn)
                .await
                .unwrap();
            let mut live = rows
                .iter()
                .map(|row| {
                    (0..columns.len())
                        .map(|i| cell(row, i).unwrap())
                        .collect::<Vec<_>>()
                })
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>();
            let mut copy = admitted
                .relation(&name)
                .unwrap()
                .iter()
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>();
            live.sort();
            copy.sort();
            assert_eq!(copy, live, "{name}");
        }
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    }
    db.close().await;
}
#[tokio::test]
async fn native_profile_refuses_other_member_canonical_tamper_and_survives_candidate_replacement() {
    let (dir, db, _, _) = fixture(true).await;
    let produced = produce(&db, OWNER, dir.path()).await;
    let m = produced.manifest();
    let ctx = context(OWNER, m);
    assert!(AdmittedMemberFile::open(
        produced.builder._file.path(),
        dir.path(),
        &context(MEMBER, m),
        m
    )
    .is_err());
    // Match B's envelope and the offered A file's byte pin. The per-file
    // identity must still refuse independently of transport and byte hashes.
    let peer = produce(&db, MEMBER, dir.path()).await;
    let mut foreign_offer = peer.manifest().clone();
    foreign_offer.bytes = m.bytes.clone();
    assert!(matches!(
        AdmittedMemberFile::open(
            produced.builder._file.path(),
            dir.path(),
            &context(MEMBER, &foreign_offer),
            &foreign_offer
        ),
        Err(Refusal::Identity)
    ));
    // Close the canonical source before offering its standalone bytes. The
    // kernel writer fence intentionally refuses an ad-hoc pooled checkpoint.
    db.close().await;
    let source_path = dir.path().join("source.db");
    let bytes = std::fs::read(&source_path).unwrap();
    let mut canonical_offer = m.clone();
    canonical_offer.bytes.sha256 = hash(&bytes);
    canonical_offer.bytes.size_bytes = bytes.len() as u64;
    assert!(matches!(
        AdmittedMemberFile::open(&source_path, dir.path(), &ctx, &canonical_offer),
        Err(Refusal::Identity)
    ));

    let admitted =
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, m).unwrap();
    let before = admitted.relation("records").unwrap();
    produced
        .builder
        .connection
        .execute(
            "UPDATE kernel_member_identity SET generation_id='changed'",
            [],
        )
        .unwrap();
    assert!(AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, m).is_err());
    assert_eq!(admitted.relation("records").unwrap(), before);
    db.close().await;
}
#[tokio::test]
async fn native_profile_ranges_require_final_live_authority_and_catalog_check() {
    let (dir, db, owner, member) = fixture(true).await;
    let mut produced = produce(&db, MEMBER, dir.path()).await;
    assert!(produced.range(&db, 0, 128, || async { true }).await.is_ok());
    assert_eq!(
        produced.range(&db, 0, 128, || async { false }).await,
        Err(Refusal::Authorization)
    );
    kernel::replace_home_policy(&db, &owner, KERNEL_ROOT_ID, &[(&owner, "manage")])
        .await
        .unwrap();
    assert_eq!(
        produced.range(&db, 0, 128, || async { true }).await,
        Err(Refusal::Authorization)
    );
    assert!(
        !kernel::kernel_effective_capability(&db, &member, KERNEL_ROOT_ID)
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
    );
    db.close().await;
}

async fn call(db: &crate::Db, account: &str, name: &str, args: Json) -> Json {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(account),
            name,
            args,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn native_profile_final_authorization_runs_after_the_catalog_await() {
    let (dir, db, owner, _) = fixture(true).await;
    let mut produced = produce(&db, MEMBER, dir.path()).await;
    let result = produced
        .range(&db, 0, 128, || async {
            kernel::replace_home_policy(&db, &owner, KERNEL_ROOT_ID, &[(&owner, "manage")])
                .await
                .unwrap();
            true
        })
        .await;
    assert_eq!(result, Err(Refusal::Authorization));
    db.close().await;
}

#[tokio::test]
async fn native_profile_checks_closed_schema_semantics_and_physical_readonly_handle() {
    let (dir, db, _, _) = fixture(true).await;
    let produced = produce(&db, OWNER, dir.path()).await;
    let mut m = produced.manifest().clone();
    let ctx = context(OWNER, &m);
    let admitted =
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &m).unwrap();
    for change in ["delta", "media", "v1"] {
        let mut wrong = m.clone();
        match change {
            "delta" => wrong.materialization = StandbyGenerationMaterialization::Delta,
            "media" => wrong.bytes.media_type = "text/plain".into(),
            _ => {
                wrong.producer.name = "native-ce".into();
                wrong.producer.schema_version = 90;
            }
        }
        assert!(matches!(
            AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &wrong),
            Err(Refusal::Schema)
        ));
    }
    assert!(admitted
        .connection
        .is_readonly(rusqlite::DatabaseName::Main)
        .unwrap());
    assert!(admitted
        .connection
        .execute("DELETE FROM main.records", [])
        .is_err());
    produced
        .builder
        .connection
        .execute("UPDATE main.records SET name='synthetic changed value'", [])
        .unwrap();
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    m.bytes.sha256 = hash(&bytes);
    m.bytes.size_bytes = bytes.len() as u64;
    assert!(matches!(
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &m),
        Err(Refusal::Content)
    ));
    produced
        .builder
        .connection
        .execute("CREATE TABLE unreviewed_payload(value TEXT)", [])
        .unwrap();
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    m.bytes.sha256 = hash(&bytes);
    m.bytes.size_bytes = bytes.len() as u64;
    assert!(matches!(
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &m),
        Err(Refusal::Schema)
    ));
    db.close().await;
}

#[tokio::test]
async fn native_profile_admission_crash_residue_is_removed_by_member_purge() {
    use crate::member_copy_lifecycle::{MemberCopyLifecycle, ReconnectAnswer, RevokedCause};
    let (dir, db, _, _) = fixture(true).await;
    let produced = produce(&db, MEMBER, dir.path()).await;
    let admitted = AdmittedMemberFile::open(
        produced.builder._file.path(),
        dir.path(),
        &context(MEMBER, produced.manifest()),
        produced.manifest(),
    )
    .unwrap();
    let AdmittedMemberFile {
        connection,
        expected: _,
        _file,
    } = admitted;
    drop(connection);
    // Simulate process death: close the descriptor without running tempfile's
    // unlink cleanup. The real lifecycle must discover the plaintext residue.
    let (file, residue) = _file.keep().unwrap();
    drop(file);
    assert_eq!(residue.parent(), Some(dir.path()));
    assert!(residue.exists());
    let mut lifecycle = MemberCopyLifecycle::open(dir.path()).unwrap();
    lifecycle
        .sign_in(
            MEMBER,
            ReconnectAnswer::Replace {
                cut_at: "2026-10-22T00:00:00Z".into(),
            },
        )
        .unwrap();
    lifecycle
        .apply_reconnect(ReconnectAnswer::Revoked {
            cause: RevokedCause::MembershipEnded,
        })
        .unwrap();
    assert!(!residue.exists());
    db.close().await;
}

async fn assert_private_capsule_excluded(canvas: bool) {
    let (dir, db, owner, _) = fixture(false).await;
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&owner, "manage")]), &owner)
        .await
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    let id = if canvas {
        "private-canvas-proof"
    } else {
        "private-app-proof"
    };
    let secret = if canvas {
        "private-canvas-object-canary"
    } else {
        "private-app-state-canary"
    };
    kernel::import_record_as(
        &db,
        &host,
        id,
        &home,
        Some(&owner),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: package.definitions[0].family.clone(),
                    version: package.definitions[0].version,
                    digest: package.definitions[0].digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Document",
                    if canvas { "canvas" } else { "artifact" },
                    Some(secret),
                    None,
                    None,
                ),
            }),
            body: Some(secret.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut state = kernel::app_state::RetainedAppState::default();
    if canvas {
        state
            .canvas_objects
            .push(json!({"canvas_id":id,"object_id":"synthetic-object","props":secret}));
    } else {
        state
            .artifact_inputs
            .push(json!({"artifact_id":id,"slot":"synthetic-slot","value":secret}));
    }
    kernel::app_state::import_as(&db, &host, id, "synthetic-origin", &state)
        .await
        .unwrap();
    let retained: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id=?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(retained.contains(secret));
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    let sql = format!("SELECT id FROM records WHERE id='{id}'");
    assert_eq!(
        call(&db, OWNER, "query_sql", json!({"sql":sql})).await["rows"],
        json!([{"id":id}])
    );
    assert_eq!(
        call(&db, MEMBER, "query_sql", json!({"sql":sql})).await["rows"],
        json!([])
    );
    let produced = produce(&db, MEMBER, dir.path()).await;
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    for excluded in [id, secret, home.as_str()] {
        assert!(!bytes
            .windows(excluded.len())
            .any(|w| w == excluded.as_bytes()));
    }
    db.close().await;
}
#[tokio::test]
async fn native_profile_excludes_invisible_app_state() {
    assert_private_capsule_excluded(false).await;
}
#[tokio::test]
async fn native_profile_excludes_invisible_canvases_and_objects() {
    assert_private_capsule_excluded(true).await;
}

#[tokio::test]
async fn native_profile_bytes_exclude_other_members_emails_accounts_and_principals() {
    let (dir, db, owner, _) = fixture(false).await;
    let account = "acct_00000000000000000000000000000004";
    let email = "synthetic-private-member@example.test";
    let principal = kernel::create_principal(&db, "account", email, account, &owner)
        .await
        .unwrap();
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER, account]).await;
    let produced = produce(&db, MEMBER, dir.path()).await;
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    let other = kernel::resolve_principal_by_binding(&db, OTHER)
        .await
        .unwrap()
        .unwrap()
        .0;
    for excluded in [
        email,
        account,
        principal.as_str(),
        OWNER,
        OTHER,
        owner.as_str(),
        other.as_str(),
    ] {
        assert!(!bytes
            .windows(excluded.len())
            .any(|w| w == excluded.as_bytes()));
    }
    db.close().await;
}
