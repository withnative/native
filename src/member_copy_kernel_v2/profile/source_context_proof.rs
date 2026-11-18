//! One bounded addition to the existing lifecycle proof, using provisioned v1
//! sources and the production importer into fresh synthetic targets only.
use super::*;
use crate::authorization::{AllowEntry, Capability};
use crate::mcp::member_stdio::MemberServedSnapshot;
use crate::member_copy_lifecycle::ReconnectAnswer;
use crate::member_copy_serving::MemberCopyServing;

pub(super) async fn exercise() {
    for case in ["held", "hidden_person", "hidden_root"] {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("legacy.db");
        let source = crate::db::create_database(source_path.to_str().unwrap())
            .await
            .unwrap();
        let owner_person = "3a610000-0000-4000-8000-000000000001";
        let member_person = "3a610000-0000-4000-8000-000000000002";
        // Real member provisioning owns the association and private-root IDs.
        // No invented Context payload, raw control row or account-config fallback.
        for (person, account) in [(owner_person, OWNER), (member_person, MEMBER)] {
            crate::member_offline_fixtures::create_member(&source, person, account).await;
            assert_eq!(
                crate::identity::resolve_stdio_account_identity(&source, Some(account))
                    .await
                    .unwrap(),
                account
            );
        }
        crate::authorization::replace_explicit_policy(
            &source,
            OWNER,
            crate::schema::ROOT_RECORD_ID,
            vec![
                AllowEntry::account(OWNER, Capability::Manage),
                AllowEntry::account(MEMBER, Capability::View),
            ],
        )
        .await
        .unwrap();
        let member_root: String =
            sqlx::query_scalar("SELECT root_record_id FROM member_contexts WHERE account_id=?")
                .bind(MEMBER)
                .fetch_one(source.pool())
                .await
                .unwrap();
        let owner_root: String =
            sqlx::query_scalar("SELECT root_record_id FROM member_contexts WHERE account_id=?")
                .bind(OWNER)
                .fetch_one(source.pool())
                .await
                .unwrap();
        // The held case deliberately has View but not Manage on the associated
        // root. Member delivery must never copy the online current_manage claim.
        crate::store::update_record(
            &source,
            &member_root,
            json!({"owner_id":owner_person,"body":"Synthetic source-context root payload"}),
        )
        .await
        .unwrap();
        let mut entries = vec![AllowEntry::account(OWNER, Capability::Manage)];
        if case != "hidden_root" {
            entries.push(AllowEntry::account(MEMBER, Capability::View));
        }
        crate::authorization::replace_explicit_policy(&source, OWNER, &member_root, entries)
            .await
            .unwrap();
        if case == "hidden_person" {
            crate::store::update_record(&source, member_person, json!({"home_id":owner_root,"owner_id":owner_person,"body":"Synthetic hidden source-context Person payload"})).await.unwrap();
        }
        source.close().await;
        let source_bytes = std::fs::read(&source_path).unwrap();
        let roster = dir.path().join("members.txt");
        std::fs::write(&roster, format!("{OWNER}\n{MEMBER}\n")).unwrap();
        let target = dir.path().join("imported.db");
        let report = crate::v1_import::run(crate::v1_import::Options {
            source: source_path.clone(),
            target: target.clone(),
            seeds: vec![],
            all: true,
            history: false,
            resume: false,
            members_file: Some(roster),
        })
        .await
        .unwrap();
        assert!(
            report.refusals.is_empty(),
            "synthetic {case}: {:?}",
            report
                .refusals
                .iter()
                .map(|issue| &issue.reason)
                .collect::<Vec<_>>()
        );
        assert!(report.state.member_contexts_prepared);
        let db = crate::db::open_database(target.to_str().unwrap())
            .await
            .unwrap();
        super::super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER]).await;
        let principal = &report.principals[MEMBER];
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        let mut snapshot = db.pool().acquire().await.unwrap();
        snapshot.close_on_drop();
        sqlx::query("BEGIN").execute(&mut *snapshot).await.unwrap();
        let generation = crate::standby::kernel_v2::coordinates(&mut snapshot)
            .await
            .unwrap();
        let origin = crate::standby::kernel_v2::origin(&mut snapshot, &generation)
            .await
            .unwrap();
        let cut = super::super::super::tests::ready(
            capture_in(&mut snapshot, &origin, MEMBER).await.unwrap(),
        );
        let selected =
            kernel::v1_state::member_context::member_delivery_on(&mut snapshot, principal)
                .await
                .unwrap();
        let online = kernel::v1_state::member_context::online_on(&mut snapshot, principal)
            .await
            .unwrap();
        if case == "held" {
            assert_eq!(
                selected,
                Some(json!({"person_record_id":member_person,"root_record_id":member_root}))
            );
            assert_eq!(
                kernel::kernel_effective_capability_on(&mut snapshot, principal, &member_root)
                    .await
                    .unwrap(),
                Capability::View
            );
            assert_eq!(online, json!({
                "status":"available",
                "identity_basis":"retained v1 member context; current native authorization",
                "person_record_id":member_person,
                "root_record_id":null,
                "root_authority":null,
            }), "online independently requires Manage; offline retains only captured View references");
        } else {
            assert!(selected.is_none());
            let hidden = if case == "hidden_person" {
                member_person
            } else {
                &member_root
            };
            assert!(kernel::read_record_on(&mut snapshot, principal, hidden)
                .await
                .unwrap()
                .is_none());
        }
        // Producer and oracle share the exact actual source transaction/cut.
        let generation_manifest = manifest(&cut);
        let artifact = produce_in(&mut snapshot, cut, dir.path(), generation_manifest)
            .await
            .unwrap();
        sqlx::query("ROLLBACK")
            .execute(&mut *snapshot)
            .await
            .unwrap();
        drop(snapshot);
        let offered = dir.path().join("offered.db");
        artifact.persist(&offered).unwrap();
        let selected_raw = serde_json::to_string(&selected).unwrap();
        let connection =
            Connection::open_with_flags(&offered, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let held_raw: String = connection
            .query_row("SELECT source_context FROM member_context", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(held_raw, selected_raw);
        let other_root_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM records WHERE id=?",
                [&owner_root],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            other_root_count, 0,
            "another member's private associated root never ships"
        );
        for private in [
            "kernel_v1_state",
            "kernel_notification_preferences",
            "kernel_hcp_entries",
            "kernel_hcp_disclosures",
            "kernel_hcp_audit",
            "kernel_hcp_resolutions",
        ] {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name=?",
                    [private],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 0,
                "only selected two-ID context, never raw private state/config"
            );
        }

        let decoded = source_context::MemberSourceContext::decode(&held_raw).unwrap();
        source_context::MemberSourceContext::validate_held(&decoded, &connection).unwrap();
        if case == "held" {
            for id in [member_person, member_root.as_str()] {
                let count: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM records WHERE id=? AND deleted_at IS NULL",
                        [id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1);
            }
        } else {
            let hidden = if case == "hidden_person" {
                member_person
            } else {
                &member_root
            };
            for table in ["records", "member_record_metadata"] {
                let column = if table == "records" {
                    "id"
                } else {
                    "record_id"
                };
                let count: i64 = connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?"),
                        [hidden],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0);
            }
        }
        drop(connection);
        let binding = context(MEMBER, artifact.manifest());
        let root = dir.path().join("device");
        let open = || {
            MemberCopyServing::open_unbound_routed(
                &root,
                Some(origin.clone()),
                "https://example.invalid".into(),
                "route-test".into(),
                test_consumer(),
            )
        };
        let mut owner = open().await.unwrap();
        owner
            .sign_in(
                MEMBER,
                ReconnectAnswer::Replace {
                    cut_at: artifact.manifest().captured_at.clone(),
                },
            )
            .await
            .unwrap();
        owner.bind_scope(&binding).unwrap();
        owner
            .admit_candidate(
                &offered,
                &serde_json::to_vec(artifact.manifest()).unwrap(),
                &binding,
            )
            .await
            .unwrap();
        let registry = || {
            let mut registry = ToolRegistry::new();
            crate::mcp::register_builtin_tools(&mut registry).unwrap();
            crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
            registry
        };
        let expected = if case == "held" {
            json!({"status":"held","identity_basis":"retained v1 member context","reference_basis":"both references visible at capture and held in this member generation","person_record_id":member_person,"root_record_id":member_root})
        } else {
            Json::Null
        };
        let request = |modern| {
            let mut request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}});
            if modern {
                request["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
            }
            request
        };
        for restart in [false, true] {
            if restart {
                owner.quiesce().await;
                drop(owner);
                owner = open().await.unwrap();
            }
            assert_eq!(
                owner.generation_id(),
                Some(artifact.manifest().generation_id().as_str())
            );
            let reader = MemberServedSnapshot::from_serving(&owner, registry()).unwrap();
            for modern in [false, true] {
                let response = reader.dispatch(request(modern)).await.unwrap();
                let value = response["result"]
                    .get("structuredContent")
                    .expect("bootstrap response");
                assert_eq!(response["result"]["isError"], false, "{response}");
                assert_eq!(
                    value.get("source_context").expect("explicit projection"),
                    &expected
                );
                assert_eq!(value["principal"]["principal_id"], *principal);
                assert_eq!(
                    value["workspace"]["primary_workspace"]["id"],
                    KERNEL_ROOT_ID
                );
                assert_eq!(
                    value["roots"]["continuation"]["arguments"]["root_id"],
                    "native:root"
                );
                assert!(!value["source_context"]
                    .to_string()
                    .contains("root_authority"));
                assert!(!value["source_context"]
                    .to_string()
                    .contains("current_manage"));
            }
        }
        owner.quiesce().await;
        drop(owner);
        // The same closure validator runs at publication and reopened admission.
        // Mutate only the synthetic offered candidate, never the admitted file.
        let connection = Connection::open(&offered).unwrap();
        for raw in [
            json!({"person_record_id":member_person,"root_record_id":"missing-source-context-root"}),
            json!({"person_record_id":"missing-source-context-person","root_record_id":member_root}),
        ] {
            let raw = raw.to_string();
            let selected = source_context::MemberSourceContext::decode(&raw).unwrap();
            assert_eq!(
                source_context::MemberSourceContext::validate_held(&selected, &connection),
                Err(Refusal::Content)
            );
            connection
                .execute("UPDATE member_context SET source_context=?", [&raw])
                .unwrap();
            assert_eq!(validate_closure(&connection), Err(Refusal::Content));
            let retained: String = connection
                .query_row("SELECT source_context FROM member_context", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(retained, raw, "no Some-to-null downgrade");
        }
        assert!(source_context::MemberSourceContext::decode(&json!({"person_record_id":member_person,"root_record_id":member_root,"root_authority":"current_manage"}).to_string()).is_err());
        drop(connection);
        assert!(
            AdmittedMemberFile::open(&offered, dir.path(), &binding, artifact.manifest()).is_err(),
            "content change is hash/fence refused before serving"
        );
        assert_eq!(kernel::dump_all_kernel_tables(&db).await.unwrap(), before);
        db.close().await;
        assert_eq!(
            std::fs::read(source_path).unwrap(),
            source_bytes,
            "source unchanged, no activated importer resume"
        );
    }
}
