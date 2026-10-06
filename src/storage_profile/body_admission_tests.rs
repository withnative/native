use super::*;
use std::time::{Duration, Instant};

fn columns(enforcement: &str, targets: Vec<StorageTarget>) -> PortabilityPolicyColumns {
    let source = active_target();
    PortabilityPolicyColumns {
        policy_revision: 1,
        enforcement: enforcement.into(),
        source_profile_id: source.id.clone(),
        source_profile_revision: source.revision as i64,
        source_mode: source.mode.clone(),
        targets: serde_json::to_string(&targets).unwrap(),
        revision_floors: serde_json::to_string(&targets).unwrap(),
        allow_conversions: "[]".into(),
        catalog_sha256: profile_set_digest(&source, &targets).unwrap(),
    }
}

#[tokio::test]
async fn snapshot_factory_matches_existing_literal_policy_decision() {
    let db = crate::create_database(":memory:").await.unwrap();
    let pending = PendingBodyPolicy::acquire(&db, Instant::now())
        .await
        .unwrap();
    let targets = vec![StorageTarget {
        id: "postgres-server".into(),
        revision: 5,
        mode: "network".into(),
    }];
    for raw in [
        None,
        Some(columns("off", targets.clone())),
        Some(columns("strict", vec![active_target()])),
        Some(columns("strict", targets)),
    ] {
        let policy = raw.clone().map(decode_policy_columns).transpose().unwrap();
        let ordinary = admit_request_operation(
            policy.as_ref(),
            &active_target(),
            "records.body.read.v1",
            Some("native.operation.record-read.v1"),
        );
        let body = pending.admit_snapshot(&db, raw);
        match (ordinary, body) {
            (Ok(()), Ok(admission)) => {
                assert_eq!(admission.context.operation, "records.body.read.v1");
                assert_eq!(
                    admission.context.capability.as_deref(),
                    Some("native.operation.record-read.v1")
                );
            }
            (Err(expected), Err(BodyPolicyFailure::Admission(actual))) => {
                assert_eq!(actual.to_string(), expected.to_string());
                assert!(actual.to_string().contains("target_support_partial"));
            }
            _ => panic!("body and existing policy admission differ"),
        }
    }
    drop(pending);
    db.close().await;
}

#[tokio::test]
async fn malformed_and_changed_policy_pins_are_not_absent_policy() {
    let db = crate::create_database(":memory:").await.unwrap();
    let pending = PendingBodyPolicy::acquire(&db, Instant::now())
        .await
        .unwrap();
    for field in ["enforcement", "targets", "revision", "source", "catalog"] {
        let mut raw = columns("strict", vec![active_target()]);
        match field {
            "enforcement" => raw.enforcement = "unknown".into(),
            "targets" => raw.targets = "{".into(),
            "revision" => raw.policy_revision = -1,
            "source" => raw.source_profile_revision = 1,
            "catalog" => raw.catalog_sha256 = "0".repeat(64),
            _ => unreachable!(),
        }
        let expected = decode_policy_columns(raw.clone()).and_then(|policy| {
            admit_request_operation(
                Some(&policy),
                &active_target(),
                "records.body.read.v1",
                Some("native.operation.record-read.v1"),
            )
        });
        let actual = match pending.admit_snapshot(&db, Some(raw)) {
            Err(BodyPolicyFailure::State(error))
                if matches!(field, "enforcement" | "targets" | "revision") =>
            {
                error
            }
            Err(BodyPolicyFailure::Admission(error)) if matches!(field, "source" | "catalog") => {
                error
            }
            _ => panic!("policy failure lost its decoder/admission origin"),
        };
        assert_eq!(actual.to_string(), expected.unwrap_err().to_string());
    }
    assert!(pending.admit_snapshot(&db, None).is_ok());
    drop(pending);
    db.close().await;
}

#[tokio::test]
async fn selected_handle_clone_matches_but_same_database_reopen_does_not() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("body-policy.db");
    let db = crate::create_database(&path.to_string_lossy())
        .await
        .unwrap();
    let reopened = crate::open_existing_database_at(&path).await.unwrap();
    let pending = PendingBodyPolicy::acquire(&db, Instant::now())
        .await
        .unwrap();
    assert!(pending.admit_snapshot(&db.clone(), None).is_ok());
    // The same persistent database identity is insufficient: the actual live
    // handle/gate association must match, before parsing supplied policy data.
    let mut malformed = columns("strict", vec![active_target()]);
    malformed.targets = "{".into();
    assert!(matches!(
        pending.admit_snapshot(&reopened, Some(malformed)),
        Err(BodyPolicyFailure::HandleMismatch)
    ));
    drop(pending);
    reopened.close().await;
    db.close().await;
}

#[tokio::test]
async fn pending_and_scoped_admission_clones_hold_actual_policy_writer_gate() {
    let db = crate::create_database(":memory:").await.unwrap();
    let pending = PendingBodyPolicy::acquire(&db, Instant::now())
        .await
        .unwrap();
    let retained = pending.clone();
    assert!(
        current_admission().is_err(),
        "pending custody is not admission"
    );
    let admission = pending.admit_snapshot(&db, None).unwrap();
    let scoped = admission
        .scope(async {
            let current = current_admission().unwrap();
            assert_eq!(current.context.operation, "records.body.read.v1");
            assert_eq!(
                PORTABILITY_OPERATION.with(|context| context.capability.clone()),
                Some("native.operation.record-read.v1".into())
            );
            current
        })
        .await;
    assert!(
        current_admission().is_err(),
        "scope leaked out of its future"
    );
    let mut writer = Box::pin(update_portability_policy(
        &db,
        PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: PortabilityEnforcement::Off,
            target_profiles: vec![],
            allow_conversions: vec![],
        },
    ));
    assert!(futures::poll!(writer.as_mut()).is_pending());
    drop(pending);
    drop(admission);
    assert!(futures::poll!(writer.as_mut()).is_pending());
    drop(retained);
    assert!(futures::poll!(writer.as_mut()).is_pending());
    drop(scoped);
    tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .unwrap()
        .unwrap();
    // This proves lease lifetime against the REAL updater, not driver/CPU ACK.
    db.close().await;
}

#[tokio::test]
async fn original_ingress_expiry_and_contended_gate_do_not_renew_deadline() {
    let db = crate::create_database(":memory:").await.unwrap();
    assert!(matches!(
        PendingBodyPolicy::acquire(&db, Instant::now() - Duration::from_secs(5)).await,
        Err(BodyPolicyFailure::Deadline)
    ));
    let writer = db.owned_portability_policy_gate().write_owned().await;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        PendingBodyPolicy::acquire(&db, Instant::now() - Duration::from_millis(4980)),
    )
    .await
    .expect("original remaining budget was replaced with a fresh five seconds");
    assert!(matches!(result, Err(BodyPolicyFailure::Deadline)));
    drop(writer);
    assert!(db.portability_policy_gate().try_write().is_ok());
    let pending = PendingBodyPolicy::acquire(&db, Instant::now() - Duration::from_millis(4900))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(matches!(
        pending.admit_snapshot(&db, None),
        Err(BodyPolicyFailure::Deadline)
    ));
    // Timeout is not an instruction to release outer-owned custody.
    assert!(db.portability_policy_gate().try_write().is_err());
    drop(pending);
    assert!(db.portability_policy_gate().try_write().is_ok());
    db.close().await;
}
