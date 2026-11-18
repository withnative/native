use super::*;

fn assert_retired(target: &Option<Db>) {
    let target = target.as_ref().expect("import acquired the target");
    assert!(target.enrolled_retirement_complete());
    for (name, pool) in [
        ("read", target.pool()),
        ("write", target.write_pool()),
        ("governed", target.governed_pool()),
    ] {
        assert!(pool.is_closed(), "{name} pool must be fenced before return");
        assert_eq!(pool.size(), 0, "{name} pool must physically drain");
    }
}

async fn reopen_and_digest(f: &Fixture) {
    let reopened = f.db().await;
    k::verify_v2_ready(&reopened).await.unwrap();
    reopened.close().await;
    assert!(!cutover::snapshot_digest(&f.target)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn success_retires_the_live_target_before_receipt_reopen() {
    let f = Fixture::new().await;
    let mut target = None;
    let report = run_retiring_target(f.options(&["task"], false), &mut target)
        .await
        .unwrap();
    assert!(report.refusals.is_empty());
    assert_retired(&target);
    reopen_and_digest(&f).await;
}

#[tokio::test]
async fn refusal_report_retires_the_acquired_target() {
    let f = Fixture::new().await;
    run(f.options(&["task"], false)).await.unwrap();
    std::fs::write(&f.members, "account-a\naccount-c\n").unwrap();
    let mut target = None;
    let report = run_retiring_target(f.options(&["task"], true), &mut target)
        .await
        .unwrap();
    assert_eq!(report.refusals.len(), 1);
    assert!(report.roster_change.is_some());
    assert_retired(&target);
    reopen_and_digest(&f).await;
}

#[tokio::test]
async fn source_binding_error_is_preserved_after_target_retirement() {
    let f = Fixture::new().await;
    run(f.options(&["task"], false)).await.unwrap();
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE database_identity SET origin_db_id='different-origin'")
        .await
        .unwrap();
    source.close().await.unwrap();
    let mut target = None;
    let Err(error) = run_retiring_target(f.options(&["task"], true), &mut target).await else {
        panic!("a different source must refuse the resume");
    };
    assert_eq!(error.to_string(), "target belongs to a different source");
    assert_retired(&target);
    reopen_and_digest(&f).await;
}

#[tokio::test]
async fn pre_acquisition_refusal_preserves_report_without_a_target() {
    let f = Fixture::new().await;
    let mut options = f.options(&["task"], false);
    options.all = true;
    options.members_file = None;
    let mut target = None;
    let report = run_retiring_target(options, &mut target).await.unwrap();
    assert!(!report.refusals.is_empty());
    assert!(target.is_none());
    assert!(!f.target.exists());
}
