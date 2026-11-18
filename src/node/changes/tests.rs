use super::*;

fn args(broker: &Broker, after: Option<Cursor>) -> FollowArgs {
    let state = broker.state.lock().unwrap();
    FollowArgs {
        account_id: state.snapshot.account_id.clone(),
        origin_database_id: state.snapshot.origin_database_id.clone(),
        after,
    }
}
fn new_broker() -> Arc<Broker> {
    Broker::new("account".into(), "origin".into(), Floor::default())
}

#[test]
fn node_changes_binding_bounds_cursor_resets_and_coalescing_are_explicit() {
    let broker = new_broker();
    assert!(broker
        .follow(FollowArgs {
            account_id: "other".into(),
            ..args(&broker, None)
        })
        .is_err());
    assert!(!broker.has_followers());
    let mut leases = vec![];
    let (lease, mut receiver, baseline, reset) = broker.follow(args(&broker, None)).unwrap();
    assert!(reset);
    leases.push(lease);
    for _ in 1..MAX_FOLLOWS {
        leases.push(broker.follow(args(&broker, None)).unwrap().0);
    }
    assert!(broker.follow(args(&broker, None)).is_err());
    leases.pop();
    let (_lease, _, _, reset) = broker
        .follow(args(&broker, Some(baseline.cursor.clone())))
        .unwrap();
    assert!(!reset);
    broker.note_floor(Floor {
        act: Some(10),
        ..Floor::default()
    });
    broker.note_floor(Floor {
        act: Some(11),
        unresolved: true,
        ..Floor::default()
    });
    let latest = receiver.borrow_and_update().clone();
    assert_eq!(latest.cursor.sequence, baseline.cursor.sequence + 2);
    assert_eq!(latest.reason, "write_floor_changed");
    assert!(
        latest.serving.applied_act.is_none(),
        "floor is not local application"
    );
    drop(_lease);
    assert!(
        broker
            .follow(args(&broker, Some(baseline.cursor)))
            .unwrap()
            .3
    );
    let restarted = new_broker();
    let old = latest.cursor;
    assert!(restarted.follow(args(&restarted, Some(old))).unwrap().3);
}

#[test]
fn node_changes_only_semantic_observations_change_the_stamp_and_regressions_reset() {
    let broker = new_broker();
    let serving = Serving {
        generation_id: Some("G1".into()),
        applied_act: Some(10),
        freshness: "fresh".into(),
        degraded_reasons: vec![],
    };
    broker.observe(serving.clone(), Authority::default());
    let (_, mut receiver, initial, _) = broker.follow(args(&broker, None)).unwrap();
    broker.observe(serving.clone(), Authority::default());
    assert!(!receiver.has_changed().unwrap());
    let advanced = Serving {
        applied_act: Some(11),
        ..serving.clone()
    };
    broker.observe(advanced, Authority::default());
    assert_eq!(receiver.borrow_and_update().reason, "serving_advanced");
    broker.observe(serving.clone(), Authority::default());
    assert_eq!(receiver.borrow_and_update().reason, "reset");
    broker.observe(Serving::default(), Authority::default());
    assert_eq!(receiver.borrow_and_update().reason, "availability_changed");
    broker.observe(serving, Authority::default());
    let recovered = receiver.borrow_and_update().clone();
    assert_eq!(recovered.reason, "reset");
    assert_eq!(recovered.cursor.sequence, initial.cursor.sequence + 4);
}
