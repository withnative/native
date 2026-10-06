//! Source-authored lifecycle barriers. UNRUN until the parent allocates a
//! composed default-feature type/runtime gate. No H3/H5 authority fixture.
use super::*;
use sqlx::ConnectOptions;

#[test]
fn body_registration_and_stop_are_one_atomic_fence() {
    for _ in 0..32 {
        let jobs = Arc::new(enrolled::BodyHandleJobs::default());
        let gate = Arc::new(std::sync::Barrier::new(2));
        let task = {
            let jobs = jobs.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                jobs.register()
            })
        };
        gate.wait();
        jobs.stop_submission();
        assert!(jobs.register().is_err());
        if let Ok(ticket) = task.join().unwrap() {
            assert!(!jobs.retirement_ready());
            ticket.no_physical_started().unwrap();
        }
        assert!(jobs.retirement_ready());
    }
}

#[tokio::test]
async fn unknown_body_drop_never_decrements_or_becomes_driver_ack() {
    let jobs = Arc::new(enrolled::BodyHandleJobs::default());
    let first = jobs.register().unwrap();
    first.physical_started().unwrap();
    drop(first);
    let second = jobs.register().unwrap();
    assert!(jobs.register().is_err());
    second.no_physical_started().unwrap();
    assert!(!jobs.drain().await);
    assert!(!jobs.retirement_ready());
    assert!(jobs.register().is_err());
    // This is synthetic lost-ticket state coverage, NOT a driver-Err proof.
}

#[tokio::test]
async fn body_options_preserve_actual_readonly_and_immutable_filename() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("body-options.db");
    let source = create_database(path.to_str().unwrap()).await.unwrap();
    checkpoint_and_close_hosted_adoption_database(source)
        .await
        .unwrap();
    let db = open_existing_database_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    let options = db.body_connection_options();
    assert_eq!(
        options.get_filename(),
        db.governed_pool.connect_options().get_filename()
    );
    let url = options.to_url_lossy();
    assert!(url
        .query_pairs()
        .any(|(k, v)| k == "immutable" && v == "true"));
    let mut raw = options.connect().await.unwrap();
    let readonly = {
        let mut locked = raw.lock_handle().await.unwrap();
        unsafe {
            libsqlite3_sys::sqlite3_db_readonly(locked.as_raw_handle().as_ptr(), c"main".as_ptr())
        }
    };
    assert_eq!(readonly, 1);
    assert!(
        sqlx::query("CREATE TABLE body_readonly_canary (id INTEGER)")
            .execute(&mut raw)
            .await
            .is_err()
    );
    raw.close().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn original_raw_cpu_finalizer_survives_observer_drop_and_handle_retry() {
    let db = create_database(":memory:").await.unwrap();
    let ticket = db.register_body_job().unwrap();
    ticket.physical_started().unwrap();
    // Genuine raw unmarked fixture connection. No body-owned guard/setup or
    // source-read service is fabricated; H3/H5 remain later integration.
    let raw = db.body_connection_options().connect().await.unwrap();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let (started, observed) = tokio::sync::oneshot::channel();
    let cpu = {
        let gate = gate.clone();
        tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let (lock, wake) = &*gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
        })
    };
    observed.await.unwrap();
    // Synchronously retains original raw-close AND registered real CPU handle.
    // Ownership boundary: this MOVES ticket. A second finish_physical call,
    // including after terminal completion, cannot be made with this ticket.
    let observer = ticket.finish_physical(raw, vec![cpu]);
    drop(observer); // BEFORE first poll; original finalizer remains owned.
    let witness = db.fence_body_retirement();
    let mut first = Box::pin(witness.drain());
    assert!(futures::poll!(first.as_mut()).is_pending());
    assert!(!witness.body_complete());
    assert!(!witness.retirement_complete());
    drop(first);
    let retry = db.fence_body_retirement();
    assert_eq!(retry.handle_id(), witness.handle_id());
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert!(retry.drain().await);
    assert!(witness.body_complete());
    assert!(witness.retirement_complete());
    assert!(db.register_body_job().is_err());
    // finish_physical consumed ticket: no second transfer exists.
}

#[tokio::test]
async fn no_start_body_completion_does_not_ack_checked_out_ordinary_pool() {
    let db = create_database(":memory:").await.unwrap();
    let ticket = db.register_body_job().unwrap();
    let held = db.pool().acquire().await.unwrap();
    let witness = db.fence_body_retirement();
    ticket.no_physical_started().unwrap();
    assert!(witness.body_complete());
    assert!(!witness.retirement_complete());
    let mut close = Box::pin(witness.drain());
    assert!(futures::poll!(close.as_mut()).is_pending());
    drop(close);
    drop(held);
    assert!(witness.drain().await);
    assert!(db.read_pool.is_closed() && db.read_pool.size() == 0);
    assert!(db.write_pool.is_closed() && db.write_pool.size() == 0);
    assert!(db.governed_pool.is_closed() && db.governed_pool.size() == 0);
}

#[tokio::test]
async fn invalid_startup_keeps_unknown_after_original_cpu_and_raw_close_complete() {
    let db = create_database(":memory:").await.unwrap();
    let ticket = db.register_body_job().unwrap();
    ticket.physical_started().unwrap();
    let raw = db.body_connection_options().connect().await.unwrap();
    // A remaining invalid transition is permanent uncertainty, not permission
    // to drop transferred resources or let their later close erase the entry.
    assert!(ticket.physical_started().is_err());
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let finished = Arc::new(AtomicBool::new(false));
    let (started, observed) = tokio::sync::oneshot::channel();
    let cpu = {
        let gate = gate.clone();
        let finished = finished.clone();
        tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let (lock, wake) = &*gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            finished.store(true, Ordering::Release);
        })
    };
    observed.await.unwrap();
    let mut observer = ticket.finish_physical(raw, vec![cpu]);
    assert!(futures::poll!(observer.as_mut()).is_pending());
    drop(observer);
    let witness = db.fence_body_retirement();
    let mut first = Box::pin(witness.drain());
    assert!(futures::poll!(first.as_mut()).is_pending());
    assert!(!finished.load(Ordering::Acquire));
    drop(first);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert!(!witness.drain().await);
    assert!(finished.load(Ordering::Acquire));
    // Observes the stored ORIGINAL physical result; it does not inject an ACK.
    assert_eq!(db.body_jobs.retained_close_result_for_test(), Some(true));
    assert!(!witness.body_complete());
    assert!(!witness.retirement_complete());
    assert!(!db.body_jobs.drain().await); // same terminal observer, no reset
    assert!(db.register_body_job().is_err());
    // Test-only ordinary-pool teardown does not resolve unknown body custody.
    tokio::join!(
        close_pool_and_drain(&db.read_pool),
        close_pool_and_drain(&db.write_pool),
        close_pool_and_drain(&db.governed_pool)
    );
    assert!(!witness.retirement_complete());
}

#[tokio::test]
async fn unstarted_resource_transfer_retains_close_without_minting_no_start_proof() {
    let db = create_database(":memory:").await.unwrap();
    let jobs = Arc::new(enrolled::BodyHandleJobs::default());
    let ticket = jobs.register().unwrap();
    let raw = db.body_connection_options().connect().await.unwrap();
    let observer = ticket.finish_physical(raw, Vec::new());
    drop(observer); // invalid registration still owns the raw-close future
    assert!(!jobs.drain().await);
    assert_eq!(jobs.retained_close_result_for_test(), Some(true));
    assert!(!jobs.retirement_ready());
    assert!(!jobs.drain().await);
    assert!(jobs.register().is_err());
    db.close().await;
}

#[tokio::test]
async fn poisoned_registration_retains_real_cleanup_and_never_becomes_retirement() {
    let db = create_database(":memory:").await.unwrap();
    let jobs = Arc::new(enrolled::BodyHandleJobs::default());
    let ticket = jobs.register().unwrap();
    ticket.physical_started().unwrap();
    let raw = db.body_connection_options().connect().await.unwrap();
    let poison = jobs.clone();
    assert!(std::thread::spawn(move || poison.poison_state_for_test())
        .join()
        .is_err());
    let completed = Arc::new(AtomicBool::new(false));
    let flag = completed.clone();
    let cpu = tokio::task::spawn_blocking(move || flag.store(true, Ordering::Release));
    let observer = ticket.finish_physical(raw, vec![cpu]);
    drop(observer);
    assert!(!jobs.drain().await);
    assert!(completed.load(Ordering::Acquire));
    assert_eq!(jobs.retained_close_result_for_test(), Some(true));
    assert!(!jobs.retirement_ready());
    assert!(!jobs.drain().await);
    assert!(jobs.register().is_err());
    db.close().await;
}

#[tokio::test]
async fn same_body_witness_cancellation_retains_raw_cpu_and_pool_cleanup() {
    let db = create_database(":memory:").await.unwrap();
    let ticket = db.register_body_job().unwrap();
    ticket.physical_started().unwrap();
    let raw = db.body_connection_options().connect().await.unwrap();
    let held = db.pool().acquire().await.unwrap();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    // Fixture release only: unwind/cancellation must not strand the real CPU.
    struct ReleaseGate(Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Drop for ReleaseGate {
        fn drop(&mut self) {
            let (lock, wake) = &*self.0;
            let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
            *released = true;
            drop(released);
            wake.notify_all();
        }
    }
    let _release_gate = ReleaseGate(gate.clone());
    let (started, observed) = tokio::sync::oneshot::channel();
    let cpu = {
        let gate = gate.clone();
        tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let (lock, wake) = &*gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
        })
    };
    observed.await.unwrap();
    let observer = ticket.finish_physical(raw, vec![cpu]);
    drop(observer);
    let witness = db.fence_body_retirement();
    let original = db.body_retirement.get().unwrap().clone();
    assert!(witness.future.ptr_eq(&original));
    let mut first = Box::pin(witness.drain());
    assert!(futures::poll!(first.as_mut()).is_pending());
    assert!(!witness.body_complete());
    assert!(!witness.retirement_complete());
    assert!(db.register_body_job().is_err());
    drop(first);
    assert!(witness.future.ptr_eq(&original));

    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let mut resumed = Box::pin(witness.drain());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                result = resumed.as_mut() => panic!("held real checkout must prevent retirement: {result}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    if witness.body_complete() && db.read_pool.is_closed() {
                        // Actual raw/registered CPU completion has been observed;
                        // Pending is now held by the real ordinary checkout.
                        assert!(db.read_pool.size() > 0);
                        break;
                    }
                }
            }
        }
    })
    .await
    .expect("original raw/CPU cleanup reaches the held pool");
    assert!(witness.body_complete());
    assert!(db.read_pool.is_closed() && db.read_pool.size() > 0);
    assert!(!witness.retirement_complete());
    drop(resumed);
    assert!(witness.future.ptr_eq(&original));
    drop(held);
    assert!(witness.drain().await);
    assert!(witness.future.ptr_eq(&original));
    assert!(witness.body_complete() && witness.retirement_complete());
    assert!(db.read_pool.is_closed() && db.read_pool.size() == 0);
    assert!(db.write_pool.is_closed() && db.write_pool.size() == 0);
    assert!(db.governed_pool.is_closed() && db.governed_pool.size() == 0);
    assert!(db.register_body_job().is_err());
}

#[tokio::test]
async fn same_body_witness_unknown_stays_false_after_original_cleanup() {
    let db = create_database(":memory:").await.unwrap();
    let ticket = db.register_body_job().unwrap();
    ticket.physical_started().unwrap();
    let raw = db.body_connection_options().connect().await.unwrap();
    assert!(ticket.physical_started().is_err());
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    // Fixture release only: unwind/cancellation must not strand the real CPU.
    struct ReleaseGate(Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Drop for ReleaseGate {
        fn drop(&mut self) {
            let (lock, wake) = &*self.0;
            let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
            *released = true;
            drop(released);
            wake.notify_all();
        }
    }
    let _release_gate = ReleaseGate(gate.clone());
    let finished = Arc::new(AtomicBool::new(false));
    let (started, observed) = tokio::sync::oneshot::channel();
    let cpu = {
        let gate = gate.clone();
        let finished = finished.clone();
        tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let (lock, wake) = &*gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            finished.store(true, Ordering::Release);
        })
    };
    observed.await.unwrap();
    let observer = ticket.finish_physical(raw, vec![cpu]);
    drop(observer);
    let witness = db.fence_body_retirement();
    let original = db.body_retirement.get().unwrap().clone();
    assert!(witness.future.ptr_eq(&original));
    let mut first = Box::pin(witness.drain());
    assert!(futures::poll!(first.as_mut()).is_pending());
    assert!(!finished.load(Ordering::Acquire));
    drop(first);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert!(!witness.drain().await);
    assert!(finished.load(Ordering::Acquire));
    assert_eq!(db.body_jobs.retained_close_result_for_test(), Some(true));
    assert!(!witness.body_complete());
    assert!(!witness.retirement_complete());
    assert!(witness.future.ptr_eq(&original));
    let another = db.fence_body_retirement();
    assert!(another.future.ptr_eq(&witness.future));
    assert!(!witness.drain().await);
    assert!(!another.drain().await);
    assert!(db.register_body_job().is_err());
    tokio::join!(
        close_pool_and_drain(&db.read_pool),
        close_pool_and_drain(&db.write_pool),
        close_pool_and_drain(&db.governed_pool)
    );
    assert!(db.read_pool.is_closed() && db.read_pool.size() == 0);
    assert!(db.write_pool.is_closed() && db.write_pool.size() == 0);
    assert!(db.governed_pool.is_closed() && db.governed_pool.size() == 0);
    assert!(!witness.drain().await);
    assert!(witness.future.ptr_eq(&original));
    assert!(!witness.body_complete() && !witness.retirement_complete());
}
