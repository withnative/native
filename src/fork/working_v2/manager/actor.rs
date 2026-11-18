//! Concrete retained owner. Only a borrowed phase may unwind. The outer frame
//! retains the actual SQLx wrapper, continuous writer, collector and generation
//! on panic, uncertain settlement or failed installation; no receiver owns it.
use super::*;
use crate::db::KernelCommitOutcome;
use crate::kernel::working_undo::{with_handle, Collector};
use futures::FutureExt;
use sha2::Digest;
use sqlx::Connection;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

type AcceptedDelta = crate::standby::AcceptedKernelDelta;
use crate::standby::kernel_v2::WorkingKernelSchema;
pub(super) enum Command {
    Append(Box<Job>),
    Reconcile(Box<AcceptedDelta>, u64),
    CanonicalChanged(u64),
    #[cfg(test)]
    RemoveMarker(String, oneshot::Sender<Result<()>>),
    #[cfg(test)]
    Drained(oneshot::Sender<()>),
    #[cfg(test)]
    ProbeSuffix(
        Box<DurableAppend>,
        crate::node::working_v2::WorkingCanonicalAnswer,
        bool,
        oneshot::Sender<Result<bool>>,
    ),
}
pub(super) struct Prepared {
    pub base: OwnerPinnedBase,
    pub caller: Caller,
    pub factory: Arc<super::super::super::ForkManager>,
    pub handle: super::super::super::ForkHandle,
    pub reservation: u64,
    pub journal: WorkingJournal,
    pub guard: BindingGuard,
    pub scope: ReadScope,
    pub contract: String,
    pub create_context: Option<replay::FirstPartyCreateContext>,
    pub state: Arc<StdMutex<WorkingState>>,
    pub fence: JournalFence,
    pub receive: mpsc::Receiver<Command>,
    pub ready: Option<oneshot::Sender<Result<Arc<Shared>>>>,
    #[cfg(test)]
    pub stopped: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    pub processed: tokio::sync::watch::Sender<u64>,
}
fn undo_error(error: impl std::fmt::Display) -> Error {
    Error::engine(error.to_string())
}
fn set_state(shared: &Shared, next: WorkingState) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // A missing trusted handoff or confirmed close is terminal for this W.
    // Phase completion is settlement, never permission to resurrect it.
    if matches!(*state, WorkingState::Quarantined | WorkingState::Closed) {
        return false;
    }
    *state = next;
    true
}

pub(super) async fn park(shared: &Shared) {
    pause_uncertain(shared);
    #[cfg(test)]
    {
        shared.parked.store(true, Ordering::Release);
        shared.parked_notice.notify_waiters();
        shared
            .settle
            .acquire()
            .await
            .expect("test settlement semaphore")
            .forget();
        shared.parked.store(false, Ordering::Release);
    }
    #[cfg(not(test))]
    std::future::pending::<()>().await;
}

impl Prepared {
    pub(super) async fn run(mut self) {
        // Prepared remains owned by this retained async frame, even if its
        // constructor or the outer driver's polling is interrupted.
        let opened = std::panic::AssertUnwindSafe(super::super::transaction::open_pinned_writer(
            &self.handle,
        ))
        .catch_unwind()
        .await;
        let (reader, mut connection) = match opened {
            Ok(Ok(opened)) => opened,
            _ => {
                if let Some(reply) = self.ready.take() {
                    let _ = reply.send(Err(Error::engine(
                        "working physical writer open failed; owner retained",
                    )));
                }
                *self.state.lock().unwrap_or_else(|e| e.into_inner()) = WorkingState::Quarantined;
                std::future::pending::<()>().await;
                unreachable!();
            }
        };
        self.handle.db = reader.clone();
        let initial_native_act = self.base.native.head_act;
        let create_context = std::sync::OnceLock::new();
        if let Some(context) = self.create_context {
            let _ = create_context.set(context);
        }
        let shared = Arc::new(Shared {
            base: self.base,
            generation: Arc::new(Generation {
                factory: self.factory,
                handle: self.handle,
                reservation: self.reservation,
            }),
            journal: self.journal,
            state: self.state,
            publication: RwLock::new(None),
            publication_notice: tokio::sync::Notify::new(),
            signals: std::sync::atomic::AtomicU64::new(0),
            base_signal: std::sync::atomic::AtomicU64::new(0),
            observed_serving_act: std::sync::atomic::AtomicI64::new(initial_native_act),
            reconciling: std::sync::atomic::AtomicBool::new(false),
            quarantined_delta: StdMutex::new(None),
            guard: self.guard,
            scope: self.scope,
            contract: self.contract,
            create_context,
            #[cfg(test)]
            replay_cleanup_fault: StdMutex::new(None),
            #[cfg(test)]
            hook: StdMutex::new(None),
            #[cfg(test)]
            parked: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            parked_notice: tokio::sync::Notify::new(),
            #[cfg(test)]
            settle: Semaphore::new(0),
        });
        let fence = self.fence;
        let initial = PublicationBase {
            publication: WorkingPublication {
                binding: shared.base.binding.clone(),
                generation: uuid::Uuid::new_v4().to_string(),
                publication: 0,
                accepted_frontier: shared.base.frontier,
                journal_revision: fence.view().prefix_revision(0).expect("empty revision"),
            },
            native: shared.base.native.clone(),
            origin: shared.base.origin.clone(),
            source_generation: shared.base.source_generation.clone(),
            genesis: shared.base.genesis.clone(),
            principal: shared.base.principal.clone(),
            original_prefix: 0,
            pending_count: 0,
            recovery_dispositions: Vec::new(),
        };
        // Exclusion/inventory and base coordinates use the SAME explicit
        // snapshot. This is private W admission, never an accepted certificate.
        let mut admission_tx =
            match super::super::transaction::construct_pinned_transaction(&mut connection).await {
                Ok(tx) => tx,
                Err(error) => {
                    if let Some(reply) = self.ready.take() {
                        let _ = reply.send(Err(error));
                    }
                    park(&shared).await;
                    return;
                }
            };
        let admitted = std::panic::AssertUnwindSafe(async {
            let tx=&mut admission_tx;
            shared.base.check_native_on(tx).await?;
            let native_schema=WorkingKernelSchema::from_fresh_native(tx).await?;
            crate::storage_profile::enforce_write_boundary_on(tx).await?;
            if !crate::kernel::working_undo_schema::exclusions(tx).await?.is_empty() {
                return Err(Error::engine("unexpected private undo on fresh W"));
            }
            let collisions:i64=sqlx::query_scalar("SELECT count(*) FROM main.sqlite_schema WHERE name IN ('working_undo','working_undo_control','working_undo_boundaries','_native_working_publication','_native_working_applied','_native_working_bases')")
                .fetch_one(&mut **tx).await?;
            if collisions!=0 { return Err(Error::engine("fresh W private schema collision")); }
            let before:Vec<(String,String,String,String)>=sqlx::query_as("SELECT type,name,tbl_name,coalesce(sql,'') FROM main.sqlite_schema ORDER BY type,name").fetch_all(&mut **tx).await?;
            initialize_publication_on(tx,&initial.publication).await?;
            sqlx::query(BASES_DDL).execute(&mut **tx).await?;
            initial.insert_on(tx).await?;
            let after:Vec<(String,String,String,String)>=sqlx::query_as("SELECT type,name,tbl_name,coalesce(sql,'') FROM main.sqlite_schema ORDER BY type,name").fetch_all(&mut **tx).await?;
            let added=after.iter().filter(|row|!before.contains(row)).collect::<Vec<_>>();
            let expected=[("_native_working_publication",PUBLICATION_DDL),("_native_working_applied",APPLIED_DDL),("_native_working_bases",BASES_DDL)];
            // SQLite also creates the one implicit PK index for the TEXT PK.
            if before.iter().any(|row|!after.contains(row)) || added.iter().any(|(kind,name,table,ddl)| {
                !expected.iter().any(|(n,sql)|kind=="table"&&name==n&&table==n&&ddl==sql)
                && !(kind=="index"&&name=="sqlite_autoindex__native_working_applied_1"&&table=="_native_working_applied"&&ddl.is_empty())
            }) { return Err(Error::engine("fresh W private inventory changed")); }
            Ok::<_,Error>(native_schema)
        }).catch_unwind().await;
        let native_schema = match admitted {
            Ok(Ok(schema)) => schema,
            _ => {
                if let Some(reply) = self.ready.take() {
                    let _ = reply.send(Err(Error::engine(
                        "working private admission failed; original wrapper retained",
                    )));
                }
                park(&shared).await;
                let _ = crate::Db::rollback_owned_kernel_connection(&mut admission_tx).await;
                return;
            }
        };
        let settled = std::panic::AssertUnwindSafe(
            reader.commit_owned_kernel_connection(&mut admission_tx, None),
        )
        .catch_unwind()
        .await;
        if !matches!(settled, Ok(KernelCommitOutcome::Committed)) {
            if let Some(reply) = self.ready.take() {
                let _ = reply.send(Err(Error::engine(
                    "working private admission commit not established",
                )));
            }
            park(&shared).await;
            let _ = crate::Db::rollback_owned_kernel_connection(&mut admission_tx).await;
            return;
        }
        drop(admission_tx);
        let collector_result = std::panic::AssertUnwindSafe(with_handle(&mut connection, |raw| {
            let keys =
                crate::kernel::working_undo::registered_primary_keys(raw).map_err(undo_error)?;
            Collector::install(raw, &keys, 100_000, 16 * 1024 * 1024).map_err(undo_error)
        }))
        .catch_unwind()
        .await;
        let collector = match collector_result {
            Ok(Ok(value)) => value,
            _ => {
                if let Some(reply) = self.ready.take() {
                    let _ = reply.send(Err(Error::engine(
                        "working collector admission failed; owner retained",
                    )));
                }
                park(&shared).await;
                return;
            }
        };
        // Only deterministic test disposal may resume a quarantined owner.
        // Production park never returns; no reaper or retry is exposed.
        macro_rules! retain_transaction {
            ($tx:ident) => {{
                park(&shared).await;
                #[cfg(test)]
                {
                    if crate::Db::rollback_owned_kernel_connection(&mut $tx)
                        .await
                        .is_err()
                    {
                        std::future::pending::<()>().await;
                    }
                    drop($tx);
                    drop(collector);
                    if connection.close().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                    self.stopped.send_replace(true);
                    return;
                }
                #[cfg(not(test))]
                {
                    unreachable!("quarantined owner cannot resume");
                }
            }};
        }
        let mut published = initial;
        // Startup is recovery-only. A changed canonical base still refuses at
        // immutable bind_base; no ordinary copy rebuild or accepted fallback.
        let startup = fence.view().proposals().to_vec();
        for ticket in startup {
            let mut tx = match super::super::transaction::construct_pinned_transaction(
                &mut connection,
            )
            .await
            {
                Ok(tx) => tx,
                Err(error) => {
                    if let Some(reply) = self.ready.take() {
                        let _ = reply.send(Err(error));
                    }
                    park(&shared).await;
                    return;
                }
            };
            let phase = std::panic::AssertUnwindSafe(async {
                let owner = replay::WorkingReplayOwner {
                    schema: &native_schema,
                    collector: &collector,
                };
                audit(&mut tx, &shared, &published, &fence, owner).await?;
                capture_replay(&mut tx, owner, &shared, &self.caller, &ticket).await?;
                let mut next = published.clone();
                let ordinal = usize::try_from(next.original_prefix).map_err(|_| paused())?;
                next.original_prefix = next.original_prefix.checked_add(1).ok_or_else(paused)?;
                next.pending_count = next.pending_count.checked_add(1).ok_or_else(paused)?;
                next.publication.publication = next
                    .publication
                    .publication
                    .checked_add(1)
                    .ok_or_else(paused)?;
                next.publication.journal_revision = fence.view().prefix_revision(
                    usize::try_from(next.original_prefix).map_err(|_| paused())?,
                )?;
                insert_marker(&mut tx, &ticket, ordinal, next.publication.publication).await?;
                write_publication(&mut tx, &published, &next).await?;
                Ok::<_, Error>(next)
            })
            .catch_unwind()
            .await;
            let next = match phase {
                Ok(Ok(next)) => next,
                other => {
                    if let Some(reply) = self.ready.take() {
                        let _ = reply.send(Err(phase_error(other)));
                    }
                    retain_transaction!(tx);
                }
            };
            let committed =
                std::panic::AssertUnwindSafe(reader.commit_owned_kernel_connection(&mut tx, None))
                    .catch_unwind()
                    .await;
            if !matches!(committed, Ok(KernelCommitOutcome::Committed)) {
                if let Some(reply) = self.ready.take() {
                    let _ = reply.send(Err(paused()));
                }
                retain_transaction!(tx);
            }
            drop(tx);
            published = next;
        }
        let located = (|| {
            if let Some((root, area)) = shared.journal.location_scope() {
                if shared.generation.factory.area.root
                    != root.join(area).join("hosted-outbox").join("forks")
                {
                    return Err(Error::engine("working storage scope changed"));
                }
                let file = super::super::super::identity(shared.generation.handle.db.path(), false)
                    .map_err(fork_error)?;
                let location = WorkingLocation {
                    version: 1,
                    area: area.clone(),
                    fork: shared
                        .generation
                        .handle
                        .directory
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(paused)?
                        .into(),
                    file_identity: [file.0, file.1],
                    reservation_bytes: shared.generation.reservation,
                    generation: published.publication.generation.clone(),
                    original_anchor_sha256: hex::encode(sha2::Sha256::digest(
                        shared.journal.anchor_bytes()?,
                    )),
                };
                shared.journal.bind_location(&location)
            } else if shared.journal.requires_location() {
                Err(Error::engine("installed working storage location missing"))
            } else {
                Ok(())
            }
        })();
        if let Err(error) = located {
            if let Some(reply) = self.ready.take() {
                let _ = reply.send(Err(error));
            }
            park(&shared).await;
            return;
        }
        let pinned = if matches!(shared.scope, ReadScope::DeclaredNotes(_))
            && shared.create_context.get().is_some()
            && published.original_prefix == 0
        {
            Ok(())
        } else {
            pin_install(
                &shared,
                &self.caller,
                &published,
                PublicationReadiness::Ready,
            )
            .await
        };
        if let Err(error) = pinned {
            if let Some(reply) = self.ready.take() {
                let _ = reply.send(Err(error));
            }
            park(&shared).await;
            return;
        }
        drop(fence);
        if let Some(reply) = self.ready.take() {
            let _ = reply.send(Ok(shared.clone()));
        }
        Commands {
            caller: self.caller,
            receive: self.receive,
            #[cfg(test)]
            stopped: self.stopped,
            #[cfg(test)]
            processed: self.processed,
        }
        .run(RunningOwner {
            shared,
            reader,
            connection,
            collector,
            native_schema,
            published,
        })
        .await;
    }
}

pub(super) struct RunningOwner {
    pub(super) shared: Arc<Shared>,
    pub(super) reader: crate::Db,
    pub(super) connection: sqlx::SqliteConnection,
    pub(super) collector: Collector,
    pub(super) native_schema: WorkingKernelSchema,
    pub(super) published: PublicationBase,
}
pub(super) struct Commands {
    pub(super) caller: Caller,
    pub(super) receive: mpsc::Receiver<Command>,
    #[cfg(test)]
    pub(super) stopped: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    pub(super) processed: tokio::sync::watch::Sender<u64>,
}
impl Commands {
    pub(super) async fn run(mut self, owner: RunningOwner) {
        let RunningOwner {
            shared,
            reader,
            mut connection,
            collector,
            native_schema,
            mut published,
        } = owner;
        macro_rules! retain_transaction {
            ($tx:ident) => {{
                park(&shared).await;
                #[cfg(test)]
                {
                    if crate::Db::rollback_owned_kernel_connection(&mut $tx)
                        .await
                        .is_err()
                    {
                        std::future::pending::<()>().await;
                    }
                    drop($tx);
                    drop(collector);
                    if connection.close().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                    self.stopped.send_replace(true);
                    return;
                }
                #[cfg(not(test))]
                {
                    unreachable!("quarantined owner cannot resume");
                }
            }};
        }
        let mut grounded_epoch = 0u64;
        let mut duplicate_wake = false;
        let mut waiting = VecDeque::<Job>::new();
        // ONE actual contiguous packet may wait for its lost settlement answer.
        // It is never reconstructed from coordinates or shared with terminal Q.
        let mut resolution_packet: Option<(Box<AcceptedDelta>, u64)> = None;
        while let Some(mut command) = if duplicate_wake {
            duplicate_wake = false;
            Some(Command::CanonicalChanged(0))
        } else if *shared.state.lock().unwrap_or_else(|e| e.into_inner()) == WorkingState::Published
            && !waiting.is_empty()
        {
            waiting
                .pop_front()
                .map(|job| Command::Append(Box::new(job)))
        } else {
            self.receive.recv().await
        } {
            if shared.guard.check().is_err() {
                set_state(&shared, WorkingState::Closed);
                break;
            }
            if matches!(command, Command::CanonicalChanged(_)) {
                if let Some((packet, epoch)) = resolution_packet.take() {
                    command = Command::Reconcile(packet, epoch);
                }
            }
            #[cfg(test)]
            if let Command::Drained(reply) = command {
                let _ = reply.send(());
                continue;
            }
            #[cfg(test)]
            if let Command::RemoveMarker(id, reply) = command {
                let result =
                    sqlx::query("DELETE FROM main._native_working_applied WHERE proposal_id=?")
                        .bind(id)
                        .execute(&mut connection)
                        .await
                        .map(|_| ())
                        .map_err(Error::from);
                let _ = reply.send(result);
                continue;
            }
            #[cfg(test)]
            if let Command::ProbeSuffix(ticket, answer, uncertain, reply) = command {
                let result = async {
                    let mut tx =
                        super::super::transaction::construct_pinned_transaction(&mut connection)
                            .await?;
                    let result = unpublished_suffix_is_unapplied(
                        &mut tx,
                        &ticket,
                        answer,
                        uncertain,
                        replay::WorkingReplayOwner {
                            schema: &native_schema,
                            collector: &collector,
                        },
                    )
                    .await;
                    crate::Db::rollback_owned_kernel_connection(&mut tx).await?;
                    result
                }
                .await;
                let _ = reply.send(result);
                continue;
            }
            if *shared.state.lock().unwrap_or_else(|e| e.into_inner()) == WorkingState::Quarantined
            {
                match command {
                    Command::Append(job) => {
                        let _ = job.reply.send(Err(paused()));
                    }
                    Command::Reconcile(delta, _) => {
                        let mut retained = shared
                            .quarantined_delta
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if retained.is_none() {
                            *retained = Some(delta);
                        }
                    }
                    _ => (),
                }
                continue;
            }
            if let Command::Append(job) = command {
                if *shared.state.lock().unwrap_or_else(|e| e.into_inner())
                    == WorkingState::AwaitingQualifiedUndo
                {
                    #[cfg(test)]
                    if let Err(error) = checkpoint(&shared, TestPoint::NativeWait).await {
                        let _ = job.reply.send(Err(error));
                        pause_uncertain(&shared);
                        break;
                    }
                    waiting.push_back(*job);
                    continue;
                }
                let Job {
                    admitted,
                    permit,
                    reply,
                    preparation,
                } = *job;
                if let Err(error) = check_state(&shared) {
                    let _ = reply.send(Err(error));
                    continue;
                }
                // Serial journal admission/revision is owned through fsync and
                // local commit/install, but NEVER across canonical HTTP.
                let captured = match shared.journal.capture().await {
                    Ok(f) => f,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        pause_uncertain(&shared);
                        break;
                    }
                };
                let journal = shared.journal.clone();
                let original = admitted.clone();
                let contract = admitted
                    .contract
                    .clone()
                    .unwrap_or_else(|| shared.contract.clone());
                let durable = tokio::task::spawn_blocking(move || {
                    journal.persist_admitted_fenced_blocking(captured, &original, contract)
                })
                .await;
                let (ticket, turn) = match durable {
                    Ok(Ok(result)) => result,
                    Ok(Err(error @ Error::Conflict(_))) => {
                        let _ = reply.send(Err(error));
                        continue;
                    }
                    _ => {
                        let _ = reply.send(Err(Error::engine(
                            "working journal persistence failed; original retained if durable",
                        )));
                        pause_uncertain(&shared);
                        break;
                    }
                };
                // The existing create-preparation owner survives receiver
                // cancellation until the sole original is actually fsynced.
                // It never spans canonical HTTP and needs no ID cache.
                drop(preparation);
                #[cfg(test)]
                let admitted = AdmittedAppend {
                    fsynced_at: admitted.fsynced_at.or(Some(std::time::Instant::now())),
                    ..admitted
                };
                #[cfg(test)]
                let fsynced = admitted.fsynced_at.expect("owned original fsync sample");
                #[cfg(test)]
                if let Err(error) = checkpoint(&shared, TestPoint::Fsynced).await {
                    let _ = reply.send(Err(error));
                    pause_uncertain(&shared);
                    break;
                }
                let epoch = shared.signals.load(Ordering::Acquire);
                if !set_state(&shared, WorkingState::Applying) {
                    let _ = reply.send(Err(paused()));
                    continue;
                }
                // ACTUAL wrapper lives outside catch. No `?`/Err return can
                // abandon it on a phase panic or indeterminate settlement.
                let mut tx =
                    match super::super::transaction::construct_pinned_transaction(&mut connection)
                        .await
                    {
                        Ok(tx) => tx,
                        Err(error) => {
                            let _ = reply.send(Err(error));
                            park(&shared).await;
                            return;
                        }
                    };
                let phase = std::panic::AssertUnwindSafe(async {
                    let next = append_phase(
                        &mut tx,
                        replay::WorkingReplayOwner {
                            schema: &native_schema,
                            collector: &collector,
                        },
                        &shared,
                        &admitted.caller,
                        &ticket,
                        &turn,
                        &published,
                    )
                    .await?;
                    #[cfg(test)]
                    checkpoint(&shared, TestPoint::Replayed).await?;
                    Ok::<_, Error>(next)
                })
                .catch_unwind()
                .await;
                let next = match phase {
                    Ok(Ok(AppendStep::Ready(next))) => *next,
                    Ok(Ok(AppendStep::NeedsReconcile)) => {
                        let can_wait=turn.view().proposals().iter().all(|original|turn.view().outcome(original.id()).is_some_and(|outcome|!outcome.uncertain()&&matches!(outcome.answer(),crate::node::working_v2::WorkingCanonicalAnswer::Pending|crate::node::working_v2::WorkingCanonicalAnswer::Accepted)));
                        let settled = std::panic::AssertUnwindSafe(
                            crate::Db::rollback_owned_kernel_connection(&mut tx),
                        )
                        .catch_unwind()
                        .await;
                        if !matches!(settled, Ok(Ok(()))) {
                            let _ = reply.send(Err(paused()));
                            retain_transaction!(tx);
                        }
                        drop(tx);
                        set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                        shared.reconciling.store(can_wait, Ordering::Release);
                        drop(turn);
                        if can_wait {
                            waiting.push_back(Job {
                                admitted,
                                permit,
                                reply,
                                preparation: None,
                            });
                        } else {
                            let _=reply.send(Err(Error::engine("AwaitingQualifiedUndo: original retained; canonical outcome unsupported")));
                            drop(permit);
                        }
                        continue;
                    }
                    Ok(Err(error)) => {
                        let _ = reply.send(Err(error));
                        pause_uncertain(&shared);
                        let settled = std::panic::AssertUnwindSafe(
                            crate::Db::rollback_owned_kernel_connection(&mut tx),
                        )
                        .catch_unwind()
                        .await;
                        if !matches!(settled, Ok(Ok(()))) {
                            retain_transaction!(tx);
                        }
                        drop(tx);
                        drop(turn);
                        drop(permit);
                        // The root rollback is acknowledged, but this owner
                        // remains quarantined with its physical collector,
                        // generation and old publication. No new BEGIN/ACK.
                        park(&shared).await;
                        #[cfg(test)]
                        {
                            drop(collector);
                            if connection.close().await.is_err() {
                                std::future::pending::<()>().await;
                            }
                            self.stopped.send_replace(true);
                            return;
                        }
                        #[cfg(not(test))]
                        {
                            let _retained = (&collector, &connection, &shared.generation);
                            unreachable!("quarantined owner cannot resume");
                        }
                    }
                    Err(_) => {
                        let _ = reply.send(Err(Error::engine(
                            "working phase panicked; original retained",
                        )));
                        retain_transaction!(tx);
                    }
                };
                let commit = std::panic::AssertUnwindSafe(
                    reader.commit_owned_kernel_connection(&mut tx, None),
                )
                .catch_unwind()
                .await;
                if !matches!(commit, Ok(KernelCommitOutcome::Committed)) {
                    let _ = reply.send(Err(Error::engine(
                        "working commit not established; old publication retained",
                    )));
                    retain_transaction!(tx);
                }
                if !set_state(&shared, WorkingState::CommittedUnpublished) {
                    // The actual lease has acknowledged COMMIT. Drop only
                    // that depth-zero wrapper, retain the physical owner and
                    // old publication, and drain notifications in terminal Q.
                    drop(tx);
                    let _ = reply.send(Err(paused()));
                    drop(turn);
                    drop(permit);
                    continue;
                }
                let installed = std::panic::AssertUnwindSafe(async {
                    #[cfg(test)]
                    checkpoint(&shared, TestPoint::Committed).await?;
                    pin_install(
                        &shared,
                        &admitted.caller,
                        &next,
                        PublicationReadiness::Ready,
                    )
                    .await
                })
                .catch_unwind()
                .await;
                if !matches!(installed, Ok(Ok(()))) {
                    let _ = reply.send(Err(Error::engine(
                        "working install failed; original and old publication retained",
                    )));
                    retain_transaction!(tx);
                }
                drop(tx); // Depth zero original Drop BEFORE another BEGIN.
                published = next;
                if shared.signals.load(Ordering::Acquire) != epoch
                    || shared.base_signal.load(Ordering::Acquire) > grounded_epoch
                {
                    set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                }
                let state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
                let _delivery = shared.guard.while_open(|| {
                    if *state == WorkingState::Published
                        && shared.signals.load(Ordering::Acquire) == epoch
                        && shared.base_signal.load(Ordering::Acquire) <= grounded_epoch
                        && shared.observed_serving_act.load(Ordering::Acquire)
                            <= published.native.head_act
                    {
                        #[cfg(test)]
                        eprintln!(
                            "working_append_fsync_to_ack_us={}",
                            fsynced.elapsed().as_micros()
                        );
                        let _ = reply.send(Ok(WorkingAck {
                            record_id: ticket
                                .primary_target()
                                .expect("validated target")
                                .to_owned(),
                            proposal_id: ticket.id().into(),
                            publication: published.publication.clone(),
                        }));
                    } else {
                        let _ = reply.send(Err(paused()));
                    }
                });
                drop(state);
                drop(turn);
                drop(permit);
                #[cfg(test)]
                self.processed.send_modify(|count| *count += 1);
                continue;
            }
            if let Command::CanonicalChanged(_wake_epoch) = command {
                let turn = match shared.journal.capture().await {
                    Ok(turn) => turn,
                    Err(_) => {
                        pause_uncertain(&shared);
                        continue;
                    }
                };
                // Epoch on the message is only a wake hint. This immutable
                // turn contains the current durable canonical revision, even
                // when an older hint is delivered after a newer one.
                let epoch = shared.signals.load(Ordering::Acquire);
                if !set_state(&shared, WorkingState::Applying) {
                    continue;
                }
                let mut tx =
                    match super::super::transaction::construct_pinned_transaction(&mut connection)
                        .await
                    {
                        Ok(tx) => tx,
                        Err(_) => {
                            park(&shared).await;
                            return;
                        }
                    };
                let phase = std::panic::AssertUnwindSafe(outcome_phase(
                    &mut tx,
                    replay::WorkingReplayOwner {
                        schema: &native_schema,
                        collector: &collector,
                    },
                    &shared,
                    &turn,
                    &published,
                ))
                .catch_unwind()
                .await;
                let next = match phase {
                    Ok(Ok(next)) => next,
                    Ok(Err(_)) => {
                        let settled = std::panic::AssertUnwindSafe(
                            crate::Db::rollback_owned_kernel_connection(&mut tx),
                        )
                        .catch_unwind()
                        .await;
                        if !matches!(settled, Ok(Ok(()))) {
                            retain_transaction!(tx);
                        }
                        drop(tx);
                        set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                        continue;
                    }
                    Err(_) => {
                        retain_transaction!(tx);
                    }
                };
                let commit = std::panic::AssertUnwindSafe(
                    reader.commit_owned_kernel_connection(&mut tx, None),
                )
                .catch_unwind()
                .await;
                if !matches!(commit, Ok(KernelCommitOutcome::Committed)) {
                    retain_transaction!(tx);
                }
                if !set_state(&shared, WorkingState::CommittedUnpublished) {
                    drop(tx);
                    drop(turn);
                    continue;
                }
                let installed = std::panic::AssertUnwindSafe(pin_install(
                    &shared,
                    &self.caller,
                    &next,
                    PublicationReadiness::Ready,
                ))
                .catch_unwind()
                .await;
                if !matches!(installed, Ok(Ok(()))) {
                    retain_transaction!(tx);
                }
                drop(tx);
                published = next;
                if shared.signals.load(Ordering::Acquire) != epoch
                    || shared.base_signal.load(Ordering::Acquire) > grounded_epoch
                {
                    set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                }
                drop(turn);
                continue;
            }
            if let Command::Reconcile(accepted, epoch) = command {
                if resolution_packet.is_some() {
                    // More than one pending interval is outside this bounded
                    // recovery. Retain both actual packets in terminal custody;
                    // never drop one and pretend its coordinates were folded.
                    pause_uncertain(&shared);
                    {
                        let mut stash = shared
                            .quarantined_delta
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if stash.is_none() {
                            *stash = Some(accepted);
                        }
                    }
                    park(&shared).await;
                    #[cfg(test)]
                    self.stopped.send_replace(true);
                    return;
                }

                let delta = accepted.delta().delta();
                let duplicate = delta.head.generation == published.native
                    && published
                        .source_generation
                        .as_ref()
                        .is_none_or(|id| id == accepted.destination());
                if delta.origin_database_id != published.origin {
                    set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                    continue;
                }
                if duplicate {
                    grounded_epoch = grounded_epoch.max(epoch);
                    duplicate_wake = true;
                    continue;
                }
                if published
                    .source_generation
                    .as_ref()
                    .is_some_and(|id| id != accepted.source())
                    || accepted.before() != &published.native
                    || delta.from_exclusive_act != published.native.head_act
                {
                    set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                    continue;
                }
                let turn = match shared.journal.capture().await {
                    Ok(f) => f,
                    Err(_) => {
                        pause_uncertain(&shared);
                        continue;
                    }
                };
                if !set_state(&shared, WorkingState::Applying) {
                    continue;
                }
                let mut tx =
                    match super::super::transaction::construct_pinned_transaction(&mut connection)
                        .await
                    {
                        Ok(tx) => tx,
                        Err(_) => {
                            park(&shared).await;
                            return;
                        }
                    };
                let phase = std::panic::AssertUnwindSafe(reconcile_phase(
                    &mut tx,
                    &collector,
                    &shared,
                    &self.caller,
                    &turn,
                    &published,
                    (&accepted, &native_schema),
                ))
                .catch_unwind()
                .await;
                let Reconciled { next, readiness } = match phase {
                    Ok(Ok(Some(reconciled))) => reconciled,
                    Ok(Ok(None)) => {
                        let settled = crate::Db::rollback_owned_kernel_connection(&mut tx).await;
                        if settled.is_err() {
                            retain_transaction!(tx);
                        }
                        drop(tx);
                        resolution_packet = Some((accepted, epoch));
                        set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                        continue;
                    }
                    Ok(Err(_)) => {
                        // A verified but unsupported interval keeps the whole
                        // old W. Only an acknowledged rollback releases its Tx.
                        let settled = std::panic::AssertUnwindSafe(
                            crate::Db::rollback_owned_kernel_connection(&mut tx),
                        )
                        .catch_unwind()
                        .await;
                        if !matches!(settled, Ok(Ok(()))) {
                            retain_transaction!(tx);
                        }
                        drop(tx);
                        set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                        continue;
                    }
                    Err(_) => {
                        retain_transaction!(tx);
                    }
                };
                let commit = std::panic::AssertUnwindSafe(
                    reader.commit_owned_kernel_connection(&mut tx, None),
                )
                .catch_unwind()
                .await;
                if !matches!(commit, Ok(KernelCommitOutcome::Committed)) {
                    retain_transaction!(tx);
                }
                if !set_state(&shared, WorkingState::CommittedUnpublished) {
                    drop(tx);
                    drop(turn);
                    continue;
                }
                let installed = std::panic::AssertUnwindSafe(async {
                    #[cfg(test)]
                    checkpoint(&shared, TestPoint::ReconcileCommitted).await?;
                    pin_install(&shared, &self.caller, &next, readiness).await
                })
                .catch_unwind()
                .await;
                if !matches!(installed, Ok(Ok(()))) {
                    retain_transaction!(tx);
                }
                drop(tx);
                published = next;
                grounded_epoch = grounded_epoch.max(epoch);
                if shared.signals.load(Ordering::Acquire) != epoch
                    || shared.base_signal.load(Ordering::Acquire) > grounded_epoch
                {
                    set_state(&shared, WorkingState::AwaitingQualifiedUndo);
                }
                drop(turn);
            }
        }
        drop(collector);
        // Only settled normal completion can release the static slot. RO read
        // workers retain the generation independently; no file reclamation.
        if connection.close().await.is_err() {
            park(&shared).await;
        }
        #[cfg(test)]
        self.stopped.send_replace(true);
    }
}
fn phase_error(
    value: std::result::Result<Result<PublicationBase>, Box<dyn std::any::Any + Send>>,
) -> Error {
    match value {
        Ok(Err(error)) => error,
        _ => Error::engine("working phase panicked; original wrapper retained"),
    }
}
#[derive(Clone, Copy)]
pub(super) enum PublicationReadiness {
    Ready,
    AwaitingAcceptedMaterialization,
}
struct Reconciled {
    next: PublicationBase,
    readiness: PublicationReadiness,
}
pub(super) async fn pin_install(
    shared: &Arc<Shared>,
    caller: &Caller,
    next: &PublicationBase,
    readiness: PublicationReadiness,
) -> Result<()> {
    let pinned = match &shared.scope {
        ReadScope::Workspace => {
            PinnedWorkingRead::pin_workspace_owned(
                shared.generation.handle.db.clone(),
                caller.clone(),
                shared.guard.clone(),
                next.read_binding(),
                shared.generation.clone(),
            )
            .await?
        }
        ReadScope::DeclaredNotes(notes) => {
            PinnedWorkingRead::pin_owned(
                shared.generation.handle.db.clone(),
                caller.clone(),
                notes.clone(),
                shared.guard.clone(),
                next.read_binding(),
                shared.generation.clone(),
            )
            .await?
        }
    };
    if pinned.publication() != &next.publication {
        return Err(Error::engine("working install header changed"));
    }
    let collection = PinnedWorkingCollection::pin_owned(
        shared.generation.handle.db.clone(),
        caller.clone(),
        shared.guard.clone(),
        next.read_binding(),
        shared.generation.clone(),
    )
    .await?;
    if collection.publication() != &next.publication {
        return Err(Error::engine("working collection install header changed"));
    }
    let mut cell = shared.publication.write().await;
    let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    shared.guard.while_open(|| {
        if !matches!(
            *state,
            WorkingState::Published | WorkingState::Applying | WorkingState::CommittedUnpublished
        ) {
            return Err(paused());
        }
        *cell = Some(Published {
            read: pinned,
            collection,
            base: next.clone(),
        });
        *state = if matches!(
            readiness,
            PublicationReadiness::AwaitingAcceptedMaterialization
        ) || shared.observed_serving_act.load(Ordering::Acquire) > next.native.head_act
        {
            WorkingState::AwaitingQualifiedUndo
        } else {
            WorkingState::Published
        };
        shared.publication_notice.notify_waiters();
        Ok(())
    })??;
    Ok(())
}

pub(super) struct AuditOutcome {
    pub(super) canonical_changed: bool,
    pub(super) transport_uncertain: bool,
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    shared: &Shared,
    previous: &PublicationBase,
    fence: &JournalFence,
    owner: replay::WorkingReplayOwner<'_>,
) -> Result<AuditOutcome> {
    let outcome = audit_on(tx, previous, fence, owner).await?;
    shared.guard.check()?;
    Ok(outcome)
}
pub(super) async fn audit_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    previous: &PublicationBase,
    fence: &JournalFence,
    owner: replay::WorkingReplayOwner<'_>,
) -> Result<AuditOutcome> {
    let mut outcome = AuditOutcome {
        canonical_changed: false,
        transport_uncertain: false,
    };
    let header: String =
        sqlx::query_scalar("SELECT state FROM main._native_working_publication WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    if header != serde_json::to_string(&previous.publication)? {
        return Err(Error::engine("working writer/publication diverged"));
    }
    let base: String =
        sqlx::query_scalar("SELECT state FROM main._native_working_bases WHERE publication=?")
            .bind(previous.publication.publication)
            .fetch_one(&mut **tx)
            .await?;
    if base != serde_json::to_string(previous)? {
        return Err(Error::engine("working immutable base changed"));
    }
    let prefix = usize::try_from(previous.original_prefix).map_err(|_| paused())?;
    if prefix > fence.view().proposals().len() {
        return Err(Error::engine("working original prefix exceeds journal"));
    }
    let rows:Vec<(String,String,String,i64,i64)>=sqlx::query_as("SELECT proposal_id,request_fingerprint,actor,publication,original_ordinal FROM main._native_working_applied ORDER BY original_ordinal").fetch_all(&mut **tx).await?;
    if i64::try_from(rows.len()).ok() != Some(previous.pending_count) {
        return Err(Error::engine(
            "working ordered prefix missing local applied marker",
        ));
    }
    for draft in &previous.recovery_dispositions {
        let ordinal = usize::try_from(draft.original_ordinal).map_err(|_| paused())?;
        let ticket = fence.view().proposals().get(ordinal).ok_or_else(paused)?;
        let resolution = fence.view().resolution(ticket.id()).ok_or_else(paused)?;
        let actual = terminal_draft_on(tx, ticket, resolution, previous, owner, ordinal)
            .await?
            .ok_or_else(paused)?;
        if &actual != draft || rows.iter().any(|row| row.0 == draft.proposal_id) {
            return Err(paused());
        }
    }
    for (id, fp, actor, pubno, ordinal) in rows {
        let original = usize::try_from(ordinal)
            .ok()
            .filter(|n| *n < prefix)
            .and_then(|n| fence.view().proposals().get(n))
            .ok_or_else(paused)?;
        if original.id() != id
            || original.fingerprint() != fp
            || original.actor() != actor
            || pubno < 1
            || pubno > previous.publication.publication
        {
            return Err(Error::engine(
                "working applied original metadata inconsistent",
            ));
        }
        let original_outcome = fence.view().outcome(original.id()).ok_or_else(paused)?;
        outcome.transport_uncertain |= original_outcome.uncertain();
        outcome.canonical_changed |=
            original_outcome.answer() != crate::node::working_v2::WorkingCanonicalAnswer::Pending;
        let exact = {
            use crate::kernel::original_settlement::{
                outcome_profile::OutcomeLookup, KeyedOutcome,
            };
            let mut snapshot = owner.outcomes(tx).await?;
            let outcome = snapshot
                .lookup(
                    &actor,
                    original.operation(),
                    original.arguments()["idempotency_key"]
                        .as_str()
                        .ok_or_else(paused)?,
                )
                .await
                .map_err(|error| Error::engine(error.code()))?;
            if let Some(conflict) = outcome.terminal_conflict() {
                return Err(Error::OriginalConflict(Box::new(conflict)));
            }
            match outcome {
                OutcomeLookup::Legacy(Some((request, _)))
                | OutcomeLookup::Typed(KeyedOutcome::Accepted { request, .. }) => {
                    request == original.fingerprint()
                }
                OutcomeLookup::Legacy(None) | OutcomeLookup::Typed(KeyedOutcome::Absent) => false,
                OutcomeLookup::Typed(KeyedOutcome::Terminal { .. }) => {
                    unreachable!("terminal handled above")
                }
            }
        };
        if !exact {
            return Err(Error::engine(
                "working local marker has no exact provider receipt",
            ));
        }
    }
    Ok(outcome)
}
pub(super) async fn write_publication(
    tx: &mut sqlx::SqliteConnection,
    previous: &PublicationBase,
    next: &PublicationBase,
) -> Result<()> {
    next.insert_on(tx).await?;
    let changed = sqlx::query(
        "UPDATE main._native_working_publication SET state=? WHERE singleton=1 AND state=?",
    )
    .bind(serde_json::to_string(&next.publication)?)
    .bind(serde_json::to_string(&previous.publication)?)
    .execute(tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(Error::engine("working publication CAS failed"));
    }
    Ok(())
}
async fn capture_replay(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    owner: replay::WorkingReplayOwner<'_>,
    shared: &Shared,
    caller: &Caller,
    ticket: &DurableAppend,
) -> Result<()> {
    let collector = owner.collector;
    crate::storage_profile::enforce_write_boundary_on(tx).await?;
    with_handle(tx, |raw| {
        collector.proposal(raw, ticket.id()).map_err(undo_error)
    })
    .await?;
    replay_ticket(tx, shared, caller, ticket, false, owner).await?;
    with_handle(tx, |raw| {
        collector
            .finish_proposal(raw, ticket.id())
            .map_err(undo_error)
    })
    .await
}
async fn insert_marker(
    tx: &mut sqlx::SqliteConnection,
    ticket: &DurableAppend,
    ordinal: usize,
    publication: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO main._native_working_applied VALUES(?,?,?,?,?)")
        .bind(ticket.id())
        .bind(ticket.fingerprint())
        .bind(ticket.actor())
        .bind(publication)
        .bind(i64::try_from(ordinal).map_err(|_| paused())?)
        .execute(tx)
        .await?;
    Ok(())
}
enum AppendStep {
    Ready(Box<PublicationBase>),
    NeedsReconcile,
}
async fn append_phase(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    owner: replay::WorkingReplayOwner<'_>,
    shared: &Shared,
    caller: &Caller,
    ticket: &DurableAppend,
    fence: &JournalFence,
    previous: &PublicationBase,
) -> Result<AppendStep> {
    let collector = owner.collector;
    with_handle(tx, |raw| collector.check(raw).map_err(undo_error)).await?;
    let audited = audit(tx, shared, previous, fence, owner).await?;
    if fence.view().has_resolution() {
        return Ok(AppendStep::NeedsReconcile);
    }
    let count = fence.view().proposals().len();
    let ordinal = fence
        .view()
        .proposals()
        .iter()
        .position(|p| p == ticket)
        .ok_or_else(paused)?;
    let prefix = usize::try_from(previous.original_prefix).map_err(|_| paused())?;
    // Retrieving an already published exact original changes no domain state
    // or publication. Transport doubt remains durable; every canonical change
    // and every fresh write still needs the existing reconciliation boundary.
    let published_retry = ordinal < prefix
        && count == prefix
        && fence.view().revision() == previous.publication.journal_revision;
    if audited.canonical_changed || (audited.transport_uncertain && !published_retry) {
        return Ok(AppendStep::NeedsReconcile);
    }
    if fence.view().prefix_revision(prefix)? != previous.publication.journal_revision {
        return Ok(AppendStep::NeedsReconcile);
    }
    if ordinal < prefix {
        if count != prefix || fence.view().revision() != previous.publication.journal_revision {
            return Err(paused());
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM main._native_working_applied WHERE proposal_id=?)",
        )
        .bind(ticket.id())
        .fetch_one(&mut **tx)
        .await?;
        if !exists && !materialized_on(tx, ticket, previous, owner).await? {
            return Err(Error::engine(
                "working ordered prefix missing local applied marker",
            ));
        }
        replay_ticket(tx, shared, caller, ticket, true, owner).await?;
        return Ok(AppendStep::Ready(Box::new(previous.clone())));
    }
    if ordinal != prefix || count != ordinal.checked_add(1).ok_or_else(paused)? {
        return Err(Error::engine("working earlier original requires recovery"));
    }
    let outcome = fence.view().outcome(ticket.id()).ok_or_else(paused)?;
    if outcome.uncertain()
        || outcome.answer() != crate::node::working_v2::WorkingCanonicalAnswer::Pending
    {
        return Ok(AppendStep::NeedsReconcile);
    }
    capture_replay(tx, owner, shared, caller, ticket).await?;
    let mut next = previous.clone();
    next.publication.publication = next
        .publication
        .publication
        .checked_add(1)
        .ok_or_else(paused)?;
    next.publication.journal_revision = fence.view().revision().into();
    next.original_prefix = i64::try_from(count).map_err(|_| paused())?;
    next.pending_count = next.pending_count.checked_add(1).ok_or_else(paused)?;
    insert_marker(tx, ticket, ordinal, next.publication.publication).await?;
    write_publication(tx, previous, &next).await?;
    check_size(shared)?;
    Ok(AppendStep::Ready(Box::new(next)))
}
async fn reconcile_phase(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    collector: &Collector,
    shared: &Shared,
    caller: &Caller,
    fence: &JournalFence,
    previous: &PublicationBase,
    fold_input: (&AcceptedDelta, &WorkingKernelSchema),
) -> Result<Option<Reconciled>> {
    let (accepted, schema) = fold_input;
    let owner = replay::WorkingReplayOwner { schema, collector };
    crate::storage_profile::enforce_write_boundary_on(tx).await?;
    with_handle(tx, |raw| collector.check(raw).map_err(undo_error)).await?;
    audit(tx, shared, previous, fence, owner).await?;
    authorize(tx, shared, caller).await?;
    // Bounded positive prefix only. All pending originals are inverted on the
    // same physical writer; private publication rows were captured with OFF.
    let first: Option<String> = sqlx::query_scalar(
        "SELECT proposal_id FROM main._native_working_applied ORDER BY original_ordinal LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(first) = first {
        with_handle(tx, |raw| collector.undo(raw, &first).map_err(undo_error)).await?;
    }
    let handle = crate::standby::kernel_v2_delta::WorkingFold::new(
        tx,
        collector,
        schema,
        &previous.native,
        &previous.origin,
    )
    .await?;
    let native = handle
        .fold(
            accepted.delta(),
            &crate::standby::phase_timings::PhaseTimings::default(),
        )
        .await?;
    let genesis = native.genesis_event_id.clone();
    let seq = native.content_event_seq;
    let mut next = PublicationBase {
        publication: WorkingPublication {
            accepted_frontier: seq,
            journal_revision: fence.view().revision().into(),
            publication: previous
                .publication
                .publication
                .checked_add(1)
                .ok_or_else(paused)?,
            ..previous.publication.clone()
        },
        native,
        origin: previous.origin.clone(),
        source_generation: previous
            .source_generation
            .as_ref()
            .map(|_| accepted.destination().to_owned()),
        genesis,
        principal: previous.principal.clone(),
        original_prefix: i64::try_from(fence.view().proposals().len()).map_err(|_| paused())?,
        pending_count: 0,
        recovery_dispositions: Vec::new(),
    };
    sqlx::query("DELETE FROM main._native_working_applied")
        .execute(&mut **tx)
        .await?;
    let mut pending_seen = false;
    let mut readiness = PublicationReadiness::Ready;
    for (ordinal, ticket) in fence.view().proposals().iter().enumerate() {
        let outcome = fence.view().outcome(ticket.id()).ok_or_else(paused)?;
        let resolution = fence.view().resolution(ticket.id());
        if let Some(resolution) = resolution {
            if ordinal.checked_add(1) != Some(fence.view().proposals().len()) {
                return Err(paused());
            }
            readiness = PublicationReadiness::AwaitingAcceptedMaterialization;
            if let Some(draft) =
                terminal_draft_on(tx, ticket, resolution, &next, owner, ordinal).await?
            {
                next.recovery_dispositions.push(draft);
                continue;
            }
        }
        let materialized = match materialized_on(tx, ticket, &next, owner).await {
            Ok(value) => value,
            Err(Error::OriginalConflict(_)) if resolution.is_some_and(|r| r.answer().is_none()) => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        if materialized {
            if pending_seen
                || (resolution.is_none()
                    && outcome.answer() == crate::node::working_v2::WorkingCanonicalAnswer::Refused)
            {
                return Err(Error::engine(
                    "accepted originals are not a supported positive prefix",
                ));
            }
            continue;
        }
        pending_seen = true;
        if outcome.uncertain() && resolution.is_none() {
            return Err(Error::engine(
                "canonical original not materialized; full W retained",
            ));
        }
        match outcome.answer() {
            _ if resolution.is_some() => {
                readiness = PublicationReadiness::AwaitingAcceptedMaterialization;
            }
            crate::node::working_v2::WorkingCanonicalAnswer::Pending => (),
            crate::node::working_v2::WorkingCanonicalAnswer::Accepted => {
                // A later accepted original may be beyond this genuine packet.
                // Retain/replay it as speculative work, never accepted accounting.
                // Consume this contiguous cut so the next packet can catch up,
                // while installation atomically keeps new ACKs paused.
                readiness = PublicationReadiness::AwaitingAcceptedMaterialization;
            }
            _ => {
                return Err(Error::engine(
                    "canonical original not materialized; full W retained",
                ))
            }
        }
        capture_replay(tx, owner, shared, caller, ticket).await?;
        insert_marker(tx, ticket, ordinal, next.publication.publication).await?;
        next.pending_count = next.pending_count.checked_add(1).ok_or_else(paused)?;
    }
    write_publication(tx, previous, &next).await?;
    check_size(shared)?;
    Ok(Some(Reconciled { next, readiness }))
}

/// A later queue receipt may arrive AFTER its accepted delta. Rebind only the
/// journal revision, with no domain fold, when every changed outcome is already
/// materialized on this grounded accepted cut. Pending markers cannot be
/// dismissed by an answer or by a provider receipt beyond that cut.
async fn outcome_phase(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    owner: replay::WorkingReplayOwner<'_>,
    shared: &Shared,
    fence: &JournalFence,
    previous: &PublicationBase,
) -> Result<PublicationBase> {
    let collector = owner.collector;
    crate::storage_profile::enforce_write_boundary_on(tx).await?;
    with_handle(tx, |raw| collector.check(raw).map_err(undo_error)).await?;
    audit(tx, shared, previous, fence, owner).await?;
    if fence.view().has_resolution() {
        return Err(paused());
    }
    let prefix = usize::try_from(previous.original_prefix).map_err(|_| paused())?;
    let proposals = fence.view().proposals();
    let included = proposals.get(..prefix).ok_or_else(paused)?;
    let suffix = proposals.get(prefix..).ok_or_else(paused)?;
    // Serial admission can leave exactly one fresh fsynced original waiting
    // behind a late answer. It is retained, not included in this publication.
    if suffix.len() > 1 {
        return Err(paused());
    }
    if let Some(ticket) = suffix.first() {
        let outcome = fence.view().outcome(ticket.id()).ok_or_else(paused)?;
        if !unpublished_suffix_is_unapplied(
            tx,
            ticket,
            outcome.answer(),
            outcome.uncertain(),
            owner,
        )
        .await?
        {
            return Err(paused());
        }
    }
    for ticket in included {
        let outcome = fence.view().outcome(ticket.id()).ok_or_else(paused)?;
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM main._native_working_applied WHERE proposal_id=?)",
        )
        .bind(ticket.id())
        .fetch_one(&mut **tx)
        .await?;
        if pending {
            if outcome.uncertain()
                || outcome.answer() != crate::node::working_v2::WorkingCanonicalAnswer::Pending
            {
                return Err(paused());
            }
        } else if outcome.answer() == crate::node::working_v2::WorkingCanonicalAnswer::Refused
            || outcome.answer() == crate::node::working_v2::WorkingCanonicalAnswer::Unsupported
            || !materialized_on(tx, ticket, previous, owner).await?
        {
            return Err(paused());
        }
    }
    let revision = fence.view().prefix_revision(prefix)?;
    if revision == previous.publication.journal_revision {
        return Ok(previous.clone());
    }
    let mut next = previous.clone();
    next.publication.publication = next
        .publication
        .publication
        .checked_add(1)
        .ok_or_else(paused)?;
    next.publication.journal_revision = revision;
    write_publication(tx, previous, &next).await?;
    Ok(next)
}

// This guard never grants applied status to a suffix. A marker or even an
// unmarked keyed native receipt makes it ineligible for answer-only rebinding.
pub(in crate::fork) async fn unpublished_suffix_is_unapplied(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ticket: &DurableAppend,
    answer: crate::node::working_v2::WorkingCanonicalAnswer,
    uncertain: bool,
    owner: replay::WorkingReplayOwner<'_>,
) -> Result<bool> {
    if uncertain || answer != crate::node::working_v2::WorkingCanonicalAnswer::Pending {
        return Ok(false);
    }
    let marked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main._native_working_applied WHERE proposal_id=?)",
    )
    .bind(ticket.id())
    .fetch_one(&mut **tx)
    .await?;
    use crate::kernel::original_settlement::{outcome_profile::OutcomeLookup, KeyedOutcome};
    let mut snapshot = owner.outcomes(tx).await?;
    let outcome = snapshot
        .lookup(
            ticket.actor(),
            ticket.operation(),
            ticket.arguments()["idempotency_key"]
                .as_str()
                .ok_or_else(paused)?,
        )
        .await
        .map_err(|error| Error::engine(error.code()))?;
    if let Some(conflict) = outcome.terminal_conflict() {
        return Err(Error::OriginalConflict(Box::new(conflict)));
    }
    let absent = match outcome {
        OutcomeLookup::Legacy(None) | OutcomeLookup::Typed(KeyedOutcome::Absent) => true,
        OutcomeLookup::Legacy(Some(_)) | OutcomeLookup::Typed(KeyedOutcome::Accepted { .. }) => {
            false
        }
        OutcomeLookup::Typed(KeyedOutcome::Terminal { .. }) => {
            unreachable!("terminal handled above")
        }
    };
    Ok(!marked && absent)
}
