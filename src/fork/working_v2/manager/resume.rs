//! Exact-cut restart of one retained W. The journal supplies originals, never
//! Caller authority; the current verified source supplies native admission.
use super::actor::{Commands, PublicationReadiness, RunningOwner};
use super::*;
use crate::kernel::working_undo::{with_handle, Collector};
use crate::standby::kernel_v2::{self, WorkingKernelSchema};
use futures::FutureExt;
use sqlx::Connection;
use std::path::PathBuf;

pub(super) struct Request {
    pub base: OwnerPinnedBase,
    pub caller: Caller,
    pub scope: ReadScope,
    pub factory: Arc<crate::fork::ForkManager>,
    pub journal: WorkingJournal,
    pub guard: BindingGuard,
    pub contract: (String, Option<replay::FirstPartyCreateContext>),
    pub fence: JournalFence,
    pub location: WorkingLocation,
}
struct File {
    path: PathBuf,
    directory: PathBuf,
    file: crate::fork::FileIdentity,
    directory_identity: crate::fork::FileIdentity,
    factory_sidecars: Option<(crate::fork::FileIdentity, crate::fork::FileIdentity)>,
}
impl File {
    fn select(request: &Request) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        request.location.validate()?;
        let (root, area) = request
            .journal
            .location_scope()
            .ok_or_else(|| Error::engine("retained working storage scope missing"))?;
        if area != &request.location.area
            || request.factory.area.root != root.join(area).join("hosted-outbox").join("forks")
        {
            return Err(Error::engine("retained working storage scope changed"));
        }
        request.factory.area.check().map_err(fork_error)?;
        let directory = request.factory.area.root.join(&request.location.fork);
        crate::fork::no_symlink_components(&directory).map_err(fork_error)?;
        let directory_identity = crate::fork::identity(&directory, true).map_err(fork_error)?;
        let directory_meta = std::fs::symlink_metadata(&directory)?;
        if directory_meta.uid() != crate::node::current_uid()
            || directory_meta.permissions().mode() & 0o777 != 0o700
        {
            return Err(Error::engine(
                "retained working directory ownership changed",
            ));
        }
        let factory_sidecars = Self::inventory(&directory)?;
        let path = directory.join("fork.sqlite");
        let file = crate::fork::identity(&path, false).map_err(fork_error)?;
        if [file.0, file.1] != request.location.file_identity {
            return Err(Error::engine("retained working file identity changed"));
        }
        let bytes = crate::fork::footprint(&directory).map_err(fork_error)?;
        if bytes > request.location.reservation_bytes
            || request.location.reservation_bytes > request.factory.limits.max_reserved_bytes
        {
            return Err(Error::engine("retained working capacity exceeded"));
        }
        Ok(Self {
            path,
            directory,
            file,
            directory_identity,
            factory_sidecars,
        })
    }
    // Verification opens partial.sqlite before publishing only its main file.
    // SQLite may leave an empty WAL and ephemeral index for that old name.
    // They are never opened, replayed or removed, and supply no authority.
    fn inventory(
        directory: &std::path::Path,
    ) -> Result<Option<(crate::fork::FileIdentity, crate::fork::FileIdentity)>> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (mut wal, mut shm) = (None, None);
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if !matches!(
                entry.file_name().to_str(),
                Some(
                    "fork.sqlite"
                        | "fork.sqlite-wal"
                        | "fork.sqlite-shm"
                        | "partial.sqlite-wal"
                        | "partial.sqlite-shm"
                )
            ) {
                return Err(Error::engine(
                    "retained working directory has unsupported files",
                ));
            }
            let meta = std::fs::symlink_metadata(entry.path())?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != crate::node::current_uid()
                || meta.permissions().mode() & 0o777 != 0o600
            {
                return Err(Error::engine("retained working file ownership changed"));
            }
            let id = crate::fork::identity(&entry.path(), false).map_err(fork_error)?;
            match entry.file_name().to_str() {
                Some("partial.sqlite-wal") => wal = Some((id, meta.len())),
                Some("partial.sqlite-shm") => shm = Some((id, meta.len())),
                _ => {}
            }
        }
        match (wal, shm) {
            (None, None) => Ok(None),
            (Some((wal, 0)), Some((shm, 32768))) => Ok(Some((wal, shm))),
            _ => Err(Error::engine(
                "retained factory verification sidecars are not inert",
            )),
        }
    }
    fn check(&self) -> Result<()> {
        if crate::fork::identity(&self.path, false).map_err(fork_error)? != self.file
            || crate::fork::identity(&self.directory, true).map_err(fork_error)?
                != self.directory_identity
        {
            return Err(Error::engine("retained working path changed"));
        }
        if Self::inventory(&self.directory)? != self.factory_sidecars {
            return Err(Error::engine(
                "retained factory verification sidecar identity changed",
            ));
        }
        Ok(())
    }
}
struct Prepared {
    request: Request,
    file: File,
    state: Arc<StdMutex<WorkingState>>,
    receive: mpsc::Receiver<actor::Command>,
    ready: Option<oneshot::Sender<Result<Arc<Shared>>>>,
    #[cfg(test)]
    stopped: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    processed: tokio::sync::watch::Sender<u64>,
}
pub(super) async fn start(request: Request) -> Result<(WorkingManager, WorkingControl)> {
    let file = File::select(&request)?;
    {
        let mut entries = request.factory.entries.lock().await;
        entries.reserved = request.location.reservation_bytes;
    }
    let state = Arc::new(StdMutex::new(WorkingState::Published));
    let (send, receive) = mpsc::channel(16);
    let (ready_send, ready) = oneshot::channel();
    #[cfg(test)]
    let (stopped_send, stopped) = tokio::sync::watch::channel(false);
    #[cfg(test)]
    let (processed_send, processed) = tokio::sync::watch::channel(0u64);
    let owner = Prepared {
        request,
        file,
        state: state.clone(),
        receive,
        ready: Some(ready_send),
        #[cfg(test)]
        stopped: stopped_send,
        #[cfg(test)]
        processed: processed_send,
    };
    let _driver = super::super::transaction::retain_writer_actor(Box::pin(owner.run()), state)?;
    let shared = ready
        .await
        .map_err(|_| Error::engine("retained working owner stopped"))??;
    let control = WorkingControl {
        shared: shared.clone(),
        send: send.downgrade(),
    };
    Ok((
        WorkingManager {
            shared,
            send,
            capacity: Arc::new(Semaphore::new(8)),
            #[cfg(test)]
            stopped,
            #[cfg(test)]
            processed,
        },
        control,
    ))
}
impl Prepared {
    fn refuse(&mut self, error: Error) {
        if let Some(reply) = self.ready.take() {
            let _ = reply.send(Err(error));
        }
    }
    async fn quarantine(&mut self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = WorkingState::Quarantined;
        self.refuse(Error::engine(
            "retained working owner disposition unavailable; original retained",
        ));
        std::future::pending::<()>().await;
    }
    async fn run(mut self) {
        // The retained slot owns this request, file locks, source lease and
        // connection constructor before the first connection/BEGIN await.
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&self.file.path)
            .create_if_missing(false)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
            .foreign_keys(true)
            .with_regexp()
            .pragma("recursive_triggers", "ON");
        let opened = std::panic::AssertUnwindSafe(sqlx::SqliteConnection::connect_with(&options))
            .catch_unwind()
            .await;
        let mut connection = match opened {
            Ok(Ok(c)) => c,
            _ => {
                self.quarantine().await;
                return;
            }
        };
        // The actual verified source snapshot was pinned before the floor
        // check. Never rollback/re-BEGIN between authority and W grounding.
        let mut source = match self.request.base.source_snapshot.take() {
            Some(source) => source,
            None => {
                self.quarantine().await;
                return;
            }
        };
        let collector_open = std::panic::AssertUnwindSafe(with_handle(&mut connection, |raw| {
            let keys = crate::kernel::working_undo::registered_primary_keys(raw)
                .map_err(|e| Error::engine(e.to_string()))?;
            Collector::open(raw, &keys).map_err(|e| Error::engine(e.to_string()))
        }))
        .catch_unwind()
        .await;
        let collector = match collector_open {
            Ok(Ok(c)) => c,
            Ok(Err(error)) => {
                if source.rollback().await.is_err() {
                    self.quarantine().await;
                    return;
                }
                if connection.close().await.is_err() {
                    self.quarantine().await;
                    return;
                }
                self.refuse(error);
                return;
            }
            Err(_) => {
                self.quarantine().await;
                return;
            }
        };
        let mut tx =
            match super::super::transaction::construct_pinned_transaction(&mut connection).await {
                Ok(tx) => tx,
                Err(_) => {
                    self.quarantine().await;
                    return;
                }
            };
        // Only the borrowed phase unwinds; the actual wrapper stays outside.
        let phase = std::panic::AssertUnwindSafe(self.audit(&mut tx, &mut source, &collector))
            .catch_unwind()
            .await;
        let audited = match phase {
            Ok(result) => result,
            Err(_) => {
                self.quarantine().await;
                return;
            }
        };
        let rolled =
            std::panic::AssertUnwindSafe(crate::Db::rollback_owned_kernel_connection(&mut tx))
                .catch_unwind()
                .await;
        if !matches!(rolled, Ok(Ok(()))) {
            self.quarantine().await;
            return;
        }
        drop(tx); // acknowledged depth zero BEFORE any reader or later BEGIN.
        let (mut published, native_schema) = match audited {
            Ok(value) => value,
            Err(error) => {
                if source.rollback().await.is_err() {
                    self.quarantine().await;
                    return;
                }
                drop(collector);
                if connection.close().await.is_err() {
                    self.quarantine().await;
                    return;
                }
                self.refuse(error);
                return;
            }
        };
        if source.rollback().await.is_err() {
            self.quarantine().await;
            return;
        }
        drop(self.request.base.source_checkpoint.take());
        let admission = AuditedWorkingRead::new(&self.file.path, self.file.file);
        let reader = match std::panic::AssertUnwindSafe(crate::db::open_audited_working_read_only(
            &admission,
        ))
        .catch_unwind()
        .await
        {
            Ok(Ok(db)) => db,
            Ok(Err(error)) => {
                self.refuse(error);
                self.quarantine().await;
                return;
            }
            Err(_) => {
                self.quarantine().await;
                return;
            }
        };
        let registry = match working_registry() {
            Ok(r) => r,
            Err(error) => {
                self.refuse(error);
                self.quarantine().await;
                return;
            }
        };
        let handle = crate::fork::ForkHandle {
            db: reader.clone(),
            registry,
            directory: self.file.directory.clone(),
            directory_identity: self.file.directory_identity,
            file_identity: self.file.file,
            base_frontier: published.publication.accepted_frontier,
            capture: None,
        };
        let Request {
            base,
            caller,
            scope,
            factory,
            journal,
            guard,
            contract,
            fence,
            location,
        } = self.request;
        let create_context = std::sync::OnceLock::new();
        if let Some(context) = contract.1 {
            let _ = create_context.set(context);
        }
        let shared = Arc::new(Shared {
            observed_serving_act: std::sync::atomic::AtomicI64::new(base.native.head_act),
            base,
            generation: Arc::new(Generation {
                factory,
                handle,
                reservation: location.reservation_bytes,
            }),
            journal,
            state: self.state,
            publication: RwLock::new(None),
            publication_notice: tokio::sync::Notify::new(),
            signals: std::sync::atomic::AtomicU64::new(0),
            base_signal: std::sync::atomic::AtomicU64::new(0),
            reconciling: std::sync::atomic::AtomicBool::new(false),
            quarantined_delta: StdMutex::new(None),
            guard,
            scope,
            contract: contract.0,
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
        macro_rules! retain_transaction {
            ($tx:ident) => {{
                if let Some(reply) = self.ready.take() {
                    let _ = reply.send(Err(Error::engine(
                        "retained working disposition unavailable; full custody retained",
                    )));
                }
                actor::park(&shared).await;
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
                    unreachable!("retained working owner cannot resume");
                }
            }};
        }
        // Retry-mode native handlers reauthorize current home/grant/context and
        // UUID proof. Their entire phase rolls back, including receipt upkeep.
        let mut auth =
            match super::super::transaction::construct_pinned_transaction(&mut connection).await {
                Ok(tx) => tx,
                Err(_) => {
                    if let Some(reply) = self.ready.take() {
                        let _ = reply.send(Err(Error::engine(
                            "working BEGIN disposition unavailable; custody retained",
                        )));
                    }
                    actor::park(&shared).await;
                    return;
                }
            };
        let authorization = std::panic::AssertUnwindSafe(async {
            for original in fence
                .view()
                .proposals()
                .iter()
                .take(usize::try_from(published.original_prefix).map_err(|_| paused())?)
            {
                if published
                    .recovery_dispositions
                    .iter()
                    .any(|draft| draft.proposal_id == original.id())
                {
                    continue;
                }
                replay_ticket(
                    &mut auth,
                    &shared,
                    &caller,
                    original,
                    true,
                    replay::WorkingReplayOwner {
                        schema: &native_schema,
                        collector: &collector,
                    },
                )
                .await?;
            }
            Ok::<_, Error>(())
        })
        .catch_unwind()
        .await;
        if !matches!(authorization, Ok(Ok(()))) {
            retain_transaction!(auth);
        }
        if crate::Db::rollback_owned_kernel_connection(&mut auth)
            .await
            .is_err()
        {
            retain_transaction!(auth);
        }
        drop(auth);
        let mut adopted = published.clone();
        adopted.source_generation = shared.base.source_generation.clone();
        adopted.publication.journal_revision = match usize::try_from(published.original_prefix)
            .ok()
            .and_then(|n| fence.view().prefix_revision(n).ok())
        {
            Some(revision) => revision,
            None => {
                actor::park(&shared).await;
                return;
            }
        };
        if adopted != published {
            adopted.publication.publication = match published.publication.publication.checked_add(1)
            {
                Some(n) => n,
                None => {
                    super::actor::park(&shared).await;
                    return;
                }
            };
            let mut tx = match super::super::transaction::construct_pinned_transaction(
                &mut connection,
            )
            .await
            {
                Ok(tx) => tx,
                Err(_) => {
                    super::actor::park(&shared).await;
                    return;
                }
            };
            let written = std::panic::AssertUnwindSafe(actor::write_publication(
                &mut tx, &published, &adopted,
            ))
            .catch_unwind()
            .await;
            if !matches!(written, Ok(Ok(()))) {
                retain_transaction!(tx);
            }
            let committed =
                std::panic::AssertUnwindSafe(reader.commit_owned_kernel_connection(&mut tx, None))
                    .catch_unwind()
                    .await;
            if !matches!(committed, Ok(crate::db::KernelCommitOutcome::Committed)) {
                retain_transaction!(tx);
            }
            drop(tx);
            published = adopted;
        }
        let installed = std::panic::AssertUnwindSafe(actor::pin_install(
            &shared,
            &caller,
            &published,
            PublicationReadiness::Ready,
        ))
        .catch_unwind()
        .await;
        if !matches!(installed, Ok(Ok(()))) {
            if let Some(reply) = self.ready.take() {
                let _ = reply.send(Err(Error::engine(
                    "working recovered publication unavailable; full custody retained",
                )));
            }
            actor::park(&shared).await;
            return;
        }
        drop(fence);
        if let Some(reply) = self.ready.take() {
            let _ = reply.send(Ok(shared.clone()));
        }
        Commands {
            caller,
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
    async fn audit(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        source: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        collector: &Collector,
    ) -> Result<(PublicationBase, WorkingKernelSchema)> {
        self.file.check()?;
        self.request.guard.check()?;
        self.request.base.check_file()?;
        self.request.base.check_native_on(source).await?;
        let actor = crate::mcp::kernel_v2::principal_on(source, &self.request.caller).await?;
        if actor != self.request.base.principal
            || crate::mcp::kernel_v2::principal_on(tx, &self.request.caller).await? != actor
        {
            return Err(Error::engine("retained working owner mismatch"));
        }
        let encoded: String = sqlx::query_scalar(
            "SELECT state FROM main._native_working_publication WHERE singleton=1",
        )
        .fetch_one(&mut **tx)
        .await?;
        let publication: WorkingPublication = serde_json::from_str(&encoded)?;
        let base_json: String =
            sqlx::query_scalar("SELECT state FROM main._native_working_bases WHERE publication=?")
                .bind(publication.publication)
                .fetch_one(&mut **tx)
                .await?;
        let published: PublicationBase = serde_json::from_str(&base_json)?;
        published.validate()?;
        if published.publication != publication
            || publication.generation != self.request.location.generation
            || publication.binding != self.request.base.binding
            || published.principal != actor
            || published.native != self.request.base.native
            || published.origin != self.request.base.origin
        {
            return Err(Error::engine(
                "retained accepted cut differs from current verified source; full W retained",
            ));
        }
        let initial_json: String =
            sqlx::query_scalar("SELECT state FROM main._native_working_bases WHERE publication=0")
                .fetch_one(&mut **tx)
                .await?;
        let initial: PublicationBase = serde_json::from_str(&initial_json)?;
        initial.validate()?;
        if initial.read_binding().anchor_bytes()? != self.request.journal.anchor_bytes()?
            || initial.publication.binding != publication.binding
            || initial.principal != actor
            || initial.publication.generation != publication.generation
            || initial.origin != published.origin
            || initial.genesis != published.genesis
        {
            return Err(Error::engine("retained original anchor differs"));
        }
        // Inventory admission is valid with the retained tail still present;
        // content grounding remains the later undo/compare/rollback proof.
        let verified = WorkingKernelSchema::from_fresh_native(source).await?;
        let schema = WorkingKernelSchema::from_retained_native(&verified, tx, collector).await?;
        let owner = replay::WorkingReplayOwner {
            schema: &schema,
            collector,
        };
        actor::audit_on(tx, &published, &self.request.fence, owner).await?;
        let prefix = usize::try_from(published.original_prefix).map_err(|_| paused())?;
        let proposals = self.request.fence.view().proposals();
        let suffix = proposals.get(prefix..).ok_or_else(paused)?;
        if suffix.len() > 1 {
            return Err(paused());
        }
        if let Some(ticket) = suffix.first() {
            let outcome = self
                .request
                .fence
                .view()
                .outcome(ticket.id())
                .ok_or_else(paused)?;
            if !actor::unpublished_suffix_is_unapplied(
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
        let markers: Vec<String> = sqlx::query_scalar(
            "SELECT proposal_id FROM main._native_working_applied ORDER BY original_ordinal",
        )
        .fetch_all(&mut **tx)
        .await?;
        let boundaries: Vec<String> = sqlx::query_scalar(
            "SELECT proposal FROM main.working_undo_boundaries ORDER BY first_seq",
        )
        .fetch_all(&mut **tx)
        .await?;
        let available: bool = sqlx::query_scalar(
            "SELECT enabled=0 AND available=1 FROM main.working_undo_control WHERE singleton=1",
        )
        .fetch_one(&mut **tx)
        .await?;
        if markers != boundaries || !available {
            return Err(Error::engine("retained undo coverage differs"));
        }
        if let Some(first) = markers.first() {
            with_handle(tx, |raw| {
                collector
                    .undo(raw, first)
                    .map_err(|e| Error::engine(e.to_string()))
            })
            .await?;
        }
        schema
            .same_native_contents_on(tx, source, collector)
            .await?;
        if kernel_v2::origin(tx, &published.native).await? != published.origin {
            return Err(Error::engine("retained native origin differs"));
        }
        for original in proposals.iter().take(prefix) {
            if published
                .recovery_dispositions
                .iter()
                .any(|draft| draft.proposal_id == original.id())
            {
                continue;
            }
            let outcome = self
                .request
                .fence
                .view()
                .outcome(original.id())
                .ok_or_else(paused)?;
            if matches!(
                outcome.answer(),
                crate::node::working_v2::WorkingCanonicalAnswer::Refused
                    | crate::node::working_v2::WorkingCanonicalAnswer::Unsupported
            ) {
                return Err(Error::engine(
                    "retained canonical outcome requires recovery; full W retained",
                ));
            }
            let materialized = materialized_on(tx, original, &published, owner).await?;
            if markers.iter().any(|id| id == original.id()) {
                if materialized {
                    return Err(Error::engine(
                        "retained speculative marker already materialized at accepted cut",
                    ));
                }
                if outcome.answer() != crate::node::working_v2::WorkingCanonicalAnswer::Pending {
                    return Err(paused());
                }
            } else if !materialized {
                return Err(Error::engine(
                    "retained original lacks grounded native effect",
                ));
            }
        }
        self.file.check()?;
        self.request.guard.check()?;
        Ok((published, schema))
    }
}
fn working_registry() -> Result<crate::mcp::ToolRegistry> {
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry)?;
    crate::mcp::register_surface_tools(&mut registry)?;
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry)?;
    Ok(registry)
}
