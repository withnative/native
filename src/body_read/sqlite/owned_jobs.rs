//! Strong retained custody under the existing Process's two semaphore slots.
//! No queue, connection pool, authority constructor or error-as-ACK path.
use super::*;
use futures::future::Shared;
use std::sync::{Mutex, OnceLock};

type Runner = Shared<BoxFuture<'static, bool>>;
#[cfg(any(test, feature = "body-read-test-support"))]
type RegistrationWatcher = (uuid::Uuid, tokio::sync::oneshot::Sender<Arc<Job>>);
#[derive(Default)]
pub(in crate::body_read) struct Registry {
    entries: Mutex<Vec<Arc<Job>>>,
    #[cfg(any(test, feature = "body-read-test-support"))]
    registrations: Mutex<Vec<RegistrationWatcher>>,
}
struct Job {
    pub(super) resources: Arc<tokio::sync::Mutex<Resources>>,
    ack_owner: Arc<()>,
    runner: OnceLock<Runner>,
    #[cfg(any(test, feature = "body-read-test-support"))]
    runner_ready: tokio::sync::Notify,
}
pub(super) struct PreparedJob(Arc<Job>);
#[cfg(any(test, feature = "body-read-test-support"))]
pub(in crate::body_read) struct TerminalObservation(Vec<Arc<Job>>);
#[cfg(any(test, feature = "body-read-test-support"))]
pub(in crate::body_read) struct RegistrationObservation(tokio::sync::oneshot::Receiver<Arc<Job>>);
#[cfg(any(test, feature = "body-read-test-support"))]
impl RegistrationObservation {
    pub(in crate::body_read) async fn registered(self) -> Option<TerminalObservation> {
        self.0.await.ok().map(|job| TerminalObservation(vec![job]))
    }
}
#[cfg(any(test, feature = "body-read-test-support"))]
impl TerminalObservation {
    pub(in crate::body_read) fn len(&self) -> usize {
        self.0.len()
    }
    pub(in crate::body_read) async fn wait(self) -> bool {
        let mut complete = true;
        for job in self.0 {
            let runner = loop {
                let ready = job.runner_ready.notified();
                tokio::pin!(ready);
                ready.as_mut().enable();
                if let Some(runner) = job.runner.get().cloned() {
                    break runner;
                }
                ready.await;
            };
            complete &= matches!(
                std::panic::AssertUnwindSafe(runner).catch_unwind().await,
                Ok(true)
            );
        }
        complete
    }
}
impl PreparedJob {
    pub(super) fn resources(&self) -> Arc<tokio::sync::Mutex<Resources>> {
        self.0.resources.clone()
    }
}
impl Registry {
    #[cfg(any(test, feature = "body-read-test-support"))]
    pub(in crate::body_read) fn observe_registration(&self, db: &Db) -> RegistrationObservation {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut observers = self.registrations.lock().unwrap_or_else(|e| e.into_inner());
        observers.retain(|(_, sender)| !sender.is_closed());
        observers.push((db.handle_id(), sender));
        RegistrationObservation(receiver)
    }
    #[cfg(any(test, feature = "body-read-test-support"))]
    pub(in crate::body_read) fn observe_terminal(&self) -> TerminalObservation {
        TerminalObservation(
            self.entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        )
    }
    pub(super) fn retain(self: &Arc<Self>, resources: Resources) -> PreparedJob {
        #[cfg(any(test, feature = "body-read-test-support"))]
        let handle = resources.db.as_ref().map(Db::handle_id);
        // The permit is already owned. Every live entry retains that same
        // permit; Process has exactly two, so this is not another capacity.
        let job = Arc::new(Job {
            ack_owner: resources.ack_owner.clone(),
            resources: Arc::new(tokio::sync::Mutex::new(resources)),
            runner: OnceLock::new(),
            #[cfg(any(test, feature = "body-read-test-support"))]
            runner_ready: tokio::sync::Notify::new(),
        });
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(job.clone());
        #[cfg(any(test, feature = "body-read-test-support"))]
        {
            let mut observers = self.registrations.lock().unwrap_or_else(|e| e.into_inner());
            for (selected, sender) in std::mem::take(&mut *observers) {
                if sender.is_closed() {
                    continue;
                }
                if Some(selected) == handle {
                    let _ = sender.send(job.clone());
                } else {
                    observers.push((selected, sender));
                }
            }
        }
        PreparedJob(job)
    }
    pub(super) fn complete(&self, ack: &PhysicalAck) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|job| !Arc::ptr_eq(&job.ack_owner, &ack.0));
    }
    pub(super) fn start(self: &Arc<Self>, prepared: PreparedJob, runner: BoxFuture<'static, bool>) {
        let job = prepared.0;
        // Only the creator receives Job; install ONCE before any first poll.
        job.runner.get_or_init(|| runner.shared());
        #[cfg(any(test, feature = "body-read-test-support"))]
        job.runner_ready.notify_waiters();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(self.drive(job));
        } // no runtime: retained unresolved custody, never ACK
    }
    fn drive(self: &Arc<Self>, job: Arc<Job>) -> BoxFuture<'static, ()> {
        let registry = self.clone();
        async move {
            let mut lifetime = PollerLifetime {
                registry: registry.clone(),
                job: job.clone(),
                terminal: false,
            };
            let runner = job.runner.get().cloned();
            let result = match runner {
                Some(runner) => std::panic::AssertUnwindSafe(runner).catch_unwind().await,
                None => {
                    lifetime.terminal = true;
                    return;
                }
            };
            // Panic/false retains resources/admissions/slot permanently. A
            // poisoned Shared runner must NOT be automatically polled again.
            lifetime.terminal = true;
            if matches!(result, Ok(true)) {
                registry
                    .entries
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|entry| !Arc::ptr_eq(entry, &job));
            }
        }
        .boxed()
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        // Production Process owns this forever. Isolated test-owner loss is
        // equally incapable of proving ACK or dropping residual admissions.
        for entry in self
            .entries
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            std::mem::forget(entry);
        }
    }
}
struct PollerLifetime {
    registry: Arc<Registry>,
    job: Arc<Job>,
    terminal: bool,
}
impl Drop for PollerLifetime {
    fn drop(&mut self) {
        if !self.terminal {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                // Resume the SAME retained future, including its pending raw
                // startup/close and borrowed resources; never reconstruct it.
                runtime.spawn(self.registry.drive(self.job.clone()));
            }
        }
    }
}
