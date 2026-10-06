//! Process-local configuration leases for the records executable only.
//! Keep the lease until the final render, refresh, verification and assertion.
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

fn restore_common_configuration() {
    native_ce::artifact_html::configure(
        native_ce::artifact_html::RuntimeConfig::new(
            "https://workbench.test",
            "https://artifacts.test",
        )
        .unwrap(),
    );
    native_ce::artifact_verify::configure(None);
    native_ce::mcp::mdx_verification::configure(None);
}

pub struct Boundary {
    lock: Arc<RwLock<()>>,
}

impl Boundary {
    fn new() -> Self {
        Self {
            lock: Arc::new(RwLock::new(())),
        }
    }

    /// An independent admission boundary for deterministic overlap controls.
    /// It does not configure globals. The control must also hold the shared
    /// runtime lease, so unrelated libtest writers cannot change its renders.
    pub fn isolated_for_overlap_control() -> Self {
        Self::new()
    }

    pub async fn reader(&self) -> OwnedRwLockReadGuard<()> {
        Arc::clone(&self.lock).read_owned().await
    }

    pub fn try_reader(&self) -> Option<OwnedRwLockReadGuard<()>> {
        Arc::clone(&self.lock).try_read_owned().ok()
    }

    fn try_writer(&self) -> Option<Writer> {
        Arc::clone(&self.lock)
            .try_write_owned()
            .ok()
            .map(|lease| Writer { _lease: lease })
    }
}

fn boundary() -> &'static Boundary {
    static BOUNDARY: OnceLock<Boundary> = OnceLock::new();
    BOUNDARY.get_or_init(|| {
        restore_common_configuration();
        Boundary::new()
    })
}

pub async fn reader() -> OwnedRwLockReadGuard<()> {
    boundary().reader().await
}

pub fn try_reader() -> Option<OwnedRwLockReadGuard<()>> {
    boundary().try_reader()
}

pub fn try_writer() -> Option<Writer> {
    boundary().try_writer()
}

/// Only tests which intentionally change configuration take this lease.
/// Restore the compatible baseline while the exclusive lease is still held,
/// including unwinding after an assertion failure.
pub struct Writer {
    _lease: OwnedRwLockWriteGuard<()>,
}

pub async fn writer() -> Writer {
    Writer {
        _lease: Arc::clone(&boundary().lock).write_owned().await,
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        restore_common_configuration();
    }
}
