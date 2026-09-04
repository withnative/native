//! Backup storage primitives for the public node.
//!
//! The public backup product owns the sink contract and its filesystem
//! implementation, free of backup-r2 and cloud SDK dependencies. Catalog-driven
//! sweep policy and hosted scheduling remain in the hosting layer.

use std::path::{Path, PathBuf};

use futures::future::BoxFuture;

use crate::error::{Error, Result};

/// Somewhere backup artifacts are put that is not the volume we are protecting.
///
/// Object-storage shaped on purpose — flat keys, no rename, no directory
/// semantics — so an implementation over S3/R2 is a thin wrapper rather than a
/// filesystem emulation. Arguments are owned to keep the returned futures
/// `'static`-friendly for callers that spawn them; the allocation is noise next
/// to moving a database.
pub trait BackupSink: Send + Sync + std::fmt::Debug {
    /// Upload `source`'s bytes under `key`, replacing anything already there.
    fn put(&self, key: String, source: PathBuf) -> BoxFuture<'_, Result<()>>;

    /// Download `key` to `dest`, creating or truncating it.
    fn get(&self, key: String, dest: PathBuf) -> BoxFuture<'_, Result<()>>;

    /// Every key beginning with `prefix`, in arbitrary order.
    fn list(&self, prefix: String) -> BoxFuture<'_, Result<Vec<String>>>;

    /// Remove `key`. Deleting an absent key succeeds — pruning races with
    /// nothing here, but an idempotent delete makes retry safe.
    fn delete(&self, key: String) -> BoxFuture<'_, Result<()>>;
}

/// A [`BackupSink`] over a local directory.
///
/// Real off-box use points this at a mounted volume or a sidecar; its main jobs
/// are being the sink the test suite exercises the whole sweep against, and
/// keeping the sweep machinery honest about the object-storage shape — it is
/// implemented with flat keys and no directory semantics leaking out.
///
/// Pointing this *at the data dir it is backing up* would be pointless (the
/// single point of failure is the volume, not the file), so don't.
#[derive(Debug, Clone)]
pub struct FsSink {
    root: PathBuf,
}

impl FsSink {
    pub fn new(root: impl Into<PathBuf>) -> FsSink {
        FsSink { root: root.into() }
    }

    /// Build a sink over `root`, refusing a directory inside `data_dir`.
    ///
    /// The single point of failure this whole module exists to survive is the
    /// *volume*, not the file — so a "backup" written onto the volume it is
    /// backing up is not one, and it fails in exactly the moment nobody can
    /// afford it to. Both binaries that read a sink location from the
    /// environment go through here, so neither can be the one that forgets.
    pub fn outside(root: impl Into<PathBuf>, data_dir: &Path) -> Result<FsSink> {
        let root = root.into();
        if std::path::absolute(&root)?.starts_with(std::path::absolute(data_dir)?) {
            return Err(Error::engine(
                "BACKUP_LOCAL_DIR is inside the data dir — a backup on the volume it protects is not a backup",
            ));
        }
        Ok(FsSink::new(root))
    }

    /// Resolve a key to a path under the root.
    ///
    /// Keys are generated internally from UUIDs and timestamps, so traversal
    /// is not a live threat — but a sink is the kind of component that later
    /// grows a user-supplied key, and a rejected `..` costs nothing now.
    fn path_for(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty()
            || key.starts_with('/')
            || key.split('/').any(|part| part == ".." || part == ".")
        {
            return Err(Error::engine(format!("unsafe backup key: {key}")));
        }
        Ok(self.root.join(key))
    }

    /// Walk `dir`, pushing every file's key (its path relative to the root).
    ///
    /// Synchronous, like everything else below `path_for` — this is only ever
    /// called from inside a [`run_blocking`] closure, never directly from
    /// async code.
    fn collect(&self, dir: &Path, out: &mut Vec<String>) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                self.collect(&path, out)?;
            } else if let Ok(relative) = path.strip_prefix(&self.root) {
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }

    /// The synchronous body of [`BackupSink::put`]. See [`run_blocking`] for
    /// why this is a separate, non-`async` method.
    fn put_blocking(&self, key: &str, source: &Path) -> Result<()> {
        let target = self.path_for(key)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write beside the target and rename: a reader (or a crashed
        // upload) must never see a half-written generation that retention
        // would then count as a good one.
        let staging = target.with_extension("partial");
        std::fs::copy(source, &staging)?;
        std::fs::rename(&staging, &target)?;
        Ok(())
    }

    /// The synchronous body of [`BackupSink::get`].
    fn get_blocking(&self, key: &str, dest: &Path) -> Result<()> {
        let source = self.path_for(key)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&source, dest)?;
        Ok(())
    }

    /// The synchronous body of [`BackupSink::list`].
    fn list_blocking(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        // Walk from the root and filter: keys are flat strings, so a
        // prefix need not land on a directory boundary.
        self.collect(&self.root.clone(), &mut keys)?;
        keys.retain(|key| key.starts_with(prefix) && !key.ends_with(".partial"));
        Ok(keys)
    }

    /// The synchronous body of [`BackupSink::delete`].
    fn delete_blocking(&self, key: &str) -> Result<()> {
        let target = self.path_for(key)?;
        match std::fs::remove_file(&target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

/// Run a synchronous closure on the blocking thread pool, flattening a task
/// panic into the crate's error type so every [`FsSink`] method has one
/// `Result` to return rather than a nested `JoinError`.
///
/// This is the shape task 75132ee asked for: `FsSink`'s bodies are synchronous
/// `std::fs` calls moving whole files (a copy is the actual database), so one
/// `spawn_blocking` per call is the fit — not `tokio::fs`, which is this same
/// primitive under the hood, called once per small operation instead of once
/// around the whole body.
async fn run_blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| Error::engine(format!("backup sink: blocking task panicked: {err}")))?
}

impl BackupSink for FsSink {
    fn put(&self, key: String, source: PathBuf) -> BoxFuture<'_, Result<()>> {
        let sink = self.clone();
        Box::pin(run_blocking(move || sink.put_blocking(&key, &source)))
    }

    fn get(&self, key: String, dest: PathBuf) -> BoxFuture<'_, Result<()>> {
        let sink = self.clone();
        Box::pin(run_blocking(move || sink.get_blocking(&key, &dest)))
    }

    fn list(&self, prefix: String) -> BoxFuture<'_, Result<Vec<String>>> {
        let sink = self.clone();
        Box::pin(run_blocking(move || sink.list_blocking(&prefix)))
    }

    fn delete(&self, key: String) -> BoxFuture<'_, Result<()>> {
        let sink = self.clone();
        Box::pin(run_blocking(move || sink.delete_blocking(&key)))
    }
}
