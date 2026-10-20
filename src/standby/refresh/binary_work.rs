//! Blocking transfer work retains the file lease even if its waiter is dropped.
use super::transfer_repr::{GzipDecodeExpectation, SnapshotTransfer};
use super::*;
use std::io::Read as _;

#[derive(Clone)]
pub(super) struct TransferLease(Arc<File>);

// Field order keeps returned output cleanup ahead of lock release when a
// canceled join drops its result without handing it back to the coordinator.
struct LeasedResult<T> {
    value: T,
    _lease: Arc<File>,
}

impl TransferLease {
    pub fn acquire(dir: &Path) -> std::result::Result<Self, AttemptError> {
        let file = open_private_lock(&dir.join("binary-work.lock")).map_err(local_io)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                AttemptError::new(
                    RefreshFailureClass::Throttled,
                    "standby transfer work is still completing",
                    Error::engine("standby transfer work is still completing"),
                )
            } else {
                local_io(error.into())
            }
        })?;
        match fs::remove_file(dir.join(DECODED_STAGE)) {
            Ok(()) => File::open(dir)
                .and_then(|file| file.sync_all())
                .map_err(|error| local_io(error.into()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(local_io(error.into())),
        }
        Ok(Self(Arc::new(file)))
    }

    pub async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> std::result::Result<T, AttemptError> + Send + 'static,
    ) -> std::result::Result<T, AttemptError> {
        let lease = self.0.clone();
        tokio::task::spawn_blocking(move || {
            // The job owns custody until it, its files and cleanup finish.
            // Dropping a timeout/abort waiter cannot release this file lock.
            LeasedResult {
                value: work(),
                _lease: lease,
            }
        })
        .await
        .map_err(|_| local_io(Error::engine("standby transfer worker failed")))?
        .value
    }
}

pub(super) const DECODED_STAGE: &str = "binary-decoded.stage.db";

/// A completed output is still owned until the coordinator hands it back.
/// Dropped join results and aborted waiters remove it after the worker ends.
#[derive(Debug)]
pub(super) struct OwnedSnapshot {
    path: PathBuf,
    file: Option<File>,
    cleanup: bool,
}

impl OwnedSnapshot {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(file),
            cleanup: true,
        }
    }

    pub fn release(mut self) {
        self.cleanup = false;
    }

    fn publish(mut self, dest: &Path) -> std::result::Result<Self, AttemptError> {
        match fs::symlink_metadata(dest) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(local_io(Error::engine(
                    "standby transfer output already exists",
                )))
            }
        }
        let file = self.file.as_ref().unwrap();
        binary_resume::verify_opened_private(&self.path, file).map_err(local_io)?;
        fs::rename(&self.path, dest).map_err(|error| local_io(error.into()))?;
        self.path = dest.into();
        binary_resume::verify_opened_private(&self.path, file).map_err(local_io)?;
        if let Some(parent) = dest.parent() {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|error| local_io(error.into()))?;
        }
        binary_resume::verify_opened_private(&self.path, file).map_err(local_io)?;
        Ok(self)
    }
}

impl Drop for OwnedSnapshot {
    fn drop(&mut self) {
        self.file.take();
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) fn complete_snapshot(
    dir: &Path,
    dest: &Path,
    ledger: &binary_resume::ResumeLedger,
) -> std::result::Result<OwnedSnapshot, AttemptError> {
    let source = binary_resume::prepare_partial_file(dir, ledger.range_size()).map_err(local_io)?;
    let stage = dir.join(DECODED_STAGE);
    let file = match ledger.transfer() {
        SnapshotTransfer::GzipV1 { .. } => {
            let encoded = ledger.encoded.as_ref().unwrap();
            transfer_repr::decode_gzip_snapshot(
                &source,
                &stage,
                &GzipDecodeExpectation {
                    encoded_size_bytes: encoded.size_bytes,
                    encoded_sha256: encoded.sha256.clone(),
                    decoded_size_bytes: ledger.size_bytes,
                    decoded_sha256: ledger.sha256.clone(),
                },
            )
            .map_err(|error| match error {
                Error::Io(_) => local_io(error),
                _ => integrity("standby gzip snapshot verification refused", error),
            })?
        }
        SnapshotTransfer::IdentityV1 => {
            let mut input =
                binary_resume::open_partial_for_read(dir, ledger.size_bytes).map_err(local_io)?;
            let file = transfer_repr::create_private_staged(&stage).map_err(local_io)?;
            let mut output = OwnedSnapshot::new(stage.clone(), file);
            let mut digest = Sha256::new();
            let mut written = 0;
            let mut buffer = [0_u8; 65536];
            loop {
                let count = input
                    .read(&mut buffer)
                    .map_err(|error| local_io(error.into()))?;
                if count == 0 {
                    break;
                }
                written += count as u64;
                if written > ledger.size_bytes {
                    return Err(integrity(
                        "standby binary snapshot size mismatch",
                        Error::engine("standby binary snapshot size mismatch"),
                    ));
                }
                digest.update(&buffer[..count]);
                output
                    .file
                    .as_mut()
                    .unwrap()
                    .write_all(&buffer[..count])
                    .map_err(|error| local_io(error.into()))?;
            }
            if written != ledger.size_bytes || hex::encode(digest.finalize()) != ledger.sha256 {
                return Err(integrity(
                    "standby binary snapshot digest mismatch",
                    Error::engine("standby binary snapshot digest mismatch"),
                ));
            }
            binary_resume::verify_opened_private(&source, &input).map_err(local_io)?;
            output
                .file
                .as_ref()
                .unwrap()
                .sync_all()
                .map_err(|error| local_io(error.into()))?;
            return output.publish(dest);
        }
    };
    OwnedSnapshot::new(stage, file).publish(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aborted_waiter_keeps_lease_until_worker_and_output_cleanup_finish() {
        let dir = tempfile::tempdir().unwrap();
        // Acquire reconciles only the fixed decoded stage; this distinct
        // output must be removed by the abandoned result's own cleanup.
        let stage = dir.path().join("owned-output.db");
        let lease = TransferLease::acquire(dir.path()).unwrap();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (resume, released) = std::sync::mpsc::channel();
        let worker_stage = stage.clone();
        let waiter = tokio::spawn(async move {
            lease
                .run(move || {
                    let file = transfer_repr::create_private_staged(&worker_stage).unwrap();
                    let output = OwnedSnapshot::new(worker_stage, file);
                    entered.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(20)).unwrap();
                    Ok(output)
                })
                .await
        });
        ready.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(stage.exists());
        let error = match TransferLease::acquire(dir.path()) {
            Ok(_) => panic!("worker lost its lease"),
            Err(error) => error,
        };
        assert_eq!(error.class, RefreshFailureClass::Throttled);
        resume.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(_lease) = TransferLease::acquire(dir.path()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!stage.exists());
    }
}
