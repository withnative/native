//! Controlled range futures exercise the production coordinator, including
//! dropping in-flight reads. They never write download bytes or the ledger.

use super::*;
use std::collections::HashMap;
use tokio::sync::{mpsc, Semaphore};

const CHUNK: usize = 1024 * 1024;
const RANGE_COUNT: usize = 7;

#[derive(Debug)]
pub(super) struct StartedRange {
    pub(super) offset: u64,
    pub(super) bearer: String,
}

pub(super) struct RangeReadControl {
    gates: Vec<Semaphore>,
    faults: Mutex<HashMap<u64, RefreshFailureClass>>,
    started: mpsc::UnboundedSender<StartedRange>,
    active: AtomicUsize,
    peak: AtomicUsize,
    active_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
}

struct ActiveRead {
    control: Arc<RangeReadControl>,
    length: usize,
}

impl Drop for ActiveRead {
    fn drop(&mut self) {
        self.control.active.fetch_sub(1, Ordering::SeqCst);
        self.control
            .active_bytes
            .fetch_sub(self.length, Ordering::SeqCst);
    }
}

impl RangeReadControl {
    pub(super) fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<StartedRange>) {
        let (started, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                gates: (0..RANGE_COUNT).map(|_| Semaphore::new(0)).collect(),
                faults: Mutex::new(HashMap::new()),
                started,
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                active_bytes: AtomicUsize::new(0),
                peak_bytes: AtomicUsize::new(0),
            }),
            receiver,
        )
    }

    pub(super) fn read(
        self: Arc<Self>,
        offset: u64,
        bearer: String,
        bytes: Vec<u8>,
    ) -> BinaryReply<Vec<u8>> {
        Box::pin(async move {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let active_bytes =
                self.active_bytes.fetch_add(bytes.len(), Ordering::SeqCst) + bytes.len();
            let _active = ActiveRead {
                control: self.clone(),
                length: bytes.len(),
            };
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.peak_bytes.fetch_max(active_bytes, Ordering::SeqCst);
            self.started.send(StartedRange { offset, bearer }).unwrap();
            // Once released, a range's gate also permits its subsequent retries.
            let _permit = self.gates[offset as usize / CHUNK].acquire().await.unwrap();
            let fault = self.faults.lock().unwrap().get(&offset).copied();
            if let Some(class) = fault {
                return Err(AttemptError::new(
                    class,
                    "controlled range refusal",
                    Error::engine("controlled range refusal"),
                ));
            }
            Ok(bytes)
        })
    }

    pub(super) fn release(&self, chunk: usize) {
        self.gates[chunk].add_permits(1);
    }

    pub(super) fn assert_dropped(&self) {
        assert_eq!(
            self.active.load(Ordering::SeqCst),
            0,
            "no range future may survive the attempt"
        );
        assert_eq!(self.active_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(
            self.peak.load(Ordering::SeqCst),
            4,
            "four requests must actually overlap"
        );
        assert!(self.peak_bytes.load(Ordering::SeqCst) <= 4 * CHUNK);
    }
}

pub(super) async fn started(receiver: &mut mpsc::UnboundedReceiver<StartedRange>) -> StartedRange {
    tokio::time::timeout(Duration::from_secs(10), receiver.recv())
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn initial_four(
    receiver: &mut mpsc::UnboundedReceiver<StartedRange>,
    control: &RangeReadControl,
) {
    let mut offsets = Vec::new();
    for _ in 0..4 {
        offsets.push(started(receiver).await.offset);
    }
    offsets.sort_unstable();
    assert_eq!(
        offsets,
        vec![0, CHUNK as u64, 2 * CHUNK as u64, 3 * CHUNK as u64]
    );
    assert_eq!(control.active.load(Ordering::SeqCst), 4);
    assert_eq!(control.peak_bytes.load(Ordering::SeqCst), 4 * CHUNK);
    assert!(
        matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "no fifth request before a slot completes"
    );
}

async fn fixture() -> (crate::Db, SnapshotFixture) {
    let db = crate::create_database(":memory:").await.unwrap();
    let (_, mut manifest) = snapshot_fixture(&db).await;
    // Acquisition-only fixture: seven distinguishable ranges, without making
    // a large SQLite capture. Admission remains covered by the HTTP/store tests.
    let bytes: Vec<u8> = (0..6 * CHUNK + 17)
        .map(|index| (index / CHUNK) as u8)
        .collect();
    manifest.snapshot.size_bytes = bytes.len() as u64;
    manifest.snapshot.sha256 = hex::encode(Sha256::digest(&bytes));
    manifest.validate().unwrap();
    (db, (bytes, manifest))
}

fn saved_offsets(dir: &Path, binding: &binary_resume::ResumeBinding) -> Vec<u64> {
    let ledger = binary_resume::load_resume_ledger(dir, binding)
        .unwrap()
        .unwrap();
    assert_eq!(
        binary_resume::revalidate_cached_ranges(dir, &ledger).unwrap(),
        ledger
    );
    ledger.completed.iter().map(|range| range.offset).collect()
}

async fn resume_missing(
    directory: &tempfile::TempDir,
    fake: &Arc<ScriptedBinaryClient>,
    manifest: &StandbySnapshotManifest,
    bytes: &[u8],
    cached: &[usize],
) {
    let (control, mut receiver) = RangeReadControl::new();
    for chunk in 0..RANGE_COUNT {
        control.release(chunk);
    }
    *fake.range_control.lock().unwrap() = Some(control.clone());
    let controller =
        resume_test_controller(directory, manifest.origin_database_id.clone(), fake.clone());
    let polls_before = fake.polls.load(Ordering::SeqCst);
    let target = directory.path().join("resumed.db");
    controller
        .download_binary_only(
            "obsolete".into(),
            &target,
            binary::FreshCaptureBudget::Allowed,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(target).unwrap(), bytes);
    assert_eq!(
        fake.starts.load(Ordering::SeqCst),
        1,
        "reuse the same export after restart"
    );
    assert!(
        fake.polls.load(Ordering::SeqCst) > polls_before,
        "reauthorize even a retained capture"
    );
    let mut requested = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        requested.push(event.offset);
    }
    requested.sort_unstable();
    assert_eq!(
        requested,
        (0..RANGE_COUNT)
            .filter(|chunk| !cached.contains(chunk))
            .map(|chunk| (chunk * CHUNK) as u64)
            .collect::<Vec<_>>()
    );
    assert_eq!(control.active.load(Ordering::SeqCst), 0);
    assert!(control.peak.load(Ordering::SeqCst) <= 4);
}

#[tokio::test]
async fn overlapping_out_of_order_ranges_abort_and_resume_only_missing() {
    let (db, (bytes, manifest)) = fixture().await;
    let directory = tempfile::tempdir().unwrap();
    let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
        bytes.clone(),
        manifest.clone(),
    ));
    let (control, mut receiver) = RangeReadControl::new();
    *fake.range_control.lock().unwrap() = Some(control.clone());
    let controller = resume_test_controller(
        &directory,
        manifest.origin_database_id.clone(),
        fake.clone(),
    );
    let dir = controller.refresh_dir.clone();
    let binding = controller.resume_binding();
    let target = directory.path().join("aborted.db");
    let task = tokio::spawn(async move {
        controller
            .download_binary_only(
                "secret".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
    });
    initial_four(&mut receiver, &control).await;
    control.release(2);
    assert_eq!(started(&mut receiver).await.offset, 4 * CHUNK as u64);
    assert_eq!(saved_offsets(&dir, &binding), vec![2 * CHUNK as u64]);
    control.release(0);
    assert_eq!(started(&mut receiver).await.offset, 5 * CHUNK as u64);
    assert_eq!(saved_offsets(&dir, &binding), vec![0, 2 * CHUNK as u64]);
    control.release(4);
    assert_eq!(started(&mut receiver).await.offset, 6 * CHUNK as u64);
    assert_eq!(
        saved_offsets(&dir, &binding),
        vec![0, 2 * CHUNK as u64, 4 * CHUNK as u64]
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    control.assert_dropped();
    tokio::task::yield_now().await;
    assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
    resume_missing(&directory, &fake, &manifest, &bytes, &[0, 2, 4]).await;
    db.close().await;
}

#[tokio::test]
async fn exhausted_in_flight_transient_preserves_sorted_ledger_and_renews_retries() {
    let (db, (bytes, manifest)) = fixture().await;
    let directory = tempfile::tempdir().unwrap();
    let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
        bytes.clone(),
        manifest.clone(),
    ));
    let (control, mut receiver) = RangeReadControl::new();
    *fake.range_control.lock().unwrap() = Some(control.clone());
    let controller = resume_test_controller(
        &directory,
        manifest.origin_database_id.clone(),
        fake.clone(),
    );
    let dir = controller.refresh_dir.clone();
    let binding = controller.resume_binding();
    let credential = controller.config.credential_file.clone();
    let target = directory.path().join("interrupted.db");
    let task = tokio::spawn(async move {
        controller
            .download_binary_only(
                "secret".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
    });
    initial_four(&mut receiver, &control).await;
    control.release(2);
    assert_eq!(started(&mut receiver).await.offset, 4 * CHUNK as u64);
    assert_eq!(saved_offsets(&dir, &binding), vec![2 * CHUNK as u64]);
    fs::write(credential, b"rotated\n").unwrap();
    control
        .faults
        .lock()
        .unwrap()
        .insert(CHUNK as u64, RefreshFailureClass::Network);
    control.release(1);
    assert_eq!(
        task.await.unwrap().unwrap_err().class,
        RefreshFailureClass::Network
    );
    control.assert_dropped();
    let mut retries = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        retries.push(event);
    }
    assert_eq!(
        retries.len(),
        2,
        "exactly three attempts including the initial in-flight request"
    );
    assert!(retries
        .iter()
        .all(|event| event.offset == CHUNK as u64 && event.bearer == "rotated"));
    assert_eq!(saved_offsets(&dir, &binding), vec![2 * CHUNK as u64]);
    assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
    resume_missing(&directory, &fake, &manifest, &bytes, &[2]).await;
    db.close().await;
}

#[tokio::test]
async fn concurrent_auth_and_terminal_refusals_do_not_retry_or_capture() {
    let (db, (bytes, manifest)) = fixture().await;
    for (class, terminal) in [
        (RefreshFailureClass::Authentication, false),
        (RefreshFailureClass::Protocol, true),
        (RefreshFailureClass::DownloadIntegrity, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
            bytes.clone(),
            manifest.clone(),
        ));
        let (control, mut receiver) = RangeReadControl::new();
        *fake.range_control.lock().unwrap() = Some(control.clone());
        let controller = resume_test_controller(
            &directory,
            manifest.origin_database_id.clone(),
            fake.clone(),
        );
        let dir = controller.refresh_dir.clone();
        let binding = controller.resume_binding();
        let target = directory.path().join("refused.db");
        let task = tokio::spawn(async move {
            controller
                .download_binary_only(
                    "secret".into(),
                    &target,
                    binary::FreshCaptureBudget::Allowed,
                )
                .await
        });
        initial_four(&mut receiver, &control).await;
        control.release(2);
        assert_eq!(started(&mut receiver).await.offset, 4 * CHUNK as u64);
        assert_eq!(saved_offsets(&dir, &binding), vec![2 * CHUNK as u64]);
        control.faults.lock().unwrap().insert(CHUNK as u64, class);
        control.release(1);
        assert_eq!(task.await.unwrap().unwrap_err().class, class);
        control.assert_dropped();
        assert!(
            receiver.try_recv().is_err(),
            "no retry for auth/protocol/integrity"
        );
        assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
        if terminal {
            assert!(!dir.join("binary-resume.json").exists());
            assert!(!dir.join("binary-resume.partial.db").exists());
            tokio::time::timeout(Duration::from_secs(2), async {
                while fake.cancels.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(fake.cancels.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(saved_offsets(&dir, &binding), vec![2 * CHUNK as u64]);
            tokio::task::yield_now().await;
            assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
            resume_missing(&directory, &fake, &manifest, &bytes, &[2]).await;
        }
    }
    db.close().await;
}
