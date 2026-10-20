//! Process-local status observations, never authority for serving or deletion.
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type CacheEntries = HashMap<(String, Vec<u8>), CachedVerification>;

#[derive(Clone, Debug, Default)]
pub(super) struct VerificationStatusCache(Arc<Mutex<CacheEntries>>);

#[derive(Clone, Debug)]
struct CachedVerification {
    stamp: StatusStamp,
    verdict: VerificationVerdict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationVerdict {
    DeviceChecked,
    VerifiedAndAdvanced,
    Invalid,
}

/// A matching, completed device observation held across one controlled refresh.
/// Status may invalidate the live entry while the writer is changing bytes;
/// only successful authenticated apply may consume this token afterwards.
pub(in crate::standby) struct VerifiedRefreshBase(CachedVerification);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StatusStamp {
    // Snapshot, manifest, unused pointer slot, journal, consumer receipt.
    files: Vec<Option<FileStamp>>,
    pointer: Option<FileStamp>,
    head: Option<GenerationHead>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: std::time::SystemTime,
    readonly: bool,
    #[cfg(unix)]
    unix: (u64, u64, u32, i64, i64),
}

fn file_stamp(path: &Path) -> Result<Option<FileStamp>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::engine("standby status input is not a regular file"));
    }
    Ok(Some(FileStamp {
        len: metadata.len(),
        modified: metadata.modified()?,
        readonly: metadata.permissions().readonly(),
        #[cfg(unix)]
        unix: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
    }))
}

impl GenerationStore {
    pub(super) fn status_stamp(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<StatusStamp> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let directory = self.root.join("generations").join(id);
        let mut files = [
            directory.join("snapshot.db"),
            directory.join("manifest.json"),
            self.root.join("current.json"),
            directory.join("snapshot.db-journal"),
            self.rebind_path(id, observed),
        ]
        .iter()
        .enumerate()
        .map(|(index, path)| {
            if index == 2 {
                Ok(None)
            } else {
                file_stamp(path)
            }
        })
        .collect::<Result<Vec<_>>>()?;
        let pointer = if self
            .read_pointer()
            .ok()
            .is_some_and(|pointer| pointer.generation_id == id)
        {
            file_stamp(&self.root.join("current.json"))?
        } else {
            files[2] = None;
            None
        };
        let mut head = self.generation_head(id)?;
        // A successful no-change hosted probe updates freshness, not database
        // validity. Other head changes (including audit failure) invalidate.
        if let Some(head) = &mut head {
            head.synced_at.clear();
        }
        Ok(StatusStamp {
            files,
            pointer,
            head,
        })
    }

    /// Only remember a completed observation. A concurrent database/head or
    /// pointer change prevents issuance. A rebind may intentionally create its
    /// own receipt during this check, so compare the other inputs separately.
    pub(super) fn verification_inputs_unchanged(
        &self,
        before: Option<StatusStamp>,
        after: &StatusStamp,
    ) -> bool {
        let Some(mut before) = before else {
            return false;
        };
        before.files[4] = after.files[4].clone();
        before == *after
    }

    pub(super) fn remember_verification(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        before: Option<StatusStamp>,
        passed: bool,
    ) {
        let Ok(after) = self.status_stamp(id, observed) else {
            return;
        };
        let Some(mut before) = before else { return };
        if passed {
            before.files[4] = after.files[4].clone();
        }
        if before != after {
            return;
        }
        self.cache_verification(id, observed, after, passed);
    }

    pub(super) fn cache_completed_verification(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        passed: bool,
    ) {
        if let Ok(stamp) = self.status_stamp(id, observed) {
            // Admission checked immutable checkpoint bytes. A cooperating
            // refresh may already have started a delta after publication;
            // never attach that checkpoint verdict to its mutable successor.
            if passed
                && stamp
                    .head
                    .as_ref()
                    .is_some_and(|head| head.advanced_in_place() || head.full_refresh_required)
            {
                return;
            }
            self.cache_verification(id, observed, stamp, passed);
        }
    }

    fn cache_verification(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        stamp: StatusStamp,
        passed: bool,
    ) {
        let Ok(consumer) = serde_jcs::to_vec(observed) else {
            return;
        };
        if let Ok(mut entries) = self.verification_status.0.lock() {
            let verdict = if !passed {
                VerificationVerdict::Invalid
            } else if stamp
                .head
                .as_ref()
                .is_some_and(GenerationHead::advanced_in_place)
            {
                VerificationVerdict::VerifiedAndAdvanced
            } else {
                VerificationVerdict::DeviceChecked
            };
            entries.insert((id.into(), consumer), CachedVerification { stamp, verdict });
        }
    }

    /// Our pointer publication changes only the descriptor. Preserve an
    /// observation only if all the other inputs still match its checked state.
    pub(super) fn refresh_cached_pointer(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) {
        let Ok(stamp) = self.status_stamp(id, observed) else {
            return;
        };
        let Ok(consumer) = serde_jcs::to_vec(observed) else {
            return;
        };
        if let Ok(mut entries) = self.verification_status.0.lock() {
            if let Some(entry) = entries.get_mut(&(id.into(), consumer)) {
                let mut previous = entry.stamp.clone();
                previous.pointer = stamp.pointer.clone();
                if previous == stamp {
                    entry.stamp = stamp;
                }
            }
        }
    }

    pub(in crate::standby) fn verified_refresh_base(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Option<VerifiedRefreshBase> {
        if self.cached_verification(id, observed) != Some(true) {
            return None;
        }
        let key = (id.into(), serde_jcs::to_vec(observed).ok()?);
        let entry = {
            let entries = self.verification_status.0.lock().ok()?;
            entries.get(&key)?.clone()
        };
        if entry.verdict == VerificationVerdict::Invalid
            || self.status_stamp(id, observed).ok().as_ref() != Some(&entry.stamp)
        {
            return None;
        }
        Some(VerifiedRefreshBase(entry))
    }

    /// The refresher holds its cross-process attempt lock across base capture,
    /// validated apply, writer close, head publication and this completion.
    /// This is advancement of an existing device verdict, not a new checkpoint
    /// check. A changed descriptor/binding or audit flag refuses the update.
    pub(in crate::standby) fn complete_validated_refresh(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        base: Option<VerifiedRefreshBase>,
        head_act: i64,
        advanced: bool,
    ) {
        let Some(VerifiedRefreshBase(base)) = base else {
            return;
        };
        let Ok(after) = self.status_stamp(id, observed) else {
            return;
        };
        let Some(head) = after.head.as_ref() else {
            return;
        };
        if head.head_act != head_act
            || head.full_refresh_required
            || (advanced && !head.advanced_in_place())
            || base.stamp.pointer != after.pointer
            || after.pointer.is_none()
            || base.stamp.files[1..] != after.files[1..]
            || after.files[3].is_some()
        {
            return;
        }
        if advanced {
            // Deltas may change bytes, size and write permissions, never the
            // pathname's underlying file. All other inputs remain pinned.
            let (Some(before), Some(current)) = (&base.stamp.files[0], &after.files[0]) else {
                return;
            };
            #[cfg(unix)]
            if before.unix.0 != current.unix.0 || before.unix.1 != current.unix.1 {
                return;
            }
        } else if base.stamp.files[0] != after.files[0] {
            return;
        }
        let Ok(consumer) = serde_jcs::to_vec(observed) else {
            return;
        };
        if let Ok(mut entries) = self.verification_status.0.lock() {
            entries.insert(
                (id.into(), consumer),
                CachedVerification {
                    stamp: after,
                    verdict: if advanced {
                        VerificationVerdict::VerifiedAndAdvanced
                    } else {
                        base.verdict
                    },
                },
            );
        }
    }

    pub(super) fn invalidate_verification(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) {
        if let (Ok(key), Ok(mut entries)) = (
            serde_jcs::to_vec(observed),
            self.verification_status.0.lock(),
        ) {
            entries.remove(&(id.into(), key));
        }
    }

    /// Metadata detects ordinary changes, not adversarial owner tampering. It
    /// is deliberately not a byte proof and is never consumed by activation,
    /// admission, fallback, successor fencing or retention.
    pub(super) fn cached_verification(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Option<bool> {
        let stamp = self.status_stamp(id, observed).ok()?;
        let consumer = serde_jcs::to_vec(observed).ok()?;
        let key = (id.into(), consumer);
        let mut entries = self.verification_status.0.lock().ok()?;
        let entry = entries.get_mut(&key)?;
        // Once demoted, a prior is independent of later pointer rewrites.
        if stamp.pointer.is_none() {
            entry.stamp.pointer = None;
        }
        if entry.stamp != stamp {
            entries.remove(&key);
            return None;
        }
        Some(entry.verdict != VerificationVerdict::Invalid)
    }
}
