//! Durable owner-local recovery, independent of journal retention.
//!
//! Dismissed payloads expire; their digest-only tombstones do not. Otherwise a
//! later retry could silently recreate an item the person already dismissed.
use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::sync::Mutex as StdMutex;

pub(super) const ITEM_VERSION: u32 = 2;
// Five complete texts, including worst-case JSON escaping, fit comfortably.
const MAX_ITEM_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecoveryKind {
    Clash,
    LocalClash,
    Refusal,
    KeyConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecoveryState {
    Open,
    Dismissed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Passage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) mine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) theirs: Option<String>,
    pub(super) base_start: usize,
    pub(super) base_end: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) at_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) at_end: Option<usize>,
    #[serde(default)]
    pub(super) theirs_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RecoveryItem {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) kind: RecoveryKind,
    pub(super) record_id: String,
    pub(super) journal_entry: String,
    pub(super) editor: String,
    pub(super) made_at: Option<u64>,
    pub(super) created_at: u64,
    pub(super) last_seen_at: u64,
    pub(super) state: RecoveryState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dismissed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) base_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) my_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) passage: Option<Passage>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Stored {
    // A distinct schema avoids retaining record/editor/reason private metadata.
    Tombstone {
        version: u32,
        id: String,
        dismissed_at: u64,
        payload_pruned: bool,
    },
    Item(Box<RecoveryItem>),
}

impl Stored {
    fn id(&self) -> &str {
        match self {
            Self::Item(item) => &item.id,
            Self::Tombstone { id, .. } => id,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct RecoveryCounts {
    pub(super) open: usize,
    pub(super) dismissed: usize,
    pub(super) tombstones: usize,
}

pub(super) fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

pub(super) fn text_digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn framed_id(parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

/// `theirs_digest` is `text_digest(theirs)`; an absent remote text must use
/// an explicit distinct sentinel (for example "unavailable").
pub(super) fn passage_id(
    record: &str,
    editor: &str,
    base: &str,
    mine: &str,
    theirs_digest: &str,
) -> String {
    framed_id(&["passage", record, editor, base, mine, theirs_digest])
}

/// Identical passages can occur at distinct locations in one prepared save.
/// Allocate in passage order, seeded with ids already owned by that save.
/// Repeating the same ordered allocation yields the same occurrence ids.
pub(super) fn next_passage_id(base_id: String, used: &mut BTreeSet<String>) -> String {
    if used.insert(base_id.clone()) {
        return base_id;
    }
    for ordinal in 1u64.. {
        let id = framed_id(&["passage-occurrence", &base_id, &ordinal.to_string()]);
        if used.insert(id.clone()) {
            return id;
        }
    }
    unreachable!("a recovery occurrence set cannot fill the u64 ordinal space")
}

pub(super) fn refusal_id(record: &str, editor: &str, entry: &str, kind: RecoveryKind) -> String {
    let kind = match kind {
        RecoveryKind::Clash => "clash",
        RecoveryKind::LocalClash => "local_clash",
        RecoveryKind::Refusal => "refusal",
        RecoveryKind::KeyConflict => "key_conflict",
    };
    framed_id(&["refusal", record, editor, entry, kind])
}

pub(super) struct RecoveryStore {
    directory: PathBuf,
    entries: StdMutex<BTreeMap<String, Stored>>,
    retention: Duration,
}

impl RecoveryStore {
    pub(super) fn open(socket_directory: &Path, retention: Duration) -> Result<Self> {
        Self::open_inner(socket_directory, retention, false)
    }

    /// Only for startup with a persisted account-erasure marker. The caller
    /// must validate/resume that marker before exposing any store operation.
    pub(super) fn open_for_pending_forget(
        socket_directory: &Path,
        retention: Duration,
    ) -> Result<Self> {
        Self::open_inner(socket_directory, retention, true)
    }

    fn open_inner(
        socket_directory: &Path,
        retention: Duration,
        pending_forget: bool,
    ) -> Result<Self> {
        let directory = socket_directory.join("unmerged");
        validate_credential_path(&directory, "node recovery directory")?;
        match fs::symlink_metadata(&directory) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(Error::engine("invalid node recovery directory"));
                }
                check_owned(&meta, 0o700)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                File::open(socket_directory)?.sync_all()?;
            }
            Err(e) => return Err(e.into()),
        }
        let store = Self {
            directory,
            entries: StdMutex::new(BTreeMap::new()),
            retention,
        };
        if !pending_forget {
            let entries = store.read_all()?;
            *store.entries.lock().expect("recovery entries") = entries;
            store.prune()?;
        }
        Ok(store)
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::engine("invalid recovery item id"));
        }
        Ok(self.directory.join(format!("{id}.json")))
    }

    // Revalidate before every mutation: an unreadable file must never turn
    // into an apparently empty recovery store or be overwritten by a retry.
    fn read_all(&self) -> Result<BTreeMap<String, Stored>> {
        validate_credential_path(&self.directory, "node recovery directory")?;
        let meta = fs::symlink_metadata(&self.directory)?;
        if !meta.is_dir() {
            return Err(Error::engine("invalid node recovery directory"));
        }
        check_owned(&meta, 0o700)?;
        let mut entries = BTreeMap::new();
        for file in fs::read_dir(&self.directory)? {
            let path = file?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Interrupted atomic writes are not established recovery facts.
            if name.ends_with(".tmp") {
                continue;
            }
            let id = name
                .strip_suffix(".json")
                .ok_or_else(|| Error::engine("unrecognised recovery file"))?;
            self.path(id)?;
            let input = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)?;
            let meta = input.metadata()?;
            check_owned(&meta, 0o600)?;
            if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_ITEM_BYTES {
                return Err(Error::engine("invalid recovery file"));
            }
            let mut bytes = Vec::new();
            input.take(MAX_ITEM_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_ITEM_BYTES {
                return Err(Error::engine("recovery item exceeds bound"));
            }
            let stored: Stored = serde_json::from_slice(&bytes)?;
            match &stored {
                Stored::Item(item) => validate_item(item)?,
                Stored::Tombstone {
                    version,
                    payload_pruned,
                    ..
                } if *version == ITEM_VERSION && *payload_pruned => {}
                _ => return Err(Error::engine("invalid recovery tombstone")),
            }
            if stored.id() != id {
                return Err(Error::engine("recovery filename/id mismatch"));
            }
            entries.insert(id.to_owned(), stored);
        }
        Ok(entries)
    }

    fn write(&self, stored: &Stored) -> Result<()> {
        let path = self.path(stored.id())?;
        let temporary =
            self.directory
                .join(format!("{}.{}.tmp", stored.id(), uuid::Uuid::new_v4()));
        let result = (|| {
            let bytes = serde_json::to_vec(stored)?;
            if bytes.len() as u64 > MAX_ITEM_BYTES {
                return Err(Error::engine("recovery item exceeds bound"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, &path)?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Update an OPEN item's payload under its existing id (also used by
    /// quarantine ownership). An intervening dismissal always wins.
    pub(super) fn upsert(&self, mut item: RecoveryItem) -> Result<RecoveryItem> {
        validate_item(&item)?;
        self.path(&item.id)?;
        let mut entries = self.entries.lock().expect("recovery entries");
        *entries = self.read_all()?;
        match entries.get(&item.id) {
            Some(Stored::Tombstone { dismissed_at, .. }) => {
                item.state = RecoveryState::Dismissed;
                item.dismissed_at = Some(*dismissed_at);
                redact(&mut item);
                item.reason = None;
                return Ok(item);
            }
            Some(Stored::Item(old)) if old.state == RecoveryState::Dismissed => {
                return Ok(old.as_ref().clone())
            }
            Some(Stored::Item(old)) => {
                if old.record_id != item.record_id || old.editor != item.editor {
                    return Err(Error::engine("recovery identity conflict"));
                }
                item.created_at = old.created_at;
                item.last_seen_at = item.last_seen_at.max(old.last_seen_at);
                item.state = RecoveryState::Open;
                item.dismissed_at = None;
            }
            None => {}
        }
        let stored = Stored::Item(Box::new(item.clone()));
        self.write(&stored)?;
        entries.insert(item.id.clone(), stored);
        Ok(item)
    }

    pub(super) fn get(&self, id: &str, include_text: bool) -> Result<Option<RecoveryItem>> {
        self.path(id)?;
        Ok(self
            .list(None, None, include_text)?
            .into_iter()
            .find(|item| item.id == id))
    }

    /// `state == None` includes both retained states. Local read callers use
    /// `Some(Open)` by default. Body fields are absent from metadata JSON.
    pub(super) fn list(
        &self,
        record_id: Option<&str>,
        state: Option<RecoveryState>,
        include_text: bool,
    ) -> Result<Vec<RecoveryItem>> {
        let mut entries = self.entries.lock().expect("recovery entries");
        *entries = self.read_all()?;
        Ok(entries
            .values()
            .filter_map(|stored| match stored {
                Stored::Item(item)
                    if record_id.is_none_or(|r| item.record_id == r)
                        && state.is_none_or(|s| item.state == s) =>
                {
                    let mut item = item.as_ref().clone();
                    if !include_text {
                        redact(&mut item);
                    }
                    Some(item)
                }
                _ => None,
            })
            .collect())
    }

    pub(super) fn dismiss(&self, id: &str) -> Result<RecoveryItem> {
        self.path(id)?;
        let mut entries = self.entries.lock().expect("recovery entries");
        *entries = self.read_all()?;
        let Some(Stored::Item(old)) = entries.get(id) else {
            return Err(Error::engine("recovery item not found"));
        };
        let mut item = old.as_ref().clone();
        if item.state == RecoveryState::Dismissed {
            return Ok(item);
        }
        item.state = RecoveryState::Dismissed;
        item.dismissed_at = Some(now_ms());
        let stored = Stored::Item(Box::new(item.clone()));
        self.write(&stored)?;
        entries.insert(id.to_owned(), stored);
        Ok(item)
    }

    /// Includes compact dismissal tombstones; migration must not recreate
    /// their erased private payloads merely because list/get hide them.
    pub(super) fn contains_id(&self, id: &str) -> Result<bool> {
        self.path(id)?;
        let mut entries = self.entries.lock().expect("recovery entries");
        *entries = self.read_all()?;
        Ok(entries.contains_key(id))
    }

    #[cfg(test)]
    pub(super) fn is_open(&self, id: &str) -> Result<bool> {
        Ok(self
            .get(id, false)?
            .is_some_and(|i| i.state == RecoveryState::Open))
    }
    pub(super) fn open_ids(&self) -> Result<BTreeSet<String>> {
        Ok(self
            .list(None, Some(RecoveryState::Open), false)?
            .into_iter()
            .map(|i| i.id)
            .collect())
    }
    pub(super) fn prune(&self) -> Result<usize> {
        self.prune_at(now_ms())
    }
    pub(super) fn prune_at(&self, now: u64) -> Result<usize> {
        let mut entries = self.entries.lock().expect("recovery entries");
        *entries = self.read_all()?;
        let expired: Vec<_> = entries
            .values()
            .filter_map(|stored| match stored {
                Stored::Item(item)
                    if item.state == RecoveryState::Dismissed
                        && item.dismissed_at.is_some_and(|at| {
                            now.saturating_sub(at)
                                >= self.retention.as_millis().min(u64::MAX as u128) as u64
                        }) =>
                {
                    Some((item.id.clone(), item.dismissed_at.unwrap()))
                }
                _ => None,
            })
            .collect();
        for (id, dismissed_at) in &expired {
            let tombstone = Stored::Tombstone {
                version: ITEM_VERSION,
                id: id.clone(),
                dismissed_at: *dismissed_at,
                payload_pruned: true,
            };
            self.write(&tombstone)?;
            entries.insert(id.clone(), tombstone);
        }
        Ok(expired.len())
    }

    /// Sign-out/account-switch boundary. This alone also removes tombstones.
    pub(super) fn wipe(&self) -> Result<()> {
        let mut entries = self.entries.lock().expect("recovery entries");
        // Explicit account-boundary erasure must also remove an owned file
        // whose JSON is damaged. Unlink never follows a file symlink.
        validate_credential_path(&self.directory, "node recovery directory")?;
        let meta = fs::symlink_metadata(&self.directory)?;
        if !meta.is_dir() {
            return Err(Error::engine("invalid node recovery directory"));
        }
        check_owned(&meta, 0o700)?;
        let mut paths = Vec::new();
        for file in fs::read_dir(&self.directory)? {
            let path = file?.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() || meta.uid() != owner_uid() {
                return Err(Error::engine("invalid recovery file at account boundary"));
            }
            paths.push(path);
        }
        for path in paths {
            fs::remove_file(path)?;
        }
        File::open(&self.directory)?.sync_all()?;
        entries.clear();
        Ok(())
    }

    pub(super) fn counts(&self) -> Result<RecoveryCounts> {
        let mut entries = self.entries.lock().expect("recovery entries");
        *entries = self.read_all()?;
        let mut counts = RecoveryCounts {
            open: 0,
            dismissed: 0,
            tombstones: 0,
        };
        for stored in entries.values() {
            match stored {
                Stored::Item(item) if item.state == RecoveryState::Open => counts.open += 1,
                Stored::Item(_) => counts.dismissed += 1,
                Stored::Tombstone { .. } => counts.tombstones += 1,
            }
        }
        Ok(counts)
    }
}

fn redact(item: &mut RecoveryItem) {
    item.base_text = None;
    item.my_text = None;
    if let Some(passage) = &mut item.passage {
        passage.base = None;
        passage.mine = None;
        passage.theirs = None;
    }
}

fn validate_item(item: &RecoveryItem) -> Result<()> {
    if item.version != ITEM_VERSION
        || (item.state == RecoveryState::Dismissed) != item.dismissed_at.is_some()
    {
        return Err(Error::engine("invalid recovery version/state"));
    }
    match item.kind {
        RecoveryKind::Clash | RecoveryKind::LocalClash => {
            let Some(passage) = &item.passage else {
                return Err(Error::engine("recovery passage missing"));
            };
            if passage.base.is_none()
                || passage.mine.is_none()
                || passage.base_start > passage.base_end
                || (!passage.theirs_truncated && passage.theirs.is_none())
            {
                return Err(Error::engine("incomplete recovery passage"));
            }
        }
        RecoveryKind::Refusal | RecoveryKind::KeyConflict
            if item.base_text.is_none() || item.my_text.is_none() =>
        {
            return Err(Error::engine("incomplete recovery refusal"))
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
