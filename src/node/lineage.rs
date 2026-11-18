//! Durable per-editor body lineage. Preparation is pure except for the queued
//! reset; the caller freezes its result in the journal before attempting a send.
//! Recovery writes must precede `complete`, and settlement must follow it.
use crate::coedit::body_merge::{hunks_between, merge_hunks, Hunk};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Several full <=1 MiB bodies plus worst-case JSON escaping fit comfortably.
const MAX_LINEAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CommittedBody {
    pub version: u64,
    pub text: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Quarantine {
    pub item: String,
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LineageState {
    Active,
    Retiring,
    Retired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Lineage {
    pub version: u32,
    pub record_id: String,
    pub editor: String,
    pub generation: u64,
    pub reset_base_version: u64,
    pub reset_base_text: String,
    pub reset_base_digest: String,
    pub d_prev: String,
    pub c_prev: CommittedBody,
    pub quarantine: Vec<Quarantine>,
    pub last_completed_entry: Option<String>,
    pub state: LineageState,
    #[serde(default)]
    pub fresh_base_required: bool,
}
/// Full recovery fact, with base/theirs coordinates in the evaluated texts and
/// draft coordinates in D_k. `item` identifies an existing owned passage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClashFact {
    pub item: Option<String>,
    pub base: String,
    pub mine: String,
    pub theirs: String,
    pub base_start: usize,
    pub base_end: usize,
    pub theirs_start: usize,
    pub theirs_end: usize,
    pub draft_start: usize,
    pub draft_end: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PreparedMerge {
    pub generation: u64,
    pub d_prev: String,
    pub c_prev: CommittedBody,
    pub d_k: String,
    pub submission: String,
    pub local_clashes: Vec<ClashFact>,
    pub updated_quarantine: Vec<Quarantine>,
    pub no_send: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Advance {
    Applied,
    AlreadyCompleted,
    GenerationChanged,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}
fn scalar_slice(text: &str, start: usize, end: usize) -> String {
    text.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}
fn touches(h: &Hunk, start: usize, end: usize) -> bool {
    h.index <= end && h.index + h.del >= start
}
/// Conservative span alignment: changed regions intersecting either edge are
/// included whole. Insertions at both edges belong to the passage. This also
/// preserves an empty deletion passage's affinity at its insertion point.
fn map_span(hunks: &[Hunk], start: usize, end: usize) -> (usize, usize) {
    let mut left = start;
    let mut right = end;
    for h in hunks {
        if touches(h, start, end) {
            left = left.min(h.index);
            right = right.max(h.index + h.del);
        }
    }
    let mut shift = 0isize;
    let mut mapped_left = left as isize;
    let mut mapped_right = right as isize;
    for h in hunks {
        let n = h.insert.chars().count();
        let delta = n as isize - h.del as isize;
        if h.index + h.del < left || (h.index + h.del == left && h.index < left) {
            mapped_left += delta;
            mapped_right += delta;
        } else if h.index <= right && h.index + h.del >= left {
            mapped_left = mapped_left.min(h.index as isize + shift);
            mapped_right += delta;
            mapped_right = mapped_right.max(h.index as isize + shift + n as isize);
        }
        shift += delta;
    }
    (
        mapped_left.max(0) as usize,
        mapped_right.max(mapped_left).max(0) as usize,
    )
}

impl PreparedMerge {
    /// Call once while assembling the immutable prepared journal record. IDs are
    /// supplied by the recovery store's passage identity function.
    pub fn assign_local_items(&mut self, mut id: impl FnMut(&ClashFact) -> String) {
        for clash in &mut self.local_clashes {
            let item = clash.item.clone().unwrap_or_else(|| id(clash));
            clash.item = Some(item.clone());
            if !self
                .updated_quarantine
                .iter()
                .any(|q| q.item == item && q.start == clash.draft_start && q.end == clash.draft_end)
            {
                self.updated_quarantine.push(Quarantine {
                    item,
                    start: clash.draft_start,
                    end: clash.draft_end,
                });
            }
        }
    }
    /// Home clash base offsets refer to frozen C_prev. Alignment to D_k is
    /// deliberately conservative: ambiguous replacement spans stay in recovery.
    pub fn home_quarantine(&self, item: String, base_start: usize, base_end: usize) -> Quarantine {
        let hunks = hunks_between(&self.c_prev.text, &self.d_k);
        let (start, end) = map_span(&hunks, base_start, base_end);
        Quarantine { item, start, end }
    }
}

/// Pure evaluation. The open ID set removes explicitly dismissed passages.
pub(super) fn evaluate(
    lineage: &Lineage,
    draft: &str,
    open: &HashSet<String>,
) -> io::Result<PreparedMerge> {
    let hunks = hunks_between(&lineage.d_prev, draft);
    let quarantine: Vec<_> = lineage
        .quarantine
        .iter()
        .filter(|q| open.contains(&q.item))
        .collect();
    let mut free = Vec::new();
    let mut owned = HashSet::new();
    for h in &hunks {
        let owners: Vec<_> = quarantine
            .iter()
            .filter(|q| touches(h, q.start, q.end))
            .collect();
        if owners.is_empty() {
            free.push(h.clone());
        } else {
            for owner in owners {
                owned.insert((owner.item.clone(), owner.start, owner.end));
            }
        }
    }
    let merged = merge_hunks(&free, &lineage.d_prev, &lineage.c_prev.text)
        .map_err(|_| invalid("invalid lineage merge hunks"))?;
    let mut local_clashes = Vec::new();
    let mut updated_quarantine = Vec::new();
    let canonical_map = hunks_between(&lineage.d_prev, &lineage.c_prev.text);
    for q in quarantine {
        let (start, end) = map_span(&hunks, q.start, q.end);
        updated_quarantine.push(Quarantine {
            item: q.item.clone(),
            start,
            end,
        });
        if owned.contains(&(q.item.clone(), q.start, q.end)) {
            let (their_start, their_end) = map_span(&canonical_map, q.start, q.end);
            local_clashes.push(ClashFact {
                item: Some(q.item.clone()),
                base: scalar_slice(&lineage.d_prev, q.start, q.end),
                mine: scalar_slice(draft, start, end),
                theirs: scalar_slice(&lineage.c_prev.text, their_start, their_end),
                base_start: q.start,
                base_end: q.end,
                theirs_start: their_start,
                theirs_end: their_end,
                draft_start: start,
                draft_end: end,
            });
        }
    }
    for merged_clash in merged.clashes {
        let c = merged_clash.clash;
        let (draft_start, draft_end) = map_span(&hunks, c.base_start, c.base_end);
        local_clashes.push(ClashFact {
            item: None,
            base: c.base,
            mine: c.mine,
            theirs: c.theirs,
            base_start: c.base_start,
            base_end: c.base_end,
            theirs_start: c.theirs_start,
            theirs_end: c.theirs_end,
            draft_start,
            draft_end,
        });
    }
    Ok(PreparedMerge {
        generation: lineage.generation,
        d_prev: lineage.d_prev.clone(),
        c_prev: lineage.c_prev.clone(),
        d_k: draft.to_owned(),
        no_send: merged.merged == lineage.c_prev.text,
        submission: merged.merged,
        local_clashes,
        updated_quarantine,
    })
}

/// Serialisation here protects individual durable operations. The gate must
/// additionally serialise prepare→complete→settle for each editor's queue.
pub(super) struct LineageStore {
    directory: PathBuf,
    lock: Mutex<()>,
}
impl LineageStore {
    pub fn new(socket_directory: &Path) -> io::Result<Self> {
        let directory = socket_directory.join("lineage");
        crate::credential_file::validate_credential_path(&directory, "node lineage directory")
            .map_err(|e| invalid(&e.to_string()))?;
        match fs::symlink_metadata(&directory) {
            Ok(m) => check_private(&m, true)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                File::open(socket_directory)?.sync_all()?;
            }
            Err(e) => return Err(e),
        }
        Ok(Self {
            directory,
            lock: Mutex::new(()),
        })
    }
    fn path(&self, record: &str, editor: &str) -> PathBuf {
        let identity = serde_json::to_string(&(record, editor)).expect("string tuple");
        self.directory.join(format!("{}.json", digest(&identity)))
    }
    fn validate_directory(&self) -> io::Result<()> {
        crate::credential_file::validate_credential_path(&self.directory, "node lineage directory")
            .map_err(|e| invalid(&e.to_string()))?;
        check_private(&fs::symlink_metadata(&self.directory)?, true)
    }
    fn read_path(&self, path: &Path) -> io::Result<Lineage> {
        self.validate_directory()?;
        crate::credential_file::validate_credential_path(path, "node lineage file")
            .map_err(|e| invalid(&e.to_string()))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        check_private(&metadata, false)?;
        if metadata.len() > MAX_LINEAGE_BYTES {
            return Err(invalid("oversized lineage file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_LINEAGE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LINEAGE_BYTES {
            return Err(invalid("oversized lineage file"));
        }
        let l: Lineage = serde_json::from_slice(&bytes)
            .map_err(|e| invalid(&format!("corrupt lineage: {e}")))?;
        if l.version != 2 || self.path(&l.record_id, &l.editor) != path {
            return Err(invalid("invalid lineage identity/version"));
        }
        if l.state != LineageState::Retired
            && (digest(&l.reset_base_text) != l.reset_base_digest
                || l.quarantine
                    .iter()
                    .any(|q| q.start > q.end || q.end > l.d_prev.chars().count()))
        {
            return Err(invalid("invalid lineage content"));
        }
        Ok(l)
    }
    fn read(&self, record: &str, editor: &str) -> io::Result<Option<Lineage>> {
        self.validate_directory()?;
        match self.read_path(&self.path(record, editor)) {
            Ok(l) => Ok(Some(l)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    /// Enumerate every durable lineage, including retirement tombstones. Only
    /// owned, private regular files in our exact atomic-temp namespace are
    /// ignored: a crash may leave a partial or fully fsynced unrenamed file.
    /// Any other unsafe, unexpected or corrupt file fails closed.
    pub fn list(&self) -> io::Result<Vec<Lineage>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        self.validate_directory()?;
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            check_private(&fs::symlink_metadata(&path)?, false)?;
            if is_atomic_temp(&entry.file_name()) {
                continue;
            }
            result.push(self.read_path(&path)?);
        }
        result.sort_by(|a, b| (&a.record_id, &a.editor).cmp(&(&b.record_id, &b.editor)));
        Ok(result)
    }
    pub fn load(&self, record: &str, editor: &str) -> io::Result<Option<Lineage>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        self.read(record, editor)
    }
    fn write(&self, lineage: &Lineage) -> io::Result<()> {
        self.validate_directory()?;
        let bytes = serde_json::to_vec(lineage).map_err(|e| invalid(&e.to_string()))?;
        if bytes.len() as u64 > MAX_LINEAGE_BYTES {
            return Err(invalid("oversized lineage file"));
        }
        let path = self.path(&lineage.record_id, &lineage.editor);
        if let Ok(meta) = fs::symlink_metadata(&path) {
            check_private(&meta, false)?;
        }
        let temporary = self
            .directory
            .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.flush()?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            File::open(&self.directory)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    /// Only call at send time, after all earlier entries have settled. A reset
    /// is durable before the prepared journal record, so crashing in between is
    /// safe: preparing again observes the identical reset generation.
    pub fn prepare(
        &self,
        record: &str,
        editor: &str,
        _entry: &str,
        declared: CommittedBody,
        draft: &str,
        open: &HashSet<String>,
    ) -> io::Result<PreparedMerge> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        let old = self.read(record, editor)?;
        if old.as_ref().is_some_and(|l| {
            (l.state == LineageState::Retired || l.fresh_base_required)
                && l.reset_base_version == declared.version
        }) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "needs_fresh_base",
            ));
        }
        let reset = old.as_ref().is_none_or(|l| {
            l.reset_base_version != declared.version
                || l.reset_base_text != declared.text
                || l.state == LineageState::Retired
        });
        let lineage = if reset {
            let generation = old.as_ref().map_or(Ok(1), |l| {
                l.generation
                    .checked_add(1)
                    .ok_or_else(|| invalid("lineage generation exhausted"))
            })?;
            let lineage = Lineage {
                version: 2,
                record_id: record.into(),
                editor: editor.into(),
                generation,
                reset_base_version: declared.version,
                reset_base_digest: digest(&declared.text),
                reset_base_text: declared.text.clone(),
                d_prev: declared.text.clone(),
                c_prev: declared,
                quarantine: Vec::new(),
                last_completed_entry: None,
                state: LineageState::Active,
                fresh_base_required: false,
            };
            self.write(&lineage)?;
            lineage
        } else {
            old.expect("existing lineage")
        };
        evaluate(&lineage, draft, open)
    }
    /// Caller has already durably written all recovery items. A refusal must
    /// never call this; no-send uses None and retains the frozen C_prev pair.
    pub fn complete(
        &self,
        record: &str,
        editor: &str,
        entry: &str,
        prepared: &PreparedMerge,
        receipt: Option<CommittedBody>,
        home_quarantine: Vec<Quarantine>,
    ) -> io::Result<Advance> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        let mut lineage = self
            .read(record, editor)?
            .ok_or_else(|| invalid("missing lineage for completion"))?;
        if lineage.generation != prepared.generation {
            return Ok(Advance::GenerationChanged);
        }
        if lineage.last_completed_entry.as_deref() == Some(entry) {
            return Ok(Advance::AlreadyCompleted);
        }
        if lineage.state == LineageState::Retired {
            return Err(invalid("cannot complete drained lineage"));
        }
        if lineage.d_prev != prepared.d_prev || lineage.c_prev != prepared.c_prev {
            return Err(invalid("lineage predecessor changed"));
        }
        let committed = match receipt {
            Some(c) => c,
            None if prepared.no_send => prepared.c_prev.clone(),
            None => return Err(invalid("missing canonical receipt")),
        };
        lineage.d_prev = prepared.d_k.clone();
        lineage.c_prev = committed;
        lineage.quarantine = prepared.updated_quarantine.clone();
        for q in home_quarantine {
            if !lineage.quarantine.iter().any(|old| old == &q) {
                lineage.quarantine.push(q);
            }
        }
        if lineage
            .quarantine
            .iter()
            .any(|q| q.start > q.end || q.end > lineage.d_prev.chars().count())
        {
            return Err(invalid("quarantine outside draft"));
        }
        lineage.last_completed_entry = Some(entry.into());
        self.write(&lineage)?;
        Ok(Advance::Applied)
    }
    /// Also used for base_unverified: require a fresh declared version without
    /// changing the last successful D_prev/C_prev.
    pub fn retire(&self, record: &str, editor: &str) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        if let Some(mut l) = self.read(record, editor)? {
            if l.state == LineageState::Active {
                l.state = LineageState::Retiring;
                self.write(&l)?;
            }
        }
        Ok(())
    }
    /// A violated preserved-base invariant differs from voluntary retirement:
    /// even already queued same-base saves must wait for a fresh base.
    pub fn mark_needs_fresh_base(&self, record: &str, editor: &str) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        if let Some(mut l) = self.read(record, editor)? {
            if l.state != LineageState::Retired {
                l.state = LineageState::Retiring;
            }
            l.fresh_base_required = true;
            self.write(&l)?;
        }
        Ok(())
    }
    /// Remove private texts only once the caller establishes the queue drained.
    /// The compact tombstone is intentionally never age-evicted.
    pub fn drain_retired(&self, record: &str, editor: &str, pending: bool) -> io::Result<()> {
        if pending {
            return Ok(());
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        if let Some(mut l) = self.read(record, editor)? {
            if l.state == LineageState::Retiring {
                l.state = LineageState::Retired;
                l.d_prev.clear();
                l.c_prev.text.clear();
                l.reset_base_text.clear();
                l.quarantine.clear();
                l.last_completed_entry = None;
                self.write(&l)?;
            }
        }
        Ok(())
    }
    /// Account sign-out/switch is a hard boundary, including tombstones.
    pub fn clear(&self) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| invalid("lineage lock poisoned"))?;
        // Account-boundary erasure never parses payloads and never follows a
        // file symlink. Validate the directory and all entries before unlinking
        // anything, so an unsafe entry does not produce a partial wipe.
        self.validate_directory()?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
                return Err(invalid("invalid lineage file at account boundary"));
            }
            paths.push(path);
        }
        for path in paths {
            fs::remove_file(path)?;
        }
        File::open(&self.directory)?.sync_all()
    }
}
/// Match exactly the name emitted by `write`, not arbitrary `.tmp` suffixes.
fn is_atomic_temp(name: &std::ffi::OsStr) -> bool {
    let Some(id) = name
        .to_str()
        .and_then(|s| s.strip_prefix('.'))
        .and_then(|s| s.strip_suffix(".tmp"))
    else {
        return false;
    };
    uuid::Uuid::parse_str(id)
        .is_ok_and(|parsed| parsed.get_version_num() == 4 && parsed.to_string() == id)
}

fn check_private(meta: &fs::Metadata, directory: bool) -> io::Result<()> {
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != if directory { 0o700 } else { 0o600 }
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err(invalid("lineage path is not private and owned"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
