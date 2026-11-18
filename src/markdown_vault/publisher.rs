//! Descriptor-relative publisher. No path component is followed through a
//! symlink, including reads, chmod, rename, unlink and startup cleanup.
use super::*;
use crate::{Error, Result};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path};

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn c(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::engine("vault path contains NUL"))
}
fn io(code: i32) -> std::io::Result<i32> {
    if code < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(code)
    }
}
pub(super) fn open(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = c(name)?;
    // SAFETY: live directory fd, NUL-terminated name; returned fd is owned.
    let fd = io(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    })?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn mkdir(dir: &File, name: &str) -> Result<()> {
    let name = c(name)?;
    io(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) })?;
    Ok(())
}
fn chmod(file: &File, mode: u32) -> Result<()> {
    io(unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) })?;
    Ok(())
}
pub(super) fn parts(path: &str) -> Result<Vec<&str>> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == ".." || p.len() > 255 || p.contains('\\'))
    {
        return Err(Error::engine("unsafe vault relative path"));
    }
    Ok(parts)
}

/// Exact text from a completed publication, never text recovered from an edit.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PublishedBase {
    pub(super) text: String,
    pub(super) act: i64,
    pub(super) generation: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct Entry {
    pub(super) digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) base: Option<PublishedBase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_rendered_digest: Option<String>,
    /// A source rename/move can leave an edited former output behind.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) latest_rendered_absent: bool,
    #[serde(default)]
    pub(super) pending_digest: Option<String>,
    #[serde(default)]
    pub(super) prior_digests: BTreeSet<String>,
    pub(super) contributors: BTreeSet<String>,
}
impl Entry {
    fn matches(&self, bytes: &[u8]) -> bool {
        let d = digest(bytes);
        self.digest == d
            || self.pending_digest.as_ref() == Some(&d)
            || self.prior_digests.contains(&d)
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub(super) contract: String,
    #[serde(default)]
    integrity: String,
    pub(super) origin: String,
    pub(super) account: String,
    #[cfg(feature = "v2-kernel-probe")]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) member_revoked: bool,
    #[cfg(feature = "v2-kernel-probe")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member_rebind_scope: Option<String>,
    pub(super) act: i64,
    #[serde(default)]
    pub(super) rendered_at: String,
    #[serde(default)]
    pub(super) successful_act: Option<i64>,
    #[serde(default)]
    pub(super) successful_generation: String,
    pub(super) files: BTreeMap<String, Entry>,
    directories: BTreeSet<String>,
    #[serde(default)]
    dirty_directories: BTreeSet<String>,
    #[serde(default)]
    directory_inputs: BTreeMap<String, BTreeSet<String>>,
    visible: BTreeSet<String>,
    pub(super) allocations: BTreeMap<String, Allocation>,
}

impl State {
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let state: Self = serde_json::from_slice(bytes)?;
        let mut value = serde_json::to_value(&state)?;
        value.as_object_mut().unwrap().remove("integrity");
        if state.integrity != digest(&serde_json::to_vec(&value)?) {
            return Err(Error::engine("vault state was modified or corrupted"));
        }
        if state.contract != VERSION {
            return Err(Error::engine("unknown vault state contract"));
        }
        Ok(state)
    }
}

pub(crate) struct Publisher {
    root: File,
    _lock: File,
    state: State,
    last_state_digest: std::cell::RefCell<Option<String>>,
}

impl Publisher {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(Error::engine(
                "vault requires an absolute non-root directory",
            ));
        }
        let mut root = File::open("/")?;
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(part) => {
                    let part = part
                        .to_str()
                        .ok_or_else(|| Error::engine("vault path must be UTF-8"))?;
                    match open(&root, part, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                        Ok(next) => root = next,
                        Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                            mkdir(&root, part)?;
                            root = open(&root, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                _ => return Err(Error::engine("vault path must be lexically unambiguous")),
            }
        }
        let existing = list(&root)?;
        if !existing.contains(&".native".to_owned()) {
            if !existing.is_empty() {
                return Err(Error::engine("vault refuses a nonempty foreign directory"));
            }
            chmod(&root, 0o700)?;
            mkdir(&root, ".native")?;
        }
        let native = open(&root, ".native", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;

        let state_bytes = read_file(&native, "state.json")?;
        let initial_state = state_bytes.is_none();
        let last_state_digest = state_bytes.as_ref().map(|bytes| digest(bytes));
        let state = match state_bytes {
            Some(bytes) => State::from_bytes(&bytes)?,
            None => {
                if !existing.is_empty() {
                    return Err(Error::engine("vault has no ownership state"));
                }
                State {
                    contract: VERSION.into(),
                    ..Default::default()
                }
            }
        };
        chmod(&root, 0o700)?;
        chmod(&native, 0o700)?;
        let lock = open(&native, "writer.lock", libc::O_RDWR | libc::O_CREAT, 0o600)?;
        lock.try_lock_exclusive()
            .map_err(|_| Error::engine("vault already has a writer"))?;
        #[allow(unused_mut)]
        let mut publisher = Self {
            root,
            _lock: lock,
            state,
            last_state_digest: std::cell::RefCell::new(last_state_digest),
        };
        if initial_state {
            publisher.save()?;
            publisher.root.sync_all()?;
        }
        publisher.cleanup()?;
        #[cfg(feature = "v2-kernel-probe")]
        if publisher.state.member_revoked {
            publisher.revoke_member()?;
        }
        Ok(publisher)
    }

    fn dir(&self, path: &str) -> Result<File> {
        let mut dir = self.root.try_clone()?;
        if path.is_empty() {
            return Ok(dir);
        }
        for part in parts(path)? {
            dir = open(&dir, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
        Ok(dir)
    }
    fn parent(&self, path: &str) -> Result<(File, String)> {
        let split = parts(path)?;
        Ok((
            self.dir(&split[..split.len() - 1].join("/"))?,
            split.last().unwrap().to_string(),
        ))
    }
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let (dir, name) = match self.parent(path) {
            Ok(value) => value,
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        read_file(&dir, &name)
    }
    fn remove(&self, path: &str) -> Result<()> {
        parts(path)?;
        let parent_path = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        let (dir, name) = match self.parent(path) {
            Ok(value) => value,
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.sync_directory(parent_path)
            }
            Err(error) => return Err(error),
        };
        // Absence may be an earlier, unsynced unlink. Flush the parent even
        // when retrying a deletion whose directory entry is already gone.
        if read_file(&dir, &name)?.is_some() {
            let name = c(&name)?;
            io(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })?;
        }
        self.sync_directory(parent_path)
    }
    fn atomic(&self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        let (dir, name) = self.parent(path)?;
        let temp = format!(".native-vault-tmp-{}", uuid::Uuid::new_v4());
        let mut file = open(
            &dir,
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let result = (|| {
            file.write_all(bytes)?;
            chmod(&file, mode)?;
            if path.starts_with(".native/") {
                file.sync_all()?;
            }
            let from = c(&temp)?;
            let to = c(&name)?;
            io(unsafe {
                libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr())
            })?;
            if path.starts_with(".native/") {
                dir.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let temp = c(&temp)?;
            unsafe { libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0) };
        }
        result
    }
    fn save(&self) -> Result<()> {
        let path = ".native/state.json";
        if let Some(current) = self.read(path)? {
            if self.last_state_digest.borrow().as_ref() != Some(&digest(&current)) {
                return Err(Error::engine("vault state has local edits"));
            }
        }
        let mut value = serde_json::to_value(&self.state)?;
        let object = value.as_object_mut().unwrap();
        object.remove("integrity");
        let checksum = digest(&serde_json::to_vec(&value)?);
        value
            .as_object_mut()
            .unwrap()
            .insert("integrity".into(), Value::String(checksum));
        let bytes = serde_json::to_vec(&value)?;
        self.atomic(path, &bytes, 0o600)?;
        *self.last_state_digest.borrow_mut() = Some(digest(&bytes));
        Ok(())
    }
    fn cleanup(&self) -> Result<()> {
        for path in std::iter::once(String::new())
            .chain(std::iter::once(".native".into()))
            .chain(self.state.directories.iter().cloned())
        {
            let dir = match self.dir(&path) {
                Ok(dir) => dir,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for name in list(&dir)? {
                if name.starts_with(".native-vault-tmp-") {
                    // Reserved temp namespace only, with no symlink traversal.
                    chmod(&dir, 0o700)?;
                    if read_file(&dir, &name)?.is_some() {
                        let name = c(&name)?;
                        io(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })?;
                    }
                }
            }
            if !path.is_empty() && path != ".native" {
                chmod(&dir, 0o555)?;
            }
        }
        Ok(())
    }
    fn remove_dir(&self, path: &str) -> Result<()> {
        parts(path)?;
        let parent_path = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        let (parent, name) = match self.parent(path) {
            Ok(value) => value,
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.sync_directory(parent_path)
            }
            Err(error) => return Err(error),
        };
        match open(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(_) => {}
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.sync_directory(parent_path)
            }
            Err(error) => return Err(error),
        }
        let name = c(&name)?;
        io(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) })?;
        self.sync_directory(parent_path)
    }
    fn sync_directory(&self, path: &str) -> Result<()> {
        #[cfg(test)]
        {
            DIRECTORY_SYNC_ATTEMPTS.with(|count| count.set(count.get() + 1));
            if FAIL_NEXT_DIRECTORY_SYNC.with(|flag| flag.replace(false)) {
                return Err(Error::engine("fixture directory fsync failed"));
            }
        }
        // A removed planned directory needs its nearest surviving ancestor
        // synced, so a lost directory entry cannot resurrect stale outputs.
        let mut current = path;
        loop {
            match self.dir(current) {
                Ok(dir) => {
                    dir.sync_all()?;
                    return Ok(());
                }
                Err(Error::Io(ref e))
                    if e.kind() == std::io::ErrorKind::NotFound && !current.is_empty() =>
                {
                    current = current
                        .rsplit_once('/')
                        .map(|(parent, _)| parent)
                        .unwrap_or("")
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn cycle(&mut self, source: &SourceSnapshot) -> Result<Vec<String>> {
        self.cycle_with_freshness(source, || Ok(source.freshness.clone()))
    }

    /// Sample serving-generation freshness after collection, rendering and
    /// publication, immediately before writing STATUS. The caller must retain
    /// the same generation lease throughout the cycle.
    pub(crate) fn cycle_with_freshness(
        &mut self,
        source: &SourceSnapshot,
        freshness: impl FnOnce() -> Result<Value>,
    ) -> Result<Vec<String>> {
        self.cycle_inner(source, freshness, false)
    }
    fn cycle_inner(
        &mut self,
        source: &SourceSnapshot,
        freshness: impl FnOnce() -> Result<Value>,
        _rebind: bool,
    ) -> Result<Vec<String>> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.state.member_revoked && !_rebind {
            return Err(Error::engine("vault member access ended"));
        }
        if source.origin.is_empty() || source.account.is_empty() {
            return Err(Error::engine("vault source binding is empty"));
        }
        if !self.state.origin.is_empty()
            && (self.state.origin != source.origin || self.state.account != source.account)
        {
            return Err(Error::engine("vault source/account binding changed"));
        }
        // Render is pure and complete. No database transaction is held here.
        let rendered = render::render(source, &self.state.allocations)?;
        for path in &self.state.directories {
            match self.dir(path) {
                Ok(dir) => chmod(&dir, 0o700)?,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let result = self.apply(source, rendered);
        let mut sealing = Ok(());
        for path in &self.state.directories {
            if let Err(error) = self.dir(path).and_then(|dir| chmod(&dir, 0o555)) {
                if !matches!(&error,Error::Io(e) if e.kind()==std::io::ErrorKind::NotFound) {
                    sealing = Err(error);
                }
            }
        }
        sealing?;
        let conflicts = result?;
        let mut status = source.status_only();
        status.freshness = freshness()?;
        self.status(&status, &conflicts)?;
        Ok(conflicts)
    }
    fn apply(&mut self, source: &SourceSnapshot, mut rendered: Rendered) -> Result<Vec<String>> {
        let visible: BTreeSet<_> = source.records.keys().cloned().collect();
        let revoked: BTreeSet<_> = self.state.visible.difference(&visible).cloned().collect();
        let purge: Vec<_> = self
            .state
            .files
            .iter()
            .filter(|(_, e)| !e.contributors.is_disjoint(&revoked))
            .map(|(p, _)| p.clone())
            .collect();
        for path in purge {
            self.remove(&path)?;
            self.state.files.remove(&path);
        }
        let mut old_dirs: Vec<_> = self.state.directories.iter().cloned().collect();
        old_dirs.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for path in old_dirs {
            let revoked_dir = self
                .state
                .directory_inputs
                .get(&path)
                .is_some_and(|ids| !ids.is_disjoint(&revoked));
            if revoked_dir {
                self.remove_dir(&path)?;
                self.state.directories.remove(&path);
                self.state.directory_inputs.remove(&path);
            }
        }
        self.state.allocations.retain(|id, _| visible.contains(id));
        self.state.visible = visible;
        self.state.origin = source.origin.clone();
        self.state.account = source.account.clone();
        self.state.act = source.act;
        let mut conflicts = Vec::new();
        let obsolete: Vec<_> = self
            .state
            .files
            .keys()
            .filter(|p| !rendered.files.contains_key(*p) && p.as_str() != ".native/STATUS.md")
            .cloned()
            .collect();
        for path in obsolete {
            let existing = self.read(&path)?;
            if existing
                .as_ref()
                .is_none_or(|b| self.state.files[&path].matches(b))
            {
                self.remove(&path)?;
                self.state.files.remove(&path);
            } else {
                let entry = self.state.files.get_mut(&path).unwrap();
                entry.latest_rendered_absent = true;
                entry.latest_rendered_digest = None;
                conflicts.push(path);
            }
        }
        // Include every output parent, including the synthetic Messages area.
        for path in rendered.files.keys() {
            let components = parts(path)?;
            for n in 1..components.len() {
                rendered
                    .directories
                    .entry(components[..n].join("/"))
                    .or_default();
            }
        }
        // Folder ancestry (rather than all child/link contributors) controls
        // directory revocation. Messages is synthetic and has no private name.
        for (path, ids) in &mut rendered.directories {
            if path == "Messages" {
                ids.clear();
            } else {
                ids.retain(|id| source.records.get(id).is_some_and(SourceRecord::folder));
            }
        }
        let mut new_dirs = Vec::new();
        for path in rendered.directories.keys() {
            match self.dir(path) {
                Ok(_) if self.state.directories.contains(path) => {}
                Ok(_) => {
                    return Err(Error::engine(
                        "vault directory collides with foreign content",
                    ))
                }
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    new_dirs.push(path.clone())
                }
                Err(error) => return Err(error),
            }
        }
        new_dirs.sort_by_key(|p| p.matches('/').count());
        // Preflight names before journaling ownership, never claim a user file
        // or directory merely because publication wanted that path.
        for path in &new_dirs {
            let (parent, name) = match self.parent(path) {
                Ok(v) => v,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            match open(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(_) => {
                    return Err(Error::engine(
                        "vault directory collides with foreign content",
                    ))
                }
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let mut writes = Vec::new();
        let mut final_entries = BTreeMap::new();
        for (path, output) in rendered.files {
            let current = match self.read(&path) {
                Ok(v) => v,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            let old = self.state.files.get(&path);
            if current
                .as_ref()
                .is_some_and(|b| old.is_none_or(|e| !e.matches(b)))
            {
                // Desired output may advance while an edited published file
                // remains untouched. Preserve its exact original base.
                if let Some(entry) = self.state.files.get_mut(&path) {
                    entry.latest_rendered_digest = Some(digest(&output.bytes));
                    entry.latest_rendered_absent = false;
                }
                conflicts.push(path);
                continue;
            }
            let dirty = old.is_some_and(|entry| {
                entry.pending_digest.is_some() || !entry.prior_digests.is_empty()
            });
            let hash = digest(&output.bytes);
            let final_entry = Entry {
                digest: hash.clone(),
                base: if path.ends_with(".md") {
                    String::from_utf8(output.bytes.clone())
                        .ok()
                        .map(|text| PublishedBase {
                            text,
                            act: source.act,
                            generation: source.generation.clone(),
                        })
                } else {
                    None
                },
                latest_rendered_digest: Some(hash.clone()),
                latest_rendered_absent: false,
                pending_digest: None,
                prior_digests: BTreeSet::new(),
                contributors: output.contributors.clone(),
            };
            let mut journal = old.cloned().unwrap_or_default();
            if let Some(pending) = journal.pending_digest.take() {
                journal.prior_digests.insert(pending);
            }
            journal.pending_digest = Some(hash.clone());
            journal.latest_rendered_digest = Some(hash.clone());
            journal.latest_rendered_absent = false;
            journal.contributors.extend(output.contributors);
            self.state.files.insert(path.clone(), journal);
            final_entries.insert(path.clone(), final_entry);
            let changed = current.as_ref().is_none_or(|b| digest(b) != hash);
            if dirty || changed {
                self.state.dirty_directories.insert(
                    path.rsplit_once('/')
                        .map(|(parent, _)| parent)
                        .unwrap_or("")
                        .to_owned(),
                );
            }
            if changed {
                writes.push((path, output.bytes));
            }
        }
        for path in &new_dirs {
            self.state.dirty_directories.insert(path.clone());
            self.state.dirty_directories.insert(
                path.rsplit_once('/')
                    .map(|(parent, _)| parent)
                    .unwrap_or("")
                    .to_owned(),
            );
        }
        self.state.directories.extend(new_dirs.iter().cloned());
        // Preserve prior directory dependencies until publication completes.
        for (path, ids) in &rendered.directories {
            self.state
                .directory_inputs
                .entry(path.clone())
                .or_default()
                .extend(ids.iter().cloned());
        }
        // One durable plan holds BOTH old and new contributors and digests.
        // Crash at any subsequent boundary remains conservatively revocable.
        self.save()?;
        #[cfg(test)]
        if FAIL_AFTER_PLAN.with(|flag| flag.replace(false)) {
            return Err(Error::engine("fixture crash after vault plan"));
        }

        for path in new_dirs {
            let (parent, name) = self.parent(&path)?;
            mkdir(&parent, &name)?;
        }
        for (path, bytes) in writes {
            self.atomic(&path, &bytes, 0o444)?;
        }
        #[cfg(test)]
        if FAIL_AFTER_WRITES.with(|flag| flag.replace(false)) {
            return Err(Error::engine(
                "fixture directory sync failure after content writes",
            ));
        }
        // A successful rename alone is not durable. Sync each distinct parent
        // before discarding ANY prior contributor/digest: a power loss must
        // never resurrect old sensitive links after the journal forgot them.
        // On sync error, self.state still holds the complete union, including
        // when the runner subsequently saves an unavailable status.
        for path in self.state.dirty_directories.clone() {
            self.sync_directory(&path)?;
        }
        self.state.dirty_directories.clear();
        for (path, entry) in final_entries {
            self.state.files.insert(path, entry);
        }
        self.state.allocations = rendered.allocations;
        let desired_directories = rendered.directories;
        for (path, inputs) in &desired_directories {
            self.state
                .directory_inputs
                .insert(path.clone(), inputs.clone());
        }
        // Remove unused owned directories bottom-up. Ordinary user contents
        // protect a non-revoked directory and are reported as a conflict.
        let mut unused: Vec<_> = self
            .state
            .directories
            .iter()
            .filter(|p| !desired_directories.contains_key(*p))
            .cloned()
            .collect();
        unused.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for path in unused {
            match self.remove_dir(&path) {
                Ok(()) => {
                    self.state.directories.remove(&path);
                    self.state.directory_inputs.remove(&path);
                }
                Err(Error::Io(ref e)) if e.raw_os_error() == Some(libc::ENOTEMPTY) => {
                    conflicts.push(path)
                }
                Err(e) => return Err(e),
            }
        }
        self.state.rendered_at = chrono::Utc::now().to_rfc3339();
        #[cfg(feature = "v2-kernel-probe")]
        {
            self.state.successful_act =
                (source.freshness["content_act"] != "not_held").then_some(source.act);
        }
        #[cfg(not(feature = "v2-kernel-probe"))]
        {
            self.state.successful_act = Some(source.act);
        }
        self.state.successful_generation = source.generation.clone();
        self.save()?;
        Ok(conflicts)
    }

    /// An existing N2 vault can only be adopted by its already authenticated
    /// member-copy binding. An unbound first request cannot erase another
    /// account's vault. A revoked tombstone already carries deletion authority.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn matches_member_copy(&self, origin: Option<&str>, account: Option<&str>) -> bool {
        self.state.member_revoked
            || (self.state.origin.is_empty() && self.state.account.is_empty())
            || (origin == Some(self.state.origin.as_str())
                && account == Some(self.state.account.as_str()))
    }

    /// This synchronous durable barrier precedes every cancellable await in
    /// the owner. Reopening completes deletion even if the process stops while
    /// copy leases are draining or the member SQLite file is being removed.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn mark_member_revoked(&mut self) -> Result<()> {
        self.state.member_revoked = true;
        self.state.member_rebind_scope = None;
        self.save()
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn mark_member_scope_change(&mut self, scope: &str) -> Result<()> {
        self.state.member_revoked = true;
        self.state.member_rebind_scope = Some(scope.into());
        self.save()
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn scope_rebind_pending(&self, scope: &str) -> bool {
        self.state.member_revoked && self.state.member_rebind_scope.as_deref() == Some(scope)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn has_scope_rebind(&self) -> bool {
        self.state.member_revoked && self.state.member_rebind_scope.is_some()
    }

    /// Only the serialized owner supplies a snapshot from a newly verified,
    /// admitted copy. Keep the durable refusal through the entire publication.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn publish_member_scope(
        &mut self,
        scope: &str,
        source: &SourceSnapshot,
    ) -> Result<()> {
        if !self.scope_rebind_pending(scope)
            || source.origin != self.state.origin
            || source.account != self.state.account
        {
            return Err(Error::engine("vault scope recovery binding refused"));
        }
        match self.cycle_inner(source, || Ok(source.freshness.clone()), true) {
            Ok(conflicts) if conflicts.is_empty() => {}
            result => {
                let _ = self.revoke_member();
                return Err(result
                    .err()
                    .unwrap_or_else(|| Error::engine("vault scope publication incomplete")));
            }
        }
        self.state.member_revoked = false;
        self.state.member_rebind_scope = None;
        if let Err(error) = self.save() {
            self.state.member_revoked = true;
            self.state.member_rebind_scope = Some(scope.into());
            let _ = self.revoke_member();
            return Err(error);
        }
        Ok(())
    }

    /// Persist refusal before the first unlink. Failed cleanup is retried on
    /// reopen; edited owned files are still purged. Foreign paths/symlinks
    /// fail visibly and can never turn a revoked vault back into a publisher.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn revoke_member(&mut self) -> Result<()> {
        // Preserve a scope-only recovery target across cleanup and restart.
        // A real revocation explicitly clears it in mark_member_revoked.
        self.state.member_revoked = true;
        self.save()?;
        for path in &self.state.directories {
            match self.dir(path) {
                Ok(dir) => chmod(&dir, 0o700)?,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let paths: Vec<_> = self.state.files.keys().cloned().collect();
        for path in paths {
            self.remove(&path)?;
            self.state.files.remove(&path);
        }
        let mut directories: Vec<_> = self.state.directories.iter().cloned().collect();
        directories.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
        for path in directories {
            self.remove_dir(&path)?;
            self.state.directories.remove(&path);
            self.state.directory_inputs.remove(&path);
        }
        self.state.visible.clear();
        self.state.allocations.clear();
        self.state.directory_inputs.clear();
        self.state.dirty_directories.clear();
        self.state.successful_act = None;
        self.state.successful_generation.clear();
        self.save()?;
        self.unavailable("member access ended")
    }

    pub(crate) fn unavailable(&mut self, reason: &str) -> Result<()> {
        let source = SourceSnapshot {
            origin: self.state.origin.clone(),
            account: self.state.account.clone(),
            act: self.state.successful_act.unwrap_or(0),
            generation: self.state.successful_generation.clone(),
            freshness: serde_json::json!({"vault_available":false,"reason":reason,"freshness":"unavailable"}),
            ..Default::default()
        };
        self.status(&source, &[])
    }

    /// Cheap tick: ages status even when the act does not move.
    pub(crate) fn status(&mut self, source: &SourceSnapshot, conflicts: &[String]) -> Result<()> {
        let path = ".native/STATUS.md";
        let current = self.read(path)?;
        if let Some(bytes) = &current {
            if self.state.files.get(path).is_none_or(|e| !e.matches(bytes)) {
                return Err(Error::engine("vault STATUS has local edits"));
            }
        }
        let availability = if source.freshness.get("vault_available") == Some(&Value::Bool(false)) {
            "unavailable / current cycle failed"
        } else {
            "authorized copy available"
        };
        let bytes=format!("# Native vault status\n\nRenderer: {VERSION}\nAvailability: {availability}\nOrigin: {}\nGeneration: {}\nLast successful content act: {}\nRendered at: {}\nStatus checked at: {}\nFreshness and refresh diagnostics: {}\n\nInspect local edits: `native vault status --vault .` from the vault root (`--json` for tools). Read-only: sends nothing, changes no files. Do not chmod generated notes; use Native MCP for writes.\n\nConflicts:\n{}\n",source.origin,source.generation,self.state.successful_act.map(|a|a.to_string()).unwrap_or_else(||"none".into()),self.state.rendered_at,chrono::Utc::now().to_rfc3339(),source.freshness,conflicts.iter().map(|p|format!("- {p}\n")).collect::<String>()).into_bytes();
        self.state.files.insert(
            path.into(),
            Entry {
                digest: current.as_ref().map(|b| digest(b)).unwrap_or_default(),
                base: None,
                latest_rendered_digest: None,
                latest_rendered_absent: false,
                pending_digest: Some(digest(&bytes)),
                prior_digests: BTreeSet::new(),
                contributors: self.state.visible.clone(),
            },
        );
        self.save()?;
        self.atomic(path, &bytes, 0o444)
    }
}

pub(super) fn read_file(dir: &File, name: &str) -> Result<Option<Vec<u8>>> {
    let mut file = match open(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(file) => file,
        Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(Error::engine(
            "vault path must be a regular, single-link file",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

pub(super) fn list(dir: &File) -> Result<Vec<String>> {
    // fdopendir owns a duplicate, so all discovery remains anchored to the
    // already checked directory rather than resolving a pathname again.
    let dot = c(".")?;
    let fd = io(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::last_os_error().into());
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map(str::to_owned);
        match name {
            Ok(name) if name != "." && name != ".." => names.push(name),
            Ok(_) => {}
            Err(_) => {
                unsafe { libc::closedir(stream) };
                return Err(Error::engine("non-UTF8 vault directory entry"));
            }
        }
    }
    unsafe { libc::closedir(stream) };
    Ok(names)
}

#[cfg(test)]
thread_local! {pub(super) static DIRECTORY_SYNC_ATTEMPTS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};pub(super) static FAIL_NEXT_DIRECTORY_SYNC:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};pub(super) static FAIL_AFTER_WRITES: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};pub(super) static FAIL_AFTER_PLAN: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};}

#[cfg(test)]
mod published_base_tests {
    use super::*;

    fn snapshot(act: i64) -> SourceSnapshot {
        SourceSnapshot {
            origin: "fixture-origin".into(),
            account: "fixture-account".into(),
            act,
            generation: format!("generation-{act}"),
            records: [("record".into(), SourceRecord::default())].into(),
            ..Default::default()
        }
    }

    fn output(text: &str) -> Rendered {
        Rendered {
            files: [(
                "note.md".into(),
                Output {
                    bytes: text.as_bytes().to_vec(),
                    contributors: ["record".into()].into(),
                },
            )]
            .into(),
            directories: BTreeMap::new(),
            allocations: BTreeMap::new(),
        }
    }

    fn edit(root: &Path, text: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("note.md");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn published_base_survives_local_edit_and_source_advance() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher
            .apply(&snapshot(1), output("published body"))
            .unwrap();
        edit(&root, "local edit");
        assert_eq!(
            publisher
                .apply(&snapshot(2), output("advanced body"))
                .unwrap(),
            ["note.md"]
        );
        let entry = &publisher.state.files["note.md"];
        let base = entry.base.as_ref().unwrap();
        assert_eq!(base.text, "published body");
        assert_eq!(base.act, 1);
        assert_eq!(base.generation, "generation-1");
        assert_eq!(entry.digest, digest(b"published body"));
        assert_eq!(
            entry.latest_rendered_digest.as_deref(),
            Some(digest(b"advanced body").as_str())
        );
        drop(publisher);
        let publisher = Publisher::open(&root).unwrap();
        assert_eq!(
            publisher.state.files["note.md"].base.as_ref().unwrap().text,
            "published body"
        );
        assert_eq!(std::fs::read(root.join("note.md")).unwrap(), b"local edit");
    }

    #[test]
    fn legacy_edited_entry_never_acquires_a_fabricated_base() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher.apply(&snapshot(1), output("original")).unwrap();
        let entry = publisher.state.files.get_mut("note.md").unwrap();
        entry.base = None;
        entry.latest_rendered_digest = None;
        publisher.save().unwrap();
        drop(publisher);
        // Missing new fields preserve the old state's integrity representation.
        let mut publisher = Publisher::open(&root).unwrap();
        edit(&root, "edited legacy text");
        publisher.apply(&snapshot(2), output("new source")).unwrap();
        assert!(publisher.state.files["note.md"].base.is_none());
        assert_eq!(publisher.state.files["note.md"].digest, digest(b"original"));
    }

    #[test]
    fn legacy_unchanged_entry_recaptures_verified_published_text() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher.apply(&snapshot(1), output("original")).unwrap();
        publisher.state.files.get_mut("note.md").unwrap().base = None;
        publisher.apply(&snapshot(1), output("original")).unwrap();
        assert_eq!(
            publisher.state.files["note.md"].base.as_ref().unwrap().text,
            "original"
        );
    }

    #[test]
    fn failed_publication_plan_keeps_previous_completed_base() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher.apply(&snapshot(1), output("original")).unwrap();
        FAIL_AFTER_PLAN.with(|flag| flag.set(true));
        assert!(publisher
            .apply(&snapshot(2), output("unpublished"))
            .is_err());
        drop(publisher);
        let publisher = Publisher::open(&root).unwrap();
        let entry = &publisher.state.files["note.md"];
        assert_eq!(entry.base.as_ref().unwrap().text, "original");
        assert_eq!(entry.digest, digest(b"original"));
        assert_eq!(std::fs::read(root.join("note.md")).unwrap(), b"original");
    }

    #[test]
    fn obsolete_edited_path_tracks_missing_output_and_source_return() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher.apply(&snapshot(1), output("original")).unwrap();
        edit(&root, "local edit");
        let mut renamed = output("renamed source");
        let new_output = renamed.files.remove("note.md").unwrap();
        renamed.files.insert("renamed.md".into(), new_output);
        assert_eq!(publisher.apply(&snapshot(2), renamed).unwrap(), ["note.md"]);
        let entry = &publisher.state.files["note.md"];
        assert!(entry.latest_rendered_absent);
        assert!(entry.latest_rendered_digest.is_none());
        assert_eq!(entry.base.as_ref().unwrap().text, "original");
        drop(publisher);
        let mut publisher = Publisher::open(&root).unwrap();
        assert!(publisher.state.files["note.md"].latest_rendered_absent);
        assert_eq!(std::fs::read(root.join("note.md")).unwrap(), b"local edit");
        publisher
            .apply(&snapshot(3), output("returned source"))
            .unwrap();
        let entry = &publisher.state.files["note.md"];
        assert!(!entry.latest_rendered_absent);
        assert_eq!(
            entry.latest_rendered_digest.as_deref(),
            Some(digest(b"returned source").as_str())
        );
        assert_eq!(entry.base.as_ref().unwrap().text, "original");
    }

    #[test]
    fn revoked_contributors_purge_retained_base_text() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher
            .apply(&snapshot(1), output("sensitive-original-body"))
            .unwrap();
        edit(&root, "local edit");
        let mut revoked = snapshot(2);
        revoked.records.clear();
        publisher
            .apply(
                &revoked,
                Rendered {
                    files: BTreeMap::new(),
                    directories: BTreeMap::new(),
                    allocations: BTreeMap::new(),
                },
            )
            .unwrap();
        assert!(!root.join("note.md").exists());
        assert!(!std::fs::read_to_string(root.join(".native/state.json"))
            .unwrap()
            .contains("sensitive-original-body"));
    }
}
