//! Cooperative physical-file custody for opted-in fresh managed adoptions.
//! No protection against privileged/raw/old writers ignoring Native admission.
//! Registered owner locks/pins stay strongly owned until process exit; no eviction.
//! This module confers no session, actor, grant or live-body writer authority.

/// Point-in-time discovery only: no owner, permission, lease or close ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFilenameFooting {
    Unmarked,
    KnownExcludedMarked,
}

pub(crate) fn body_filename_footing(
    filename: &std::path::Path,
) -> crate::Result<BodyFilenameFooting> {
    #[cfg(unix)]
    {
        unix::body_filename_footing(filename)
    }
    #[cfg(not(unix))]
    {
        unsupported_admit_writable_filename(filename)?;
        Ok(BodyFilenameFooting::Unmarked)
    }
}

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use super::maintenance_candidates;
    use crate::{Error, Result};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    #[derive(Debug)]
    pub struct PathPin {
        path: PathBuf,
        file: File,
        dev: u64,
        ino: u64,
        mount: String,
        directory: bool,
    }

    fn open_no_follow(path: &Path, directory: bool) -> Result<File> {
        // O_NONBLOCK prevents a raced replacement with a FIFO from blocking.
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(
                libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 },
            )
            .open(path)?)
    }

    impl PathPin {
        pub fn device(&self) -> u64 {
            self.dev
        }
        pub fn mount(&self) -> &str {
            &self.mount
        }

        pub fn open(path: &Path, directory: bool) -> Result<Self> {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink()
                || (directory && !metadata.is_dir())
                || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
            {
                return Err(Error::engine(format!(
                    "managed path must be a real directory or a single-link regular file: {}",
                    path.display()
                )));
            }
            let file = open_no_follow(path, directory)?;
            let opened = file.metadata()?;
            if (metadata.dev(), metadata.ino()) != (opened.dev(), opened.ino()) {
                return Err(Error::engine(format!(
                    "managed path changed during admission: {}",
                    path.display()
                )));
            }
            let pin = Self {
                path: path.to_path_buf(),
                mount: mount_identity(&file)?,
                dev: opened.dev(),
                ino: opened.ino(),
                file,
                directory,
            };
            pin.revalidate()?;
            Ok(pin)
        }

        pub fn revalidate(&self) -> Result<()> {
            let observed = std::fs::symlink_metadata(&self.path)?;
            if observed.file_type().is_symlink()
                || (observed.dev(), observed.ino()) != (self.dev, self.ino)
                || (self.directory && !observed.is_dir())
                || (!self.directory && (!observed.is_file() || observed.nlink() != 1))
            {
                return Err(Error::engine(format!(
                    "managed path identity changed: {}",
                    self.path.display()
                )));
            }
            let current = open_no_follow(&self.path, self.directory)?;
            let metadata = current.metadata()?;
            let held = self.file.metadata()?;
            if (metadata.dev(), metadata.ino()) != (self.dev, self.ino)
                || (self.directory && !metadata.is_dir())
                || (!self.directory
                    && (!metadata.is_file() || metadata.nlink() != 1 || held.nlink() != 1))
                || mount_identity(&current)? != self.mount
                || mount_identity(&self.file)? != self.mount
            {
                return Err(Error::engine(format!(
                    "managed path inode or mount changed: {}",
                    self.path.display()
                )));
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn mount_identity(file: &File) -> Result<String> {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        info.lines()
            .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
            .filter(|id| id.parse::<u64>().is_ok())
            .map(str::to_owned)
            .ok_or_else(|| Error::engine("managed path FD has no Linux mount identity"))
    }

    #[cfg(target_os = "macos")]
    fn mount_identity(file: &File) -> Result<String> {
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs initializes the buffer on success; file lives through
        // the call and f_mntonname is a kernel supplied NUL-terminated name.
        if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(
            unsafe { std::ffi::CStr::from_ptr(stat.f_mntonname.as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn mount_identity(_file: &File) -> Result<String> {
        Err(Error::engine(
            "HOSTED managed-path mount admission supports Linux and macOS",
        ))
    }

    fn platform_root_alias(path: &Path) -> Result<bool> {
        #[cfg(target_os = "macos")]
        if ["/var", "/tmp", "/etc"]
            .iter()
            .any(|alias| path == Path::new(alias))
        {
            return Ok(std::fs::canonicalize(path)?
                == Path::new("/private").join(path.strip_prefix("/").expect("absolute alias")));
        }
        let _ = path;
        Ok(false)
    }

    pub fn check_root_components(path: &Path) -> Result<()> {
        let mut prefix = PathBuf::new();
        for component in path.components() {
            prefix.push(component.as_os_str());
            if std::fs::symlink_metadata(&prefix)?.file_type().is_symlink()
                && !platform_root_alias(&prefix)?
            {
                return Err(Error::engine(format!(
                    "managed root contains a symlink component: {}",
                    prefix.display()
                )));
            }
        }
        Ok(())
    }

    pub fn check_sqlite_consumer_path(path: &Path) -> Result<()> {
        let spelling = path
            .to_str()
            .ok_or_else(|| Error::engine("managed SQLite path must be lossless UTF-8"))?;
        // Match the real probe/preflight/migration/verification consumers, rather
        // than maintaining a parallel approximation of SQLx URL decoding.
        let options: sqlx::sqlite::SqliteConnectOptions = format!("sqlite:{spelling}")
            .parse()
            .map_err(|err| Error::engine(format!("managed SQLite path cannot be parsed: {err}")))?;
        if spelling.contains('?') || options.get_filename().as_os_str() != path.as_os_str() {
            return Err(Error::engine(
                "managed SQLite path changes under consumer URL parsing or contains query syntax",
            ));
        }
        Ok(())
    }

    /// Resource ceiling, not a session/protocol limit. Reservations that fail after
    /// strong insertion retain their entry; pre-insertion failures release safely.
    pub const MAX_PROCESS_OWNERS: usize = 1024;
    pub const METADATA_DIRECTORY: &str = ".native-custody";
    const FORMAT: u32 = 1;
    const MAX_METADATA_BYTES: u64 = 8192;

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Intent {
        version: u32,
        root: PathBuf,
        path: PathBuf,
        generation: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Generation {
        version: u32,
        generation: String,
        dev: u64,
        ino: u64,
        mount: String,
        lock_dev: u64,
        lock_ino: u64,
        lock_mount: String,
    }

    #[derive(Debug)]
    struct Owner {
        intent: Intent,
        execution: std::sync::Arc<crate::db::enrolled::ExecutionOwner>,
        pins: Vec<PathPin>,
        lock: PathPin,
        file: Option<PathPin>,
    }

    impl Owner {
        fn revalidate(&self) -> Result<()> {
            for pin in &self.pins {
                pin.revalidate()?;
            }
            self.lock.revalidate()?;
            if let Some(file) = &self.file {
                file.revalidate()?;
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct Registry {
        owners: HashMap<PathBuf, Owner>,
    }

    static OWNERS: OnceLock<Mutex<Registry>> = OnceLock::new();

    fn registry() -> Result<std::sync::MutexGuard<'static, Registry>> {
        OWNERS
            .get_or_init(|| Mutex::new(Registry::default()))
            .lock()
            .map_err(|_| Error::engine("custody owner registry is poisoned"))
    }

    fn present(path: &Path) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn physical_path(path: &Path) -> Result<PathBuf> {
        let absolute = std::path::absolute(path)?;
        if present(&absolute)? {
            return Ok(std::fs::canonicalize(absolute)?);
        }
        let ancestor = absolute
            .ancestors()
            .skip(1)
            .find(|p| p.exists())
            .ok_or_else(|| Error::engine("custody filename has no existing ancestor"))?;
        Ok(std::fs::canonicalize(ancestor)?.join(
            absolute
                .strip_prefix(ancestor)
                .map_err(|_| Error::engine("custody filename escapes its ancestor"))?,
        ))
    }

    // Resolve parent aliases but retain the supplied basename. A replaced
    // enrolled filename that redirects to an unmanaged file must not escape
    // its original reservation by canonicalizing the final component away.
    fn locator_path(path: &Path) -> Result<PathBuf> {
        let absolute = std::path::absolute(path)?;
        let parent = absolute
            .parent()
            .ok_or_else(|| Error::engine("SQLite filename has no parent"))?;
        let name = absolute
            .file_name()
            .ok_or_else(|| Error::engine("SQLite filename has no basename"))?;
        Ok(physical_path(parent)?.join(name))
    }

    fn marked(path: &Path, registry: &Registry) -> Result<bool> {
        let (_, expected, slot) = paths(path)?;
        Ok(present(&expected)? || present(&slot)? || registry.owners.contains_key(path))
    }

    fn paths(path: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let parent = path
            .parent()
            .ok_or_else(|| Error::engine("custody filename has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| Error::engine("custody filename has no basename"))?;
        let mut expected_name = name.to_os_string();
        expected_name.push(".expected.json");
        let metadata = parent.join(METADATA_DIRECTORY);
        Ok((
            metadata.clone(),
            metadata.join(expected_name),
            metadata.join(name),
        ))
    }

    fn read_metadata<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        read_metadata_pinned(path).map(|(value, _pin)| value)
    }

    fn read_metadata_pinned<T: serde::de::DeserializeOwned>(path: &Path) -> Result<(T, PathPin)> {
        let pin = PathPin::open(path, false)?;
        if pin.file.metadata()?.len() > MAX_METADATA_BYTES {
            return Err(Error::engine("custody metadata exceeds its bound"));
        }
        let mut bytes = Vec::new();
        (&pin.file)
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)?;
        pin.revalidate()?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(Error::engine("custody metadata exceeds its bound"));
        }
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::engine("malformed custody metadata"))?;
        Ok((value, pin))
    }

    struct BodyPresence {
        path: PathBuf,
        present: bool,
    }

    impl BodyPresence {
        fn observe(path: PathBuf) -> Result<Self> {
            let present = present(&path)?;
            Ok(Self { path, present })
        }

        fn revalidate(&self) -> Result<()> {
            if present(&self.path)? != self.present {
                return Err(Error::engine(
                    "body custody presence changed during discovery",
                ));
            }
            Ok(())
        }
    }

    fn same_body_pin(a: &PathPin, b: &PathPin) -> bool {
        (a.dev, a.ino, &a.mount) == (b.dev, b.ino, &b.mount)
    }

    /// Nonacquiring observation of this filename only. Pins never escape.
    /// Final rechecks detect inconsistent observations, not an atomic snapshot.
    pub(super) fn body_filename_footing(filename: &Path) -> Result<super::BodyFilenameFooting> {
        use super::BodyFilenameFooting::{KnownExcludedMarked, Unmarked};
        if filename == Path::new(":memory:") {
            return Ok(Unmarked);
        }
        let path = physical_path(filename)?;
        let locator = locator_path(filename)?;
        if [filename, path.as_path(), locator.as_path()]
            .iter()
            .any(|p| p.components().any(|c| c.as_os_str() == METADATA_DIRECTORY))
        {
            return Err(Error::engine(
                "custody artifacts are not body SQLite storage",
            ));
        }
        // Do not initialize OWNERS, acquire writer custody or consult an
        // ExecutionOwner/Db marker as an unmanaged classification shortcut.
        let owners = OWNERS
            .get()
            .map(|registry| {
                registry
                    .lock()
                    .map_err(|_| Error::engine("custody owner registry is poisoned"))
            })
            .transpose()?;
        let is_marked = |candidate: &Path| -> Result<bool> {
            let (_, expected, slot) = paths(candidate)?;
            Ok(present(&expected)?
                || present(&slot)?
                || owners
                    .as_ref()
                    .is_some_and(|r| r.owners.contains_key(candidate)))
        };
        let resolved_marked = is_marked(&path)?;
        let locator_marked = is_marked(&locator)?;
        let (metadata, expected, slot) = paths(&path)?;
        if !resolved_marked && !locator_marked {
            if present(&metadata)? {
                PathPin::open(&metadata, true)?.revalidate()?;
            }
            return Ok(Unmarked);
        }
        if locator != path {
            return Err(Error::engine(
                "body custody consumer redirects a marked filename",
            ));
        }
        // D1: only a missing FINAL component is permitted for complete pending.
        let destination = BodyPresence::observe(path.clone())?;
        let absolute = std::path::absolute(filename)?;
        check_root_components(if destination.present {
            &absolute
        } else {
            absolute
                .parent()
                .ok_or_else(|| Error::engine("custody filename has no parent"))?
        })?;
        check_sqlite_consumer_path(filename)?;
        let lock_path = slot.join("owner.lock");
        let ready_path = slot.join("generation.json");
        let mut observations = vec![destination];
        for required in [&metadata, &expected, &slot, &lock_path] {
            let observation = BodyPresence::observe(required.clone())?;
            if !observation.present {
                return Err(Error::engine("body custody reservation is incomplete"));
            }
            observations.push(observation);
        }
        let (intent, expected_pin) = read_metadata_pinned::<Intent>(&expected)?;
        validate_intent(&intent, &path)?;
        let mut pins = envelope(&intent)?;
        pins.push(expected_pin);
        let lock = PathPin::open(&lock_path, false)?;
        if lock.dev != pins[0].dev || lock.mount != pins[0].mount {
            return Err(Error::engine("custody lock is on a foreign mount"));
        }
        let owner = owners.as_ref().and_then(|r| r.owners.get(&path));
        if let Some(owner) = owner {
            if owner.intent != intent {
                return Err(Error::engine("body custody retained intent differs"));
            }
            owner.revalidate()?;
            if !same_body_pin(&owner.lock, &lock) {
                return Err(Error::engine("body custody retained lock differs"));
            }
        }
        let ready = BodyPresence::observe(ready_path.clone())?;
        let ready_present = ready.present;
        observations.push(ready);
        if ready_present {
            let (generation, ready_pin) = read_metadata_pinned::<Generation>(&ready_path)?;
            let file = live_file(&intent)?;
            if generation != generation_for(&intent, &file, &lock) {
                return Err(Error::engine("custody file generation changed"));
            }
            if owner
                .and_then(|o| o.file.as_ref())
                .is_some_and(|retained| !same_body_pin(retained, &file))
            {
                return Err(Error::engine("body custody retained file differs"));
            }
            pins.push(ready_pin);
            pins.push(file);
        } else {
            if owner.is_some_and(|o| o.file.is_some()) {
                return Err(Error::engine(
                    "finalized body custody generation is missing",
                ));
            }
            if observations[0].present {
                pins.push(live_file(&intent)?);
            }
        }
        // Keep the three fixed sidecar observations/pins to the final recheck,
        // even in absent-destination pending. No body or directory enumeration.
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut name = intent.path.as_os_str().to_os_string();
            name.push(suffix);
            let observation = BodyPresence::observe(PathBuf::from(name))?;
            if observation.present {
                let pin = PathPin::open(&observation.path, false)?;
                if pin.dev != pins[0].dev || pin.mount != pins[0].mount {
                    return Err(Error::engine("custody sidecar is on a foreign mount"));
                }
                pins.push(pin);
            }
            observations.push(observation);
        }
        pins.push(lock);
        if let Some(owner) = owner {
            owner.revalidate()?;
        }
        for pin in &pins {
            pin.revalidate()?;
        }
        for observation in &observations {
            observation.revalidate()?;
        }
        Ok(KnownExcludedMarked)
    }

    #[cfg(test)]
    mod body_footing_tests {
        use super::*;
        use crate::managed_custody::BodyFilenameFooting::{KnownExcludedMarked, Unmarked};
        use std::os::unix::{ffi::OsStringExt, fs::symlink};

        fn reservation() -> (tempfile::TempDir, PathBuf, Enrollment) {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("databases")).unwrap();
            let generation = uuid::Uuid::new_v4().to_string();
            let path = std::fs::canonicalize(root.path().join("databases"))
                .unwrap()
                .join(format!("{generation}.db"));
            let enrollment = reserve_fresh_adoption(root.path(), &path, &generation).unwrap();
            (root, path, enrollment)
        }

        fn assert_excluded(path: &Path) {
            assert_eq!(body_filename_footing(path).unwrap(), KnownExcludedMarked);
        }

        #[test]
        fn complete_pending_absent_then_single_link_then_finalized_is_observation_only() {
            let (_root, path, enrollment) = reservation();
            assert!(!present(&path).unwrap());
            assert_excluded(&path);
            assert!(registry().unwrap().owners[&path].file.is_none());
            std::fs::write(&path, b"body never read or changed by discovery").unwrap();
            assert_excluded(&path);
            assert!(registry().unwrap().owners[&path].file.is_none());
            let before = std::fs::read(&path).unwrap();
            enrollment.finalize().unwrap();
            assert_excluded(&path);
            assert!(registry().unwrap().owners[&path].file.is_some());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }

        #[test]
        fn ready_published_before_retaining_file_does_not_mutate_owner() {
            let (_root, path, enrollment) = reservation();
            std::fs::write(&path, b"single-link ready canary").unwrap();
            let (_, _, slot) = paths(&path).unwrap();
            // Exact finalize publication phase before owner.file/pin retention.
            let generation = {
                let owners = registry().unwrap();
                generation_for(
                    &enrollment.intent,
                    &live_file(&enrollment.intent).unwrap(),
                    &owners.owners[&path].lock,
                )
            };
            write_metadata(&slot.join("generation.json"), &generation).unwrap();
            assert_excluded(&path);
            assert!(registry().unwrap().owners[&path].file.is_none());
            enrollment.finalize().unwrap();
            assert_excluded(&path);
        }

        #[test]
        fn unmanaged_memory_and_non_utf8_neighbor_do_not_inherit_reservation() {
            let (_root, path, _enrollment) = reservation();
            let parent = path.parent().unwrap();
            let ordinary = parent.join("ordinary.db");
            let non_utf8 = parent.join(std::ffi::OsString::from_vec(vec![b'd', 0xff]));
            for file in [&ordinary, &non_utf8] {
                std::fs::write(file, b"unmanaged").unwrap();
                assert_eq!(body_filename_footing(file).unwrap(), Unmarked);
            }
            assert_eq!(
                body_filename_footing(Path::new(":memory:")).unwrap(),
                Unmarked
            );
            assert_eq!(
                body_filename_footing(&parent.join("absent-ordinary.db")).unwrap(),
                Unmarked
            );
        }

        #[test]
        fn torn_reservations_never_use_pending_exclusion() {
            // Pre-return expected-only and expected+slot-without-lock phases.
            for slot_present in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let parent = root.path().join("databases");
                std::fs::create_dir(&parent).unwrap();
                let path = parent.join("torn.db");
                let intent =
                    intent_for(root.path(), &path, &uuid::Uuid::new_v4().to_string()).unwrap();
                let (metadata, expected, slot) = paths(&path).unwrap();
                std::fs::create_dir(metadata).unwrap();
                write_metadata(&expected, &intent).unwrap();
                if slot_present {
                    std::fs::create_dir(slot).unwrap();
                }
                assert!(body_filename_footing(&path).is_err());
            }
            // Completed reservations lose each required metadata entry in turn.
            for missing_expected in [true, false] {
                let (_root, path, _enrollment) = reservation();
                let (_, expected, slot) = paths(&path).unwrap();
                std::fs::remove_file(if missing_expected {
                    expected
                } else {
                    slot.join("owner.lock")
                })
                .unwrap();
                assert!(body_filename_footing(&path).is_err());
            }
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("slot-only.db");
            let (metadata, _, slot) = paths(&path).unwrap();
            std::fs::create_dir(metadata).unwrap();
            std::fs::create_dir(slot).unwrap();
            assert!(body_filename_footing(&path).is_err());
        }

        #[test]
        fn intent_and_generation_closed_decode_and_byte_bounds_refuse_corruption() {
            for generation_metadata in [false, true] {
                for corruption in 0..4 {
                    let (_root, path, enrollment) = reservation();
                    if generation_metadata {
                        std::fs::write(&path, b"database").unwrap();
                        enrollment.finalize().unwrap();
                    }
                    let (_, expected, slot) = paths(&path).unwrap();
                    let metadata = if generation_metadata {
                        slot.join("generation.json")
                    } else {
                        expected
                    };
                    let original = std::fs::read(&metadata).unwrap();
                    let bytes = match corruption {
                        0 => b"{".to_vec(),
                        1 => vec![b' '; MAX_METADATA_BYTES as usize + 1],
                        2 => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&original).unwrap();
                            value["unexpected"] = serde_json::json!(true);
                            serde_json::to_vec(&value).unwrap()
                        }
                        _ => {
                            let mut bytes = original;
                            bytes.pop();
                            bytes.extend_from_slice(b",\"version\":1}");
                            bytes
                        }
                    };
                    std::fs::write(&metadata, bytes).unwrap();
                    assert!(body_filename_footing(&path).is_err());
                }
            }
        }

        #[test]
        fn wrong_intent_stale_generation_and_replaced_lock_or_file_refuse() {
            for corruption in 0..4 {
                let (root, path, enrollment) = reservation();
                std::fs::write(&path, b"original file").unwrap();
                enrollment.finalize().unwrap();
                let (_, expected, slot) = paths(&path).unwrap();
                match corruption {
                    0 => {
                        let mut intent: Intent = read_metadata(&expected).unwrap();
                        intent.generation = uuid::Uuid::new_v4().to_string();
                        std::fs::write(expected, serde_json::to_vec(&intent).unwrap()).unwrap();
                    }
                    1 => {
                        let ready = slot.join("generation.json");
                        let mut generation: Generation = read_metadata(&ready).unwrap();
                        generation.ino = generation.ino.wrapping_add(1);
                        std::fs::write(ready, serde_json::to_vec(&generation).unwrap()).unwrap();
                    }
                    2 => {
                        let lock = slot.join("owner.lock");
                        std::fs::rename(&lock, slot.join("old.lock")).unwrap();
                        std::fs::write(lock, b"").unwrap();
                    }
                    _ => {
                        std::fs::rename(&path, root.path().join("old.db")).unwrap();
                        std::fs::write(&path, b"replacement file").unwrap();
                    }
                }
                assert!(body_filename_footing(&path).is_err());
            }
        }

        #[test]
        fn finalized_missing_ready_or_target_cannot_downgrade_to_pending() {
            for ready_missing in [true, false] {
                let (_root, path, enrollment) = reservation();
                std::fs::write(&path, b"database").unwrap();
                enrollment.finalize().unwrap();
                let (_, _, slot) = paths(&path).unwrap();
                std::fs::remove_file(if ready_missing {
                    slot.join("generation.json")
                } else {
                    path.clone()
                })
                .unwrap();
                assert!(body_filename_footing(&path).is_err());
            }
        }

        #[test]
        fn pending_multilink_sidecar_alias_and_marked_path_aliases_refuse() {
            let (root, path, _enrollment) = reservation();
            std::fs::write(&path, b"pending").unwrap();
            let link = root.path().join("stage.db");
            std::fs::hard_link(&path, &link).unwrap();
            assert!(body_filename_footing(&path).is_err());
            std::fs::remove_file(link).unwrap();
            assert_excluded(&path);
            let sidecar = PathBuf::from(format!("{}-wal", path.display()));
            symlink(&path, &sidecar).unwrap();
            assert!(body_filename_footing(&path).is_err());
            std::fs::remove_file(sidecar).unwrap();
            let alias = root.path().join("alias.db");
            symlink(&path, &alias).unwrap();
            assert!(body_filename_footing(&alias).is_err());
            let parent_alias = root.path().join("alias-directory");
            symlink(path.parent().unwrap(), &parent_alias).unwrap();
            assert!(body_filename_footing(&parent_alias.join(path.file_name().unwrap())).is_err());
            let (_, _, slot) = paths(&path).unwrap();
            assert!(body_filename_footing(&slot.join("owner.lock")).is_err());
        }

        #[test]
        fn final_presence_recheck_refuses_appearance_and_disappearance() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("observation");
            let absent = BodyPresence::observe(path.clone()).unwrap();
            std::fs::write(&path, b"appeared").unwrap();
            assert!(absent.revalidate().is_err());
            let present = BodyPresence::observe(path.clone()).unwrap();
            std::fs::remove_file(path).unwrap();
            assert!(present.revalidate().is_err());
        }

        fn cold_fixture_bytes(path: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
            let (_, expected, slot) = paths(path).unwrap();
            let mut files = vec![
                path.to_path_buf(),
                expected,
                slot.join("owner.lock"),
                slot.join("generation.json"),
                path.with_file_name("cold-unmarked.db"),
            ];
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut name = path.as_os_str().to_os_string();
                name.push(suffix);
                files.push(PathBuf::from(name));
            }
            files
                .into_iter()
                .map(|file| {
                    let bytes = match std::fs::read(&file) {
                        Ok(bytes) => Some(bytes),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => panic!("cold fixture read failed: {error}"),
                    };
                    (file, bytes)
                })
                .collect()
        }

        #[test]
        fn cold_process_body_footing_probe() {
            let Some(path) = std::env::var_os("NATIVE_BODY_FOOTING_COLD_PATH").map(PathBuf::from)
            else {
                // Ordinary suite invocation is harmless; only the exact child
                // invocation below supplies a genuine parent-created fixture.
                return;
            };
            let mode = std::env::var("NATIVE_BODY_FOOTING_COLD_MODE").unwrap();
            assert!(OWNERS.get().is_none());
            let (metadata, expected, slot) = paths(&path).unwrap();
            assert!(metadata.is_dir());
            assert!(expected.is_file());
            assert!(slot.is_dir());
            assert!(slot.join("owner.lock").is_file());
            match mode.as_str() {
                "pending-absent" => {
                    assert!(!present(&path).unwrap());
                    assert!(!present(&slot.join("generation.json")).unwrap());
                }
                "pending-present" => {
                    assert!(present(&path).unwrap());
                    assert!(!present(&slot.join("generation.json")).unwrap());
                }
                "finalized" => {
                    assert!(present(&path).unwrap());
                    assert!(present(&slot.join("generation.json")).unwrap());
                }
                _ => panic!("unknown cold body-footing fixture mode"),
            }
            let before = cold_fixture_bytes(&path);
            assert_excluded(&path);
            assert!(OWNERS.get().is_none());
            assert_eq!(
                body_filename_footing(&path.with_file_name("cold-unmarked.db")).unwrap(),
                Unmarked
            );
            assert!(OWNERS.get().is_none());
            assert_eq!(cold_fixture_bytes(&path), before);
            assert!(metadata.is_dir());
            assert!(slot.is_dir());
            println!("BODY-FOOTING-COLD-COMPLETE:{mode}");
        }

        async fn cold_process_fixture(mode: &str) {
            let (_root, path, enrollment) = reservation();
            match mode {
                "pending-absent" => {}
                "pending-present" | "finalized" => {
                    std::fs::write(&path, b"cold body bytes \xef\xbb\xbf unchanged").unwrap();
                    if mode == "finalized" {
                        enrollment.finalize().unwrap();
                    }
                }
                _ => panic!("unknown parent cold body-footing fixture mode"),
            }
            std::fs::write(
                path.with_file_name("cold-unmarked.db"),
                b"ordinary neighbor",
            )
            .unwrap();
            let before = cold_fixture_bytes(&path);
            let test_name = format!(
                "{}::cold_process_body_footing_probe",
                module_path!().split_once("::").unwrap().1
            );
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &test_name, "--nocapture"])
                    .env("NATIVE_BODY_FOOTING_COLD_PATH", &path)
                    .env("NATIVE_BODY_FOOTING_COLD_MODE", mode)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .expect("bounded cold body-footing child")
            .unwrap();
            assert!(
                output.status.success(),
                "cold child failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout)
                .contains(&format!("BODY-FOOTING-COLD-COMPLETE:{mode}")));
            assert_eq!(cold_fixture_bytes(&path), before);
            let owners = registry().unwrap();
            assert_eq!(owners.owners[&path].file.is_some(), mode == "finalized");
        }

        #[tokio::test]
        async fn cold_process_complete_pending_absent_does_not_initialize_owners() {
            cold_process_fixture("pending-absent").await;
        }

        #[tokio::test]
        async fn cold_process_complete_pending_single_link_does_not_initialize_owners() {
            cold_process_fixture("pending-present").await;
        }

        #[tokio::test]
        async fn cold_process_finalized_without_local_owner_does_not_initialize_owners() {
            cold_process_fixture("finalized").await;
        }
    }

    fn sync_directory(path: &Path) -> Result<()> {
        PathPin::open(path, true)?.file.sync_all()?;
        Ok(())
    }

    // Immutable create-only metadata. A torn write remains detectable and refuses;
    // recovery never overwrites malformed evidence or replaces a stable lock inode.
    fn write_metadata<T: Serialize>(path: &Path, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value)
            .map_err(|_| Error::engine("cannot encode custody metadata"))?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(Error::engine("custody metadata exceeds its bound"));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_directory(
            path.parent()
                .ok_or_else(|| Error::engine("metadata has no parent"))?,
        )
    }

    fn intent_for(root: &Path, path: &Path, generation: &str) -> Result<Intent> {
        if uuid::Uuid::parse_str(generation)
            .map(|v| v.to_string() != generation)
            .unwrap_or(true)
        {
            return Err(Error::engine("custody generation must be a canonical UUID"));
        }
        let root = std::fs::canonicalize(root)?;
        let path = physical_path(path)?;
        check_root_components(&root)?;
        check_sqlite_consumer_path(&path)?;
        if path.parent().and_then(Path::parent) != Some(root.as_path()) {
            return Err(Error::engine(
                "custody file must be inside an immediate root subdirectory",
            ));
        }
        Ok(Intent {
            version: FORMAT,
            root,
            path,
            generation: generation.into(),
        })
    }

    fn validate_intent(intent: &Intent, path: &Path) -> Result<()> {
        if intent.version != FORMAT
            || intent_for(&intent.root, path, &intent.generation)? != *intent
        {
            return Err(Error::engine("unsupported or inconsistent custody intent"));
        }
        Ok(())
    }

    fn envelope(intent: &Intent) -> Result<Vec<PathPin>> {
        validate_intent(intent, &intent.path)?;
        let mut pins = intent
            .root
            .ancestors()
            .map(|p| PathPin::open(p, true))
            .collect::<Result<Vec<_>>>()?;
        let parent = PathPin::open(
            intent
                .path
                .parent()
                .ok_or_else(|| Error::engine("custody path has no parent"))?,
            true,
        )?;
        if parent.dev != pins[0].dev || parent.mount != pins[0].mount {
            return Err(Error::engine("custody parent is on a foreign mount"));
        }
        let (metadata, expected, slot) = paths(&intent.path)?;
        for directory in [metadata, slot] {
            let pin = PathPin::open(&directory, true)?;
            if pin.dev != parent.dev || pin.mount != parent.mount {
                return Err(Error::engine("custody metadata is on a foreign mount"));
            }
            pins.push(pin);
        }
        let expected_pin = PathPin::open(&expected, false)?;
        if expected_pin.dev != parent.dev || expected_pin.mount != parent.mount {
            return Err(Error::engine("custody reservation is on a foreign mount"));
        }
        pins.push(expected_pin);
        pins.push(parent);
        Ok(pins)
    }

    fn generation_for(intent: &Intent, file: &PathPin, lock: &PathPin) -> Generation {
        Generation {
            version: FORMAT,
            generation: intent.generation.clone(),
            dev: file.dev,
            ino: file.ino,
            mount: file.mount.clone(),
            lock_dev: lock.dev,
            lock_ino: lock.ino,
            lock_mount: lock.mount.clone(),
        }
    }

    fn live_file(intent: &Intent) -> Result<PathPin> {
        let file = PathPin::open(&intent.path, false)?;
        let parent = PathPin::open(
            intent
                .path
                .parent()
                .ok_or_else(|| Error::engine("custody path has no parent"))?,
            true,
        )?;
        if file.dev != parent.dev || file.mount != parent.mount {
            return Err(Error::engine("custody database is on a foreign mount"));
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut name = intent.path.as_os_str().to_os_string();
            name.push(suffix);
            let sidecar = PathBuf::from(name);
            if present(&sidecar)? {
                let pin = PathPin::open(&sidecar, false)?;
                if pin.dev != parent.dev || pin.mount != parent.mount {
                    return Err(Error::engine("custody sidecar is on a foreign mount"));
                }
            }
        }
        Ok(file)
    }

    fn acquire(registry: &mut Registry, intent: &Intent, limit: usize) -> Result<()> {
        let (_, expected, slot) = paths(&intent.path)?;
        let stored: Intent = read_metadata(&expected)?;
        if stored != *intent {
            return Err(Error::engine("custody intent changed"));
        }
        if let Some(owner) = registry.owners.get(&intent.path) {
            if owner.intent != *intent {
                return Err(Error::engine("process owner generation cannot be replaced"));
            }
            return owner.revalidate();
        }
        if registry.owners.len() >= limit {
            return Err(Error::engine(
                "process custody owner capacity exhausted; restart required",
            ));
        }
        let pins = envelope(intent)?;
        let lock = PathPin::open(&slot.join("owner.lock"), false)?;
        if lock.dev != pins[0].dev || lock.mount != pins[0].mount {
            return Err(Error::engine("custody lock is on a foreign mount"));
        }
        let ready = slot.join("generation.json");
        if present(&ready)? {
            let generation: Generation = read_metadata(&ready)?;
            if generation.version != FORMAT
                || generation.generation != intent.generation
                || generation.lock_dev != lock.dev
                || generation.lock_ino != lock.ino
                || generation.lock_mount != lock.mount
            {
                return Err(Error::engine("custody stable lock generation changed"));
            }
        }
        fs2::FileExt::try_lock_exclusive(&lock.file)
            .map_err(|_| Error::engine("custody database is owned by another process"))?;
        lock.revalidate()?;
        // Strong registry retention, even if every Db/pool closes or detaches.
        registry.owners.insert(
            intent.path.clone(),
            Owner {
                intent: intent.clone(),
                execution: std::sync::Arc::new(crate::db::enrolled::ExecutionOwner::new(
                    intent.path.clone(),
                    intent.generation.clone(),
                )),
                pins,
                lock,
                file: None,
            },
        );
        Ok(())
    }

    /// Testable, immutable enrollment token. Only fresh adoption calls this producer;
    /// root/layout/catalog checks remain in held. No existing-file conversion.
    #[derive(Debug)]
    pub struct Enrollment {
        intent: Intent,
    }

    pub fn reserve_fresh_adoption(
        root: &Path,
        path: &Path,
        generation: &str,
    ) -> Result<Enrollment> {
        let mut owners = registry()?;
        reserve_in(&mut owners, root, path, generation, MAX_PROCESS_OWNERS)
    }

    fn reserve_in(
        registry: &mut Registry,
        root: &Path,
        path: &Path,
        generation: &str,
        limit: usize,
    ) -> Result<Enrollment> {
        let intent = intent_for(root, path, generation)?;
        let (metadata, expected, slot) = paths(&intent.path)?;
        if !registry.owners.contains_key(&intent.path) && registry.owners.len() >= limit {
            return Err(Error::engine(
                "process custody owner capacity exhausted; no publication admitted",
            ));
        }
        if present(&expected)? {
            let stored: Intent = read_metadata(&expected)?;
            if stored != intent {
                return Err(Error::engine("custody reservation differs from adoption"));
            }
        } else {
            if present(&intent.path)? || present(&slot)? {
                return Err(Error::engine(
                    "missing expected custody reservation or existing-file conversion refused",
                ));
            }
            if !present(&metadata)? {
                std::fs::create_dir(&metadata)?;
                sync_directory(intent.path.parent().unwrap())?;
            }
            PathPin::open(&metadata, true)?.revalidate()?;
            // Detectable durable pending reservation BEFORE destination publication.
            write_metadata(&expected, &intent)?;
        }
        if !present(&slot)? {
            std::fs::create_dir(&slot)?;
            sync_directory(&metadata)?;
        }
        PathPin::open(&slot, true)?.revalidate()?;
        let lock_path = slot.join("owner.lock");
        if !present(&lock_path)? {
            if registry.owners.contains_key(&intent.path) || present(&slot.join("generation.json"))?
            {
                return Err(Error::engine("retained or ready custody lock is missing"));
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&lock_path)?
                .sync_all()?;
            sync_directory(&slot)?;
        }
        acquire(registry, &intent, limit)?;
        Ok(Enrollment { intent })
    }

    impl Enrollment {
        /// After staged link removal/verified absence: fresh single-link admission,
        /// immutable generation, fsync metadata directory, then consumer admission.
        pub fn finalize(&self) -> Result<()> {
            let mut registry = registry()?;
            let owner = registry
                .owners
                .get_mut(&self.intent.path)
                .ok_or_else(|| Error::engine("custody reservation has no process owner"))?;
            owner.revalidate()?;
            let (_, expected, _) = paths(&self.intent.path)?;
            if read_metadata::<Intent>(&expected)? != self.intent {
                return Err(Error::engine(
                    "custody reservation changed before finalization",
                ));
            }
            let file = live_file(&self.intent)?;
            let generation = generation_for(&self.intent, &file, &owner.lock);
            let (_, _, slot) = paths(&self.intent.path)?;
            let ready = slot.join("generation.json");
            if present(&ready)? {
                if read_metadata::<Generation>(&ready)? != generation {
                    return Err(Error::engine("custody file generation changed"));
                }
            } else {
                write_metadata(&ready, &generation)?;
            }
            sync_directory(&slot)?;
            sync_directory(slot.parent().unwrap())?;
            if owner.file.is_none() {
                owner.pins.push(PathPin::open(&ready, false)?);
                owner.file = Some(file);
            }
            owner.revalidate()
        }
    }

    /// Discover using the REAL SQLite consumer filename (after SQLx URL parsing).
    /// Resolved aliases find enrollment first, then unsupported spellings refuse.
    /// Unmanaged files retain independent multi-open behavior.
    pub fn admit_writable_filename(filename: &Path) -> Result<()> {
        if filename == Path::new(":memory:") {
            return Ok(());
        }
        let path = physical_path(filename)?;
        if path
            .components()
            .any(|c| c.as_os_str() == METADATA_DIRECTORY)
        {
            return Err(Error::engine(
                "custody artifacts are not writable SQLite storage",
            ));
        }
        let (metadata, expected, slot) = paths(&path)?;
        let mut registry = registry()?;
        let locator = locator_path(filename)?;
        if locator != path && marked(&locator, &registry)? {
            return Err(Error::engine(
                "custody consumer redirects an enrolled filename",
            ));
        }
        if !marked(&path, &registry)? {
            if present(&metadata)? {
                PathPin::open(&metadata, true)?.revalidate()?;
            }
            return Ok(());
        }
        check_root_components(&std::path::absolute(filename)?)?;
        check_sqlite_consumer_path(filename)?;
        let intent: Intent = read_metadata(&expected)?;
        validate_intent(&intent, &path)?;
        let generation: Generation = read_metadata(&slot.join("generation.json"))?;
        let file = live_file(&intent)?;
        let lock = PathPin::open(&slot.join("owner.lock"), false)?;
        if generation != generation_for(&intent, &file, &lock) {
            return Err(Error::engine("custody file generation changed"));
        }
        acquire(&mut registry, &intent, MAX_PROCESS_OWNERS)?;
        let owner = registry.owners.get_mut(&path).unwrap();
        lock.revalidate()?;
        if generation != generation_for(&intent, &file, &owner.lock) {
            return Err(Error::engine("custody owner lock changed during admission"));
        }
        if owner.file.is_none() {
            owner
                .pins
                .push(PathPin::open(&slot.join("generation.json"), false)?);
            owner.file = Some(file);
        }
        owner.revalidate()
    }

    /// Read-only pool detection acquires no process writer ownership. Pending
    /// or malformed markers still select the deny-main-write guard, not authority.
    pub(crate) fn enrolled_read_filename(filename: &Path) -> Result<bool> {
        if filename == Path::new(":memory:") || filename.as_os_str().is_empty() {
            return Ok(false);
        }
        let path = physical_path(filename)?;
        let locator = locator_path(filename)?;
        let owners = registry()?;
        Ok(marked(&path, &owners)?
            || marked(&locator, &owners)?
            || path
                .components()
                .any(|c| c.as_os_str() == METADATA_DIRECTORY))
    }

    /// Internal generation-bound execution identity; does not grant any SQL role.
    pub(crate) fn execution_for_filename(
        filename: &Path,
    ) -> Result<Option<std::sync::Arc<crate::db::enrolled::ExecutionOwner>>> {
        admit_writable_filename(filename)?;
        if filename == Path::new(":memory:") {
            return Ok(None);
        }
        let path = physical_path(filename)?;
        let registry = registry()?;
        Ok(registry
            .owners
            .get(&path)
            .map(|owner| owner.execution.clone()))
    }

    /// First rollout does not port maintenance. Refuse before direct writes,
    /// replacement, unlink, or copying a source into a candidate alias.
    pub fn refuse_maintenance(path: &Path) -> Result<()> {
        if path
            .components()
            .any(|c| c.as_os_str() == METADATA_DIRECTORY)
        {
            return Err(Error::engine(
                "custody metadata/lock artifacts cannot be removed or replaced",
            ));
        }
        // Filesystem callers use the literal pathname; SQLite maintenance may
        // URL-decode it. Check both, preserving ordinary non-UTF-8 FS targets.
        for filename in maintenance_candidates(path) {
            let locator = locator_path(&filename)?;
            let owners = registry()?;
            if marked(&locator, &owners)? {
                return Err(Error::engine(
                    "enrolled custody filename cannot be removed or replaced",
                ));
            }
            drop(owners);
            let resolved = physical_path(&filename)?;
            for path in maintenance_candidates(&resolved) {
                if path
                    .components()
                    .any(|c| c.as_os_str() == METADATA_DIRECTORY)
                {
                    return Err(Error::engine(
                        "resolved custody artifacts cannot be removed or replaced",
                    ));
                }
                let (_, expected, slot) = paths(&path)?;
                if present(&expected)? || present(&slot)? || registry()?.owners.contains_key(&path)
                {
                    return Err(Error::engine(
                        "enrolled custody storage does not support maintenance/replacement/deletion; process restart alone does not authorize it",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Catalog-side durable adoption intent requires metadata even if current
    /// enrollment configuration is off. Missing metadata is never ordinary storage.
    pub fn require_enrolled_filename(filename: &Path) -> Result<()> {
        let path = physical_path(filename)?;
        let (_, expected, slot) = paths(&path)?;
        if !present(&expected)? || !present(&slot)? {
            return Err(Error::engine(
                "expected adoption custody metadata is missing",
            ));
        }
        admit_writable_filename(filename)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use sqlx::Connection;
        use std::os::unix::fs::symlink;

        fn destination() -> (tempfile::TempDir, PathBuf, String) {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("databases")).unwrap();
            let generation = uuid::Uuid::new_v4().to_string();
            let path = root
                .path()
                .join("databases")
                .join(format!("{generation}.db"));
            (root, path, generation)
        }

        fn publish(root: &Path, path: &Path, generation: &str) -> Enrollment {
            let enrollment = reserve_fresh_adoption(root, path, generation).unwrap();
            std::fs::write(path, b"physical pin canary").unwrap();
            enrollment.finalize().unwrap();
            enrollment
        }

        #[test]
        fn pending_reservation_and_failed_single_link_admission_never_become_writable() {
            let (root, path, generation) = destination();
            let enrollment = reserve_fresh_adoption(root.path(), &path, &generation).unwrap();
            assert!(admit_writable_filename(&path).is_err());
            let stage = root.path().join("stage.db");
            std::fs::write(&stage, b"canary").unwrap();
            std::fs::hard_link(&stage, &path).unwrap();
            assert!(enrollment.finalize().is_err());
            assert!(admit_writable_filename(&path).is_err());
            std::fs::remove_file(stage).unwrap();
            let resumed = reserve_fresh_adoption(root.path(), &path, &generation).unwrap();
            resumed.finalize().unwrap();
            admit_writable_filename(&path).unwrap();
            let (_, _, slot) = paths(&physical_path(&path).unwrap()).unwrap();
            let lock_inode = std::fs::metadata(slot.join("owner.lock")).unwrap().ino();
            resumed.finalize().unwrap();
            assert_eq!(
                std::fs::metadata(slot.join("owner.lock")).unwrap().ino(),
                lock_inode
            );
        }

        #[test]
        fn aliases_malformed_missing_metadata_and_stale_generations_refuse_without_touching_body() {
            let (root, path, generation) = destination();
            publish(root.path(), &path, &generation);
            let before = std::fs::read(&path).unwrap();
            let alias = root.path().join("alias.db");
            symlink(&path, &alias).unwrap();
            assert!(admit_writable_filename(&alias).is_err());
            let dir_alias = root.path().join("alias-directory");
            symlink(path.parent().unwrap(), &dir_alias).unwrap();
            assert!(admit_writable_filename(&dir_alias.join(path.file_name().unwrap())).is_err());
            assert!(refuse_maintenance(&alias).is_err());
            assert!(refuse_maintenance(&PathBuf::from(format!("{}-wal", path.display()))).is_err());
            let (_, expected, slot) = paths(&physical_path(&path).unwrap()).unwrap();
            let ready = slot.join("generation.json");
            assert!(refuse_maintenance(&ready).is_err());
            let bytes = std::fs::read(&ready).unwrap();
            std::fs::write(&ready, b"{}").unwrap();
            assert!(admit_writable_filename(&path).is_err());
            std::fs::write(&ready, &bytes).unwrap();
            let mut stale: Generation = serde_json::from_slice(&bytes).unwrap();
            stale.ino = stale.ino.wrapping_add(1);
            std::fs::write(&ready, serde_json::to_vec(&stale).unwrap()).unwrap();
            assert!(admit_writable_filename(&path).is_err());
            std::fs::write(&ready, bytes).unwrap();
            let expected_bytes = std::fs::read(&expected).unwrap();
            std::fs::remove_file(&expected).unwrap();
            assert!(require_enrolled_filename(&path).is_err());
            assert!(admit_writable_filename(&path).is_err());
            std::fs::write(&expected, expected_bytes).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }

        #[test]
        fn physical_file_and_stable_lock_replacement_cannot_inherit_generation() {
            let (root, path, generation) = destination();
            publish(root.path(), &path, &generation);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::rename(&path, root.path().join("old.db")).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(admit_writable_filename(&path).is_err());
            assert!(reserve_fresh_adoption(root.path(), &path, &generation).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);

            let (root, path, generation) = destination();
            publish(root.path(), &path, &generation);
            let replacement = root.path().join("ordinary.db");
            std::fs::write(&replacement, b"ordinary").unwrap();
            std::fs::rename(&path, root.path().join("old.db")).unwrap();
            symlink(&replacement, &path).unwrap();
            assert!(admit_writable_filename(&path).is_err());
            assert!(refuse_maintenance(&path).is_err());
            assert_eq!(std::fs::read(&replacement).unwrap(), b"ordinary");

            let (root, path, generation) = destination();
            publish(root.path(), &path, &generation);
            let (_, _, slot) = paths(&physical_path(&path).unwrap()).unwrap();
            let lock = slot.join("owner.lock");
            assert!(admit_writable_filename(&lock).is_err());
            std::fs::rename(&lock, slot.join("old.lock")).unwrap();
            std::fs::write(&lock, b"").unwrap();
            assert!(admit_writable_filename(&path).is_err());
            assert!(reserve_fresh_adoption(root.path(), &path, &generation).is_err());
        }

        #[test]
        fn unmanaged_non_utf8_filesystem_maintenance_remains_ordinary() {
            use std::os::unix::ffi::OsStringExt;
            let root = tempfile::tempdir().unwrap();
            let path = root
                .path()
                .join(std::ffi::OsString::from_vec(vec![b'd', 0xff]));
            std::fs::write(&path, b"ordinary").unwrap();
            refuse_maintenance(&path).unwrap();
        }

        #[test]
        fn existing_files_and_pre_enrollment_hardlinks_cannot_be_converted() {
            let (root, path, generation) = destination();
            std::fs::write(&path, b"ordinary").unwrap();
            assert!(reserve_fresh_adoption(root.path(), &path, &generation).is_err());
            let (root, path, generation) = destination();
            let enrollment = reserve_fresh_adoption(root.path(), &path, &generation).unwrap();
            std::fs::write(&path, b"ordinary").unwrap();
            std::fs::hard_link(&path, root.path().join("alias.db")).unwrap();
            assert!(enrollment.finalize().is_err());
            assert!(admit_writable_filename(&path).is_err());
        }

        #[test]
        fn process_resource_capacity_refuses_before_lock_acquisition() {
            let (root, path, generation) = destination();
            // Exercise the actual producer limit without global ceiling mutation.
            let mut registry = Registry::default();
            assert!(
                reserve_in(&mut registry, root.path(), &path, &generation, 0)
                    .unwrap_err()
                    .to_string()
                    .contains("capacity")
            );
            assert!(registry.owners.is_empty());
            assert!(!path.exists());
            assert!(!path.parent().unwrap().join(METADATA_DIRECTORY).exists());
        }

        async fn probe(path: &Path, mode: &str) {
            let test_name = format!(
                "{}::subprocess_owner_probe",
                module_path!().split_once("::").unwrap().1
            );
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &test_name, "--nocapture"])
                    .env("NATIVE_CUSTODY_TEST_PATH", path)
                    .env("NATIVE_CUSTODY_TEST_MODE", mode)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .expect("bounded subprocess ownership probe")
            .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("CUSTODY-PROBE-COMPLETE"));
        }

        #[tokio::test]
        async fn subprocess_owner_probe() {
            let Some(path) = std::env::var_os("NATIVE_CUSTODY_TEST_PATH").map(PathBuf::from) else {
                return;
            };
            if std::env::var("NATIVE_CUSTODY_TEST_MODE").unwrap() == "refuse" {
                let error = crate::db::open_database_at(&path).await.unwrap_err();
                assert!(
                    error.to_string().contains("owned by another process"),
                    "{error}"
                );
            } else {
                let root = path.parent().unwrap().parent().unwrap();
                let stage = root.join("stage.db");
                let db = crate::create_database(&stage.to_string_lossy())
                    .await
                    .unwrap();
                crate::db::checkpoint_and_close_hosted_adoption_database(db)
                    .await
                    .unwrap();
                let generation = path.file_stem().unwrap().to_str().unwrap();
                let enrollment = reserve_fresh_adoption(root, &path, generation).unwrap();
                std::fs::hard_link(&stage, &path).unwrap();
                std::fs::remove_file(&stage).unwrap();
                enrollment.finalize().unwrap();
                let db = crate::db::open_existing_database_at(&path).await.unwrap();
                let pool = db.write_pool().clone();
                let detached = pool.acquire().await.unwrap().detach();
                let tx = crate::db::begin_write(&pool).await.unwrap();
                let notification = std::sync::Arc::new(tokio::sync::Notify::new());
                let notified = notification.clone();
                let waiting_pool = pool.clone();
                let queued = tokio::spawn(async move {
                    crate::db::with_before_begin_write_notification(
                        notified,
                        crate::db::begin_write(&waiting_pool),
                    )
                    .await
                });
                tokio::time::timeout(std::time::Duration::from_secs(5), notification.notified())
                    .await
                    .unwrap();
                queued.abort();
                assert!(queued.await.unwrap_err().is_cancelled());
                drop(tx); // SQLx queued rollback does not own the custody lock.
                let other = crate::db::open_existing_database_at(&path).await.unwrap();
                assert_ne!(db.handle_id(), other.handle_id());
                other.close().await;
                db.close().await;
                probe(&path, "refuse").await;
                detached.close().await.unwrap();
                pool.close().await;
                probe(&path, "refuse").await;
            }
            println!("CUSTODY-PROBE-COMPLETE");
        }

        #[tokio::test]
        async fn real_sqlite_process_exit_is_the_only_owner_handoff_even_after_db_close() {
            let (root, path, _) = destination();
            probe(&path, "enroll").await; // Child owns and closes real pools, then exits.
            let db = crate::db::open_existing_database_at(&path).await.unwrap();
            let clone = db.clone();
            assert_eq!(db.handle_id(), clone.handle_id());
            probe(&path, "refuse").await;
            db.close().await;
            drop(clone);
            probe(&path, "refuse").await;
            assert!(root.path().exists());
        }

        #[tokio::test]
        async fn unmanaged_real_sqlite_independent_opens_remain_available() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("ordinary.db");
            let first = crate::create_database(&path.to_string_lossy())
                .await
                .unwrap();
            let second = crate::db::open_existing_database_at(&path).await.unwrap();
            assert_ne!(first.handle_id(), second.handle_id());
            first.close().await;
            second.close().await;
        }
    }
}

#[cfg(not(unix))]
pub const METADATA_DIRECTORY: &str = ".native-custody";

#[cfg(not(unix))]
pub const MAX_PROCESS_OWNERS: usize = 1024;

// Custody is unavailable on unsupported platforms. Only this consumer's
// expected reservation/slot refuses; an unrelated enrolled neighbor does not.
#[cfg(not(unix))]
pub fn admit_writable_filename(filename: &std::path::Path) -> crate::Result<()> {
    unsupported_admit_writable_filename(filename)
}

// Also compiled in lib-tests on Unix so filename-specific discovery has an
// actual test consumer without pretending to acquire custody on other OSes.
#[cfg(any(not(unix), test))]
fn unsupported_admit_writable_filename(filename: &std::path::Path) -> crate::Result<()> {
    use std::path::{Path, PathBuf};
    fn present(path: &Path) -> crate::Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn physical(path: &Path) -> crate::Result<PathBuf> {
        let absolute = std::path::absolute(path)?;
        if present(&absolute)? {
            return Ok(std::fs::canonicalize(absolute)?);
        }
        let ancestor = absolute
            .ancestors()
            .skip(1)
            .find(|p| p.exists())
            .ok_or_else(|| crate::Error::engine("SQLite filename has no existing ancestor"))?;
        Ok(std::fs::canonicalize(ancestor)?.join(
            absolute
                .strip_prefix(ancestor)
                .map_err(|_| crate::Error::engine("invalid SQLite filename"))?,
        ))
    }
    if filename == Path::new(":memory:") {
        return Ok(());
    }
    let supplied = std::path::absolute(filename)?;
    let resolved = physical(filename)?;
    let parent = supplied
        .parent()
        .ok_or_else(|| crate::Error::engine("SQLite filename has no parent"))?;
    let name = supplied
        .file_name()
        .ok_or_else(|| crate::Error::engine("SQLite filename has no basename"))?;
    // Retain the basename while resolving parent aliases, as on Unix. Final
    // symlink replacement cannot discard the original slot's expectation.
    let locator = physical(parent)?.join(name);
    for candidate in [&supplied, &locator, &resolved] {
        if candidate
            .components()
            .any(|c| c.as_os_str() == METADATA_DIRECTORY)
        {
            return Err(crate::Error::engine(
                "custody admission is unsupported on this platform",
            ));
        }
        let parent = candidate
            .parent()
            .ok_or_else(|| crate::Error::engine("SQLite filename has no parent"))?;
        let name = candidate
            .file_name()
            .ok_or_else(|| crate::Error::engine("SQLite filename has no basename"))?;
        let metadata = parent.join(METADATA_DIRECTORY);
        let mut expected = name.to_os_string();
        expected.push(".expected.json");
        if present(&metadata.join(expected))? || present(&metadata.join(name))? {
            return Err(crate::Error::engine(
                "custody admission is unsupported on this platform",
            ));
        }
    }
    Ok(())
}

// Preserve filesystem semantics while also recognizing SQLx's actual consumer
// filename. A parser failure cannot produce a SQLite write; literal FS callers
// still need admission. Each input contributes at most two filenames/sidecars.
fn maintenance_candidates(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut candidates = vec![path.to_path_buf()];
    if let Some(spelling) = path.to_str() {
        if let Ok(options) = format!(
            "sqlite:{}",
            spelling.strip_prefix("file:").unwrap_or(spelling)
        )
        .parse::<sqlx::sqlite::SqliteConnectOptions>()
        {
            if options.get_filename() != path {
                candidates.push(options.get_filename().to_path_buf());
            }
        }
    }
    for filename in candidates.clone() {
        if let Some(name) = filename.file_name().and_then(|name| name.to_str()) {
            if let Some(base) = ["-wal", "-shm", "-journal"]
                .iter()
                .find_map(|suffix| name.strip_suffix(suffix))
            {
                candidates.push(filename.with_file_name(base));
            }
        }
    }
    candidates
}

#[cfg(not(unix))]
pub fn refuse_maintenance(path: &std::path::Path) -> crate::Result<()> {
    for filename in maintenance_candidates(path) {
        admit_writable_filename(&filename)?;
    }
    Ok(())
}

#[cfg(test)]
mod unsupported_discovery_tests {
    use super::*;

    #[test]
    fn unmanaged_neighbor_remains_available_but_specific_pending_or_malformed_slot_refuses() {
        let root = tempfile::tempdir().unwrap();
        let ordinary = root.path().join("ordinary.db");
        let enrolled = root.path().join("enrolled.db");
        std::fs::write(&ordinary, b"ordinary").unwrap();
        std::fs::write(&enrolled, b"enrolled").unwrap();
        let metadata = root.path().join(METADATA_DIRECTORY);
        std::fs::create_dir(&metadata).unwrap();
        let expected = metadata.join("enrolled.db.expected.json");
        // Even malformed/pending metadata is a refusal, not an unmanaged open.
        std::fs::write(&expected, b"malformed").unwrap();
        unsupported_admit_writable_filename(&ordinary).unwrap();
        assert!(unsupported_admit_writable_filename(&enrolled).is_err());
        let options: sqlx::sqlite::SqliteConnectOptions =
            format!("sqlite:{}/enrolled%2Edb", root.path().display())
                .parse()
                .unwrap();
        assert_eq!(options.get_filename(), enrolled.as_path());
        assert!(unsupported_admit_writable_filename(options.get_filename()).is_err());
        std::fs::remove_file(expected).unwrap();
        std::fs::create_dir(metadata.join("enrolled.db")).unwrap();
        unsupported_admit_writable_filename(&ordinary).unwrap();
        assert!(unsupported_admit_writable_filename(&enrolled).is_err());
        assert!(unsupported_admit_writable_filename(&metadata.join("owner.lock")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_discovery_finds_parent_alias_and_final_component_expectations() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("storage");
        std::fs::create_dir(&directory).unwrap();
        let enrolled = directory.join("enrolled.db");
        let ordinary = root.path().join("ordinary.db");
        std::fs::write(&enrolled, b"enrolled").unwrap();
        std::fs::write(&ordinary, b"ordinary").unwrap();
        let metadata = directory.join(METADATA_DIRECTORY);
        std::fs::create_dir(&metadata).unwrap();
        std::fs::write(metadata.join("enrolled.db.expected.json"), b"pending").unwrap();
        let alias = root.path().join("alias");
        symlink(&directory, &alias).unwrap();
        assert!(unsupported_admit_writable_filename(&alias.join("enrolled.db")).is_err());
        std::fs::remove_file(&enrolled).unwrap();
        symlink(&ordinary, &enrolled).unwrap();
        assert!(unsupported_admit_writable_filename(&enrolled).is_err());
        unsupported_admit_writable_filename(&ordinary).unwrap();
    }
}

#[cfg(not(unix))]
pub(crate) fn execution_for_filename(
    filename: &std::path::Path,
) -> crate::Result<Option<std::sync::Arc<crate::db::enrolled::ExecutionOwner>>> {
    admit_writable_filename(filename)?;
    Ok(None)
}

#[cfg(not(unix))]
pub(crate) fn enrolled_read_filename(filename: &std::path::Path) -> crate::Result<bool> {
    unsupported_admit_writable_filename(filename).map(|_| false)
}
