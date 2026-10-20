//! Durable node instance identity and fresh process incarnation for saver leases.
//! The instance is never silently regenerated from corrupt or unsafe state.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct SaverIdentity {
    pub instance: String,
    pub boot: String,
}

impl SaverIdentity {
    pub fn load(state_dir: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(state_dir)
            .map_err(|e| Error::engine(format!("cannot inspect saver identity directory: {e}")))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(Error::engine("unsafe saver identity directory"));
        }
        let path = state_dir.join("instance-id");
        if !path
            .try_exists()
            .map_err(|e| Error::engine(format!("cannot inspect saver identity: {e}")))?
        {
            // Link publishes complete, synced bytes without replacing a winner
            // from a concurrent opener. A crash before publication leaves only
            // an ignored private temporary file, never a partial instance ID.
            let temporary = state_dir.join(format!(".instance-{}", uuid::Uuid::new_v4()));
            let created = (|| -> Result<()> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&temporary)
                    .map_err(|e| Error::engine(format!("cannot create saver instance: {e}")))?;
                file.write_all(uuid::Uuid::new_v4().to_string().as_bytes())
                    .and_then(|_| file.sync_all())
                    .map_err(|e| Error::engine(format!("cannot sync saver instance: {e}")))?;
                match std::fs::hard_link(&temporary, &path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(Error::engine(format!("cannot publish saver instance: {e}")))
                    }
                }
                Ok(())
            })();
            let cleanup = std::fs::remove_file(&temporary);
            created?;
            cleanup.map_err(|e| {
                Error::engine(format!("cannot remove saver identity temporary: {e}"))
            })?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|e| Error::engine(format!("cannot open saver identity: {e}")))?;
        let meta = file
            .metadata()
            .map_err(|e| Error::engine(format!("cannot stat saver identity: {e}")))?;
        if !meta.is_file()
            || meta.len() != 36
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(Error::engine("unsafe saver instance identity"));
        }
        let mut instance = String::new();
        file.read_to_string(&mut instance)
            .map_err(|e| Error::engine(format!("cannot read saver identity: {e}")))?;
        let parsed = uuid::Uuid::parse_str(&instance)
            .map_err(|_| Error::engine("corrupt saver instance identity"))?;
        if parsed.is_nil() || parsed.to_string() != instance {
            return Err(Error::engine("noncanonical saver instance identity"));
        }
        // Also sync a previously published instance: a publisher can have
        // crashed after the link and before syncing its directory entry.
        File::open(state_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| Error::engine(format!("cannot sync saver identity directory: {e}")))?;
        let parent = state_dir
            .parent()
            .ok_or_else(|| Error::engine("saver identity directory has no parent"))?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| Error::engine(format!("cannot sync saver identity parent: {e}")))?;
        Ok(Self {
            instance,
            boot: uuid::Uuid::new_v4().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn restart_preserves_instance_but_changes_boot() {
        let dir = private_dir();
        let first = SaverIdentity::load(dir.path()).unwrap();
        let second = SaverIdentity::load(dir.path()).unwrap();
        assert_eq!(first.instance, second.instance);
        assert_ne!(first.boot, second.boot);
        assert_eq!(
            std::fs::metadata(dir.path().join("instance-id"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn concurrent_openers_share_only_the_published_instance() {
        let dir = private_dir();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = dir.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    SaverIdentity::load(&path).unwrap()
                })
            })
            .collect();
        let identities: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(identities
            .iter()
            .all(|id| id.instance == identities[0].instance));
        let boots: std::collections::HashSet<_> = identities.iter().map(|id| &id.boot).collect();
        assert_eq!(boots.len(), 8);
    }

    #[test]
    fn corrupt_public_or_symlink_identity_is_never_replaced() {
        let dir = private_dir();
        let path = dir.path().join("instance-id");
        std::fs::write(&path, "bad").unwrap();
        assert!(SaverIdentity::load(dir.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"bad");
        std::fs::remove_file(&path).unwrap();
        let id = SaverIdentity::load(dir.path()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SaverIdentity::load(dir.path()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), id.instance);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("absent"), &path).unwrap();
        assert!(SaverIdentity::load(dir.path()).is_err());
        assert!(!dir.path().join("absent").exists());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("alias")).unwrap();
        assert!(SaverIdentity::load(&dir.path().join("alias")).is_err());
    }
}
