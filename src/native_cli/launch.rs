//! Executable selection for saved service and client launches.
//!
//! Keep the invoked launcher spelling when it still names this executable.
//! This is deliberately separate from node self-restart, which must continue
//! running its captured immutable executable rather than select an update.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Find an absolute, verified path for a future launch, preserving symlinks.
/// No installation layout is inferred: direct version/development invocations
/// stay direct. Missing argv0, changed launchers/PATH/cwd, or an invocation
/// that cannot be safely normalized fall back to canonical `current_exe`.
/// If that executable no longer exists, return an error rather than save a
/// launch command that cannot run. Shell wrappers that replace argv0 with the
/// version path also stay direct. Adoption must repair those saved paths
/// explicitly. Verification is a point-in-time identity check, not
/// a lock against a subsequent launcher switch.
pub fn saved_launch_exe() -> std::io::Result<PathBuf> {
    let current_exe = std::env::current_exe()?;
    resolve_saved_launch_exe(
        &current_exe,
        std::env::args_os().next().as_deref(),
        std::env::current_dir().ok().as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

pub(crate) fn resolve_saved_launch_exe(
    current_exe: &Path,
    argv0: Option<&OsStr>,
    cwd: Option<&Path>,
    path_env: Option<&OsStr>,
) -> std::io::Result<PathBuf> {
    // Retain service detection's existing canonical, present fallback contract.
    // Use the same observed identity for candidate verification and fallback.
    let observed = if current_exe.is_absolute() {
        current_exe.to_path_buf()
    } else {
        cwd.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot resolve relative current executable without a current directory",
            )
        })?
        .join(current_exe)
    }
    .canonicalize()?;
    let candidate = (|| {
        let invoked = Path::new(argv0.filter(|arg| !arg.is_empty())?);
        let absolute = |path: &Path| {
            if path.is_absolute() {
                Some(path.to_path_buf())
            } else {
                Some(cwd?.join(path))
            }
        };
        if invoked.is_absolute() || invoked.components().count() > 1 {
            absolute(invoked)
        } else {
            // Follow PATH order, including relative/empty entries. Do not skip
            // a different executable to find a later entry matching our own.
            std::env::split_paths(path_env?).find_map(|dir| {
                let path = absolute(&dir.join(invoked))?;
                is_executable(&path).then_some(path)
            })
        }
    })();
    if let Some(candidate) = candidate {
        if is_executable(&candidate) {
            if let Ok(invoked) = candidate.canonicalize() {
                if invoked == observed {
                    // Service definitions require a normalized absolute path.
                    // Remove lexical dots without resolving symlinks. Folding
                    // `..` across a symlink can change its meaning, so verify
                    // the normalized spelling too before saving it.
                    let mut normalized = PathBuf::new();
                    for part in candidate.components() {
                        match part {
                            Component::CurDir => {}
                            Component::ParentDir => {
                                normalized.pop();
                            }
                            _ => normalized.push(part.as_os_str()),
                        }
                    }
                    if normalized.canonicalize().ok().as_ref() == Some(&observed) {
                        return Ok(normalized);
                    }
                }
            }
        }
    }
    Ok(observed)
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    struct Install {
        _dir: tempfile::TempDir,
        root: PathBuf,
        version: PathBuf,
        launcher: PathBuf,
    }

    impl Install {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let version = root.join("versions/one/native");
            let launcher = root.join("bin/native");
            std::fs::create_dir_all(version.parent().unwrap()).unwrap();
            std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
            std::fs::write(&version, "version one").unwrap();
            std::fs::set_permissions(&version, std::fs::Permissions::from_mode(0o755)).unwrap();
            symlink("../versions/one/native", &launcher).unwrap();
            Self {
                _dir: dir,
                root,
                version,
                launcher,
            }
        }

        fn resolve(&self, argv0: Option<&Path>, path: Option<&OsStr>) -> PathBuf {
            resolve_saved_launch_exe(
                &self.version,
                argv0.map(Path::as_os_str),
                Some(&self.root),
                path,
            )
            .unwrap()
        }
    }

    #[test]
    fn stable_symlink_is_preserved_for_absolute_and_relative_invocations() {
        let install = Install::new();
        assert_eq!(
            install.resolve(Some(&install.launcher), None),
            install.launcher
        );
        assert_eq!(
            install.resolve(Some(Path::new("bin/native")), None),
            install.launcher
        );
        assert_eq!(
            install.resolve(Some(Path::new("./bin/native")), None),
            install.launcher
        );
    }

    #[test]
    fn parent_relative_invocation_is_normalized_without_resolving_launcher() {
        let install = Install::new();
        let cwd = install.root.join("work");
        std::fs::create_dir(&cwd).unwrap();
        let selected = resolve_saved_launch_exe(
            &install.version,
            Some(OsStr::new("../bin/native")),
            Some(&cwd),
            None,
        )
        .unwrap();
        assert_eq!(selected, install.launcher);
    }

    #[test]
    fn normalization_cannot_select_a_different_executable_through_symlink_parent() {
        let install = Install::new();
        let nested = install.root.join("other/nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::copy(&install.version, install.root.join("other/native")).unwrap();
        symlink(&nested, install.root.join("link")).unwrap();
        // Lexically link/../bin/native names our launcher, but actually
        // resolves under other/, so neither identity check may be skipped.
        std::fs::create_dir(install.root.join("other/bin")).unwrap();
        std::fs::copy(&install.version, install.root.join("other/bin/native")).unwrap();
        assert_eq!(
            install.resolve(Some(Path::new("link/../bin/native")), None),
            install.version
        );
        // The inverse: original resolves to our executable, folded does not.
        symlink(&install.version, install.root.join("other/selected")).unwrap();
        assert_eq!(
            install.resolve(Some(Path::new("link/../selected")), None),
            install.version
        );
    }

    #[test]
    fn path_lookup_preserves_absolute_relative_and_empty_entries() {
        let install = Install::new();
        for path in [install.root.join("bin").into_os_string(), "bin".into()] {
            assert_eq!(
                install.resolve(Some(Path::new("native")), Some(&path)),
                install.launcher
            );
        }
        let selected = resolve_saved_launch_exe(
            &install.version,
            Some(OsStr::new("native")),
            install.launcher.parent(),
            Some(OsStr::new("")),
        )
        .unwrap();
        assert_eq!(selected, install.launcher);
    }

    #[test]
    fn changed_launcher_and_wrong_first_path_entry_fall_back_without_searching_on() {
        let install = Install::new();
        let other = install.root.join("other/native");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::copy(&install.version, &other).unwrap();
        let path =
            std::env::join_paths([other.parent().unwrap(), install.launcher.parent().unwrap()])
                .unwrap();
        assert_eq!(
            install.resolve(Some(Path::new("native")), Some(&path)),
            install.version
        );
        std::fs::remove_file(&install.launcher).unwrap();
        symlink(&other, &install.launcher).unwrap();
        assert_eq!(
            install.resolve(Some(&install.launcher), None),
            install.version
        );
    }

    #[test]
    fn unverifiable_and_direct_invocations_keep_current_executable() {
        let install = Install::new();
        for argv0 in [
            None,
            Some(Path::new("")),
            Some(Path::new("missing/native")),
            Some(&install.version),
        ] {
            assert_eq!(install.resolve(argv0, None), install.version);
        }
        assert_eq!(
            install.resolve(Some(Path::new("native")), None),
            install.version
        );
        assert_eq!(
            resolve_saved_launch_exe(&install.version, Some(OsStr::new("bin/native")), None, None)
                .unwrap(),
            install.version
        );
        std::fs::set_permissions(&install.version, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            install.resolve(Some(&install.launcher), None),
            install.version
        );
    }

    #[test]
    fn fallback_canonicalizes_noncanonical_and_relative_current_executable() {
        let install = Install::new();
        for observed in [
            install.root.join("versions/one/../one/native"),
            install.launcher.clone(),
            PathBuf::from("versions/one/native"),
        ] {
            // Absent/unusable argv0 exercises the production fallback path.
            let selected =
                resolve_saved_launch_exe(&observed, None, Some(&install.root), None).unwrap();
            assert_eq!(selected, install.version);
            assert!(selected.is_absolute());
        }
        // Canonicalizing observed identity must not canonicalize a verified
        // launcher returned for future launches.
        let selected = resolve_saved_launch_exe(
            &install.root.join("versions/one/../one/native"),
            Some(install.launcher.as_os_str()),
            Some(&install.root),
            None,
        )
        .unwrap();
        assert_eq!(selected, install.launcher);
    }

    #[test]
    fn missing_current_executable_errors_instead_of_saving_a_dead_fallback() {
        let install = Install::new();
        for missing in [
            install.root.join("missing/native"),
            install.root.join("versions/one/native (deleted)"),
            PathBuf::from("missing/native"),
        ] {
            for argv0 in [None, Some(install.launcher.as_os_str())] {
                let error = resolve_saved_launch_exe(&missing, argv0, Some(&install.root), None)
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            }
        }
        assert!(
            resolve_saved_launch_exe(Path::new("versions/one/native"), None, None, None).is_err()
        );
        std::fs::remove_file(&install.version).unwrap();
        assert!(
            resolve_saved_launch_exe(&install.version, None, Some(&install.root), None).is_err()
        );
    }

    #[test]
    fn generated_service_and_client_commands_keep_the_verified_launcher() {
        let install = Install::new();
        let selected = install.resolve(Some(&install.launcher), None);
        let config = install.root.join("node.json");
        let unit = crate::native_cli::service::render_systemd_unit(&selected, &config).unwrap();
        let plist =
            crate::native_cli::service::render_launchd_plist(&selected, &config, &install.root)
                .unwrap();
        assert!(unit.contains(&format!(
            "ExecStart=\"{}\" node serve",
            install.launcher.display()
        )));
        assert!(plist.contains(&format!("<string>{}</string>", install.launcher.display())));
        let command =
            crate::native_cli::connect::desired_command(&selected, &install.root.join("local.db"));
        assert_eq!(command[0], install.launcher.to_str().unwrap());
        assert!(!unit.contains(install.version.to_str().unwrap()));
        assert!(!plist.contains(install.version.to_str().unwrap()));
    }
}
