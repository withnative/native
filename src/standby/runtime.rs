use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::standby_snapshot::{ObservedInstalledConsumerIdentity, StandbyConsumerPlatform};

/// Local, non-secret configuration that binds one standby installation to its
/// hosted route and portable database identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyRuntimeConfig {
    pub replica_root: PathBuf,
    pub hosted_route_database_id: String,
    pub origin_database_id: String,
}

impl StandbyRuntimeConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::engine(format!("invalid standby runtime config: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let mut components = self.replica_root.components();
        let rooted = matches!(components.next(), Some(Component::RootDir));
        let mut normal_components = 0;
        let unambiguous = components.all(|component| match component {
            Component::Normal(_) => {
                normal_components += 1;
                true
            }
            Component::RootDir
            | Component::Prefix(_)
            | Component::CurDir
            | Component::ParentDir => false,
        });
        if !rooted || !unambiguous || normal_components == 0 {
            return Err(Error::engine(
                "standby replica_root must be an absolute, lexically unambiguous non-root path",
            ));
        }
        let route = self.hosted_route_database_id.as_str();
        if route.is_empty()
            || route.trim() != route
            || route.len() > 256
            || route.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "standby hosted_route_database_id must contain 1..=256 non-control characters with no leading or trailing whitespace",
            ));
        }
        if !crate::identity::is_database_id(&self.origin_database_id) {
            return Err(Error::engine(
                "standby origin_database_id must be a valid Native database id",
            ));
        }
        Ok(())
    }
}

/// Observe the exact installed executable and compiled compatibility identity
/// that a promoted standby manifest must name before its bytes can be served.
pub fn observe_installed_consumer_identity() -> Result<ObservedInstalledConsumerIdentity> {
    // Opening procfs observes the inode this process is executing even if an
    // installer atomically replaces the pathname after startup.
    #[cfg(target_os = "linux")]
    let executable = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let executable = std::env::current_exe().map_err(|error| {
        Error::engine(format!(
            "cannot resolve installed standby executable: {error}"
        ))
    })?;
    observe_consumer_identity_at(&executable, crate::FULL_GIT_SHA)
}

fn observe_consumer_identity_at(
    executable: &Path,
    source_sha: &str,
) -> Result<ObservedInstalledConsumerIdentity> {
    if !lowercase_hex(source_sha, 40) {
        // Naming the remedy matters more than naming the invariant. `build.rs`
        // deliberately stamps "dev" for local builds, so an ordinary
        // `cargo build` produces a binary that starts, reports itself
        // status-only, and serves nothing — with an error that described the
        // rule it violated but never the cause or the fix.
        return Err(Error::engine(format!(
            "installed standby source identity must be 40 lowercase hexadecimal characters, \
             but this binary was stamped {source_sha:?}. Build the standby artifact with \
             NATIVE_CE_GIT_SHA set to the full 40-character commit SHA; local builds stamp \
             \"dev\" by design and cannot serve a standby generation."
        )));
    }
    let metadata = executable.metadata().map_err(|error| {
        Error::engine(format!(
            "cannot inspect installed standby executable {}: {error}",
            executable.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::engine(format!(
            "installed standby executable is not a regular file: {}",
            executable.display()
        )));
    }

    let platform = installed_platform()?;
    let artifact_sha256 = sha256_file(executable)?;
    Ok(ObservedInstalledConsumerIdentity {
        platform,
        source_sha: source_sha.into(),
        artifact_sha256,
        engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
        ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
    })
}

fn installed_platform() -> Result<StandbyConsumerPlatform> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok(StandbyConsumerPlatform::LinuxX8664)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Err(Error::engine(
            "installed standby platform is not supported; expected linux-x86_64",
        ))
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const ORIGIN_ID: &str = "ndb_0123456789abcdef0123456789abcdef";

    fn config_json(replica_root: &Path) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "replica_root": replica_root,
            "hosted_route_database_id": "hosted-route-1",
            "origin_database_id": ORIGIN_ID,
        }))
        .unwrap()
    }

    #[test]
    fn runtime_config_is_strict_and_identity_bound() {
        let directory = tempfile::tempdir().unwrap();
        let replica_root = directory.path().join("replica");
        let config = StandbyRuntimeConfig::from_json(&config_json(&replica_root)).unwrap();
        assert_eq!(config.replica_root, replica_root);
        assert_eq!(config.hosted_route_database_id, "hosted-route-1");
        assert_eq!(config.origin_database_id, ORIGIN_ID);

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&config_json(&replica_root)).unwrap();
        unknown["future"] = serde_json::json!(true);
        assert!(StandbyRuntimeConfig::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let mut missing_origin: serde_json::Value =
            serde_json::from_slice(&config_json(&replica_root)).unwrap();
        missing_origin
            .as_object_mut()
            .unwrap()
            .remove("origin_database_id");
        assert!(
            StandbyRuntimeConfig::from_json(&serde_json::to_vec(&missing_origin).unwrap()).is_err()
        );

        let mut invalid_origin: serde_json::Value =
            serde_json::from_slice(&config_json(&replica_root)).unwrap();
        invalid_origin["origin_database_id"] = serde_json::json!("not-a-database-id");
        assert!(
            StandbyRuntimeConfig::from_json(&serde_json::to_vec(&invalid_origin).unwrap()).is_err()
        );
    }

    #[test]
    fn runtime_config_rejects_ambiguous_roots_and_routes() {
        let relative = Path::new("relative/replica");
        assert!(StandbyRuntimeConfig::from_json(&config_json(relative)).is_err());
        assert!(StandbyRuntimeConfig::from_json(&config_json(Path::new("/tmp/.."))).is_err());

        let mut blank_route: serde_json::Value =
            serde_json::from_slice(&config_json(Path::new("/var/lib/native-standby"))).unwrap();
        blank_route["hosted_route_database_id"] = serde_json::json!(" route ");
        assert!(
            StandbyRuntimeConfig::from_json(&serde_json::to_vec(&blank_route).unwrap()).is_err()
        );
    }

    #[test]
    fn executable_observation_hashes_injected_bytes_and_source_identity() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("mcp-stdio");
        fs::write(&executable, b"installed executable bytes").unwrap();
        let source_sha = "a".repeat(40);

        let observed = observe_consumer_identity_at(&executable, &source_sha);
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            assert!(observed.is_err());
            return;
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let observed = observed.unwrap();
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(observed.platform, StandbyConsumerPlatform::LinuxX8664);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(observed.source_sha, source_sha);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(
            observed.artifact_sha256,
            hex::encode(Sha256::digest(b"installed executable bytes"))
        );
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(
            observed.engine_schema_version,
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        );
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(observed.ddl_sha256, crate::schema::FROZEN_DDL_SHA256);

        // A local build stamps "dev" and cannot serve. The rejection must name
        // the remedy, not just the violated invariant: this failure is the
        // first thing anyone packaging the artifact will hit, and an error that
        // only restates the rule sends them reading source to find the cause.
        let rejected = observe_consumer_identity_at(&executable, "dev")
            .expect_err("a 'dev' stamp cannot identify a servable standby artifact");
        let message = rejected.to_string();
        assert!(
            message.contains("NATIVE_CE_GIT_SHA"),
            "the rejection must name the variable to set, got: {message}"
        );
        assert!(
            message.contains("dev"),
            "the rejection must quote the stamp it observed, got: {message}"
        );
    }
}
