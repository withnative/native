//! Deployment-authoritative, opt-in signing for installed-app launches.
use std::sync::Arc;

use native_artifact_html::{bundle_url, html::RuntimeConfig};
use native_artifact_runtime::deployment_keyring::DeploymentKeyring;
use serde_json::{json, Value};

use crate::mcp::registry::Caller;

/// Supplied before surface-tool registration by the held composition root.
/// V1 retains ticket delivery without configuration; KernelV2 refuses delivery.
/// Caller arguments cannot install keys.
#[derive(Clone, Debug)]
pub struct AppBundleDelivery {
    /// Held constructs this seam only when enabled; embedders may explicitly
    /// disable a configured signer and retain the ticket fallback.
    pub enabled: bool,
    pub runtime: RuntimeConfig,
    pub keyring: Option<Arc<DeploymentKeyring>>,
}

impl AppBundleDelivery {
    /// Native sample delivery never falls back to an unguarded one-use ticket.
    /// The signed preview marker selects receipt admission on every GET.
    #[cfg(feature = "v2-kernel-probe")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preview_launch(
        &self,
        caller: &Caller,
        package: &str,
        install_event: &str,
        digest: &str,
        receipt: &str,
        now: u64,
        expires: u64,
    ) -> Option<Value> {
        if !self.enabled || caller.is_trusted_local() {
            return None;
        }
        let keyring = self.keyring.as_ref()?;
        let hex = digest.strip_prefix("sha256:")?;
        let fields = bundle_url::IssueFields {
            principal: caller.hosting_principal()?.into(),
            database: caller.hosting_database()?.into(),
            session: caller.hosting_session_id()?.into(),
            package: package.into(),
            install_event: install_event.into(),
            parent_origin: self.runtime.resolve_parent_origin(None).ok()?,
            adapter_revision: crate::artifact_html::ADAPTER_REVISION,
        };
        let cap = bundle_url::issue_preview(
            keyring,
            &self.runtime.artifact_origin,
            hex,
            &fields,
            receipt,
            now,
            expires,
        )
        .ok()?;
        Some(json!({
            "url":format!("{}{}{hex}/{cap}",self.runtime.artifact_origin,bundle_url::ROUTE_PATH),
            "kind":"reusable.v1","expires_at_secs":expires,
            "bridge_version":crate::artifact_html::BRIDGE_VERSION,
        }))
    }

    /// Ordinary artifacts have separate signed authority from installs/previews.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn artifact_launch(
        &self,
        caller: &Caller,
        artifact: &str,
        digest: &str,
        parent: Option<&str>,
        now: u64,
    ) -> Option<Value> {
        if !self.enabled || caller.is_trusted_local() {
            return None;
        }
        let fields = bundle_url::IssueFields {
            principal: caller.hosting_principal()?.into(),
            database: caller.hosting_database()?.into(),
            session: caller.hosting_session_id()?.into(),
            package: "native.artifact-render".into(),
            install_event: artifact.into(),
            parent_origin: self.runtime.resolve_parent_origin(parent).ok()?,
            adapter_revision: crate::artifact_html::ADAPTER_REVISION,
        };
        let cap = bundle_url::issue_artifact(
            self.keyring.as_ref()?,
            &self.runtime.artifact_origin,
            digest,
            &fields,
            now,
        )
        .ok()?;
        Some(
            json!({"url":format!("{}{}{digest}/{cap}",self.runtime.artifact_origin,bundle_url::ROUTE_PATH),
            "expires_in_ms":bundle_url::ARTIFACT_LIFETIME_SECONDS*1000,"bridge_version":crate::artifact_html::BRIDGE_VERSION}),
        )
    }

    /// A failed eligibility or cap bound always leaves the ticket path available.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn launch(
        &self,
        caller: &Caller,
        package: &str,
        install_event: &str,
        digest: &str,
        parent_origin: Option<&str>,
        now: u64,
    ) -> Option<Value> {
        if !self.enabled || caller.is_trusted_local() {
            return None;
        }
        let keyring = self.keyring.as_ref()?;
        let database = caller.hosting_database()?;
        let principal = caller.hosting_principal()?;
        let session = caller.hosting_session_id()?;
        let hex = digest.strip_prefix("sha256:")?;
        let parent = self.runtime.resolve_parent_origin(parent_origin).ok()?;
        let cap = bundle_url::issue(
            keyring,
            &self.runtime.artifact_origin,
            hex,
            &bundle_url::IssueFields {
                principal: principal.into(),
                database: database.into(),
                session: session.into(),
                package: package.into(),
                install_event: install_event.into(),
                parent_origin: parent,
                adapter_revision: crate::artifact_html::ADAPTER_REVISION,
            },
            now,
        )
        .ok()?;
        Some(json!({
            "url": format!("{}{}{hex}/{cap}", self.runtime.artifact_origin, bundle_url::ROUTE_PATH),
            "kind": "reusable.v1",
            "expires_at_secs": now.checked_add(bundle_url::LIFETIME_SECONDS)?,
            "bridge_version": crate::artifact_html::BRIDGE_VERSION,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AppBundleDelivery {
        AppBundleDelivery {
            enabled: true,
            runtime: RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap(),
            keyring: Some(Arc::new(DeploymentKeyring::from_json_bundle(
                r#"{"active_key_id":"test","keys":[{"id":"test","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#,
            ).unwrap())),
        }
    }
    fn caller() -> Caller {
        // Fixture stands in for authenticated hosted cookie ingress.
        unsafe {
            Caller::authenticated("account")
                .with_hosting_context("principal", "database")
                .with_verified_hosting_session("11111111-1111-4111-8111-111111111111")
        }
    }
    fn launch(config: &AppBundleDelivery, caller: &Caller, digest: &str) -> Option<Value> {
        config.launch(caller, "example.app", "install", digest, None, 1000)
    }
    fn digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    #[test]
    fn signed_launch_round_trips_with_full_pin_and_clock() {
        let config = config();
        let response = launch(&config, &caller(), &digest()).unwrap();
        assert_eq!(response["kind"], "reusable.v1");
        assert_eq!(response["expires_at_secs"], 4540);
        assert!(response.get("expires_in_ms").is_none());
        let url = response["url"].as_str().unwrap();
        let (hex, cap) = url
            .strip_prefix(&format!(
                "{}{}",
                config.runtime.artifact_origin,
                bundle_url::ROUTE_PATH
            ))
            .unwrap()
            .split_once('/')
            .unwrap();
        let fields = bundle_url::verify(
            config.keyring.as_ref().unwrap(),
            &config.runtime.artifact_origin,
            hex,
            cap,
            1000,
        )
        .unwrap();
        assert_eq!(format!("sha256:{hex}"), digest());
        assert_eq!(
            fields.adapter_revision,
            crate::artifact_html::ADAPTER_REVISION
        );
        assert_eq!(fields.principal, "principal");
        assert_eq!(fields.database, "database");
        assert_eq!(fields.session, "11111111-1111-4111-8111-111111111111");
        assert_eq!(fields.package, "example.app");
        assert_eq!(fields.install_event, "install");
        assert_eq!(fields.parent_origin, "https://parent.test");
        assert_eq!(fields.iat, 1000);
        assert_eq!(fields.exp, 4540);
    }

    #[test]
    fn invalid_pins_and_oversized_urls_leave_ticket_path_available() {
        let mut config = config();
        for pin in [
            "a".repeat(64),
            format!("SHA256:{}", "a".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
        ] {
            assert!(launch(&config, &caller(), &pin).is_none(), "{pin}");
        }
        // A canonical but very long origin consumes the complete URL budget.
        let origin = format!("https://{}.test", "a.".repeat(700));
        config.runtime = RuntimeConfig::new("https://parent.test", origin).unwrap();
        assert!(launch(&config, &caller(), &digest()).is_none());
    }

    #[test]
    fn incomplete_deployment_or_hosted_footing_leaves_ticket_path_available() {
        let mut config = config();
        let hosted = caller();
        config.enabled = false;
        assert!(launch(&config, &hosted, &digest()).is_none());
        config.enabled = true;
        config.keyring = None;
        assert!(launch(&config, &hosted, &digest()).is_none());
        let config = self::config();
        let no_session =
            Caller::authenticated("account").with_hosting_context("principal", "database");
        assert!(launch(&config, &no_session, &digest()).is_none());
        let no_database = unsafe {
            Caller::authenticated("account")
                .with_verified_hosting_session("11111111-1111-4111-8111-111111111111")
        };
        assert!(launch(&config, &no_database, &digest()).is_none());
        let legacy_local = unsafe {
            Caller::local()
                .with_hosting_context("principal", "database")
                .with_verified_hosting_session("11111111-1111-4111-8111-111111111111")
        };
        assert!(launch(&config, &legacy_local, &digest()).is_none());
    }
}
