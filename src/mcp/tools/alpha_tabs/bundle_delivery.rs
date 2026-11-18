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
    ///
    /// The cap is bound to whatever the serve path can re-admit on every GET:
    /// the cookie session when ingress attached one (unchanged), otherwise a
    /// bearer JWT that ingress verified for this request. A JWT-bound cap
    /// expires no later than the token. Neither binding comes from arguments.
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
        let session = caller.hosting_session_id();
        let jwt = if session.is_none() {
            Some(caller.hosting_jwt_binding()?)
        } else {
            None
        };
        let fields = bundle_url::IssueFields {
            principal: caller.hosting_principal()?.into(),
            database: caller.hosting_database()?.into(),
            session: session.unwrap_or_default().into(),
            package: "native.artifact-render".into(),
            install_event: artifact.into(),
            parent_origin: self.runtime.resolve_parent_origin(parent).ok()?,
            adapter_revision: crate::artifact_html::ADAPTER_REVISION,
        };
        let keyring = self.keyring.as_ref()?;
        let origin = &self.runtime.artifact_origin;
        let (cap, lifetime) = match jwt {
            None => (
                bundle_url::issue_artifact(keyring, origin, digest, &fields, now).ok()?,
                bundle_url::ARTIFACT_LIFETIME_SECONDS,
            ),
            Some(jwt) => (
                bundle_url::issue_artifact_for_jwt(keyring, origin, digest, &fields, jwt, now)
                    .ok()?,
                bundle_url::ARTIFACT_LIFETIME_SECONDS.min(jwt.token_exp.checked_sub(now)?),
            ),
        };
        Some(
            json!({"url":format!("{}{}{digest}/{cap}",self.runtime.artifact_origin,bundle_url::ROUTE_PATH),
            "expires_in_ms":lifetime*1000,"bridge_version":crate::artifact_html::BRIDGE_VERSION}),
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
        assert_eq!(
            fields.binding,
            bundle_url::CapBinding::Session("11111111-1111-4111-8111-111111111111".into())
        );
        assert_eq!(fields.package, "example.app");
        assert_eq!(fields.install_event, "install");
        assert_eq!(fields.parent_origin, "https://parent.test");
        assert_eq!(fields.iat, 1000);
        assert_eq!(fields.exp, 4540);
    }

    #[cfg(feature = "v2-kernel-probe")]
    fn jwt() -> bundle_url::JwtBinding {
        bundle_url::JwtBinding {
            subject: "user_subject".into(),
            jti: Some("token-1".into()),
            token_iat: 900,
            token_exp: 1120,
        }
    }

    #[cfg(feature = "v2-kernel-probe")]
    fn artifact_cap(config: &AppBundleDelivery, response: &Value) -> bundle_url::VerifiedFields {
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
        bundle_url::verify(
            config.keyring.as_ref().unwrap(),
            &config.runtime.artifact_origin,
            hex,
            cap,
            1000,
        )
        .unwrap()
    }

    #[cfg(feature = "v2-kernel-probe")]
    #[test]
    fn artifact_launch_binds_a_verified_jwt_when_no_session_exists() {
        let config = config();
        let hex = "a".repeat(64);
        // SAFETY: fixture stands in for verified hosted JWT ingress.
        let jwt_caller = unsafe {
            Caller::authenticated("account")
                .with_hosting_context("principal", "database")
                .with_verified_hosting_jwt_binding(jwt())
        };
        let response = config
            .artifact_launch(&jwt_caller, "artifact-1", &hex, None, 1000)
            .unwrap();
        // The link never outlives the token: 120 s left, not 300 s.
        assert_eq!(response["expires_in_ms"], 120_000);
        let fields = artifact_cap(&config, &response);
        assert!(fields.artifact_render);
        assert_eq!(fields.binding, bundle_url::CapBinding::Jwt(jwt()));
        assert_eq!(fields.principal, "principal");
        assert_eq!(fields.database, "database");
        assert_eq!(fields.install_event, "artifact-1");
        assert_eq!(fields.exp, 1120);
        // An expired token, or no hosted footing, mints nothing.
        let expired = unsafe {
            Caller::authenticated("account")
                .with_hosting_context("principal", "database")
                .with_verified_hosting_jwt_binding(bundle_url::JwtBinding {
                    token_exp: 1000,
                    ..jwt()
                })
        };
        assert!(config
            .artifact_launch(&expired, "artifact-1", &hex, None, 1000)
            .is_none());
        let unrouted =
            unsafe { Caller::authenticated("account").with_verified_hosting_jwt_binding(jwt()) };
        assert!(config
            .artifact_launch(&unrouted, "artifact-1", &hex, None, 1000)
            .is_none());
        // Changing the hosting identity drops the binding with the session.
        let switched = jwt_caller.with_hosting_context("other", "other-database");
        assert!(switched.hosting_jwt_binding().is_none());
        assert!(config
            .artifact_launch(&switched, "artifact-1", &hex, None, 1000)
            .is_none());
        // Neither binding: unchanged refusal.
        let neither =
            Caller::authenticated("account").with_hosting_context("principal", "database");
        assert!(config
            .artifact_launch(&neither, "artifact-1", &hex, None, 1000)
            .is_none());
    }

    #[cfg(feature = "v2-kernel-probe")]
    #[test]
    fn artifact_launch_for_a_cookie_session_is_unchanged() {
        let config = config();
        let hex = "a".repeat(64);
        let response = config
            .artifact_launch(&caller(), "artifact-1", &hex, None, 1000)
            .unwrap();
        assert_eq!(response["expires_in_ms"], 300_000);
        let fields = artifact_cap(&config, &response);
        assert_eq!(
            fields.binding,
            bundle_url::CapBinding::Session("11111111-1111-4111-8111-111111111111".into())
        );
        assert_eq!(fields.exp, 1300);
        // A session, when present, is always the binding.
        let both = unsafe { caller().with_verified_hosting_jwt_binding(jwt()) };
        let fields = artifact_cap(
            &config,
            &config
                .artifact_launch(&both, "artifact-1", &hex, None, 1000)
                .unwrap(),
        );
        assert_eq!(
            fields.binding,
            bundle_url::CapBinding::Session("11111111-1111-4111-8111-111111111111".into())
        );
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
