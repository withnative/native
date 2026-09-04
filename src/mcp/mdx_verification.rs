//! Hosted issuer boundary for one-use `native.mdx.v2` verification documents.
//!
//! The public engine prepares and verifies the browser-observation contract,
//! while the held Workbench package owns the renderer assets and frozen
//! document routes behind this dependency-inversion seam. Hosted runtime
//! composition installs an issuer before accepting requests; standalone builds
//! fail closed when none is installed.

use std::sync::{Arc, OnceLock, RwLock};

use serde_json::Value;

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub artifact_id: String,
    pub source_event_id: String,
    pub source_event_seq: i64,
    pub snapshot_event_id: String,
    pub snapshot_event_seq: i64,
    pub body_digest: String,
    pub dependency_closure_digest: String,
    pub render_digest: String,
    pub style_digest: Option<String>,
    pub adapter_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub url: String,
    pub digest: String,
    pub bytes: usize,
    pub kind: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    pub plan_digest: String,
    pub harness_url: String,
    pub artifact_digest: String,
    pub renderer_digest: String,
    pub document_digest: String,
    pub csp_digest: String,
    pub resources: Vec<Resource>,
}

#[derive(Clone, Debug)]
pub struct IssueRequest<'a> {
    pub identity: &'a Identity,
    pub plan: &'a Value,
    pub stylesheet: Option<&'a str>,
    pub principal: &'a str,
    pub database: Option<&'a str>,
}

pub trait Issuer: Send + Sync {
    fn issue(&self, request: IssueRequest<'_>) -> Result<Issued>;
}

struct IssuerSlot {
    issuer: RwLock<Option<Arc<dyn Issuer>>>,
}

impl IssuerSlot {
    fn empty() -> Self {
        Self {
            issuer: RwLock::new(None),
        }
    }

    fn configure(&self, issuer: Option<Arc<dyn Issuer>>) {
        *self
            .issuer
            .write()
            .expect("MDX verification issuer lock poisoned") = issuer;
    }

    fn configured(&self) -> bool {
        self.issuer
            .read()
            .expect("MDX verification issuer lock poisoned")
            .is_some()
    }

    fn issue(&self, request: IssueRequest<'_>) -> Result<Issued> {
        let issuer = self
            .issuer
            .read()
            .expect("MDX verification issuer lock poisoned")
            .clone()
            .ok_or_else(|| Error::engine("MDX verification document issuer is unavailable"))?;
        issuer.issue(request)
    }
}

fn issuer_slot() -> &'static IssuerSlot {
    static ISSUER: OnceLock<IssuerSlot> = OnceLock::new();
    ISSUER.get_or_init(IssuerSlot::empty)
}

/// Install or clear the held issuer used by the public artifact tool.
///
/// This is runtime composition, not a stable extension point. Reconfiguration
/// exists so process-isolated contract tests can prove the unavailable path.
#[doc(hidden)]
pub fn configure(issuer: Option<Arc<dyn Issuer>>) {
    issuer_slot().configure(issuer);
}

/// Read-only probe for whether the held issuer is installed.
///
/// The artifact response layer uses this (together with the browser-verifier
/// configuration) to report per-runtime verification availability without
/// attempting issuance.
#[doc(hidden)]
pub fn configured() -> bool {
    issuer_slot().configured()
}

pub(crate) fn issue(request: IssueRequest<'_>) -> Result<Issued> {
    issuer_slot().issue(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    fn identity() -> Identity {
        Identity {
            artifact_id: "artifact-one".into(),
            source_event_id: "source-event-one".into(),
            source_event_seq: 12,
            snapshot_event_id: "snapshot-event-one".into(),
            snapshot_event_seq: 15,
            body_digest: "1".repeat(64),
            dependency_closure_digest: "2".repeat(64),
            render_digest: "3".repeat(64),
            style_digest: None,
            adapter_revision: 4,
        }
    }

    type ObservedRequest = (Identity, Value, Option<String>, String, Option<String>);

    struct RecordingIssuer {
        observed: Arc<Mutex<Option<ObservedRequest>>>,
    }

    impl Issuer for RecordingIssuer {
        fn issue(&self, request: IssueRequest<'_>) -> Result<Issued> {
            *self.observed.lock().unwrap() = Some((
                request.identity.clone(),
                request.plan.clone(),
                request.stylesheet.map(str::to_owned),
                request.principal.to_owned(),
                request.database.map(str::to_owned),
            ));
            Ok(Issued {
                plan_digest: "4".repeat(64),
                harness_url: "https://workbench.test/harness".into(),
                artifact_digest: "5".repeat(64),
                renderer_digest: "6".repeat(64),
                document_digest: "7".repeat(64),
                csp_digest: "8".repeat(64),
                resources: vec![Resource {
                    url: "https://workbench.test/renderer.js".into(),
                    digest: "9".repeat(64),
                    bytes: 17,
                    kind: "script",
                }],
            })
        }
    }

    #[test]
    fn empty_slot_fails_closed() {
        let identity = identity();
        let plan = json!({"kind": "safe_tree"});
        let error = IssuerSlot::empty()
            .issue(IssueRequest {
                identity: &identity,
                plan: &plan,
                stylesheet: None,
                principal: "principal-one",
                database: None,
            })
            .unwrap_err();
        assert!(error.to_string().contains("issuer is unavailable"));
    }

    #[test]
    fn configured_slot_delegates_the_exact_borrowed_request_and_response() {
        let observed = Arc::new(Mutex::new(None));
        let slot = IssuerSlot::empty();
        slot.configure(Some(Arc::new(RecordingIssuer {
            observed: observed.clone(),
        })));
        let identity = identity();
        let plan = json!({"kind": "safe_tree"});
        let issued = slot
            .issue(IssueRequest {
                identity: &identity,
                plan: &plan,
                stylesheet: Some(".artifact { color: red; }"),
                principal: "principal-one",
                database: Some("database-one"),
            })
            .unwrap();
        assert_eq!(
            issued,
            Issued {
                plan_digest: "4".repeat(64),
                harness_url: "https://workbench.test/harness".into(),
                artifact_digest: "5".repeat(64),
                renderer_digest: "6".repeat(64),
                document_digest: "7".repeat(64),
                csp_digest: "8".repeat(64),
                resources: vec![Resource {
                    url: "https://workbench.test/renderer.js".into(),
                    digest: "9".repeat(64),
                    bytes: 17,
                    kind: "script",
                }],
            }
        );
        assert_eq!(
            observed.lock().unwrap().as_ref().unwrap(),
            &(
                identity,
                plan,
                Some(".artifact { color: red; }".into()),
                "principal-one".into(),
                Some("database-one".into())
            )
        );
    }
}
