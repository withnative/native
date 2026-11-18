//! Credential-free installed bundle reads. Admission runs on every page;
//! composition and CSP are shared with hosted delivery, never reimplemented.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::mcp::{Caller, ToolKind, ToolRegistry};
use crate::{db::Db, Error, Result};

const PAGE_LIMIT: usize = 524_288;
const DOCUMENT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Args {
    pub package: String,
    pub expected_install_event_id: String,
    pub parent_origin: String,
    #[serde(default)]
    offset: usize,
    length: Option<usize>,
    expected_document_sha256: Option<String>,
}

impl Args {
    pub(crate) fn parse(value: Value) -> Result<Self> {
        let args: Self = super::parse_args("read_app_bundle", value)?;
        super::alpha_tabs::require_package(&args.package)?;
        if args.expected_install_event_id.trim().is_empty()
            || args.expected_install_event_id.len() > 128
            || args.parent_origin.len() > 2048
            || !(1..=PAGE_LIMIT).contains(&args.length.unwrap_or(PAGE_LIMIT))
        {
            return Err(Error::engine(
                "read_app_bundle: invalid arguments [invalid_params]",
            ));
        }
        if args.expected_document_sha256.as_ref().is_some_and(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        }) {
            return Err(Error::engine(
                "read_app_bundle: invalid document digest [invalid_params]",
            ));
        }
        Ok(args)
    }
}

/// Local and standby nodes have one first-party parent. Hosted parents must be in the
/// runtime allowlist; parsing and artifact-origin exclusion use hosted policy.
fn resolve_parent(
    raw: &str,
    desktop_only: bool,
    config: Option<crate::artifact_html::RuntimeConfig>,
) -> Result<String> {
    let parent = crate::artifact_html::RuntimeConfig::exact_parent_origin(raw)
        .map_err(|_| Error::engine("read_app_bundle: invalid parent [invalid_parent_origin]"))?;
    if config.as_ref().is_some_and(|c| c.artifact_origin == parent) {
        return Err(Error::engine(
            "read_app_bundle: artifact parent refused [parent_origin_not_allowed]",
        ));
    }
    if desktop_only && parent == "native-ui://app" {
        return Ok(parent);
    }
    if let Some(config) = config.filter(|_| !desktop_only) {
        return config.resolve_parent_origin(Some(&parent)).map_err(|_| {
            Error::engine("read_app_bundle: parent refused [parent_origin_not_allowed]")
        });
    }
    Err(Error::engine(
        "read_app_bundle: parent refused [parent_origin_not_allowed]",
    ))
}

pub(crate) fn refuse_app(caller: &Caller) -> Result<()> {
    if caller.host_asserted_app().is_some() {
        return Err(Error::engine(
            "read_app_bundle is not available to apps [app_operation_refused]",
        ));
    }
    Ok(())
}

pub(crate) fn response(
    mut args: Args,
    body: String,
    artifact_id: String,
    version: String,
    body_limit: usize,
    desktop_only: bool,
) -> Result<Value> {
    args.parent_origin = resolve_parent(
        &args.parent_origin,
        desktop_only,
        crate::artifact_html::configuration(),
    )?;
    let document =
        crate::artifact_html::compose_bundle_delivery(&body, &args.parent_origin, body_limit)
            .map_err(|e| Error::engine(format!("read_app_bundle: refused [{}]", e.code)))?;
    if document.len() > DOCUMENT_LIMIT {
        return Err(Error::engine(
            "read_app_bundle: composed document too large [bundle_too_large]",
        ));
    }
    let document_sha256 = hex::encode(Sha256::digest(document.as_bytes()));
    if args
        .expected_document_sha256
        .as_ref()
        .is_some_and(|expected| expected != &document_sha256)
    {
        return Err(Error::engine(
            "read_app_bundle: document changed [cas_mismatch]",
        ));
    }
    if args.offset > document.len() {
        return Err(Error::engine(
            "read_app_bundle: offset beyond document [invalid_range]",
        ));
    }
    let headers = crate::artifact_html::bundle_delivery_headers(&args.parent_origin)?;
    let headers = headers
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().to_owned(),
                Value::String(
                    value
                        .to_str()
                        .map_err(|_| Error::engine("invalid bundle header"))?
                        .to_owned(),
                ),
            ))
        })
        .collect::<Result<serde_json::Map<String, Value>>>()?;
    let end = document.len().min(
        args.offset
            .saturating_add(args.length.unwrap_or(PAGE_LIMIT)),
    );
    Ok(json!({
        "package":args.package, "install_event_id":args.expected_install_event_id,
        "artifact_id":artifact_id, "version":version,
        "source_sha256":super::alpha_tabs::alpha_tab_bundle_digest(&body),
        "document_sha256":document_sha256,
        "parent_origin":args.parent_origin, "headers":headers,
        "media_type":"text/html; charset=utf-8", "encoding":"base64",
        "offset":args.offset, "length":end-args.offset, "total_bytes":document.len(),
        "next_offset":if end < document.len() { Some(end) } else { None },
        "content":STANDARD.encode(&document.as_bytes()[args.offset..end]),
    }))
}

async fn read(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    refuse_app(&caller)?;
    let args = Args::parse(arguments)?;
    let (body, artifact, version, limit) = super::alpha_tabs::read_bundle_source(
        &db,
        &caller,
        &args.package,
        &args.expected_install_event_id,
    )
    .await?;
    response(
        args,
        body,
        artifact,
        version,
        limit,
        db.open_mode() == crate::db::DatabaseOpenMode::StandbyReadOnly
            || caller.hosting_database().is_none(),
    )
}

pub(crate) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(ToolKind::ReadAppBundle,
        "Read an adopted installed app as paged base64 HTML, composed for parent_origin with hosted CSP. Rechecks the caller's install on every page; mints no ticket or URL. Pin subsequent pages with expected_document_sha256 and verify document_sha256 after assembly; source_sha256 identifies exact installed source bytes.",
        json!({"type":"object","properties":{
            "package":{"type":"string"}, "expected_install_event_id":{"type":"string","minLength":1,"maxLength":128},
            "parent_origin":{"type":"string","maxLength":2048}, "offset":{"type":"integer","minimum":0},
            "length":{"type":"integer","minimum":1,"maximum":PAGE_LIMIT},
            "expected_document_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Document digest from page 1; refuses changed documents with cas_mismatch."}
        },"required":["package","expected_install_event_id","parent_origin"],"additionalProperties":false}), read)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bundle</title></head><body>Exact source</body></html>"#;

    fn args() -> Value {
        json!({"package":"test.bundle","expected_install_event_id":"event","parent_origin":"native-ui://app"})
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[test]
    fn read_app_bundle_is_in_node_observational_read_surface() {
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let rows = crate::mcp::executor_prototype::standby_operation_rows(
            &registry,
            crate::mcp::registry::EngineKind::Sqlite,
        )
        .unwrap();
        let row = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["executor"] == "artifacts_read" && row["operation"] == "read_app_bundle"
            })
            .expect("bundle read is catalogued");
        assert_eq!(row["offline_advertised"], true);
        assert_eq!(row["access"], "read");
        assert_eq!(row["plan_required"], false);
    }

    #[test]
    fn read_app_bundle_parent_policy_and_canonicalization() {
        let config =
            crate::artifact_html::RuntimeConfig::new("https://shell.test", "https://artifact.test")
                .unwrap()
                .with_parent_origins(["native-ui://app"])
                .unwrap();
        assert_eq!(
            resolve_parent("https://SHELL.test:443/", false, Some(config.clone())).unwrap(),
            "https://shell.test"
        );
        for standby in [false, true] {
            for parent in ["https://artifact.test", "https://unknown.test"] {
                assert!(resolve_parent(parent, standby, Some(config.clone()))
                    .unwrap_err()
                    .to_string()
                    .contains("parent_origin_not_allowed"));
            }
            assert!(
                resolve_parent("https://shell.test/path", standby, Some(config.clone()))
                    .unwrap_err()
                    .to_string()
                    .contains("invalid_parent_origin")
            );
            assert_eq!(
                resolve_parent("native-ui://app", standby, Some(config.clone())).unwrap(),
                "native-ui://app"
            );
        }
        for parent in ["https://shell.test", "http://localhost:8080"] {
            assert!(resolve_parent(parent, true, Some(config.clone()))
                .unwrap_err()
                .to_string()
                .contains("parent_origin_not_allowed"));
        }
    }

    #[test]
    fn read_app_bundle_document_pin_and_range_edges() {
        let read = |value| {
            response(
                Args::parse(value).unwrap(),
                BODY.into(),
                "artifact".into(),
                "1".into(),
                crate::artifact_html::BODY_LIMIT,
                true,
            )
        };
        let whole = read(args()).unwrap();
        let bytes = STANDARD.decode(whole["content"].as_str().unwrap()).unwrap();
        let total = whole["total_bytes"].as_u64().unwrap() as usize;
        assert_eq!(bytes.len(), total);
        assert_eq!(
            whole["document_sha256"],
            hex::encode(Sha256::digest(&bytes))
        );
        let mut page = args();
        page["offset"] = json!(total);
        page["expected_document_sha256"] = whole["document_sha256"].clone();
        let empty = read(page.clone()).unwrap();
        assert_eq!(empty["content"], "");
        assert_eq!(empty["length"], 0);
        assert!(empty["next_offset"].is_null());
        page["offset"] = json!(total + 1);
        assert!(read(page.clone())
            .unwrap_err()
            .to_string()
            .contains("invalid_range"));
        page["offset"] = json!(total - 17);
        page["length"] = json!(17);
        let last = read(page.clone()).unwrap();
        assert_eq!(
            STANDARD.decode(last["content"].as_str().unwrap()).unwrap(),
            bytes[total - 17..]
        );
        assert!(last["next_offset"].is_null());
        page["expected_document_sha256"] = json!("0".repeat(64));
        assert!(read(page).unwrap_err().to_string().contains("cas_mismatch"));
    }

    #[test]
    fn read_app_bundle_page_bounds_and_exact_parent() {
        for length in [0, PAGE_LIMIT + 1] {
            let mut value = args();
            value["length"] = json!(length);
            assert!(Args::parse(value)
                .unwrap_err()
                .to_string()
                .contains("invalid_params"));
        }
        let mut oversized = args();
        oversized["parent_origin"] = json!("a".repeat(2049));
        assert!(Args::parse(oversized)
            .unwrap_err()
            .to_string()
            .contains("invalid_params"));
        let mut value = args();
        value["offset"] = json!(usize::MAX);
        let error = response(
            Args::parse(value).unwrap(),
            BODY.into(),
            "artifact".into(),
            "1".into(),
            crate::artifact_html::BODY_LIMIT,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid_range"), "{error}");
        for parent in [
            "*",
            "https://example.test/path",
            "https://example.test https://other.test",
        ] {
            let mut value = args();
            value["parent_origin"] = json!(parent);
            assert!(response(
                Args::parse(value).unwrap(),
                BODY.into(),
                "artifact".into(),
                "1".into(),
                crate::artifact_html::BODY_LIMIT,
                true
            )
            .is_err());
        }
    }
}
