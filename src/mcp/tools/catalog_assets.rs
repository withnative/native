//! Trusted compiled catalog assets. Never supplied by tool arguments.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
fn invalid(message: &str) -> Error {
    Error::engine(format!("catalog publication: {message}"))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("missing catalog field"))
}
/// Trusted composition input, never deserialized from tool arguments. The host
/// supplies only its embedded catalog and content-addressed payload assets.
#[derive(Clone)]
pub struct CatalogAssets {
    pub(crate) catalog: Value,
    payloads: BTreeMap<String, Vec<u8>>,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl CatalogAssets {
    pub fn from_embedded(catalog: &[u8], payloads: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        if catalog.len() > 128 * 1024 || payloads.len() > 32 {
            return Err(invalid("catalog bounds exceeded"));
        }
        let catalog: Value = serde_json::from_slice(catalog)?;
        validate_catalog(&catalog)?;
        let assets = Self { catalog, payloads };
        for entry in assets.catalog["entries"]
            .as_array()
            .expect("validated entries")
        {
            assets.select(string(entry, "package")?, string(entry, "version")?)?;
        }
        Ok(assets)
    }
    pub(crate) fn select(&self, package: &str, version: &str) -> Result<(Value, Vec<u8>, String)> {
        let entry = self.catalog["entries"]
            .as_array()
            .expect("validated entries")
            .iter()
            .find(|e| e["package"] == package && e["version"] == version)
            .ok_or_else(|| invalid("package/version absent from host catalog"))?;
        let bytes = self
            .payloads
            .get(string(entry, "payload_path")?)
            .ok_or_else(|| invalid("host catalog payload missing"))?;
        let body = verify_payload(entry, bytes)?;
        Ok((entry.clone(), bytes.clone(), body))
    }
}

pub(crate) fn validate_catalog(catalog: &Value) -> Result<()> {
    let entries = catalog["entries"]
        .as_array()
        .ok_or_else(|| invalid("catalog entries missing"))?;
    let mut bytes = serde_json::to_vec(entries)?;
    bytes.push(b'\n');
    if catalog["schema"] != "native.first-party-catalog.v1"
        || entries.is_empty()
        || entries.len() > 32
        || catalog["digest"] != hash(&bytes)
    {
        return Err(invalid("catalog schema/digest/bounds mismatch"));
    }
    let mut packages = BTreeSet::new();
    for entry in entries {
        let package = string(entry, "package")?;
        let sha = string(entry, "payload_sha256")?;
        if !packages.insert(package)
            || sha.len() != 64
            || !sha
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || entry["payload_path"] != format!("packages/{sha}.json")
        {
            return Err(invalid("ambiguous catalog or invalid payload address"));
        }
        crate::mcp::tools::alpha_tabs::require_package(package)?;
        crate::mcp::tools::alpha_tabs::require_version(string(entry, "version")?)?;
    }
    Ok(())
}

pub(crate) fn verify_payload(entry: &Value, bytes: &[u8]) -> Result<String> {
    if bytes.len() > 4 * 1024 * 1024 || entry["payload_sha256"] != hash(bytes) {
        return Err(invalid("catalog payload content hash mismatch"));
    }
    let payload: Value = serde_json::from_slice(bytes)?;
    let mut create = payload["create"].clone();
    crate::mcp::tools::body_encoding::decode_arguments("create_record", &mut create, &["body"])?;
    let body = string(&create, "body")?.to_owned();
    verify_retained_payload(entry, bytes, &body)?;
    Ok(body)
}

/// Replay uses the recorded HTML and immutable v1 digest evidence. Transport
/// decoding and current package admission policy run only at publication.
pub(crate) fn verify_retained_payload(entry: &Value, bytes: &[u8], body: &str) -> Result<()> {
    if bytes.len() > 4 * 1024 * 1024 || entry["payload_sha256"] != hash(bytes) {
        return Err(invalid("catalog payload content hash mismatch"));
    }
    let payload: Value = serde_json::from_slice(bytes)?;
    let create = &payload["create"];
    let declaration = &payload["declaration"];
    let bundle = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(body);
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(declaration)?;
    let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
        &bundle,
        &declaration_digest,
        "native.html.v1",
    );
    if payload["schema"] != "native.first-party-payload.v1"
        || entry["runtime"] != "native.html.v1"
        || entry["contract"] != "native.app.v2"
        || declaration["contract"] != "native.app.v2"
        || create["type"] != "Document"
        || create["kind"] != "artifact"
        || create["facets"]["runtime"] != "native.html.v1"
        || create["facets"]["app_package"] != "true"
        || entry["bundle_sha256"] != bundle
        || entry["body_digest"] != bundle
        || entry["body_bytes"] != body.len()
        || entry["declaration_digest"] != declaration_digest
        || entry["digest"] != digest
        || payload["expected"]["body_digest"] != bundle
        || payload["expected"]["body_bytes"] != body.len()
    {
        return Err(invalid(
            "catalog payload source/declaration/digest mismatch",
        ));
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub artifact_id: String,
    pub package: String,
    pub version: String,
    pub expected_body_digest: String,
    /// Explicit null admits only a never-installed, private catalog source.
    #[serde(deserialize_with = "Option::<String>::deserialize")]
    pub expected_install_event_id: Option<String>,
    pub reason: String,
    pub idempotency_key: Option<String>,
}

#[cfg(test)]
pub(crate) fn fixture_assets(body: &str, package: &str, version: &str) -> CatalogAssets {
    let declaration = serde_json::json!({"contract":"native.app.v2","needs":[],"effects":[]});
    let bundle = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(body);
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration).unwrap();
    let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
        &bundle,
        &declaration_digest,
        "native.html.v1",
    );
    let payload = serde_json::json!({"schema":"native.first-party-payload.v1","declaration":declaration,
        "create":{"type":"Document","kind":"artifact","facets":{"runtime":"native.html.v1","app_package":"true"},"body":body},
        "expected":{"body_bytes":body.len(),"body_digest":bundle}});
    let bytes = serde_json::to_vec(&payload).unwrap();
    let sha = hash(&bytes);
    let path = format!("packages/{sha}.json");
    let entries = serde_json::json!([{"package":package,"version":version,"runtime":"native.html.v1","contract":"native.app.v2","bundle_sha256":bundle,"body_digest":bundle,"body_bytes":body.len(),"declaration_digest":declaration_digest,"digest":digest,"payload_path":path,"payload_sha256":sha}]);
    let mut encoded = serde_json::to_vec(&entries).unwrap();
    encoded.push(b'\n');
    let catalog = serde_json::json!({"schema":"native.first-party-catalog.v1","digest":hash(&encoded),"entries":entries});
    CatalogAssets::from_embedded(
        &serde_json::to_vec(&catalog).unwrap(),
        BTreeMap::from([(path, bytes)]),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_payloads_bind_content_identity_and_declaration() {
        let assets = fixture_assets("<html>test</html>", "agent.docs", "0.12.9");
        assert!(assets.select("agent.docs", "0.12.8").is_err());
        let (mut entry, bytes, _) = assets.select("agent.docs", "0.12.9").unwrap();
        entry["digest"] = Value::String("00".repeat(32));
        assert!(verify_payload(&entry, &bytes).is_err());
        let mut changed = bytes.clone();
        changed.push(b' ');
        assert!(verify_payload(&assets.catalog["entries"][0], &changed).is_err());
        let mut duplicate = assets.catalog.clone();
        duplicate["entries"]
            .as_array_mut()
            .unwrap()
            .push(assets.catalog["entries"][0].clone());
        let mut encoded = serde_json::to_vec(&duplicate["entries"]).unwrap();
        encoded.push(b'\n');
        duplicate["digest"] = Value::String(hash(&encoded));
        assert!(validate_catalog(&duplicate).is_err());
    }
}

/// No caller-selected target, owner, declaration, source bytes or placement.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializeRequest {
    pub package: String,
    pub version: String,
    pub expected_install_event_id: String,
    pub predecessor_artifact_id: String,
    pub reason: String,
    pub idempotency_key: String,
}
