//! Host-owned admitted releases. Author policy requests a major, never a path.
use super::*;
use serde::Deserialize;

const JS_MAX: usize = 65536;
const TYPES_MAX: usize = 32768;
const METADATA_MAX: usize = 1024;
// Covers a full DNS hostname (including a trailing dot), HTTPS and a
// nondefault port with room to spare; applies to parent and artifact origins.
pub(super) const ORIGIN_MAX: usize = 512;
// JSON escaping can expand each byte sixfold, plus the surrounding quotes.
const ORIGIN_JSON_MAX: usize = ORIGIN_MAX.checked_mul(6).unwrap().checked_add(2).unwrap();
pub(super) const TRUSTED_OVERHEAD: usize = BOOTSTRAP
    .len()
    .checked_add(JS_MAX)
    .unwrap()
    .checked_add(METADATA_MAX)
    .unwrap()
    .checked_add(ORIGIN_JSON_MAX)
    .unwrap()
    .checked_add(17)
    .unwrap();
pub(super) const DELIVERED_MAX: usize = PACKAGE_BODY_LIMIT.checked_add(TRUSTED_OVERHEAD).unwrap();

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KitRelease {
    pub version: String,
    pub major: u32,
    pub layer: String,
    pub factory: String,
    pub bridge: String,
    pub js_sha256: String,
    pub types_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema: String,
    releases: Vec<CatalogEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    version: String,
    major: u32,
    manifest: String,
    manifest_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema: String,
    version: String,
    major: u32,
    layer: String,
    factory: String,
    bridge: String,
    js: Asset,
    types: Asset,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    file: String,
    bytes: usize,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: String,
    selections: Vec<Selection>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    major: u32,
    version: String,
}

#[derive(Clone)]
struct ResolvedKit {
    release: KitRelease,
    js: Arc<str>,
}
type ReleaseAssets<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8]);
/// Immutable admitted inventory and explicit major selection. Cloning retains
/// the same admitted bytes; constructing another selection affects new sessions.
#[derive(Clone)]
pub struct KitDelivery {
    selected: BTreeMap<u32, ResolvedKit>,
}
fn invalid() -> ValidationFailure {
    ValidationFailure::new(
        "kit_admission_failed",
        "invalid supplied kit inventory or selector",
        json!({"phase":"delivery"}),
    )
}
fn version(value: &str, major: u32) -> std::result::Result<[u32; 3], ValidationFailure> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 || !(1..=65535).contains(&major) {
        return Err(invalid());
    }
    let mut numbers = [0; 3];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty()
            || p.len() > 5
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return Err(invalid());
        }
        numbers[i] = p.parse::<u32>().map_err(|_| invalid())?;
        if numbers[i] > 65535 {
            return Err(invalid());
        }
    }
    if numbers[0] != major {
        return Err(invalid());
    }
    Ok(numbers)
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    cap: usize,
) -> std::result::Result<T, ValidationFailure> {
    if bytes.len() > cap {
        return Err(invalid());
    }
    serde_json::from_slice(bytes).map_err(|_| invalid())
}
impl KitDelivery {
    pub(super) fn selected_major(&self, major: u32) -> bool {
        self.selected.contains_key(&major)
    }
    /// Select only from the production compile-time inventory. No runtime I/O.
    /// Schema: native.app-kit.selector.v1; selections: [{major, version}].
    pub fn from_selector(selector: &str) -> std::result::Result<Self, ValidationFailure> {
        Self::admit(
            include_bytes!("../../kit-releases/catalog.json"),
            &[
                (
                    "1.0.0",
                    include_bytes!("../../kit-releases/1.0.0/manifest.json"),
                    include_bytes!("../../kit-releases/1.0.0/core.js"),
                    include_bytes!("../../kit-releases/1.0.0/core.d.ts"),
                ),
                (
                    "1.1.0",
                    include_bytes!("../../kit-releases/1.1.0/manifest.json"),
                    include_bytes!("../../kit-releases/1.1.0/core.js"),
                    include_bytes!("../../kit-releases/1.1.0/core.d.ts"),
                ),
            ],
            selector,
        )
    }
    fn admit(
        catalog: &[u8],
        assets: &[ReleaseAssets<'_>],
        selector: &str,
    ) -> std::result::Result<Self, ValidationFailure> {
        let catalog: Catalog = parse(catalog, 65536)?;
        if catalog.schema != "native.app-kit.catalog.v1"
            || catalog.releases.is_empty()
            || catalog.releases.len() > 128
            || assets.len() != catalog.releases.len()
        {
            return Err(invalid());
        }
        let mut admitted = BTreeMap::new();
        let mut previous = None;
        for (entry, (asset_version, manifest, js, types)) in catalog.releases.iter().zip(assets) {
            let order = version(&entry.version, entry.major)?;
            if previous.is_some_and(|p| p >= order)
                || *asset_version != entry.version
                || entry.manifest != format!("{}/manifest.json", entry.version)
                || !hash(&entry.manifest_sha256)
                || hex::encode(Sha256::digest(manifest)) != entry.manifest_sha256
            {
                return Err(invalid());
            }
            previous = Some(order);
            let m: ReleaseManifest = parse(manifest, 8192)?;
            if m.schema != "native.app-kit.release.v1"
                || m.version != entry.version
                || m.major != entry.major
                || m.layer != "core"
                || m.factory != "native.app-kit.core.factory.v1"
                || m.bridge != BRIDGE_VERSION
            {
                return Err(invalid());
            }
            for (a, bytes, file, cap) in [
                (&m.js, *js, "core.js", JS_MAX),
                (&m.types, *types, "core.d.ts", TYPES_MAX),
            ] {
                if a.file != file
                    || a.bytes == 0
                    || a.bytes > cap
                    || bytes.len() != a.bytes
                    || !hash(&a.sha256)
                    || hex::encode(Sha256::digest(bytes)) != a.sha256
                    || std::str::from_utf8(bytes).is_err()
                {
                    return Err(invalid());
                }
            }
            let js = std::str::from_utf8(js).map_err(|_| invalid())?;
            if js.to_ascii_lowercase().contains("</script") || js.contains("<!--") {
                return Err(invalid());
            }
            let release = KitRelease {
                version: m.version,
                major: m.major,
                layer: m.layer,
                factory: m.factory,
                bridge: m.bridge,
                js_sha256: m.js.sha256,
                types_sha256: m.types.sha256,
            };
            if serde_json::to_string(&release)
                .map_err(|_| invalid())?
                .len()
                > METADATA_MAX
            {
                return Err(invalid());
            }
            admitted.insert(
                entry.version.clone(),
                ResolvedKit {
                    release,
                    js: Arc::from(js),
                },
            );
        }
        let selector: Selector = parse(selector.as_bytes(), 65536)?;
        if selector.schema != "native.app-kit.selector.v1"
            || selector.selections.len() > catalog.releases.len()
        {
            return Err(invalid());
        }
        let mut selected = BTreeMap::new();
        for s in selector.selections {
            version(&s.version, s.major)?;
            let r = admitted.get(&s.version).ok_or_else(invalid)?.clone();
            if r.release.major != s.major || selected.insert(s.major, r).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self { selected })
    }
    pub(super) fn compose(
        &self,
        source: &str,
        origin: &str,
        manifest: &Manifest,
    ) -> std::result::Result<(String, Option<KitRelease>), ValidationFailure> {
        let resolved = manifest
            .kit_policy
            .as_ref()
            .map(|p| {
                self.selected
                    .get(&p.major)
                    .ok_or_else(|| unavailable(p.major))
            })
            .transpose()?;
        let insertion = bootstrap_insertion_offset(source)?;
        if origin.len() > ORIGIN_MAX {
            return Err(invalid());
        }
        let (factory, metadata) = match resolved {
            Some(r) => (
                r.js.as_ref(),
                serde_json::to_string(&r.release).map_err(|_| invalid())?,
            ),
            None => ("null", "null".into()),
        };
        let origin_json = serde_json::to_string(origin).map_err(|_| invalid())?;
        let tokens = Regex::new("__NATIVE_(?:WORKBENCH_ORIGIN|KIT_FACTORY|KIT_RELEASE)__")
            .expect("bootstrap tokens");
        let bootstrap = tokens.replace_all(BOOTSTRAP, |c: &regex::Captures<'_>| match &c[0] {
            "__NATIVE_WORKBENCH_ORIGIN__" => origin_json.as_str(),
            "__NATIVE_KIT_FACTORY__" => factory,
            _ => metadata.as_str(),
        });
        let bytes = composition_len(source.len(), bootstrap.len())?;
        let mut html = String::with_capacity(bytes);
        html.push_str(&source[..insertion]);
        html.push_str("<script>");
        html.push_str(&bootstrap);
        html.push_str("</script>");
        html.push_str(&source[insertion..]);
        Ok((html, resolved.map(|r| r.release.clone())))
    }
}
impl Default for KitDelivery {
    fn default() -> Self {
        static DEFAULT: OnceLock<KitDelivery> = OnceLock::new();
        DEFAULT.get_or_init(|| Self::from_selector(r#"{"schema":"native.app-kit.selector.v1","selections":[{"major":1,"version":"1.1.0"}]}"#).expect("admitted embedded kit")).clone()
    }
}

pub(super) fn unavailable(major: u32) -> ValidationFailure {
    ValidationFailure::new(
        "kit_major_unavailable",
        format!("Native app kit major {major} is unavailable on this host"),
        json!({"phase":"delivery","major":major}),
    )
}
pub(super) fn composition_len(
    source: usize,
    bootstrap: usize,
) -> std::result::Result<usize, ValidationFailure> {
    let bytes = source
        .checked_add(bootstrap)
        .and_then(|n| n.checked_add(17))
        .ok_or_else(invalid)?;
    if source > PACKAGE_BODY_LIMIT
        || bootstrap
            .checked_add(17)
            .is_none_or(|n| n > TRUSTED_OVERHEAD)
        || bytes > DELIVERED_MAX
    {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(test)]
impl KitDelivery {
    pub(super) fn fixture(selection: &str, js_bytes: usize) -> Self {
        let a_manifest = include_bytes!("../../kit-releases/1.0.0/manifest.json");
        let a_js = include_bytes!("../../kit-releases/1.0.0/core.js");
        let types = include_bytes!("../../kit-releases/1.0.0/core.d.ts");
        let mut b_js = std::str::from_utf8(a_js)
            .unwrap()
            .replace("const version = \"1.0.0\"", "const version = \"1.0.1\"")
            .into_bytes();
        b_js.extend_from_slice(b"\n/* test-only B */");
        b_js.resize(js_bytes.max(b_js.len()), b' ');
        let mut b: Value = serde_json::from_slice(a_manifest).unwrap();
        b["version"] = json!("1.0.1");
        b["js"]["bytes"] = json!(b_js.len());
        b["js"]["sha256"] = json!(hex::encode(Sha256::digest(&b_js)));
        let b_manifest = serde_json::to_vec(&b).unwrap();
        let catalog=serde_json::to_vec(&json!({"schema":"native.app-kit.catalog.v1","releases":[
            {"version":"1.0.0","major":1,"manifest":"1.0.0/manifest.json","manifest_sha256":hex::encode(Sha256::digest(a_manifest))},
            {"version":"1.0.1","major":1,"manifest":"1.0.1/manifest.json","manifest_sha256":hex::encode(Sha256::digest(&b_manifest))}
        ]})).unwrap();
        Self::admit(&catalog,&[("1.0.0",a_manifest,a_js,types),("1.0.1",&b_manifest,&b_js,types)],&json!({"schema":"native.app-kit.selector.v1","selections":[{"major":1,"version":selection}]}).to_string()).unwrap()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str =
        include_str!("../../../../packages/alpha-tab-kit/test/fixtures/core-source.html");
    #[test]
    fn kit_and_legacy_delivery_share_host_owned_skin_exposure() {
        let delivery = KitDelivery::default();
        let manifest = validate(SOURCE).unwrap();
        let (kit_html, _) = delivery
            .compose(SOURCE, "https://host.test", &manifest)
            .unwrap();
        assert!(kit_html.contains("get skin(){return skinFeature?skinApi:undefined}"));
        assert!(kit_html.contains("skinCreate=Document.prototype.createElement"));
        let legacy = SOURCE.replace(r#"<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":1}</script>"#, "");
        let (legacy_html, kit) = delivery
            .compose(&legacy, "https://host.test", &validate(&legacy).unwrap())
            .unwrap();
        assert!(kit.is_none());
        assert!(legacy_html.contains("...(skinFeature?{skin:skinApi}:{})"));
        assert!(legacy_html.contains("type===\"native.skin\")receiveSkin"));
    }

    #[test]
    fn kit_delivery_selector_shared_vectors() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../packages/alpha-tab-kit/test/vectors/kit-selector.json"
        ))
        .unwrap();
        for v in vectors.as_array().unwrap() {
            assert_eq!(
                KitDelivery::from_selector(&v["selector"].to_string()).is_ok(),
                v["valid"].as_bool().unwrap(),
                "{}",
                v["name"]
            );
        }
    }
    #[test]
    fn kit_delivery_retained_session_selection_and_author_restoration() {
        let a = KitDelivery::fixture("1.0.0", 0);
        let b = KitDelivery::fixture("1.0.1", 0);
        let manifest = validate(SOURCE).unwrap();
        let old = a.compose(SOURCE, "https://parent.test", &manifest).unwrap();
        let new = b.compose(SOURCE, "https://parent.test", &manifest).unwrap();
        assert_eq!(old.1.as_ref().unwrap().version, "1.0.0");
        assert_eq!(new.1.as_ref().unwrap().version, "1.0.1");
        assert_ne!(old.0, new.0);
        assert_eq!(
            a.compose(SOURCE, "https://parent.test", &manifest).unwrap(),
            old
        );
        // Source restoration selects current host ownership; validation identity stays author-only.
        assert_eq!(validate(SOURCE).unwrap().body_digest, manifest.body_digest);
        assert_eq!(
            b.compose(SOURCE, "https://parent.test", &manifest).unwrap(),
            new
        );
        let legacy=SOURCE.replace(r#"<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":1}</script>"#,"");
        assert!(b
            .compose(&legacy, "https://parent.test", &validate(&legacy).unwrap())
            .unwrap()
            .1
            .is_none());
        let unavailable = SOURCE.replace("\"major\":1", "\"major\":2");
        assert_eq!(
            b.compose(
                &unavailable,
                "https://parent.test",
                &validate(&unavailable).unwrap()
            )
            .unwrap_err()
            .code,
            "kit_major_unavailable"
        );
    }
    #[test]
    fn kit_delivery_corruption_shared_vectors_fail_admission() {
        let cases: Vec<String> = serde_json::from_str(include_str!(
            "../../../../packages/alpha-tab-kit/test/vectors/kit-asset-corruption.json"
        ))
        .unwrap();
        for case in cases {
            let mut js = include_bytes!("../../kit-releases/1.0.0/core.js").to_vec();
            let mut types = include_bytes!("../../kit-releases/1.0.0/core.d.ts").to_vec();
            let mut m: Value =
                serde_json::from_slice(include_bytes!("../../kit-releases/1.0.0/manifest.json"))
                    .unwrap();
            match case.as_str() {
                "hash" => m["js"]["sha256"] = json!("0".repeat(64)),
                "length" => m["js"]["bytes"] = json!(js.len() + 1),
                "utf8" => js = vec![255],
                "unsafe-inline" => js = b"(() => null)() /* </ScRiPt */".to_vec(),
                "js-cap" => js = vec![b' '; JS_MAX + 1],
                "types-utf8" => types = vec![255],
                "manifest-extra" => m["extra"] = json!(true),
                _ => {}
            }
            if !matches!(case.as_str(), "hash" | "length") {
                m["js"]["bytes"] = json!(js.len());
                m["js"]["sha256"] = json!(hex::encode(Sha256::digest(&js)));
            }
            m["types"]["bytes"] = json!(types.len());
            m["types"]["sha256"] = json!(hex::encode(Sha256::digest(&types)));
            let manifest = serde_json::to_vec(&m).unwrap();
            let mut c = json!({"schema":"native.app-kit.catalog.v1","releases":[{"version":"1.0.0","major":1,"manifest":"1.0.0/manifest.json","manifest_sha256":hex::encode(Sha256::digest(&manifest))}]});
            if case == "catalog-extra" {
                c["extra"] = json!(true);
            }
            if case == "manifest-hash" {
                c["releases"][0]["manifest_sha256"] = json!("0".repeat(64));
            }
            assert!(KitDelivery::admit(&serde_json::to_vec(&c).unwrap(),&[("1.0.0",&manifest,&js,&types)],r#"{"schema":"native.app-kit.selector.v1","selections":[{"major":1,"version":"1.0.0"}]}"#).is_err(),"{case}");
        }
    }
    #[test]
    fn kit_delivery_legacy_custody_and_browser_evidence() {
        let config = RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap();
        let store = Mutex::new(TicketStore::default());
        let manifest = validate(SOURCE).unwrap();
        let launch = issue_launch_in_store(
            SOURCE, &manifest, "owner", None, "fixture", &config, None, None, &store, None,
        )
        .unwrap();
        let newer = issue_launch_in_store_with_kit(
            SOURCE,
            &manifest,
            "owner",
            None,
            "fixture",
            &config,
            None,
            None,
            &store,
            None,
            &KitDelivery::fixture("1.0.1", 0),
        )
        .unwrap();
        assert_eq!(newer.kit_release.as_ref().unwrap().version, "1.0.1");
        let rollback = issue_launch_in_store_with_kit(
            SOURCE,
            &manifest,
            "owner",
            None,
            "fixture",
            &config,
            None,
            None,
            &store,
            None,
            &KitDelivery::fixture("1.0.0", 0),
        )
        .unwrap();
        assert_eq!(rollback.kit_release.as_ref().unwrap().version, "1.0.0");
        let token = launch.url.rsplit('/').next().unwrap();
        let store = store.lock().unwrap();
        let ticket = &store.entries[token];
        assert_eq!(launch.kit_release.as_ref().unwrap().version, "1.1.0");
        assert_eq!(ticket._body_digest, manifest.body_digest);
        assert_eq!(
            ticket.html,
            KitDelivery::default()
                .compose(SOURCE, "https://parent.test", &manifest)
                .unwrap()
                .0
        );
        // Optional ignored evidence for the cached-browser proof; no tracked output.
        if let Ok(dir) = std::env::var("NATIVE_KIT_DELIVERY_EVIDENCE_DIR") {
            std::fs::write(
                std::path::Path::new(&dir).join("real-core-delivery.html"),
                &ticket.html,
            )
            .unwrap();
        }
    }
    #[test]
    fn source_starter_guide_bytes_have_rust_ticket_custody() {
        let guide = include_str!("../../../../src/mcp/guides/app-builder-1.0.0.md");
        let sources: Vec<_> = guide
            .split("```html\n")
            .skip(1)
            .map(|part| part.split("```").next().unwrap())
            .collect();
        assert_eq!(sources.len(), 2);
        let config = RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap();
        let store = Mutex::new(TicketStore::default());
        for (index, source) in sources.iter().enumerate() {
            let manifest = validate(source).unwrap();
            let launch = issue_launch_in_store(
                source,
                &manifest,
                "owner",
                None,
                "source-starter",
                &config,
                None,
                None,
                &store,
                None,
            )
            .unwrap();
            let token = launch.url.rsplit('/').next().unwrap();
            let store = store.lock().unwrap();
            let ticket = &store.entries[token];
            assert_eq!(launch.kit_release.as_ref().unwrap().version, "1.1.0");
            if let Ok(dir) = std::env::var("NATIVE_KIT_DELIVERY_EVIDENCE_DIR") {
                std::fs::write(
                    std::path::Path::new(&dir).join(format!("real-starter-{index}.html")),
                    &ticket.html,
                )
                .unwrap();
            }
        }
    }
    #[tokio::test]
    async fn kit_delivery_sample_tickets_pin_release_and_clones_share_custody() {
        use axum::body::{to_bytes, Body};
        use tower::ServiceExt;
        // Instance-owned stores: redemption try_locks below can never
        // observe a busy process-wide legacy store held by a concurrent
        // legacy-launch test. Clones retain the same three stores, so the
        // custody-sharing assertions exercise the normal lookup path.
        let config = RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap();
        let a = LaunchDelivery::isolated_fixture(config.clone())
            .with_kit_selection(KitDelivery::fixture("1.0.0", 0));
        let b = a.with_kit_selection(KitDelivery::fixture("1.0.1", 0));
        let manifest = validate(SOURCE).unwrap();
        let pending = a
            .reserve_sample_launch(SOURCE, &manifest, "owner", None, "fixture")
            .unwrap();
        assert_eq!(
            pending.descriptor().kit_release.as_ref().unwrap().version,
            "1.0.0"
        );
        let newer = b
            .issue_launch(SOURCE, &manifest, "owner", None, "fixture")
            .unwrap();
        assert_eq!(newer.kit_release.as_ref().unwrap().version, "1.0.1");
        let url = pending.descriptor().url.clone();
        let deadline = pending.original_ticket_deadline();
        pending
            .try_lock_for_publication(deadline)
            .unwrap()
            .commit(deadline)
            .unwrap();
        let response = b
            .clone()
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri(Url::parse(&url).unwrap().path())
                    .header(HOST, "artifact.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(
            to_bytes(response.into_body(), DELIVERED_MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            html,
            KitDelivery::fixture("1.0.0", 0)
                .compose(SOURCE, "https://parent.test", &manifest)
                .unwrap()
                .0
        );
        let rollback = b.with_kit_selection(KitDelivery::fixture("1.0.0", 0));
        let response = rollback
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri(Url::parse(&newer.url).unwrap().path())
                    .header(HOST, "artifact.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(
            to_bytes(response.into_body(), DELIVERED_MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            html,
            KitDelivery::fixture("1.0.1", 0)
                .compose(SOURCE, "https://parent.test", &manifest)
                .unwrap()
                .0
        );
    }
    #[test]
    fn kit_delivery_long_canonical_origins_preserve_legacy_and_opted_in_delivery() {
        let hostname = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let legacy = SOURCE.replace(
            r#"<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":1}</script>"#,
            "",
        );
        assert_ne!(legacy, SOURCE);
        for port in ["", ":65535"] {
            let origin = format!("https://{hostname}{port}");
            assert_eq!(origin.len(), 261 + port.len());
            let config = RuntimeConfig::new(&origin, origin.replace("aaa", "eee")).unwrap();
            let delivery = LaunchDelivery::new(config);
            for source in [legacy.as_str(), SOURCE] {
                let manifest = validate(source).unwrap();
                let (html, release) = delivery.kit.compose(source, &origin, &manifest).unwrap();
                assert!(html.contains(&serde_json::to_string(&origin).unwrap()));
                assert_eq!(release.is_some(), source == SOURCE);
                assert!(html.len() <= DELIVERED_MAX);
                assert!(delivery
                    .body_context(&origin)
                    .unwrap()
                    .prepare(
                        source.to_owned(),
                        Sha256::digest(source.as_bytes()).into(),
                        PACKAGE_BODY_LIMIT
                    )
                    .is_ok());
                assert!(delivery
                    .reserve_sample_launch(source, &manifest, "owner", None, "fixture")
                    .is_ok());
            }
        }
        assert!(KitDelivery::default()
            .compose(
                SOURCE,
                &"a".repeat(ORIGIN_MAX + 1),
                &validate(SOURCE).unwrap()
            )
            .is_err());
    }
    #[test]
    fn kit_delivery_checked_maximum_and_overflow() {
        let b = KitDelivery::fixture("1.0.1", JS_MAX);
        let source = format!(
            "{}{}",
            SOURCE,
            " ".repeat(PACKAGE_BODY_LIMIT - SOURCE.len())
        );
        let m = validate_with_limit(&source, PACKAGE_BODY_LIMIT).unwrap();
        let (html, _) = b.compose(&source, "https://parent.test", &m).unwrap();
        assert!(html.len() > PACKAGE_BODY_LIMIT + JS_MAX);
        assert!(html.len() <= DELIVERED_MAX);
        assert_eq!(m.body_utf8_bytes, PACKAGE_BODY_LIMIT);
        assert!(composition_len(usize::MAX, 1).is_err());
        assert!(composition_len(1, usize::MAX).is_err());
        assert!(composition_len(PACKAGE_BODY_LIMIT, TRUSTED_OVERHEAD - 17).is_ok());
        assert!(composition_len(PACKAGE_BODY_LIMIT, TRUSTED_OVERHEAD - 16).is_err());
    }
}
