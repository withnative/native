//! Drift guard for the alpha tab kit (`packages/alpha-tab-kit`).
//!
//! The kit lets an alpha tab package be checked and installed from outside
//! this repository (decision `8a2ea04`). It mirrors limits and rules that
//! live here, so this test fails when they move without the kit moving:
//!
//! - every engine-backed value in `limits.json` equals the constant it names,
//!   or sits exactly on the boundary of the behaviour it names;
//! - every such value is asserted here (a new kit limit with no assertion
//!   fails `every_engine_backed_limit_is_asserted`);
//! - the vendored bridge script is byte-identical to `BOOTSTRAP`;
//! - the kit's digest vectors recompute here, including a declaration the
//!   hosted server confirmed at install;
//! - the kit's SQL, declaration, package and version corpora get the same
//!   admitted/refused verdict from the engine as the kit's own tests expect.
//!
//! Values marked `js_literal` mirror the demo shell, not the engine; the
//! kit's own `node --test` suite checks those against the shell source.
//!
//! If this fails after an intentional engine change, update
//! `packages/alpha-tab-kit` (limits.json, and the module the failing value
//! feeds) in the same change.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use super::{
    alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    alpha_tab_sample_input, parse_sql_need_entry, require_declaration, require_package,
    require_reason, require_version, ALPHA_TAB_DIGEST_VERSION, ARTIFACT_RENDER_NEED,
    ARTIFACT_RENDER_RESULT_MAX_CHARS, ATTENTION_QUERY_NEED, CANVAS_ID_MAX_CHARS,
    CANVAS_SCENE_LIMIT_MAX, CANVAS_SCENE_NEED, CANVAS_SCENE_PAGE_MAX_CHARS,
    RECORDS_RESOLVE_REFERENCE_NEED, RECORDS_SEARCH_NEED, RECORD_CHANGES_LIMIT_MAX,
    RECORD_CHANGES_NEED, RECORD_CHANGES_PAGE_MAX_CHARS, RECORD_ID_MAX_CHARS, REFERENCE_MAX_CHARS,
    SEARCH_LIMIT_MAX, SEARCH_QUERY_MAX_CHARS, SQL_NEED_RESULT_FIELDS,
    SQL_PARAM_TEXT_DEFAULT_MAX_LEN, SQL_PARAM_TEXT_HARD_CAP, SQL_SNAPSHOT_KEY_MAX_CHARS,
    SQL_SNAPSHOT_LABEL_MAX_CHARS, SQL_SNAPSHOT_MAX_NEEDS, SQL_SNAPSHOT_MAX_PARAMS,
    SQL_SNAPSHOT_NEED, SQL_SNAPSHOT_ROW_CAP, SQL_SNAPSHOT_SQL_MAX_BYTES,
};
use crate::artifact_html as html;
use crate::query::sql_contract as contract;

const LIMITS: &str = include_str!("../../../packages/alpha-tab-kit/limits.json");
const BRIDGE: &str =
    include_str!("../../../packages/alpha-tab-kit/src/fake-host/bridge-bootstrap.js");
const VECTORS: &str =
    include_str!("../../../packages/alpha-tab-kit/test/vectors/digest-vectors.json");
const CORPUS: &str = include_str!("../../../packages/alpha-tab-kit/test/vectors/corpus.json");

fn limits() -> Value {
    serde_json::from_str(LIMITS).expect("packages/alpha-tab-kit/limits.json is JSON")
}

/// The `value` of one limits.json leaf, by dotted path.
fn kit(path: &str) -> Value {
    let mut node = limits();
    for part in path.split('.') {
        node = node
            .get(part)
            .cloned()
            .unwrap_or_else(|| panic!("limits.json has no '{path}'"));
    }
    node.get("value")
        .cloned()
        .unwrap_or_else(|| panic!("limits.json '{path}' has no value"))
}

fn same(path: &str, engine: Value, symbol: &str) {
    assert_eq!(
        kit(path),
        engine,
        "packages/alpha-tab-kit/limits.json '{path}' no longer matches {symbol}; update the kit with this change"
    );
}

fn names(path: &str) -> BTreeSet<String> {
    kit(path)
        .as_array()
        .unwrap_or_else(|| panic!("limits.json '{path}' is not an array"))
        .iter()
        .map(|value| value.as_str().expect("string entry").to_owned())
        .collect()
}

/// Leaves this file asserts. `every_engine_backed_limit_is_asserted` fails
/// if limits.json grows an engine-backed leaf that is not listed here.
const ASSERTED: &[&str] = &[
    "digest.version",
    "install.runtime",
    "install.package_max_bytes",
    "install.package_label_max_bytes",
    "install.version_max_bytes",
    "install.version_part_max_digits",
    "install.reason_max_bytes",
    "declaration.max_entries",
    "declaration.name_max_bytes",
    "declaration.sql_snapshot_need",
    "declaration.sql_snapshot_max_needs",
    "declaration.sql_need_key_max_chars",
    "declaration.label_max_chars",
    "declaration.sql_max_bytes",
    "declaration.max_params",
    "declaration.param_text_default_max_len",
    "declaration.param_text_hard_cap",
    "declaration.param_name_max_chars",
    "declaration.param_types",
    "declaration.facet_set_effect",
    "declaration.facet_set_values_max",
    "declaration.comment_create_effect",
    "declaration.comment_create_max_body_bytes",
    "declaration.comment_create_positions",
    "declaration.message_react_effect",
    "declaration.message_react_emoji",
    "declaration.title_set_effect",
    "declaration.host_need_names",
    "reads.sql_snapshot_row_cap",
    "reads.search_query_max_chars",
    "reads.search_limit_max",
    "reads.reference_max_chars",
    "reads.sql_result_fields",
    "reads.canvas_scene_limit_max",
    "reads.canvas_id_max_chars",
    "reads.canvas_scene_cursor_max_chars",
    "reads.canvas_scene_page_max_chars",
    "reads.canvas_scene_field_max_bytes",
    "reads.record_changes_limit_max",
    "reads.record_id_max_chars",
    "reads.record_changes_cursor_max_chars",
    "reads.record_changes_page_max_chars",
    "reads.record_changes_value_max_chars",
    "reads.record_changes_max_references",
    "reads.record_changes_max_payload_bytes",
    "reads.record_changes_field_max_chars",
    "reads.record_changes_reason_max_chars",
    "reads.artifact_render_result_max_chars",
    "reads.truncation_hint",
    "sql.max_sql_bytes",
    "sql.max_placeholder",
    "sql.max_rows",
    "sql.max_columns",
    "sql.max_cell_encoded_bytes",
    "sql.max_result_encoded_bytes",
    "sql.deadline_ms",
    "sql.relations",
    "sql.portable_functions",
    "sql.dropped_functions",
    "sql.forbidden_words",
    "sql.clock_keywords",
    "html.body_max_bytes",
    "html.data_asset_max_bytes",
    "html.data_assets_total_max_bytes",
    "html.dom_node_max",
    "html.css_rule_max",
    "html.input_json_max_bytes",
    "html.input_records_max",
    "html.bridge_message_max_bytes",
    "html.forbidden_elements",
    "html.url_attributes",
    "html.data_mime_types",
    "bridge.version",
    "bridge.adapter_revision",
    "bridge.validator_version",
    "bridge.bootstrap_sha256",
    "bridge.pending_read_cap",
    "bridge.read_params_max_chars",
    "bridge.answer_max_chars",
    "bridge.view_state_max_chars",
    "bridge.csp",
    "sample_input",
];

#[test]
fn dormant_body_bound_mirrors_kit_without_sendability_claim() {
    let proposed = &limits()["proposed_body_set"];
    assert_eq!(proposed["effect"], json!(super::BODY_SET_EFFECT));
    assert_eq!(
        proposed["max_body_bytes"],
        json!(super::BODY_SET_MAX_BODY_BYTES)
    );
    assert_eq!(proposed["status"], json!("provisional-raw-utf8-bound"));
    assert_eq!(
        proposed["encoded_budget_status"],
        json!("dedicated Body envelope 6 * raw cap + 64 KiB; engine encoded values and replay payloads 4 MiB; rollout and host compatibility require qualification")
    );
}

#[test]
fn every_engine_backed_limit_is_asserted() {
    fn walk(prefix: &str, node: &Value, out: &mut Vec<(String, bool)>) {
        let Some(object) = node.as_object() else {
            return;
        };
        if object.contains_key("value") {
            out.push((prefix.to_owned(), object.contains_key("js_literal")));
            return;
        }
        for (key, child) in object {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            walk(&path, child, out);
        }
    }
    let mut leaves = Vec::new();
    walk("", &limits(), &mut leaves);
    let asserted: BTreeSet<&str> = ASSERTED.iter().copied().collect();
    for (path, shell_only) in &leaves {
        assert!(
            *shell_only || asserted.contains(path.as_str()),
            "limits.json '{path}' is not asserted by alpha_tab_kit_drift.rs; add an assertion (or mark it js_literal if it mirrors the demo shell)"
        );
    }
    for path in ASSERTED {
        assert!(
            leaves.iter().any(|(leaf, _)| leaf == path),
            "alpha_tab_kit_drift.rs asserts '{path}', which limits.json no longer has"
        );
    }
}

#[test]
fn reaction_emoji_lists_agree_across_gates() {
    // The canonical five live at three gates: event validation
    // (`src/events.rs`), consent parse (`effect_bounds.rs`) and manifest
    // validation (`mdx_v2.rs`, upstream crate so it cannot share the
    // source). One assertion stops silent divergence of the contract.
    let seam = super::super::effect_bounds::MESSAGE_REACT_EMOJIS;
    let manifest = native_artifact_runtime::mdx_v2::MESSAGE_REACT_EMOJIS;
    let events = crate::events::MESSAGE_REACTION_EMOJIS;
    assert_eq!(seam, manifest, "effect_bounds drifted from mdx_v2");
    assert_eq!(seam, events, "effect_bounds drifted from events");
}

#[test]
fn install_and_declaration_limits_match_the_engine() {
    same(
        "digest.version",
        json!(ALPHA_TAB_DIGEST_VERSION),
        "ALPHA_TAB_DIGEST_VERSION",
    );
    same(
        "install.runtime",
        json!(html::RUNTIME_ID),
        "html::RUNTIME_ID",
    );
    same(
        "declaration.sql_snapshot_need",
        json!(SQL_SNAPSHOT_NEED),
        "SQL_SNAPSHOT_NEED",
    );
    same(
        "declaration.sql_snapshot_max_needs",
        json!(SQL_SNAPSHOT_MAX_NEEDS),
        "SQL_SNAPSHOT_MAX_NEEDS",
    );
    same(
        "declaration.sql_need_key_max_chars",
        json!(SQL_SNAPSHOT_KEY_MAX_CHARS),
        "SQL_SNAPSHOT_KEY_MAX_CHARS",
    );
    same(
        "declaration.label_max_chars",
        json!(SQL_SNAPSHOT_LABEL_MAX_CHARS),
        "SQL_SNAPSHOT_LABEL_MAX_CHARS",
    );
    same(
        "declaration.sql_max_bytes",
        json!(SQL_SNAPSHOT_SQL_MAX_BYTES),
        "SQL_SNAPSHOT_SQL_MAX_BYTES",
    );
    same(
        "declaration.max_params",
        json!(SQL_SNAPSHOT_MAX_PARAMS),
        "SQL_SNAPSHOT_MAX_PARAMS",
    );
    same(
        "declaration.param_text_default_max_len",
        json!(SQL_PARAM_TEXT_DEFAULT_MAX_LEN),
        "SQL_PARAM_TEXT_DEFAULT_MAX_LEN",
    );
    same(
        "declaration.param_text_hard_cap",
        json!(SQL_PARAM_TEXT_HARD_CAP),
        "SQL_PARAM_TEXT_HARD_CAP",
    );
    same(
        "declaration.facet_set_effect",
        json!(super::FACET_SET_EFFECT),
        "FACET_SET_EFFECT",
    );
    same(
        "declaration.facet_set_values_max",
        json!(super::FACET_SET_VALUES_MAX),
        "FACET_SET_VALUES_MAX",
    );
    same(
        "declaration.comment_create_effect",
        json!(super::COMMENT_CREATE_EFFECT),
        "COMMENT_CREATE_EFFECT",
    );
    same(
        "declaration.comment_create_max_body_bytes",
        json!(super::COMMENT_CREATE_MAX_BODY_BYTES),
        "COMMENT_CREATE_MAX_BODY_BYTES",
    );
    same(
        "declaration.comment_create_positions",
        json!(super::COMMENT_CREATE_POSITIONS),
        "COMMENT_CREATE_POSITIONS",
    );
    same(
        "declaration.message_react_effect",
        json!(super::MESSAGE_REACT_EFFECT),
        "MESSAGE_REACT_EFFECT",
    );
    same(
        "declaration.message_react_emoji",
        json!(super::super::effect_bounds::MESSAGE_REACT_EMOJIS),
        "MESSAGE_REACT_EMOJIS",
    );
    same(
        "declaration.title_set_effect",
        json!(super::TITLE_SET_EFFECT),
        "TITLE_SET_EFFECT",
    );
    same(
        "declaration.host_need_names",
        json!([
            ATTENTION_QUERY_NEED,
            RECORDS_SEARCH_NEED,
            RECORDS_RESOLVE_REFERENCE_NEED,
            CANVAS_SCENE_NEED,
            RECORD_CHANGES_NEED,
            ARTIFACT_RENDER_NEED
        ]),
        "the host need names",
    );
    same(
        "reads.sql_snapshot_row_cap",
        json!(SQL_SNAPSHOT_ROW_CAP),
        "SQL_SNAPSHOT_ROW_CAP",
    );
    same(
        "reads.search_query_max_chars",
        json!(SEARCH_QUERY_MAX_CHARS),
        "SEARCH_QUERY_MAX_CHARS",
    );
    same(
        "reads.search_limit_max",
        json!(SEARCH_LIMIT_MAX),
        "SEARCH_LIMIT_MAX",
    );
    same(
        "reads.reference_max_chars",
        json!(REFERENCE_MAX_CHARS),
        "REFERENCE_MAX_CHARS",
    );
    same(
        "reads.sql_result_fields",
        json!(SQL_NEED_RESULT_FIELDS),
        "SQL_NEED_RESULT_FIELDS",
    );
    same(
        "reads.canvas_scene_limit_max",
        json!(CANVAS_SCENE_LIMIT_MAX),
        "CANVAS_SCENE_LIMIT_MAX",
    );
    same(
        "reads.canvas_id_max_chars",
        json!(CANVAS_ID_MAX_CHARS),
        "CANVAS_ID_MAX_CHARS",
    );
    same(
        "reads.canvas_scene_cursor_max_chars",
        json!(super::super::canvas::SceneCursor::MAX_CHARS),
        "SceneCursor::MAX_CHARS",
    );
    same(
        "reads.canvas_scene_page_max_chars",
        json!(CANVAS_SCENE_PAGE_MAX_CHARS),
        "CANVAS_SCENE_PAGE_MAX_CHARS",
    );
    same(
        "reads.canvas_scene_field_max_bytes",
        json!(super::super::canvas::TAB_SCENE_FIELD_MAX_BYTES),
        "TAB_SCENE_FIELD_MAX_BYTES",
    );
    same(
        "reads.record_changes_limit_max",
        json!(RECORD_CHANGES_LIMIT_MAX),
        "RECORD_CHANGES_LIMIT_MAX",
    );
    same(
        "reads.record_id_max_chars",
        json!(RECORD_ID_MAX_CHARS),
        "RECORD_ID_MAX_CHARS",
    );
    same(
        "reads.record_changes_cursor_max_chars",
        json!(super::RecordChangesCursor::MAX_CHARS),
        "RecordChangesCursor::MAX_CHARS",
    );
    same(
        "reads.record_changes_page_max_chars",
        json!(RECORD_CHANGES_PAGE_MAX_CHARS),
        "RECORD_CHANGES_PAGE_MAX_CHARS",
    );
    same(
        "reads.record_changes_value_max_chars",
        json!(super::super::history::TAB_CHANGE_VALUE_MAX_CHARS),
        "TAB_CHANGE_VALUE_MAX_CHARS",
    );
    same(
        "reads.record_changes_max_references",
        json!(super::super::history::TAB_CHANGE_MAX_REFERENCES),
        "TAB_CHANGE_MAX_REFERENCES",
    );
    same(
        "reads.record_changes_max_payload_bytes",
        json!(super::super::history::TAB_CHANGE_MAX_PAYLOAD_BYTES),
        "TAB_CHANGE_MAX_PAYLOAD_BYTES",
    );
    same(
        "reads.record_changes_field_max_chars",
        json!(super::super::history::TAB_CHANGE_FIELD_MAX_CHARS),
        "TAB_CHANGE_FIELD_MAX_CHARS",
    );
    same(
        "reads.record_changes_reason_max_chars",
        json!(super::super::history::TAB_CHANGE_REASON_MAX_CHARS),
        "TAB_CHANGE_REASON_MAX_CHARS",
    );
    same(
        "reads.artifact_render_result_max_chars",
        json!(ARTIFACT_RENDER_RESULT_MAX_CHARS),
        "ARTIFACT_RENDER_RESULT_MAX_CHARS",
    );
    same(
        "reads.truncation_hint",
        json!(contract::truncation_hint()),
        "sql_contract::truncation_hint",
    );
    same(
        "sample_input",
        alpha_tab_sample_input(),
        "alpha_tab_sample_input",
    );
}

/// Literal limits with no named constant, probed at and one past the edge.
#[test]
fn literal_install_limits_sit_on_the_engine_boundary() {
    let n = |path: &str| kit(path).as_u64().expect("integer limit") as usize;

    let label = n("install.package_label_max_bytes");
    assert!(require_package(&format!("a.{}", "b".repeat(label))).is_ok());
    assert!(require_package(&format!("a.{}", "b".repeat(label + 1))).is_err());
    let package = n("install.package_max_bytes");
    let fill = |len: usize| {
        let mut out = "a.".repeat(len / 2);
        out.truncate(len - 1);
        out.push('a');
        out
    };
    assert!(require_package(&fill(package)).is_ok());
    assert!(require_package(&fill(package + 1)).is_err());

    let digits = n("install.version_part_max_digits");
    assert!(require_version(&format!("{}.0.0", "1".repeat(digits))).is_ok());
    assert!(require_version(&format!("{}.0.0", "1".repeat(digits + 1))).is_err());
    let version = n("install.version_max_bytes");
    let part = "1".repeat(digits);
    let long = format!("{part}.{part}.{part}");
    // Three maximal parts plus two dots must fit the whole-version bound.
    assert!(long.len() <= version && require_version(&long).is_ok());

    let reason = n("install.reason_max_bytes");
    assert!(require_reason("t", &"r".repeat(reason)).is_ok());
    assert!(require_reason("t", &"r".repeat(reason + 1)).is_err());

    let entries = n("declaration.max_entries");
    let effects = |count: usize| json!({"needs": [], "effects": (0..count).map(|i| format!("e.{i}")).collect::<Vec<_>>()});
    assert!(require_declaration(&effects(entries)).is_ok());
    assert!(require_declaration(&effects(entries + 1)).is_err());
    let name = n("declaration.name_max_bytes");
    assert!(require_declaration(&json!({"needs": ["n".repeat(name)], "effects": []})).is_ok());
    assert!(require_declaration(&json!({"needs": ["n".repeat(name + 1)], "effects": []})).is_err());

    let param = n("declaration.param_name_max_chars");
    let with_param = |param_name: String| {
        json!({"need": SQL_SNAPSHOT_NEED, "key": "kit.a", "label": "L",
               "sql": "SELECT id FROM records WHERE id = ?1",
               "params": [{"name": param_name, "type": "text"}]})
    };
    assert!(parse_sql_need_entry(&with_param(format!("p{}", "a".repeat(param - 1)))).is_ok());
    assert!(parse_sql_need_entry(&with_param(format!("p{}", "a".repeat(param)))).is_err());

    let types = names("declaration.param_types");
    for param_type in ["text", "integer", "timestamp_ms", "boolean", "real", "uuid"] {
        let entry = json!({"need": SQL_SNAPSHOT_NEED, "key": "kit.a", "label": "L",
            "sql": "SELECT id FROM records WHERE last_activity_at_ms > ?1 ORDER BY id LIMIT 1",
            "params": [{"name": "p", "type": param_type}]});
        assert_eq!(
            parse_sql_need_entry(&entry).is_ok(),
            types.contains(param_type),
            "limits.json declaration.param_types disagrees with SqlParamType::parse on '{param_type}'"
        );
    }
}

#[test]
fn sql_contract_matches_the_engine() {
    same(
        "sql.max_sql_bytes",
        json!(contract::MAX_SQL_BYTES),
        "MAX_SQL_BYTES",
    );
    same(
        "sql.max_placeholder",
        json!(contract::MAX_PARAMETERS),
        "MAX_PARAMETERS",
    );
    same("sql.max_rows", json!(contract::MAX_ROWS), "MAX_ROWS");
    same(
        "sql.max_columns",
        json!(contract::MAX_COLUMNS),
        "MAX_COLUMNS",
    );
    same(
        "sql.max_cell_encoded_bytes",
        json!(contract::MAX_CELL_ENCODED_BYTES),
        "MAX_CELL_ENCODED_BYTES",
    );
    same(
        "sql.max_result_encoded_bytes",
        json!(contract::MAX_RESULT_ENCODED_BYTES),
        "MAX_RESULT_ENCODED_BYTES",
    );
    same(
        "sql.deadline_ms",
        json!(contract::QUERY_DEADLINE_MS),
        "QUERY_DEADLINE_MS",
    );
    let relations: BTreeSet<String> = contract::LOGICAL_RELATIONS
        .iter()
        .map(|relation| relation.name.to_owned())
        .collect();
    assert_eq!(
        names("sql.relations"),
        relations,
        "limits.json sql.relations no longer matches LOGICAL_RELATIONS"
    );
    let mut portable: BTreeSet<String> = contract::PORTABLE_FUNCTIONS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    portable.insert("like".to_owned());
    assert_eq!(
        names("sql.portable_functions"),
        portable,
        "limits.json sql.portable_functions no longer matches PORTABLE_FUNCTIONS (+ like)"
    );
    for name in names("sql.dropped_functions") {
        assert!(
            contract::portable_function_repair(&name).is_some(),
            "limits.json lists '{name}' as dropped, but portable_function_repair admits it"
        );
    }
    let refusal = |sql: &str| {
        crate::query::sql::validate(sql)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
    };
    for word in names("sql.forbidden_words") {
        let message = refusal(&format!("SELECT id FROM records WHERE {word} = 1"));
        assert!(
            message.contains(&format!("prohibited token '{word}'")),
            "limits.json lists '{word}' as forbidden, but the classifier said: {message}"
        );
    }
    for word in names("sql.clock_keywords") {
        let message = refusal(&format!("SELECT {word} AS t"));
        assert!(
            message.contains(&format!("{word} is unavailable")),
            "limits.json lists '{word}' as a clock keyword, but the classifier said: {message}"
        );
    }
}

fn document(body: &str) -> String {
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Kit</title></head><body><main><h1>Kit</h1>{body}</main></body></html>")
}

fn rule_of(source: &str) -> Option<String> {
    html::validate(source).err().map(|failure| {
        failure.details["rule"]
            .as_str()
            .unwrap_or(failure.code)
            .to_owned()
    })
}

#[test]
fn html_policy_matches_the_engine() {
    same("html.body_max_bytes", json!(html::BODY_LIMIT), "BODY_LIMIT");
    same(
        "html.data_asset_max_bytes",
        json!(html::DATA_ASSET_EACH_LIMIT),
        "DATA_ASSET_EACH_LIMIT",
    );
    same(
        "html.data_assets_total_max_bytes",
        json!(html::DATA_ASSET_TOTAL_LIMIT),
        "DATA_ASSET_TOTAL_LIMIT",
    );
    same(
        "html.dom_node_max",
        json!(html::DOM_NODE_LIMIT),
        "DOM_NODE_LIMIT",
    );
    same(
        "html.css_rule_max",
        json!(html::CSS_RULE_LIMIT),
        "CSS_RULE_LIMIT",
    );
    same(
        "html.input_json_max_bytes",
        json!(html::INPUT_JSON_LIMIT),
        "INPUT_JSON_LIMIT",
    );
    same(
        "html.input_records_max",
        json!(html::INPUT_RECORD_LIMIT),
        "INPUT_RECORD_LIMIT",
    );
    same(
        "html.bridge_message_max_bytes",
        json!(html::BRIDGE_MESSAGE_LIMIT),
        "BRIDGE_MESSAGE_LIMIT",
    );
    assert_eq!(
        rule_of(&document("")),
        None,
        "the kit's baseline document must validate"
    );
    for tag in names("html.forbidden_elements") {
        if tag == "frame" {
            // The HTML parser drops <frame> outside a frameset, so it can
            // never reach the walk from <body>; the kit refuses it anyway.
            continue;
        }
        assert_eq!(
            rule_of(&document(&format!("<{tag}></{tag}>"))).as_deref(),
            Some("forbidden-element"),
            "limits.json lists <{tag}> as forbidden"
        );
    }
    for attribute in names("html.url_attributes") {
        assert_eq!(
            rule_of(&document(&format!("<span {attribute}=\"x\">x</span>"))).as_deref(),
            Some("url-attribute"),
            "limits.json lists {attribute} as URL-bearing"
        );
    }
    for mime in names("html.data_mime_types") {
        assert_eq!(
            rule_of(&document(&format!(
                "<img alt=\"\" src=\"data:{mime};base64,aQ==\">"
            ))),
            None,
            "limits.json lists {mime} as a permitted data asset"
        );
    }
    assert!(
        rule_of(&document(
            "<img alt=\"\" src=\"data:image/gif;base64,aQ==\">"
        ))
        .is_some(),
        "a MIME the kit does not list must stay refused"
    );
}

#[test]
fn vendored_bridge_is_the_engine_bootstrap() {
    same(
        "bridge.version",
        json!(html::BRIDGE_VERSION),
        "BRIDGE_VERSION",
    );
    same(
        "bridge.adapter_revision",
        json!(html::ADAPTER_REVISION),
        "ADAPTER_REVISION",
    );
    same(
        "bridge.validator_version",
        html::descriptor()["validator"]["version"].clone(),
        "html::descriptor() validator.version",
    );
    same(
        "bridge.bootstrap_sha256",
        json!(html::bootstrap_digest()),
        "html::bootstrap_digest",
    );
    assert_eq!(
        hex::encode(Sha256::digest(BRIDGE.as_bytes())),
        html::bootstrap_digest(),
        "packages/alpha-tab-kit/src/fake-host/bridge-bootstrap.js is not the engine's BOOTSTRAP; re-extract it from crates/artifact-html/src/html.rs"
    );
    let limits = limits();
    for leaf in [
        "pending_read_cap",
        "read_params_max_chars",
        "answer_max_chars",
        "view_state_max_chars",
    ] {
        let literal = limits["bridge"][leaf]["bootstrap_literal"]
            .as_str()
            .expect("bootstrap_literal");
        let value = limits["bridge"][leaf]["value"].to_string();
        assert!(
            BRIDGE.contains(literal) && literal.contains(&value),
            "bridge.{leaf}: the bootstrap no longer contains `{literal}` with {value}"
        );
    }
    let origin = "https://kit.example";
    assert_eq!(
        kit("bridge.csp")
            .as_str()
            .expect("csp template")
            .replace("{origin}", origin),
        html::content_security_policy(origin).expect("origin"),
        "limits.json bridge.csp no longer matches content_security_policy"
    );
}

#[test]
fn kit_digest_vectors_recompute() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("digest-vectors.json");
    for case in vectors["bundle"].as_array().expect("bundle vectors") {
        assert_eq!(
            alpha_tab_bundle_digest(case["body"].as_str().expect("body")),
            case["bundle_sha256"],
            "{}",
            case["name"]
        );
    }
    for case in vectors["declaration"]
        .as_array()
        .expect("declaration vectors")
    {
        assert_eq!(
            alpha_tab_declaration_digest(&case["declaration"]).expect("canonical declaration"),
            case["declaration_digest"],
            "{}",
            case["name"]
        );
    }
    for case in vectors["digest"].as_array().expect("digest vectors") {
        assert_eq!(
            alpha_tab_digest(
                case["bundle_sha256"].as_str().expect("bundle_sha256"),
                case["declaration_digest"]
                    .as_str()
                    .expect("declaration_digest"),
                case["runtime"].as_str().expect("runtime"),
            ),
            case["digest"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn kit_corpus_gets_the_same_verdict_from_the_engine() {
    let corpus: Value = serde_json::from_str(CORPUS).expect("corpus.json");
    for case in corpus["sql"].as_array().expect("sql cases") {
        let mut entry = json!({"need": SQL_SNAPSHOT_NEED, "key": "kit.case",
            "label": "Kit corpus case", "sql": case["sql"]});
        if let Some(params) = case.get("params") {
            entry["params"] = params.clone();
        }
        let verdict = parse_sql_need_entry(&entry);
        assert_eq!(
            verdict.is_ok(),
            case["admitted"].as_bool().expect("admitted"),
            "sql case '{}': engine said {:?}",
            case["name"],
            verdict.err()
        );
    }
    for case in corpus["declaration"].as_array().expect("declaration cases") {
        let verdict = require_declaration(&case["declaration"]);
        assert_eq!(
            verdict.is_ok(),
            case["admitted"].as_bool().expect("admitted"),
            "declaration case '{}': engine said {:?}",
            case["name"],
            verdict.err().map(|error| error.to_string())
        );
    }
    type IdCheck = fn(&str) -> crate::error::Result<()>;
    let checks: [(&str, IdCheck); 2] =
        [("packages", require_package), ("versions", require_version)];
    for (key, check) in checks {
        for case in corpus[key].as_array().expect("id cases") {
            let value = case["value"].as_str().expect("value");
            assert_eq!(
                check(value).is_ok(),
                case["admitted"].as_bool().expect("admitted"),
                "{key} case '{value}'"
            );
        }
    }
}
