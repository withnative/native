use super::*;
use crate::mcp::{
    registry::{EngineHandle, ToolRegistry},
    Caller,
};
use crate::{
    events::KERNEL_ROOT_ID,
    holding::*,
    kernel,
    member_copy_transport::{test_consumer, CredentialSelection},
    replica_generation::*,
    standby_snapshot::*,
};
use serde_json::{json, Value as Json};
#[path = "metadata_performance_proof.rs"]
mod metadata_performance_proof;
#[path = "source_context_proof.rs"]
mod source_context_proof;

const OWNER: &str = "acct_00000000000000000000000000000001";
const OTHER: &str = "acct_00000000000000000000000000000003";
const MEMBER: &str = "acct_00000000000000000000000000000002";

// The native online surface also exposes the physical carrier; the existing
// member RecordRow deliberately serializes only this interpreted contract.
// Validate every documented variant before comparing that carrier. Missing,
// marked unavailable and unknown shapes must never become an absent value.
fn lifecycle_carrier(value: &Json) -> Option<&str> {
    fn fields<'a>(
        value: &'a Json,
        required: &[&str],
        optional: &[&str],
    ) -> &'a serde_json::Map<String, Json> {
        let object = value
            .as_object()
            .expect("lifecycle shape must be an object");
        assert!(
            required.iter().all(|key| object.contains_key(*key)),
            "missing lifecycle field: {value}"
        );
        assert!(
            object
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())),
            "unknown lifecycle field: {value}"
        );
        object
    }
    fn text<'a>(value: &'a Json, key: &str) -> &'a str {
        value
            .get(key)
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("lifecycle field {key} must be text: {value}"))
    }
    fn identity(value: &Json, keys: &[&str]) {
        fields(value, keys, &[]);
        for key in keys {
            text(value, key);
        }
    }
    match text(value, "status") {
        "governed" => {
            fields(
                value,
                &["status", "axis", "vocabulary", "value", "terminality"],
                &[],
            );
            identity(&value["axis"], &["key", "label"]);
            identity(&value["vocabulary"], &["id", "name"]);
            identity(&value["value"], &["raw", "id", "canonical"]);
            assert!(matches!(
                text(value, "terminality"),
                "open" | "terminal_positive" | "terminal_negative"
            ));
            Some(text(&value["value"], "raw"))
        }
        "unclassified" => {
            fields(value, &["status", "raw", "reason"], &[]);
            assert!(matches!(
                text(value, "reason"),
                "no_governing_vocabulary"
                    | "unknown_or_inactive_value"
                    | "uninterpretable_schema_or_value"
            ));
            Some(text(value, "raw"))
        }
        "absent" => {
            fields(value, &["status"], &["axis", "vocabulary"]);
            if let Some(axis) = value.get("axis") {
                identity(axis, &["key", "label"]);
            }
            if let Some(vocabulary) = value.get("vocabulary") {
                identity(vocabulary, &["id", "name"]);
            }
            None
        }
        status => panic!("unsupported lifecycle status {status}: {value}"),
    }
}

// Only the documented live-clock cutoff is removed, after validating the
// mandatory exact UTC-millisecond representation and this actual call's bounds.
fn scan_without_clock(
    value: &Json,
    before: chrono::DateTime<chrono::Utc>,
    after: chrono::DateTime<chrono::Utc>,
    days: i64,
) -> Json {
    let mut value = value.clone();
    let thresholds = value
        .get_mut("thresholds")
        .expect("scan thresholds")
        .as_object_mut()
        .expect("threshold object");
    let mut keys = thresholds.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        [
            "high_degree_min",
            "recent_cutoff",
            "recent_window_days",
            "sample_limit",
            "saturation_threshold"
        ]
    );
    assert_eq!(thresholds["recent_window_days"], days);
    let text = thresholds
        .get("recent_cutoff")
        .expect("live-clock cutoff")
        .as_str()
        .expect("cutoff text");
    let cutoff = chrono::DateTime::parse_from_rfc3339(text).expect("valid cutoff timestamp");
    assert_eq!(
        cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        text,
        "exact UTC millisecond format"
    );
    assert_eq!(cutoff.offset().local_minus_utc(), 0);
    assert!(
        cutoff.timestamp_millis() >= (before - chrono::Duration::days(days)).timestamp_millis()
    );
    assert!(cutoff.timestamp_millis() <= (after - chrono::Duration::days(days)).timestamp_millis());
    thresholds
        .remove("recent_cutoff")
        .expect("validated cutoff");
    value
}

fn dashboard_without_clock(
    value: &Json,
    before: chrono::DateTime<chrono::Utc>,
    after: chrono::DateTime<chrono::Utc>,
    days: i64,
) -> Json {
    let mut value = value
        .as_object()
        .expect("dashboard response object")
        .clone();
    assert_eq!(
        value.get("stale_after_days").expect("dashboard threshold"),
        &json!(days)
    );
    let clock = value
        .remove("stale_cutoff")
        .expect("dashboard live-clock cutoff");
    let text = clock.as_str().expect("dashboard cutoff text");
    let cutoff = chrono::DateTime::parse_from_rfc3339(text).expect("dashboard RFC3339 cutoff");
    assert_eq!(cutoff.offset().local_minus_utc(), 0);
    assert_eq!(cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(), text);
    assert!(
        cutoff.timestamp_millis() >= (before - chrono::Duration::days(days)).timestamp_millis()
    );
    assert!(cutoff.timestamp_millis() <= (after - chrono::Duration::days(days)).timestamp_millis());
    Json::Object(value)
}

fn assert_native_member_bootstrap(
    value: &Json,
    online: &Json,
    expected_world: &Json,
    counts: (i64, i64),
    holding: &Json,
    observed_between: (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
    carried: Option<&str>,
) -> Json {
    let (before, after) = observed_between;
    let mut keys = value
        .as_object()
        .expect("bootstrap object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        [
            "contract",
            "current_world",
            "diagnostics",
            "engine",
            "instructions",
            "intentful_sessions",
            "next_steps",
            "orientation",
            "pending_obligations",
            "principal",
            "roots",
            "run",
            "run_context",
            "session",
            "source_context",
            "standby_context",
            "standing_context",
            "tool_exposure",
            "workspace"
        ]
    );
    assert_eq!(
        value
            .get("source_context")
            .expect("explicit unselected source tuple"),
        &Json::Null
    );
    assert_eq!(
        value.get("principal").expect("native principal"),
        online.get("principal").expect("online native principal")
    );
    assert_eq!(
        value["principal"].as_object().unwrap().len(),
        4,
        "actual native footing, no invented legacy email/private home"
    );
    assert_eq!(
        value["orientation"],
        json!({"template_key":crate::instructions::ENGINE_ORIENTATION_TEMPLATE_KEY,"template_version":crate::instructions::ENGINE_ORIENTATION_TEMPLATE_VERSION,"content":crate::instructions::ENGINE_ORIENTATION,"ownership":"build-owned and guaranteed independently of portable instruction resolution"})
    );
    assert_eq!(
        value
            .get("instructions")
            .expect("captured native instructions"),
        online
            .get("instructions")
            .expect("actual online instructions")
    );
    let source_root = &online["roots"]["items"]
        .as_array()
        .expect("online root items")[0];
    let root = json!({"id":source_root.get("id").expect("root id"),"type":source_root.get("type").expect("root type"),"kind":source_root.get("kind").expect("root kind"),"name":source_root.get("name").expect("root name"),"persistence":source_root.get("persistence").expect("root persistence"),"child_count":source_root.get("child_count").expect("root child count")});
    assert_eq!(
        value["roots"],
        json!({"items":[root],"total":1,"continuation":{"tool":"get_structure","arguments":{"root_id":"native:root"}}})
    );
    assert_eq!(
        value["workspace"],
        json!({"scope":"one connected Native database and one primary workspace","primary_workspace":{"id":online["workspace"]["primary_workspace"].get("id").expect("source workspace id"),"name":online["workspace"]["primary_workspace"].get("name").expect("source workspace name"),"name_truncated":false},"records_visible":counts.0,"record_count_truncated":false,"record_count_qualification":"admitted slice rows visible to this member; hidden, withdrawn and nonexistent records are absent, never zeroed","registered_humans_visible":counts.1,"human_count_truncated":false,"human_count_qualification":"caller-bound verified Person records in the admitted native slice; not proof of an exhaustive roster","known_limitations":["personal-home and multi-workspace orientation are outside the current native-ce bootstrap horizon"]})
    );
    let mut world = value
        .get("current_world")
        .expect("current world")
        .as_object()
        .unwrap()
        .clone();
    let observed = world.remove("observed_at").expect("observed time");
    let text = observed.as_str().expect("time text");
    let parsed = chrono::DateTime::parse_from_rfc3339(text).expect("actual UTC time");
    assert_eq!(parsed.offset().local_minus_utc(), 0);
    assert_eq!(
        parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        text
    );
    assert!(parsed.timestamp() >= before.timestamp() && parsed.timestamp() <= after.timestamp());
    assert_eq!(
        Json::Object(world),
        *expected_world,
        "full bounded source-authorized world contract"
    );
    let marker =
        |surface: &str| json!({"unavailable_offline":{"surface":surface,"retry":"when_online"}});
    assert_eq!(value["run"], marker("bootstrap.run"));
    assert_eq!(value["pending_obligations"], marker("bootstrap.claim"));
    assert_eq!(value["intentful_sessions"], marker("bootstrap.intent"));
    assert_eq!(
        value["standing_context"]["pending_onboarding_obligations"],
        marker("bootstrap.claim")
    );
    assert_eq!(
        value["standing_context"]["portable_instructions"],
        json!({"status":online["instructions"].get("status").expect("actual instruction status"),"entry_count":online["instructions"]["entries"].as_array().unwrap().len(),"exact_entries_path":"/instructions/entries","diagnostics_path":"/instructions/diagnostics","note":"Binding layers only (workspace + member). Obligation-derived sources are unavailable offline; see /pending_obligations."})
    );
    let key = value["session"]["run_key"]
        .as_str()
        .expect("local correlation key");
    assert!(matches!(
        crate::runkey::validate_full(Some(key)),
        crate::runkey::KeyOutcome::Valid(_)
    ));
    if let Some(carried) = carried {
        assert_eq!(key, carried);
    }
    assert_eq!(
        value["session"],
        json!({"run_key":key,"reuse_required":false,"nondurable":true,"guidance":"Member-copy run key: minted locally without storage reads and never persisted. Pass it for call correlation within this session only; it carries no run history and survives no reconnect.","whole_run_rollback":false})
    );
    assert!(value["run_context"].get("established").is_none());
    assert_eq!(
        value["run_context"]
            .get("intent")
            .expect("no durable intent"),
        &Json::Null
    );
    assert_eq!(
        value["run_context"]
            .get("run_key")
            .expect("correlation input echo"),
        &carried.map_or(Json::Null, |key| json!(key))
    );
    if let Some(carried) = carried {
        assert_eq!(
            value["run_context"],
            json!({"run_key":carried,"intent":null,"follow_path":format!("/workbench/runs/{carried}"),"follow_url":format!("/workbench/runs/{carried}"),"notes":[crate::domain_transaction::request::RELATIVE_FOLLOW_LINK_NOTE]})
        );
    }
    let steps = value["next_steps"]["items"].as_array().expect("next steps");
    assert_eq!(
        steps
            .iter()
            .map(|s| s["tool"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "set_intent",
            "get_record",
            "query_sql",
            "search",
            "get_dashboard",
            "get_structure"
        ]
    );
    for step in steps {
        assert_eq!(
            step["arguments"]
                .get("run_key")
                .expect("next step uses exact local key"),
            key
        );
    }
    assert_eq!(
        steps[1]["arguments"]["ids"],
        json!([expected_world["recent_activity"]["items"][0]
            .get("id")
            .expect("source recent id")])
    );
    assert_eq!(steps[5]["arguments"]["root_id"], "native:root");
    assert_eq!(value["contract"]["version"], "native.bootstrap.v3");
    assert_eq!(value["contract"]["member_copy"], true);
    assert_eq!(value["contract"]["intent_agnostic"], true);
    let sizes = &value["diagnostics"]["component_bytes"];
    let bytes = |v: &Json| serde_json::to_vec(v).unwrap().len() as u64;
    for (key, component) in [
        ("contract", value["contract"].clone()),
        ("orientation", value["orientation"].clone()),
        (
            "footing",
            json!({"principal":value["principal"],"workspace":value["workspace"],"standing_context":value["standing_context"],"source_context":value["source_context"]}),
        ),
        ("current_world", value["current_world"].clone()),
        ("intentful_sessions", value["intentful_sessions"].clone()),
        ("next_steps", value["next_steps"].clone()),
        ("session", value["session"].clone()),
        (
            "compatibility",
            json!({"engine":value["engine"],"run":value["run"],"roots":value["roots"]}),
        ),
        (
            "instruction_context",
            json!({"instructions":value["instructions"],"pending_obligations":value["pending_obligations"]}),
        ),
    ] {
        assert_eq!(
            sizes.get(key).expect("reported component size"),
            bytes(&component)
        );
        let cap = value["contract"]["bounds_bytes"]
            .get(key)
            .expect("component bound")
            .as_u64()
            .unwrap();
        assert!(bytes(&component) <= cap);
    }
    assert_eq!(sizes.as_object().unwrap().len(), 10);
    assert!(sizes["json_envelope"].as_u64().unwrap() > 0);
    assert_eq!(
        value["engine"],
        json!({"name":"native-kernel-v2","version":crate::ENGINE_VERSION,"schema_version":0,"user_version":0})
    );
    assert_eq!(
        value["diagnostics"].get("engine").unwrap(),
        &value["engine"]
    );
    assert_eq!(
        value
            .get("standby_context")
            .expect("actual generation disclosure"),
        holding
    );
    assert_eq!(
        value["tool_exposure"]["authorization_semantics"],
        "independent: every exact-name call retains its ordinary authorization and validation"
    );
    assert!(bytes(&value["tool_exposure"]) <= 8192);
    assert!(bytes(value) <= crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOTAL_BYTES as u64);
    let mut normalized = value.clone();
    normalized["current_world"]
        .as_object_mut()
        .unwrap()
        .remove("observed_at")
        .unwrap();
    normalized
}

// Native online currently emits breadth-first, (name,id)-ordered frontiers;
// existing member trees emit depth-first id paths after the same sibling cap.
// Validate that exact ordering difference, while comparing complete node facts.
fn assert_structure_member_parity(
    member: &Json,
    online: &Json,
    holding: &Json,
    successions: &std::collections::BTreeMap<String, Json>,
) {
    let mut member = member.as_object().expect("member structure object").clone();
    let mut online = online.as_object().expect("online structure object").clone();
    assert_eq!(
        member.remove("standby_context").expect("tree holding"),
        *holding
    );
    assert!(!online.contains_key("standby_context"));
    assert!(!member.contains_key("run_context"));
    assert_eq!(
        online.remove("run_context").expect("online run footing"),
        json!({
            "run_key":null,"intent":null,
            "notes":["This call is not attached to a run. Pass run_key on every call to correlate them — use the required key issued by bootstrap."]
        })
    );
    let native_nodes = online.remove("nodes").expect("native nodes");
    let native_nodes = native_nodes.as_array().expect("native nodes array");
    let member_nodes = member.remove("nodes").expect("member nodes");
    let member_nodes = member_nodes.as_array().expect("member nodes array");
    assert_eq!(member, online, "all non-node structure fields");
    let expected: std::collections::BTreeMap<&str, &Json> = native_nodes
        .iter()
        .map(|node| {
            let object = node.as_object().expect("native node object");
            let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
            keys.sort();
            assert_eq!(
                keys,
                [
                    "archived",
                    "child_count",
                    "containment_path_visible",
                    "custody_boundary",
                    "depth",
                    "home_id",
                    "id",
                    "kind",
                    "last_activity_at",
                    "name",
                    "persistence",
                    "type"
                ]
            );
            (node["id"].as_str().expect("native id"), node)
        })
        .collect();
    assert_eq!(
        expected.len(),
        native_nodes.len(),
        "no duplicate native nodes"
    );
    assert_eq!(
        member_nodes.len(),
        expected.len(),
        "entire tree, not a visible subset"
    );
    let root = member
        .get("root_id")
        .expect("root field")
        .as_str()
        .expect("root id");
    // Placement aliases share the virtual root frontier, but actual home_id
    // fields below remain compared exactly against the online source.
    fn parent_key<'a>(node: &'a Json, root: &'a str) -> &'a str {
        let parent = node["home_id"].as_str().expect("non-root parent");
        if ["native:root", "kernel:root"].contains(&root)
            && ["native:root", "kernel:root"].contains(&parent)
        {
            root
        } else {
            parent
        }
    }
    let mut breadth_first = Vec::new();
    let mut frontier = vec![root];
    while !frontier.is_empty() {
        assert!(
            breadth_first.len() <= expected.len(),
            "acyclic online result"
        );
        let mut next = Vec::new();
        for parent in frontier {
            breadth_first.push(parent);
            let mut children = expected
                .iter()
                .filter(|(id, node)| **id != root && parent_key(node, root) == parent)
                .map(|(id, node)| (node["name"].as_str().expect("source name"), *id))
                .collect::<Vec<_>>();
            children.sort();
            next.extend(children.into_iter().map(|(_, id)| id));
        }
        frontier = next;
    }
    assert_eq!(
        native_nodes
            .iter()
            .map(|node| node["id"].as_str().expect("online id"))
            .collect::<Vec<_>>(),
        breadth_first,
        "exact native online breadth-first name/id ordering"
    );
    let mut paths = Vec::new();
    for (id, node) in &expected {
        let mut reverse = vec![*id];
        let mut cursor = *node;
        while cursor["id"] != root {
            assert!(reverse.len() <= 101, "cycle/depth bound in source result");
            let parent = parent_key(cursor, root);
            cursor = expected
                .get(parent)
                .expect("source result includes each parent");
            reverse.push(parent);
        }
        reverse.reverse();
        assert_eq!(node["depth"], json!(reverse.len() - 1));
        paths.push((format!(",{},", reverse.join(",")), *id));
    }
    paths.sort();
    assert_eq!(
        member_nodes
            .iter()
            .map(|n| n["id"].as_str().expect("held id"))
            .collect::<Vec<_>>(),
        paths.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
        "exact existing member DFS-by-id-path order"
    );
    for node in member_nodes {
        let mut node = node.as_object().expect("held node object").clone();
        let id = node["id"].as_str().expect("held node id").to_owned();
        if let Some(succession) = successions.get(&id) {
            assert_eq!(
                node.remove("superseded_by")
                    .expect("existing member successor enrichment"),
                *succession
            );
            assert!(
                expected[id.as_str()].get("superseded_by").is_none(),
                "native online does not yet add member successor companion"
            );
        } else {
            assert!(
                !node.contains_key("superseded_by"),
                "no fabricated successor"
            );
        }
        assert_eq!(
            json!(node),
            *expected[id.as_str()],
            "complete actual node identity/placement/archive/count/custody/path facts"
        );
    }
}

// Only documented source-footing differences are removed. Every preview
// decision, catalogue, kind fact, assessment, bound and digest stays compared.
fn assert_preview_member_parity(member: &Json, online: &Json, generation: &str, holding: &Json) {
    let mut member = member.as_object().expect("member preview object").clone();
    let mut online = online
        .as_object()
        .expect("native online preview object")
        .clone();
    assert_eq!(
        member
            .remove("standby_context")
            .expect("preview member footing"),
        *holding
    );
    assert!(!online.contains_key("standby_context"));
    // The online registry attaches its ordinary unattached-run echo. Native
    // member dispatch uses the shared engine-free protocol path, whose run
    // context is absent; it neither mints nor reads a canonical run/session.
    assert!(!member.contains_key("run_context"));
    assert_eq!(
        online
            .remove("run_context")
            .expect("online registry run footing"),
        json!({
            "run_key":null,"intent":null,
            "notes":["This call is not attached to a run. Pass run_key on every call to correlate them — use the required key issued by bootstrap."]
        })
    );
    let member_basis = member
        .get_mut("advisory_basis")
        .expect("member preview basis")
        .as_object_mut()
        .expect("member basis object");
    assert_eq!(
        member_basis
            .remove("schema_state_revision")
            .expect("generation-bound schema revision"),
        json!(format!("native-member:{generation}"))
    );
    assert!(!member_basis.contains_key("kernel_content_head"));
    assert!(!member_basis.contains_key("event_heads"));
    let online_basis = online
        .get_mut("advisory_basis")
        .expect("online preview basis")
        .as_object_mut()
        .expect("online basis object");
    let head = online_basis
        .remove("kernel_content_head")
        .expect("real native kernel head")
        .as_i64()
        .expect("kernel head integer");
    assert!(head > 0);
    assert_eq!(
        online_basis
            .remove("schema_state_revision")
            .expect("native schema revision"),
        json!(format!("kernel-schema-state-v1:content:{head}"))
    );
    assert!(!online_basis.contains_key("event_heads"));
    assert_eq!(member, online, "complete shared preview contract");
}

fn assert_suggestions_member_parity(member: &Json, online: &Json, holding: &Json) {
    let mut member = member
        .as_object()
        .expect("member suggestion response")
        .clone();
    let mut online = online
        .as_object()
        .expect("native suggestion response")
        .clone();
    assert_eq!(
        member
            .remove("standby_context")
            .expect("suggestion holding"),
        *holding
    );
    assert!(!member.contains_key("run_context"));
    assert!(!online.contains_key("standby_context"));
    assert_eq!(
        online
            .remove("run_context")
            .expect("online suggestion run footing"),
        json!({
            "run_key":null,"intent":null,
            "notes":["This call is not attached to a run. Pass run_key on every call to correlate them — use the required key issued by bootstrap."]
        })
    );
    assert_eq!(
        member, online,
        "complete source-selected native/member suggestion contract"
    );
}

fn assert_facets_member_parity(
    member: &Json,
    online: &Json,
    holding: &Json,
    owner: Option<&(Json, Json)>,
) {
    let mut member = member.as_object().expect("member facet response").clone();
    let mut online = online.as_object().expect("native facet response").clone();
    assert_eq!(
        member.remove("standby_context").expect("facet holding"),
        *holding
    );
    assert!(!member.contains_key("run_context"));
    assert_eq!(
        online
            .remove("run_context")
            .expect("online facet run footing"),
        json!({
            "run_key":null,"intent":null,
            "notes":["This call is not attached to a run. Pass run_key on every call to correlate them — use the required key issued by bootstrap."]
        })
    );
    assert!(!online.contains_key("standby_context"));
    if let Some((native_owner, selected_owner)) = owner {
        // Native non-Message metadata exposes its source principal; the member
        // surface holds only the source-authorised visible owner record. Both
        // representations are witnessed explicitly before comparing the fold.
        let member_spine = member
            .get("spine")
            .expect("member record spine")
            .as_object()
            .expect("member record spine object");
        assert_eq!(
            member_spine.get("owner").expect("selected owner field"),
            selected_owner
        );
        let online_spine = online
            .get_mut("spine")
            .expect("native record spine")
            .as_object_mut()
            .expect("native record spine object");
        assert_eq!(
            online_spine.get("owner").expect("native owner field"),
            native_owner
        );
        online_spine.insert("owner".into(), selected_owner.clone());
    }
    if let Some(values) = online.get_mut("values") {
        let values = values.as_array_mut().expect("native facet values");
        let member_values = member
            .get("values")
            .expect("member values field")
            .as_array()
            .expect("member facet values");
        assert_eq!(values.len(), member_values.len());
        for (online, member) in values.iter_mut().zip(member_values) {
            assert!(!member
                .as_object()
                .expect("member facet value object")
                .contains_key("version"));
            let token = online
                .as_object_mut()
                .expect("native facet value object")
                .remove("version")
                .expect("native observation version");
            assert!(
                matches!(native_artifact_runtime::artifact_intents::FacetVersion::parse(token.as_str().expect("version string")),
                Some(native_artifact_runtime::artifact_intents::FacetVersion::Observation { event_seq }) if event_seq > 0)
            );
        }
    } else {
        assert!(!member.contains_key("values"));
    }
    assert_eq!(
        member, online,
        "complete native/member facet facts except planned version omission"
    );
}

// Native Get carries actual kernel identity instead of the optional legacy
// catalogue KindResolution. The member pipeline preserves that native fact;
// it must not fabricate a CoreKind classification to fill the legacy field.
fn assert_get_member_parity(
    offline: &Json,
    online: &Json,
    child_references: &std::collections::BTreeMap<String, String>,
    source_links: &[Json],
) {
    fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
        value
            .get(key)
            .unwrap_or_else(|| panic!("missing {key}: {value}"))
    }
    fn project(value: &Json, keys: &[&str]) -> Json {
        Json::Object(
            keys.iter()
                .map(|key| ((*key).into(), field(value, key).clone()))
                .collect(),
        )
    }
    let member = field(offline, "records")
        .as_array()
        .expect("member records");
    let native = field(online, "records").as_array().expect("native records");
    assert_eq!(member.len(), native.len());
    for (member, native) in member.iter().zip(native) {
        assert_eq!(field(member, "status"), "found");
        for key in [
            "id",
            "status",
            "type",
            "kind",
            "body",
            "summary",
            "home_id",
            "archived",
            "kernel_v2",
            "containment_path_visible",
            "child_count",
            "links_out_count",
            "links_in_count",
            "comment_count",
            "suggestion_count",
            "citation_count",
            "lifecycle_interpretation",
        ] {
            assert_eq!(
                field(member, key),
                field(native, key),
                "get {key}, id={}",
                member["id"]
            );
        }
        let children = field(member, "children")
            .as_array()
            .expect("member children");
        let source_children = field(native, "children")
            .as_array()
            .expect("native children");
        assert_eq!(children.len(), source_children.len());
        for (child, source) in children.iter().zip(source_children) {
            assert_eq!(
                project(child, &["id", "type", "kind", "name", "archived"]),
                project(source, &["id", "type", "kind", "name", "archived"])
            );
            // Existing member summaries add source-selected address fields;
            // native online summaries intentionally return only the five
            // child fields above. Do not derive a prefix from this slice.
            let id = field(child, "id").as_str().expect("child id");
            let reference = child_references
                .get(id)
                .expect("actual source-selected child reference");
            assert_eq!(field(child, "display_reference"), reference);
            assert_eq!(field(child, "record_path_full"), &json!(format!("/{id}")));
            assert_eq!(field(child, "record_path"), &json!(format!("/{reference}")));
        }
        let interpretation = field(member, "lifecycle_interpretation");
        assert_eq!(
            field(native, "lifecycle"),
            &json!(lifecycle_carrier(interpretation))
        );
        assert!(
            member.get("lifecycle").is_none(),
            "member uses interpreted lifecycle"
        );
        assert!(member.get("kind_governance").is_none());
        assert!(native.get("kind_governance").is_none());
        assert!(field(member, "kernel_v2").is_object());
        assert!(field(member, "bears_shape").is_boolean());
        assert!(field(member, "custody_boundary").is_boolean());
        assert!(member.get("version").is_none());
        assert!(member.get("record_version").is_none());
        for key in ["links_out", "links_in"] {
            let a = field(member, key).as_array().expect("member link window");
            let b = field(native, key).as_array().expect("native link window");
            assert_eq!(a.len(), b.len(), "{key}");
            for (a, b) in a.iter().zip(b) {
                // Member other-end summaries and selected display references
                // enrich the same native link; they are not native raw fields.
                let keys = &[
                    "source_id",
                    "target_id",
                    "relationship",
                    "note",
                    "created_at",
                ];
                assert_eq!(project(a, keys), project(b, keys), "{key}");
                match field(b, "id") {
                    Json::String(_) => assert_eq!(field(a, "id"), field(b, "id")),
                    Json::Null => {
                        // Native raw legacy links have no addressable link ID.
                        // The existing member LinkRow carries the public SQL
                        // projection's logical identity. Check actual authorised
                        // source staging, not a locally invented ID formula.
                        let candidates = source_links
                            .iter()
                            .filter(|row| {
                                ["source_id", "target_id", "relationship"]
                                    .iter()
                                    .all(|key| field(row, key) == field(b, key))
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(candidates.len(), 1, "unique source-staged legacy link");
                        let source_id = field(candidates[0], "id");
                        assert!(source_id.is_string());
                        assert_eq!(field(a, "id"), source_id);
                    }
                    other => panic!("unsupported native link id shape: {other}"),
                }
            }
        }
        let facets = |row: &Json| {
            field(row, "facets")
                .as_array()
                .expect("facets")
                .iter()
                .map(|v| project(v, &["key", "value", "vocab_ref"]))
                .collect::<Vec<_>>()
        };
        assert_eq!(facets(member), facets(native));
        if let Some(comments) = native.get("comments") {
            let comments = comments.as_array().expect("native comments");
            let held = field(member, "comments")
                .as_array()
                .expect("member comments");
            assert_eq!(held.len(), comments.len());
            for (held, native) in held.iter().zip(comments) {
                assert_eq!(
                    project(held, &["id", "body", "summary", "position", "root_id"]),
                    project(native, &["id", "body", "summary", "position", "root_id"])
                );
                // Native nested comments explicitly defer typed interpretation;
                // the existing member summary presents it instead of raw state.
                assert_eq!(
                    field(native, "lifecycle"),
                    &json!(lifecycle_carrier(field(held, "lifecycle_interpretation")))
                );
                assert!(held.get("lifecycle").is_none());
            }
        } else {
            assert!(member.get("comments").is_none());
        }
        if let Some(blob) = native.get("blob") {
            assert_eq!(
                field(member, "blob"),
                blob,
                "actual source-selected blob metadata"
            );
        }
    }
}

fn manifest(cut: &NativeMemberCut) -> ReplicaGenerationManifest {
    ReplicaGenerationManifest {
        contract: REPLICA_GENERATION_CONTRACT.into(),
        version: REPLICA_GENERATION_VERSION,
        origin_database_id: cut.origin_database_id.clone(),
        hosted_route_database_id: "route-test".into(),
        captured_at: "2026-10-22T00:00:00Z".into(),
        snapshot_completed_at: "2026-10-22T00:00:01Z".into(),
        producer: StandbySnapshotEngineIdentity {
            name: "native-ce".into(),
            source_sha: "a".repeat(40),
            schema_version: 1,
            ddl_sha256: "b".repeat(64),
        },
        consumer: test_consumer(),
        bytes: StandbySnapshotBytes {
            media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
            size_bytes: 1024,
            sha256: "c".repeat(64),
        },
        materialization: StandbyGenerationMaterialization::Snapshot,
        scope: ReplicaScope::Member {
            scope_ref: "scope-one".into(),
        },
        ordering: ReplicaOrdering::Scoped { ordinal: 1 },
        holding: HoldingDisclosureV2::member("scope-one".into(), 1),
        profile: ReplicaProfile::MemberReadKernelV2 {
            engine: crate::standby::kernel_v2::ENGINE.into(),
            member_schema_digest: schema_digest(),
            identity: cut.profile_identity(),
        },
        content_digest: "e".repeat(64),
        own_writes: ReplicaOwnWrites::not_computed(),
        frontier: None,
        schema_incomplete_for: vec![],
    }
}
fn context(account: &str, manifest: &ReplicaGenerationManifest) -> MemberCopyContext {
    MemberCopyContext::new(
        account.into(),
        "https://example.invalid".into(),
        "route-test".into(),
        manifest.origin_database_id.clone(),
        test_consumer(),
        "scope-one".into(),
        CredentialSelection::for_test(b"synthetic credential"),
    )
}

async fn collection_fixture(
    db: &crate::Db,
    owner: &str,
    mention_target: &str,
) -> (Vec<(String, usize)>, Vec<String>, String, String) {
    let folder = call(
        db,
        OWNER,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Offline collection folder"}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let selection = call(
        db,
        OWNER,
        "create_record",
        json!({"type":"Collection","kind":"selection","name":"Offline collection selection"}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Listing held renderer metadata does not execute source or apps.
    call(db, OWNER, "create_record", json!({"type":"Document","kind":"artifact","name":"Visible collection renderer","facets":{"runtime":"native.mdx.v2"},"links":[{"target_id":folder,"relationship":"renders"}]})).await;
    let mut ids = Vec::new();
    for index in 0..51 {
        ids.push(call(db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":format!("Collection member {index:03}"),"home_id":folder,"links":[{"target_id":selection,"relationship":"member_of"}]})).await["id"].as_str().unwrap().to_owned());
    }
    let hidden = call(db, OWNER, "manage_messages", json!({"action":"send","id":uuid::Uuid::new_v4().to_string(),"body":"Synthetic private collection member","addressed_to":["person:other"],"origin":{"type":"direct","participant_ids":["person:owner","person:other"]},"expectation":"reply","idempotency_key":"collection-private-direct","reason":"Synthetic offline collection audience proof"})).await["id"].as_str().unwrap().to_owned();
    // Sealed Messages prohibit generic links. Exercise private selection
    // membership through an ordinary document under actual home authority;
    // the Direct remains a separate audience-exclusion candidate in saved IDs.
    let private = kernel::create_home(db, KERNEL_ROOT_ID, Some(&[(owner, "manage")]), owner)
        .await
        .unwrap();
    kernel::replace_home_policy(db, owner, &private, &[(owner, "manage")])
        .await
        .unwrap();
    for package in [
        crate::v2_standard::document4_package(),
        crate::v2_standard::v1_compat::package(),
    ] {
        let identity = package.identity().unwrap();
        kernel::adopt_package_at(
            db,
            owner,
            &private,
            &package,
            Some(&identity),
            &package.declared_reads,
        )
        .await
        .unwrap();
    }
    let private_document = call(db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Offline journey","home_id":private,"links":[{"target_id":selection,"relationship":"member_of"}]})).await["id"].as_str().unwrap().to_owned();
    let private_resolver = call(db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Only private resolver witness","home_id":private})).await["id"].as_str().unwrap().to_owned();
    // Messaging sends accept caller-selected IDs through the supported native
    // operation. Actual Direct audience authority creates the hidden sibling;
    // no raw row edits, generated-ID collision search or fake catalogue.
    let reference_record = "c01dcafe-1000-4000-8000-000000000001".to_owned();
    let hidden_collision = "c01dcaf0-1000-4000-8000-000000000002".to_owned();
    call(db, OWNER, "manage_messages", json!({"action":"send","id":reference_record,"body":"Visible source-selected reference target","addressed_to":["person:member"],"origin":{"type":"direct","participant_ids":["person:owner","person:member"]},"expectation":"reply","idempotency_key":"reference-visible-direct","reason":"Synthetic source-selected reference and body mention proof"})).await;
    call(db, OWNER, "manage_messages", json!({"action":"send","id":hidden_collision,"body":format!("Private n8v.to/{mention_target}"),"addressed_to":["person:other"],"origin":{"type":"direct","participant_ids":["person:owner","person:other"]},"expectation":"reply","idempotency_key":"reference-private-direct","reason":"Synthetic hidden reference collision and private body exclusion proof"})).await;
    // Message mention presentation is explicitly not held on member copies.
    // Exercise current body-scanner evidence on an ordinary visible Document;
    // the real Directs above remain the globally colliding reference targets.
    let mention_record = call(db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Visible body mention witness","body":format!("See n8v.to/{mention_target} and [[{mention_target}]] plus [[c01dcaf]]")})).await["id"].as_str().unwrap().to_owned();
    ids.push(private_document.clone());
    ids.push(hidden.clone());
    let mut collections = vec![(folder, 51), (selection, 51)];
    for (name, extra, membership, expected) in [
        ("Default saved page", json!({}), None, 50),
        ("Explicit all matching", json!({}), Some("all_matching"), 51),
        (
            "Authored saved page",
            json!({"limit":2,"offset":1}),
            Some("all_matching"),
            2,
        ),
    ] {
        let mut query = json!({"steps":[{"step":"filter","ids":ids}],"order":"name_asc"});
        query
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let mut facets = json!({"query":json!({"v":"0.2","query":query}).to_string()});
        if let Some(membership) = membership {
            facets["input_membership"] = json!(membership);
        }
        let collection = call(
            db,
            OWNER,
            "create_record",
            json!({"type":"Collection","kind":"query","name":name,"facets":facets}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        collections.push((collection, expected));
    }
    (
        collections,
        vec![hidden, private_document, hidden_collision, private_resolver],
        reference_record,
        mention_record,
    )
}

#[tokio::test]
async fn native_profile_lifecycle_reads_restart_and_replayed_pair_refusal() {
    use crate::mcp::member_stdio::MemberServedSnapshot;
    use crate::member_copy_lifecycle::ReconnectAnswer;
    use crate::member_copy_serving::MemberCopyServing;
    for imported_governance in [false, true] {
        let (dir, db, owner_principal, member_principal) = fixture(false).await;
        const SUGGEST_VOCAB: &str = "N3 suggestion priorities";
        let (suggestion_vocabulary, dashboard_vocabulary) = {
            // Create a real user vocabulary through supported metadata APIs.
            // Fresh native imports only the authored vocabularies; the governance case
            // also imports the real seeded catalogue, never fabricated kinds.
            let legacy = crate::db::create_database(":memory:").await.unwrap();
            use crate::meta::vocabulary as vocab;
            let vocabulary = vocab::create_vocabulary(&legacy, SUGGEST_VOCAB, None)
                .await
                .unwrap();
            let later = vocab::propose_value_with_metadata_as(
                &legacy,
                &vocabulary,
                "later",
                Some("Can wait"),
                20.0,
                vocab::VocabularyValueTerminality::Open,
                None,
            )
            .await
            .unwrap();
            let urgent = vocab::propose_value_with_metadata_as(
                &legacy,
                &vocabulary,
                "urgent",
                Some("Attend first"),
                10.0,
                vocab::VocabularyValueTerminality::Open,
                None,
            )
            .await
            .unwrap();
            vocab::promote_value(&legacy, &later).await.unwrap();
            vocab::promote_value(&legacy, &urgent).await.unwrap();
            vocab::propose_value(&legacy, &vocabulary, "proposed-label", None)
                .await
                .unwrap();
            let retired = vocab::propose_value(&legacy, &vocabulary, "retired-label", None)
                .await
                .unwrap();
            vocab::promote_value(&legacy, &retired).await.unwrap();
            vocab::deprecate_value(&legacy, &retired).await.unwrap();
            let alias = vocab::propose_value(&legacy, &vocabulary, "old-urgent-label", None)
                .await
                .unwrap();
            vocab::promote_value(&legacy, &alias).await.unwrap();
            vocab::alias_value(&legacy, &alias, &urgent).await.unwrap();
            let dashboard_vocab = vocab::create_vocabulary(&legacy, "N3 dashboard lifecycle", None)
                .await
                .unwrap();
            for (value, terminality) in [
                ("open", vocab::VocabularyValueTerminality::Open),
                ("done", vocab::VocabularyValueTerminality::TerminalPositive),
            ] {
                let value = vocab::propose_value_with_metadata_as(
                    &legacy,
                    &dashboard_vocab,
                    value,
                    None,
                    0.0,
                    terminality,
                    None,
                )
                .await
                .unwrap();
                vocab::promote_value(&legacy, &value).await.unwrap();
            }
            let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
                .await
                .unwrap()
                .unwrap()
                .0;
            let mut rows = vec![];
            for section in ["vocabularies", "vocabulary_values"] {
                let scope_column = if section == "vocabularies" {
                    "id"
                } else {
                    "vocabulary_id"
                };
                for row in sqlx::query(&format!(
                    "SELECT * FROM {section} WHERE (?1=1 OR {scope_column} IN (SELECT value FROM json_each(?2))) ORDER BY id"
                ))
                .bind(imported_governance)
                .bind(json!([vocabulary, dashboard_vocab]).to_string())
                .fetch_all(legacy.pool())
                .await
                .unwrap()
                {
                    use sqlx::Column;
                    let mut object = serde_json::Map::new();
                    for (index, column) in row.columns().iter().enumerate() {
                        object.insert(
                            column.name().to_owned(),
                            json_cell(cell(&row, index).unwrap()).unwrap(),
                        );
                    }
                    let value = Json::Object(object);
                    rows.push(kernel::v1_state::ImportedState {
                        section: section.into(),
                        source_id: value["id"].as_str().unwrap().into(),
                        origin: "synthetic-seeded-governance".into(),
                        value_json: Some(value.to_string()),
                        account_principal: None,
                        record_id: None,
                        observed_at: "2026-10-24T00:00:00Z".into(),
                        snapshot: json!({}),
                    });
                }
            }
            for batch in rows.chunks(256) {
                kernel::v1_state::import_state_batch_as(&db, &host, batch)
                    .await
                    .unwrap();
            }
            legacy.close().await;
            (vocabulary, dashboard_vocab)
        };
        let id = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Offline journey","body":"synthetic admitted body","home_id":KERNEL_ROOT_ID,"facets":{"n3_facet_string":"synthetic current facet"}})).await["id"].as_str().unwrap().to_owned();
        let attachment = call(
            &db,
            OWNER,
            "attach_text",
            json!({"record_id":id,"text":"synthetic inline attachment","filename":"member.txt"}),
        )
        .await["attachment_id"]
            .as_str()
            .unwrap()
            .to_owned();
        // Supported sealed import stores a real typed carrier and immutable blob
        // binding. No catalogue/projection rows are fabricated for this proof.
        let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        let package = crate::v2_standard::v1_compat::package();
        let pin = &package.definitions[0];
        let imported = uuid::Uuid::new_v4().to_string();
        let imported_bytes = b"synthetic imported attachment";
        let imported_meta =
            crate::blob::new_blob_meta(imported_bytes, Some("text/plain"), Some("imported.txt"));
        kernel::import_record_with_blob_as(
            &db,
            &host,
            &imported,
            KERNEL_ROOT_ID,
            Some(
                &kernel::resolve_principal_by_binding(&db, OWNER)
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            ),
            &kernel::ImportRecordState {
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: pin.family.clone(),
                        version: pin.version,
                        digest: pin.digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        "Document",
                        "attachment",
                        Some("Imported attachment"),
                        None,
                        None,
                    ),
                }),
                facets: vec![kernel::FacetObservation {
                    key: "blob_ref".into(),
                    value: Some(imported_meta.id.clone()),
                    value_num: None,
                    vocab_ref: None,
                    as_of: imported_meta.created_at.clone(),
                }],
                ..Default::default()
            },
            Some((imported_bytes, &imported_meta)),
        )
        .await
        .unwrap();
        kernel::import_generic_link_as(
            &db,
            &host,
            &kernel::GenericLink {
                link_id: uuid::Uuid::new_v4().to_string(),
                source_id: imported.clone(),
                target_id: id.clone(),
                relationship: "part_of".into(),
                note: None,
                created_at: imported_meta.created_at.clone(),
                actor: None,
            },
        )
        .await
        .unwrap();
        let comment=call(&db,OWNER,"create_record",json!({"type":"Annotation","kind":"comment","name":"Resolver root","body":"Synthetic root comment","lifecycle":"open","links":[{"target_id":id,"relationship":"part_of"}]})).await["id"].as_str().unwrap().to_owned();
        let reply=call(&db,OWNER,"create_record",json!({"type":"Annotation","kind":"comment","name":"Resolver reply","body":"Synthetic reply comment","links":[{"target_id":comment,"relationship":"part_of"}]})).await["id"].as_str().unwrap().to_owned();
        call(
            &db,
            OWNER,
            "update_record",
            json!({"id":comment,"lifecycle":"resolved","summary":"Synthetic resolution"}),
        )
        .await;
        let ordinary_comments_query =
            json!({"steps":[{"step":"filter","ids":[id,comment,reply]}],"order":"name_asc"});
        let explicit_comments_query = json!({"steps":[{"step":"filter","ids":[comment,reply],"types":["Annotation"],"kinds":["comment"]}],"order":"name_asc"});
        let (collections, hidden_collection_member, reference_record, mention_record) =
            collection_fixture(&db, &owner_principal, &id).await;
        // Native has no online resolve_many handler yet. Pin the existing
        // member operation contract using actual supported native identities;
        // do not substitute an online get response or fabricate catalogue rows.
        let mut duplicate_ids = Vec::new();
        for _ in 0..2 {
            duplicate_ids.push(
                call(
                    &db,
                    OWNER,
                    "create_record",
                    json!({"type":"Document","kind":"note","name":"Resolver duplicate"}),
                )
                .await["id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        duplicate_ids.sort();
        call(&db, OWNER, "create_record", json!({"type":"Annotation","kind":"attribution","name":"Resolver attribution","links":[{"target_id":duplicate_ids[0],"relationship":"part_of"}]})).await;
        let archived = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Document","kind":"note","name":"Resolver archived","home_id":collections[0].0}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let archived_view = kernel::read_record_as(&db, &owner_principal, &archived)
            .await
            .unwrap()
            .unwrap();
        kernel::set_archived_as(
            &db,
            &owner_principal,
            &archived,
            true,
            archived_view.revision,
        )
        .await
        .unwrap();
        let successor = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Renderer successor","links":[{"target_id":id,"relationship":"supersedes"}]})).await["id"].as_str().unwrap().to_owned();
        let tree_root = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Collection","kind":"folder","name":"Structure proof root"}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let tree_branch = call(&db, OWNER, "create_record", json!({"type":"Collection","kind":"folder","name":"A structure branch","home_id":tree_root})).await["id"].as_str().unwrap().to_owned();
        for name in ["A nested structure note", "Z nested structure note"] {
            call(
                &db,
                OWNER,
                "create_record",
                json!({"type":"Document","kind":"note","name":name,"home_id":tree_branch}),
            )
            .await;
        }
        call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Z structure sibling","home_id":tree_root})).await;
        // Use the existing native account-only folder creation contract.
        // A logical Collection ID is not itself a kernel-home ID; the create
        // operation owns its real self-policy/child-home binding.
        let tree_private = call(&db, OWNER, "create_record", json!({"type":"Collection","kind":"folder","name":"Private structure branch","home_id":tree_root,"access_policy":"account_only"})).await["id"].as_str().unwrap().to_owned();
        let tree_private_child = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Private structure descendant","body":"Synthetic private structure payload","home_id":tree_private})).await["id"].as_str().unwrap().to_owned();
        for private in [&tree_private, &tree_private_child] {
            assert!(
                kernel::read_record_as(&db, &owner_principal, private)
                    .await
                    .unwrap()
                    .is_some(),
                "real owner-visible private subtree"
            );
            assert!(
                kernel::read_record_as(&db, &member_principal, private)
                    .await
                    .unwrap()
                    .is_none(),
                "actual source-hidden subtree"
            );
        }
        let owner_tree = call(
            &db,
            OWNER,
            "get_structure",
            json!({"root_id":tree_root,"max_depth":1}),
        )
        .await;
        assert_eq!(
            owner_tree["nodes"][0]["child_count"], 3,
            "owner sees the real private sibling before member visibility filtering"
        );
        assert!(owner_tree["nodes"]
            .as_array()
            .expect("owner tree")
            .iter()
            .any(|node| node["id"] == tree_private));
        let search_root = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Collection","kind":"folder","name":"Lexical proof folder"}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut lexical_ids = std::collections::BTreeMap::new();
        for (key, name, body) in [
            ("exact", "n3quartz", "n3quartz"),
            ("title", "n3quartz guide", "quiet"),
            ("body", "Body witness", "n3quartz n3quartz"),
            ("prefix", "n3quartzlater", "quiet"),
            ("infix", "Midn3quartzCase", "quiet"),
            ("sibling", "Sibling witness", "quiet"),
            ("archive", "n3quartz archived", "quiet"),
        ] {
            let record=call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":name,"body":body,"home_id":search_root})).await["id"].as_str().unwrap().to_owned();
            lexical_ids.insert(key, record);
        }
        let search_archived =
            kernel::read_record_as(&db, &owner_principal, &lexical_ids["archive"])
                .await
                .unwrap()
                .unwrap();
        kernel::set_archived_as(
            &db,
            &owner_principal,
            &lexical_ids["archive"],
            true,
            search_archived.revision,
        )
        .await
        .unwrap();
        let search_private=call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":"n3quartz private","body":"Synthetic private search payload","home_id":search_root,"access_policy":"account_only"})).await["id"].as_str().unwrap().to_owned();
        let search_comment=call(&db,OWNER,"create_record",json!({"type":"Annotation","kind":"comment","name":"n3quartz comment","body":"n3quartz","links":[{"target_id":lexical_ids["exact"],"relationship":"part_of"}]})).await["id"].as_str().unwrap().to_owned();
        let search_successor=call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":"Search successor","home_id":KERNEL_ROOT_ID,"links":[{"target_id":lexical_ids["exact"],"relationship":"supersedes"}]})).await["id"].as_str().unwrap().to_owned();
        for (target, relationship) in [
            (&lexical_ids["exact"], "n3_scan_self"),
            (&lexical_ids["title"], "n3_scan_a"),
            (&lexical_ids["title"], "n3_scan_b"),
            (&search_private, "n3_scan_private"),
        ] {
            call(&db,OWNER,"manage_links",json!({"action":"add","source_id":lexical_ids["exact"],"target_id":target,"relationship":relationship})).await;
        }
        let resolved = |index: usize, input: &str, id: &str, record_type: &str, kind: &str| json!({"index":index,"input":input,"status":"resolved","match":{"id":id,"name":input,"type":record_type,"kind":kind}});
        let missing =
            |index: usize, input: &str| json!({"index":index,"input":input,"status":"not_found"});
        let duplicate = |index: usize| json!({"index":index,"input":"Resolver duplicate","status":"ambiguous","match_count":2,"matches":duplicate_ids.iter().map(|id| json!({"id":id,"name":"Resolver duplicate","type":"Document","kind":"note"})).collect::<Vec<_>>()});
        let expected = |results: Json,
                        counts: (usize, usize, usize),
                        record_type: Option<&str>,
                        kind: Option<&str>,
                        archived: bool| json!({"results":results,"counts":{"resolved":counts.0,"not_found":counts.1,"ambiguous":counts.2,"not_held":0},"type":record_type,"kind":kind,"include_archived":archived,"match":"exact"});
        let resolution_cases = vec![
            (
                json!({"names":["Offline journey","Resolver duplicate","Only private resolver witness","offline journey","Offline journey","Resolver archived","Resolver root","Resolver reply","Resolver attribution"]}),
                expected(
                    json!([
                        resolved(0, "Offline journey", &id, "Document", "note"),
                        duplicate(1),
                        missing(2, "Only private resolver witness"),
                        missing(3, "offline journey"),
                        resolved(4, "Offline journey", &id, "Document", "note"),
                        missing(5, "Resolver archived"),
                        resolved(6, "Resolver root", &comment, "Annotation", "comment"),
                        resolved(7, "Resolver reply", &reply, "Annotation", "comment"),
                        missing(8, "Resolver attribution")
                    ]),
                    (4, 4, 1),
                    None,
                    None,
                    false,
                ),
            ),
            (
                json!({"names":["Resolver duplicate"],"type":"Document","kind":"note"}),
                expected(
                    json!([duplicate(0)]),
                    (0, 0, 1),
                    Some("Document"),
                    Some("note"),
                    false,
                ),
            ),
            (
                json!({"names":["Resolver archived"],"include_archived":true}),
                expected(
                    json!([resolved(
                        0,
                        "Resolver archived",
                        &archived,
                        "Document",
                        "note"
                    )]),
                    (1, 0, 0),
                    None,
                    None,
                    true,
                ),
            ),
            (
                json!({"names":["Offline journey"],"type":"Collection"}),
                expected(
                    json!([missing(0, "Offline journey")]),
                    (0, 1, 0),
                    Some("Collection"),
                    None,
                    false,
                ),
            ),
            (
                json!({"names":["Resolver root","Resolver reply"],"type":"Annotation","kind":"comment"}),
                expected(
                    json!([
                        resolved(0, "Resolver root", &comment, "Annotation", "comment"),
                        resolved(1, "Resolver reply", &reply, "Annotation", "comment")
                    ]),
                    (2, 0, 0),
                    Some("Annotation"),
                    Some("comment"),
                    false,
                ),
            ),
        ];
        // Actual supported source import of schema declarations, including a
        // malformed private scoped declaration. The source selector must hide
        // it before interpretation/capture, not downgrade a resolver error.
        let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        let observed_at = "2026-10-24T00:00:00Z";
        let dashboard_root = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Collection","kind":"folder","name":"Dashboard proof folder"}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let bootstrap_shared=call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":"Bootstrap workspace source","body":"Synthetic bootstrap standing instruction"})).await["id"].as_str().unwrap().to_owned();
        let bootstrap_empty = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Document","kind":"note","name":"Bootstrap empty source"}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let bootstrap_private=call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":"Bootstrap private source","body":"Synthetic private bootstrap instruction","access_policy":"account_only"})).await["id"].as_str().unwrap().to_owned();
        for (binding, scope, actor, record) in [
            (
                "n3-bootstrap-workspace",
                "database",
                None,
                &bootstrap_shared,
            ),
            (
                "n3-bootstrap-empty",
                "account",
                Some(member_principal.as_str()),
                &bootstrap_empty,
            ),
            ("n3-bootstrap-private", "database", None, &bootstrap_private),
            (
                "n3-bootstrap-owner",
                "account",
                Some(owner_principal.as_str()),
                &bootstrap_private,
            ),
        ] {
            kernel::import_instruction_binding_as(
                &db,
                &host,
                &kernel::ImportInstructionBinding {
                    id: binding.into(),
                    scope_kind: scope.into(),
                    scope_id: if scope == "database" {
                        "native:database".into()
                    } else if actor == Some(member_principal.as_str()) {
                        MEMBER.into()
                    } else {
                        OWNER.into()
                    },
                    account_principal: actor.map(str::to_owned),
                    source_record_id: record.clone(),
                    position: 0,
                    enabled: true,
                    created_at: observed_at.into(),
                    actor: None,
                },
            )
            .await
            .unwrap();
        }
        let schema_data = json!({"shapes":{"Document":{"facets":{
            "n3_preview_score":{"type":"number"},"n3_preview_required":{"required":true},
            "n3_suggest_priority":{"type":"string","vocab":SUGGEST_VOCAB}
        }}}});
        let schema_rows = [
            ("n3-preview-global", None, schema_data.to_string()),
            ("n3-dashboard-scope", Some(dashboard_root.clone()), json!({"shapes":{"WorkItem":{"facets":{"lifecycle":{"type":"string","vocab":dashboard_vocabulary,"axis":{"key":"n3_dashboard_state","label":"N3 dashboard state"}}}}}}).to_string()),
            ("n3-facet-visible-scope", Some(collections[0].0.clone()), json!({"shapes":{"Collection":{"facets":{"n3_scope_label":{"type":"string"},"n3_suggest_priority":{"type":"string","vocab":SUGGEST_VOCAB}}}}}).to_string()),
            ("n3-preview-private", Some(hidden_collection_member[1].clone()), "malformed private schema".to_owned()),
        ].into_iter().map(|(id, anchor, data)| kernel::v1_state::ImportedState {
            section: "schema_config".into(), source_id: id.into(), origin: "synthetic-preview-schema".into(),
            value_json: Some(json!({"id":id,"layer":"user","name":id,"data":data,"applies_to_collection_id":anchor,"version_lineage":null,"created_at":observed_at}).to_string()),
            account_principal: None, record_id: None, observed_at: observed_at.into(), snapshot: json!({}),
        }).collect::<Vec<_>>();
        kernel::v1_state::import_state_batch_as(
            &db,
            &host,
            std::slice::from_ref(
                schema_rows
                    .iter()
                    .find(|r| r.source_id == "n3-dashboard-scope")
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
        // Real native writes under an authored scoped lifecycle vocabulary;
        // deliberately old records use the supported sealed import metadata
        // contract, never direct projection/clock edits or fabricated kinds.
        let mut dashboard_ids = std::collections::BTreeMap::new();
        for (key, typ, kind, lifecycle) in [
            ("active", "WorkItem", "task", Some("open")),
            ("done", "WorkItem", "task", Some("done")),
            ("unclassified", "Document", "note", Some("mystery")),
            ("waiting", "Document", "note", None),
            ("hidden_only", "Document", "note", None),
            ("archived_only", "Document", "note", None),
            ("archived", "WorkItem", "task", Some("open")),
        ] {
            let record = call(&db, OWNER, "create_record", json!({"type":typ,"kind":kind,"name":format!("Dashboard {key}"),"lifecycle":lifecycle,"home_id":dashboard_root})).await["id"].as_str().unwrap().to_owned();
            dashboard_ids.insert(key, record);
        }
        let dashboard_private = call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":"Dashboard private","body":"Synthetic private dashboard payload","access_policy":"account_only","home_id":dashboard_root})).await["id"].as_str().unwrap().to_owned();
        let dashboard_external = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Document","kind":"note","name":"Dashboard external blocker"}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let dashboard_successor = call(
            &db,
            OWNER,
            "create_record",
            json!({"type":"Document","kind":"note","name":"Dashboard successor"}),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let dashboard_home =
            kernel::read_record_as(&db, &owner_principal, &dashboard_ids["active"])
                .await
                .unwrap()
                .unwrap()
                .home_id;
        for (key, at) in [
            ("oldest", "2000-01-01T00:00:00.000Z"),
            ("older", "2001-01-01T00:00:00.000Z"),
        ] {
            let record = uuid::Uuid::new_v4().to_string();
            let state = kernel::ImportRecordState {
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: pin.family.clone(),
                        version: pin.version,
                        digest: pin.digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        "WorkItem",
                        "task",
                        Some(&format!("Dashboard {key}")),
                        None,
                        Some("open"),
                    ),
                }),
                metadata: Some(kernel::RecordMetadata {
                    persistence: "occurrent".into(),
                    maturity: Some("captured".into()),
                    last_activity_at: at.into(),
                }),
                ..Default::default()
            };
            kernel::import_record_as(
                &db,
                &host,
                &record,
                &dashboard_home,
                Some(&owner_principal),
                &state,
            )
            .await
            .unwrap();
            dashboard_ids.insert(key, record.clone());
        }
        for (source, target, relationship) in [
            (&dashboard_ids["older"], &dashboard_ids["done"], "blocks"),
            (&dashboard_external, &dashboard_ids["active"], "blocks"),
            (&dashboard_private, &dashboard_ids["hidden_only"], "blocks"),
            (
                &dashboard_ids["archived"],
                &dashboard_ids["archived_only"],
                "blocks",
            ),
            (
                &dashboard_ids["waiting"],
                &dashboard_ids["older"],
                "depends_on",
            ),
            (&dashboard_successor, &dashboard_ids["active"], "supersedes"),
        ] {
            if source == &dashboard_ids["older"] {
                // A preserved imported edge keeps the imported source activity
                // clock; native link mutations correctly advance their source.
                kernel::import_generic_link_as(
                    &db,
                    &host,
                    &kernel::GenericLink {
                        link_id: uuid::Uuid::new_v4().to_string(),
                        source_id: source.clone(),
                        target_id: target.clone(),
                        relationship: relationship.into(),
                        note: None,
                        created_at: "2001-01-01T00:00:00.000Z".into(),
                        actor: None,
                    },
                )
                .await
                .unwrap();
            } else {
                call(&db,OWNER,"manage_links",json!({"action":"add","source_id":source,"target_id":target,"relationship":relationship})).await;
            }
        }
        call(
            &db,
            OWNER,
            "archive_record",
            json!({"id":dashboard_ids["archived"],"reason":"synthetic archived blocker"}),
        )
        .await;
        let dashboard_source = call(&db,MEMBER,"query_sql",json!({"sql":"SELECT id,type,kind,name,home_id,lifecycle,maturity,last_activity_at,archived FROM records WHERE home_id=?1 OR id=?1 ORDER BY last_activity_at DESC,id","parameters":[{"type":"text","value":dashboard_root}]})).await;
        let dashboard_rows = dashboard_source["rows"]
            .as_array()
            .expect("source authorized dashboard rows")
            .iter()
            .map(|r| (r["id"].as_str().unwrap().to_owned(), r.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(dashboard_rows.len(), 10); // root + 9 visible children, including archived
        assert!(!dashboard_rows.contains_key(&dashboard_private));
        assert!(
            kernel::read_record_as(&db, &owner_principal, &dashboard_private)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            kernel::read_record_as(&db, &member_principal, &dashboard_private)
                .await
                .unwrap()
                .is_none()
        );
        let dashboard_links=call(&db,MEMBER,"query_sql",json!({"sql":"SELECT source_id,target_id,relationship FROM links WHERE (target_id IN (?1,?2,?3,?4) AND relationship='blocks') OR (source_id=?5 AND relationship='depends_on') ORDER BY source_id,target_id,relationship","parameters":[{"type":"text","value":dashboard_ids["active"]},{"type":"text","value":dashboard_ids["done"]},{"type":"text","value":dashboard_ids["hidden_only"]},{"type":"text","value":dashboard_ids["archived_only"]},{"type":"text","value":dashboard_ids["waiting"]}]})).await;
        let mut expected_dashboard_links = vec![
            json!({"source_id":dashboard_external,"target_id":dashboard_ids["active"],"relationship":"blocks"}),
            json!({"source_id":dashboard_ids["older"],"target_id":dashboard_ids["done"],"relationship":"blocks"}),
            json!({"source_id":dashboard_ids["archived"],"target_id":dashboard_ids["archived_only"],"relationship":"blocks"}),
            json!({"source_id":dashboard_ids["waiting"],"target_id":dashboard_ids["older"],"relationship":"depends_on"}),
        ];
        expected_dashboard_links.sort_by(|a, b| {
            a["source_id"]
                .as_str()
                .unwrap()
                .cmp(b["source_id"].as_str().unwrap())
                .then(
                    a["target_id"]
                        .as_str()
                        .unwrap()
                        .cmp(b["target_id"].as_str().unwrap()),
                )
                .then(
                    a["relationship"]
                        .as_str()
                        .unwrap()
                        .cmp(b["relationship"].as_str().unwrap()),
                )
        });
        assert_eq!(dashboard_links["rows"], json!(expected_dashboard_links));
        let dashboard_get = call(&db,MEMBER,"get_record",json!({"ids":dashboard_ids.values().collect::<Vec<_>>(),"children_limit":0,"links_limit":0})).await;
        let dashboard_interpretations = dashboard_get["records"]
            .as_array()
            .expect("native dashboard get witness")
            .iter()
            .map(|r| {
                let interpretation = r
                    .get("lifecycle_interpretation")
                    .expect("source lifecycle interpretation");
                lifecycle_carrier(interpretation);
                (r["id"].as_str().unwrap().to_owned(), interpretation.clone())
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for key in ["active", "oldest", "older", "archived"] {
            let interpreted = &dashboard_interpretations[&dashboard_ids[key]];
            assert_eq!(interpreted["status"], "governed");
            assert_eq!(interpreted["terminality"], "open");
            assert_eq!(lifecycle_carrier(interpreted), Some("open"));
        }
        assert_eq!(
            dashboard_interpretations[&dashboard_ids["done"]]["terminality"],
            "terminal_positive"
        );
        assert_eq!(
            dashboard_interpretations[&dashboard_ids["unclassified"]],
            json!({"status":"unclassified","raw":"mystery","reason":"no_governing_vocabulary"})
        );
        for key in ["waiting", "hidden_only", "archived_only"] {
            assert_eq!(
                lifecycle_carrier(&dashboard_interpretations[&dashboard_ids[key]]),
                None
            );
        }
        assert_eq!(
            dashboard_rows[&dashboard_ids["oldest"]]["last_activity_at"],
            "2000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            dashboard_rows[&dashboard_ids["older"]]["last_activity_at"],
            "2001-01-01T00:00:00.000Z"
        );
        assert_eq!(dashboard_rows[&dashboard_ids["archived"]]["archived"], 1);
        let mut source = db.pool().acquire().await.unwrap();
        let dashboard_reference =
            crate::mcp::kernel_v2::member_display_reference_on(&mut source, &dashboard_root)
                .await
                .unwrap()
                .expect("source-safe dashboard scope reference");
        let dashboard_successor_reference =
            crate::mcp::kernel_v2::member_display_reference_on(&mut source, &dashboard_successor)
                .await
                .unwrap()
                .expect("source-safe dashboard superseder reference");
        drop(source);
        kernel::v1_state::import_state_batch_as(&db, &host, &schema_rows)
            .await
            .unwrap();
        super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
        let mut preview_reads = Vec::new();
        for arguments in [
            json!({}),
            json!({"type":"Document"}),
            json!({"type":"Document","kind":"note"}),
            json!({"type":"Document","kind":"note","facets":{"n3_preview_score":7,"n3_preview_required":"present"}}),
            json!({"type":"Document","kind":"note","facets":{"n3_preview_score":"invalid","n3_preview_required":"present"}}),
            json!({"type":"Document","kind":"note","facets":{"n3_preview_score":7}}),
        ] {
            let online = call(&db, MEMBER, "preview_record_shape", arguments.clone()).await;
            assert!(!online.to_string().contains("n3-preview-private"));
            assert!(!online.to_string().contains(&hidden_collection_member[1]));
            assert_eq!(
                online
                    .get("zero_authoritative_writes")
                    .expect("preview write guarantee"),
                &json!(true)
            );
            preview_reads.push((arguments, online));
        }
        assert_eq!(preview_reads[3].1["proposed_facets"]["status"], "accepted");
        assert_eq!(preview_reads[4].1["proposed_facets"]["status"], "rejected");
        assert_eq!(preview_reads[5].1["proposed_facets"]["status"], "rejected");
        let mut suggestion_reads = Vec::new();
        for (arguments, governed) in [
            (
                json!({"type":"Document","facet_key":"n3_suggest_priority"}),
                true,
            ),
            (
                json!({"type":"Document","kind":"note","facet_key":"n3_suggest_priority"}),
                true,
            ),
            (
                json!({"record_id":id,"facet_key":"n3_suggest_priority"}),
                true,
            ),
            (
                json!({"record_id":archived,"facet_key":"n3_suggest_priority"}),
                true,
            ),
            (
                json!({"record_id":collections[0].0,"facet_key":"n3_suggest_priority"}),
                true,
            ),
            (
                json!({"type":"Collection","facet_key":"n3_suggest_priority"}),
                false,
            ),
            (
                json!({"record_id":reply,"facet_key":"n3_suggest_priority"}),
                false,
            ),
            (
                json!({"record_id":id,"facet_key":"n3_preview_score"}),
                false,
            ),
            (
                json!({"type":"Document","facet_key":"undeclared_facet"}),
                false,
            ),
            (
                json!({"record_id":reference_record,"facet_key":"n3_suggest_priority"}),
                false,
            ),
        ] {
            let online = call(&db, MEMBER, "suggest_facet_values", arguments.clone()).await;
            let suggestions = online
                .get("suggestions")
                .expect("actual native suggestion field")
                .as_array()
                .expect("native suggestion array");
            if governed {
                assert_eq!(
                    online["vocabulary"],
                    json!({"id":suggestion_vocabulary,"name":SUGGEST_VOCAB})
                );
                assert_eq!(online["declared_type"], "string");
                assert_eq!(
                    suggestions
                        .iter()
                        .map(|v| v
                            .get("value")
                            .expect("actual value label")
                            .as_str()
                            .expect("label string"))
                        .collect::<Vec<_>>(),
                    vec!["urgent", "later"],
                    "real metadata API ordinal order; proposed/retired/aliased values excluded"
                );
                for value in suggestions {
                    assert_eq!(value["status"], "active");
                    assert!(value.get("alias_of").expect("actual alias state").is_null());
                    assert!(value
                        .get("metadata")
                        .expect("actual value metadata")
                        .is_object());
                    assert_eq!(value["vocabulary_id"], suggestion_vocabulary);
                }
            } else {
                assert!(online
                    .get("vocabulary")
                    .expect("ungoverned vocabulary field")
                    .is_null());
                assert!(suggestions.is_empty());
            }
            assert!(!online.to_string().contains("n3-preview-private"));
            assert!(!online.to_string().contains(&hidden_collection_member[1]));
            suggestion_reads.push((arguments, online));
        }
        let mut facet_reads = Vec::new();
        let mut facet_owners = std::collections::BTreeMap::new();
        let mut facet_raw_owners = BTreeSet::new();
        for arguments in [
            json!({"type":"Document"}),
            json!({"type":"Document","kind":"note"}),
            json!({"record_id":id}),
            json!({"record_id":imported}),
            json!({"record_id":comment}),
            json!({"record_id":reply}),
            json!({"record_id":archived}),
            json!({"record_id":collections[0].0}),
            json!({"record_id":reference_record}),
        ] {
            let online = call(&db, MEMBER, "resolve_facets", arguments.clone()).await;
            assert!(!online.to_string().contains("n3-preview-private"));
            assert!(!online.to_string().contains(&hidden_collection_member[1]));
            if let Some(record_id) = arguments.get("record_id").and_then(Json::as_str) {
                let mut source = db.pool().begin().await.unwrap();
                let record = kernel::read_record_on(&mut source, &member_principal, record_id)
                    .await
                    .unwrap()
                    .expect("actual source-authorised facet target");
                facet_raw_owners.insert(
                    record
                        .owner_id
                        .clone()
                        .expect("fixture source owner principal"),
                );
                let selected = crate::mcp::kernel_v2::member_visible_person_on(
                    &mut source,
                    &member_principal,
                    record.owner_id.as_deref(),
                )
                .await
                .unwrap();
                let person = selected
                    .as_deref()
                    .expect("fixture must exercise a selected visible owner");
                let visible_owner = kernel::read_record_on(&mut source, &member_principal, person)
                    .await
                    .unwrap()
                    .expect("selected owner is an actual source-visible record");
                assert_eq!(visible_owner.id, person);
                let source_owner = if record_id == reference_record {
                    assert!(
                        kernel::messaging::on(&mut source, record_id)
                            .await
                            .unwrap()
                            .is_some(),
                        "actual native Message owner presentation"
                    );
                    json!(selected)
                } else {
                    // No raw principal is an ordinary visible owner record in
                    // this fixture; source selection maps it to its real Person.
                    let principal = record
                        .owner_id
                        .as_deref()
                        .expect("fixture native owner principal");
                    assert!(
                        kernel::read_record_on(&mut source, &member_principal, principal)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    json!(record.owner_id)
                };
                if record_id == imported {
                    assert_eq!(
                        record.owner_id.as_deref(),
                        Some(owner_principal.as_str()),
                        "supported import retained its actual source owner"
                    );
                }
                assert_eq!(
                    online["spine"]
                        .get("owner")
                        .expect("native facet owner field"),
                    &source_owner
                );
                facet_owners.insert(record_id.to_owned(), (source_owner, json!(selected)));
                source.rollback().await.unwrap();
            }
            facet_reads.push((arguments, online));
        }
        assert_eq!(facet_reads[4].1["spine"]["lifecycle"], "resolved");
        assert!(facet_reads[5].1["spine"]
            .get("lifecycle")
            .expect("reply lifecycle field")
            .is_null());
        assert_eq!(facet_reads[6].1["archived"], true);
        assert_eq!(facet_reads[7].1["bears_shape"], true);
        assert!(facet_reads[2].1["values"]
            .as_array()
            .expect("actual source current facets")
            .iter()
            .any(|facet| facet["key"] == "n3_facet_string"
                && facet["value"] == "synthetic current facet"));
        let mut collection_reads = Vec::new();
        for (collection, expected) in collections {
            let online = call(&db, MEMBER, "open_collection", json!({"id":collection})).await;
            assert_eq!(online["status"], "opened", "{online}");
            assert_eq!(
                online["input"]["records"].as_array().unwrap().len(),
                expected,
                "{online}"
            );
            for hidden in &hidden_collection_member {
                assert!(!online.to_string().contains(hidden));
            }
            collection_reads.push((collection, online));
        }
        let online_imported = call(
            &db,
            MEMBER,
            "read_attachment",
            json!({"attachment_id":imported,"offset":10,"length":8}),
        )
        .await;
        assert_eq!(online_imported["content"], "imported");
        let ordinary_online =
            call(&db, MEMBER, "query_record", ordinary_comments_query.clone()).await;
        let comments_online =
            call(&db, MEMBER, "query_record", explicit_comments_query.clone()).await;
        assert_eq!(ordinary_online["total"],1,"native default family rule; imported_governance={imported_governance}: {ordinary_online}");
        assert_eq!(comments_online["total"],2,"native root+stored reply after resolution; imported_governance={imported_governance}: {comments_online}");
        let mut archive_queries = Vec::new();
        for include in [false, true] {
            let arguments = json!({"steps":[{"step":"filter","ids":[id,archived],"include_archived":include}],"order":"name_asc"});
            let online = call(&db, MEMBER, "query_record", arguments.clone()).await;
            assert_eq!(
                online["total"],
                if include { 2 } else { 1 },
                "actual native archive filter: {online}"
            );
            archive_queries.push((arguments, online));
        }
        let mut get_reads = Vec::new();
        for arguments in [
            json!({"ids":[collection_reads[0].0],"children_limit":0,"links_limit":0,"include_comments":true,"comments_limit":0}),
            json!({"ids":[collection_reads[0].0],"children_limit":2,"children_offset":1,"links_limit":1,"links_offset":0}),
            json!({"ids":[collection_reads[0].0],"children_limit":100,"links_limit":0}),
            json!({"ids":[archived],"children_limit":0,"links_limit":0}),
            json!({"ids":[id,comment,reply,attachment,imported,reference_record,mention_record],"children_limit":0,"links_limit":1,"links_offset":1,"include_comments":true,"comments_limit":2,"comments_offset":0}),
        ] {
            let online = call(&db, MEMBER, "get_record", arguments.clone()).await;
            get_reads.push((arguments, online));
        }
        let requested_ids = get_reads
            .iter()
            .flat_map(|(args, _)| args["ids"].as_array().unwrap().iter())
            .map(|id| id.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let source_links = call(&db, MEMBER, "query_sql", json!({
            "sql":"SELECT id,source_id,target_id,relationship,note,created_at FROM links WHERE source_id IN (SELECT value FROM json_each(?1)) OR target_id IN (SELECT value FROM json_each(?1))",
            "parameters":[{"type":"text","value":serde_json::to_string(&requested_ids).unwrap()}]
        })).await;
        let source_links = source_links["rows"]
            .as_array()
            .expect("actual authorised source links")
            .clone();
        let mut child_references = std::collections::BTreeMap::new();
        for (_, online) in &get_reads {
            for record in online["records"].as_array().expect("online get records") {
                for child in record["children"].as_array().expect("online child window") {
                    let id = child["id"].as_str().expect("online child id");
                    let mut connection = db.pool().acquire().await.unwrap();
                    let reference =
                        crate::mcp::kernel_v2::member_display_reference_on(&mut connection, id)
                            .await
                            .unwrap()
                            .expect("source child safe reference");
                    child_references.insert(id.to_owned(), reference);
                }
            }
        }
        let successor_reference = {
            let mut connection = db.pool().acquire().await.unwrap();
            crate::mcp::kernel_v2::member_display_reference_on(&mut connection, &successor)
                .await
                .unwrap()
                .expect("actual source-selected successor reference")
        };
        let source_reference = {
            let mut connection = db.pool().acquire().await.unwrap();
            crate::mcp::kernel_v2::member_display_reference_on(&mut connection, &reference_record)
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            source_reference, "c01dcafe",
            "hidden sibling requires source-selected eight hex reference"
        );
        let mut structure_reads = Vec::new();
        for arguments in [
            json!({"root_id":tree_root}),
            json!({"root_id":tree_root,"max_depth":0}),
            json!({"root_id":tree_root,"max_depth":1,"max_children_per_node":0}),
            json!({"root_id":tree_root,"max_depth":2,"max_children_per_node":1}),
            json!({"root_id":tree_root,"max_depth":101,"exclude_types":["Document"]}),
            json!({"root_id":tree_root,"exclude_types":["Collection"]}),
            json!({"root_id":collection_reads[0].0,"max_depth":1,"max_children_per_node":1}),
            json!({"root_id":collection_reads[0].0,"max_depth":1,"include_archived":true}),
            json!({"root_id":archived,"include_archived":false,"exclude_types":["Document"]}),
            json!({"root_id":id,"max_depth":0}),
            json!({"root_id":comment,"max_depth":1}),
        ] {
            let online = call(&db, MEMBER, "get_structure", arguments.clone()).await;
            for hidden in [
                &tree_private,
                &tree_private_child,
                &hidden_collection_member[0],
                &hidden_collection_member[1],
                &hidden_collection_member[2],
            ] {
                assert!(
                    !online.to_string().contains(hidden),
                    "tree source privacy: {online}"
                );
            }
            let nodes = online["nodes"].as_array().expect("actual native structure");
            assert!(!nodes.is_empty());
            if arguments == json!({"root_id":tree_root}) {
                assert_eq!(
                    nodes.len(),
                    5,
                    "complete nested tree with hidden subtree excluded"
                );
            }
            if arguments["root_id"] == tree_root {
                assert_eq!(
                    nodes[0]["child_count"],
                    if arguments["exclude_types"] == json!(["Document"])
                        || arguments["exclude_types"] == json!(["Collection"])
                    {
                        1
                    } else {
                        2
                    }
                );
            }
            if arguments["root_id"] == collection_reads[0].0 {
                assert_eq!(
                    nodes[0]["child_count"],
                    if arguments["include_archived"] == true {
                        52
                    } else {
                        51
                    }
                );
            }
            structure_reads.push((arguments, online));
        }
        let lexical_source=call(&db,MEMBER,"query_sql",json!({"sql":"SELECT id,type,kind,name,home_id,body,archived,lifecycle,last_activity_at FROM records WHERE home_id=?1 OR id=?1 ORDER BY id","parameters":[{"type":"text","value":search_root}]})).await;
        let lexical_rows = lexical_source["rows"]
            .as_array()
            .expect("actual authorised native lexical rows")
            .iter()
            .map(|row| {
                (
                    row["id"].as_str().expect("source lexical id").to_owned(),
                    row.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for record in lexical_ids.values() {
            assert!(
                lexical_rows.contains_key(record),
                "real selected source lexical identity"
            );
        }
        assert!(
            !lexical_rows.contains_key(&search_private),
            "source policy filters private lexical candidate"
        );
        assert!(
            kernel::read_record_as(&db, &owner_principal, &search_private)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            kernel::read_record_as(&db, &member_principal, &search_private)
                .await
                .unwrap()
                .is_none()
        );
        let mut lexical_references = std::collections::BTreeMap::new();
        for record in lexical_ids
            .values()
            .chain([&search_root, &search_successor].into_iter())
        {
            let mut source = db.pool().acquire().await.unwrap();
            let reference = crate::mcp::kernel_v2::member_display_reference_on(&mut source, record)
                .await
                .unwrap()
                .expect("actual source-selected lexical reference");
            lexical_references.insert(record.clone(), reference);
        }
        let tree_successions = std::collections::BTreeMap::from([
            (
                id.clone(),
                json!({"items":[{"id":successor,"name":"Renderer successor","display_reference":successor_reference}],"total_count":1}),
            ),
            (
                dashboard_ids["active"].clone(),
                json!({"items":[{"id":dashboard_successor,"name":"Dashboard successor","display_reference":dashboard_successor_reference}],"total_count":1}),
            ),
            (
                lexical_ids["exact"].clone(),
                json!({"items":[{"id":search_successor,"name":"Search successor","display_reference":lexical_references[&search_successor]}],"total_count":1}),
            ),
        ]);
        // Native online uses its own tiered search, without member near misses.
        // Compare only justified common identity/placement facts, never scores,
        // snippets, total membership or a fabricated full-response oracle.
        let native_lexical = call(
            &db,
            MEMBER,
            "search",
            json!({"query":"n3quartz","scope":search_root,"limit":200}),
        )
        .await;
        assert_eq!(native_lexical["thin"], false);
        assert!(native_lexical.get("near_misses").is_none());
        assert!(!native_lexical["hits"]
            .as_array()
            .expect("native tiered hits")
            .is_empty());
        for hit in native_lexical["hits"].as_array().unwrap() {
            let source = lexical_rows
                .get(hit["id"].as_str().expect("native tiered id"))
                .expect("tiered hit has actual authorised staged identity");
            for field in ["id", "type", "kind", "name", "home_id"] {
                assert_eq!(
                    hit.get(field).expect("native common field"),
                    source.get(field).expect("source common field")
                );
            }
            assert!(hit.get("score").expect("native score").is_number());
            assert!(hit.get("snippet").expect("native snippet").is_string());
        }
        let scan_source_get=call(&db,MEMBER,"get_record",json!({"ids":lexical_ids.values().chain([&search_root].into_iter()).collect::<Vec<_>>(),"children_limit":0,"links_limit":0})).await;
        let scan_interpretations = scan_source_get["records"]
            .as_array()
            .expect("source scan sample interpretations")
            .iter()
            .map(|record| {
                assert_eq!(record["status"], "found");
                let interpretation = record
                    .get("lifecycle_interpretation")
                    .expect("actual source interpretation");
                assert_eq!(
                    lifecycle_carrier(interpretation),
                    None,
                    "fixture is genuinely absent, not defaulted"
                );
                (
                    record["id"]
                        .as_str()
                        .expect("source interpreted id")
                        .to_owned(),
                    interpretation.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let scan_links_source=call(&db,MEMBER,"query_sql",json!({"sql":"SELECT source_id,target_id,relationship FROM links WHERE source_id=?1 OR target_id=?1 OR source_id=?2 OR target_id=?2","parameters":[{"type":"text","value":lexical_ids["exact"]},{"type":"text","value":lexical_ids["title"]}]})).await;
        let scan_links_source = scan_links_source["rows"]
            .as_array()
            .expect("authorised source scan edges");
        assert_eq!(scan_links_source.iter().filter(|link|link["source_id"]==lexical_ids["exact"]||link["target_id"]==lexical_ids["exact"]).count(),5,"self once, two distinct title links, source-visible comment and out-of-scope successor");
        assert_eq!(
            scan_links_source
                .iter()
                .filter(|link| link["source_id"] == lexical_ids["title"]
                    || link["target_id"] == lexical_ids["title"])
                .count(),
            2
        );
        assert_eq!(
            scan_links_source
                .iter()
                .filter(|link| link["source_id"] == lexical_ids["exact"]
                    && link["target_id"] == lexical_ids["exact"])
                .count(),
            1
        );
        assert!(
            !json!(scan_links_source)
                .to_string()
                .contains(&search_private),
            "private endpoint excluded before metrics"
        );
        let before = std::fs::read(dir.path().join("source.db")).unwrap();
        let root = dir.path().join("device");
        std::fs::create_dir(&root).unwrap();
        let source_before_bootstrap = kernel::dump_all_kernel_tables(&db).await.unwrap();
        let mut bootstrap_registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut bootstrap_registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut bootstrap_registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut bootstrap_registry).unwrap();
        let native_bootstrap = bootstrap_registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated(MEMBER).with_suppressed_request_persistence(),
                "bootstrap",
                json!({}),
            )
            .await
            .unwrap();
        assert_eq!(
            source_before_bootstrap,
            kernel::dump_all_kernel_tables(&db).await.unwrap(),
            "actual read-only native bootstrap creates no source run"
        );
        assert_eq!(
            native_bootstrap["principal"],
            json!({"principal_id":member_principal,"kind":"account","display_name":"Member","identity_basis":"authenticated kernel auth_binding"})
        );
        assert_eq!(native_bootstrap["run"]["durable"], false);
        assert_eq!(native_bootstrap["run"]["status"], "not_established");
        let source_root_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM main.kernel_records WHERE id IN ('kernel:root','native:root')",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            source_root_count, 0,
            "actual policy root has no ordinary source record in either governance fixture"
        );
        let native_root_tree = call(
            &db,
            MEMBER,
            "get_structure",
            json!({"root_id":"native:root"}),
        )
        .await;
        let native_kernel_root_tree = call(
            &db,
            MEMBER,
            "get_structure",
            json!({"root_id":KERNEL_ROOT_ID,"max_depth":1,"max_children_per_node":2}),
        )
        .await;
        assert_eq!(native_root_tree["nodes"][0]["id"], "native:root");
        assert!(
            native_root_tree["nodes"][0]["child_count"]
                .as_i64()
                .unwrap()
                > 2
        );
        assert_eq!(
            native_root_tree["nodes"][0]["containment_path_visible"],
            true
        );

        let bootstrap_source_ids = json!([bootstrap_shared, bootstrap_empty]).to_string();
        let bootstrap_source=call(&db,MEMBER,"query_sql",json!({"sql":"SELECT r.id,r.type,r.kind,r.name,r.home_id,r.lifecycle,COALESCE(r.last_activity_at,r.updated_at,r.created_at) AS observed_activity_at FROM records r WHERE r.deleted_at IS NULL AND r.archived=0 AND NOT (r.type='Annotation' AND COALESCE(r.kind,'') IN ('attribution','acknowledgement','comment','suggestion','citation')) AND NOT (r.type='Entity' AND r.kind IS 'semantic-unit') AND r.id NOT IN ('kernel:root','native:root','native:unfiled') AND r.id NOT LIKE 'native:%' AND r.id NOT IN (SELECT value FROM json_each(?1)) AND NOT EXISTS(SELECT 1 FROM bindings b WHERE b.record_id=r.id AND b.system='account' AND b.is_canonical=1) ORDER BY observed_activity_at DESC,r.id LIMIT 65","parameters":[{"type":"text","value":bootstrap_source_ids}]})).await;
        let bootstrap_rows = bootstrap_source["rows"]
            .as_array()
            .expect("actual authorized bounded bootstrap source rows")
            .iter()
            .take(64)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            bootstrap_source["rows"].as_array().unwrap().len(),
            65,
            "literal fixture exceeds the bounded world scan"
        );
        assert_eq!(bootstrap_rows.len(), 64);
        assert!(
            !bootstrap_rows.iter().any(|row| row["id"] == id),
            "the main document's succession edge is outside this bounded preview"
        );
        for excluded in [
            &bootstrap_empty,
            &bootstrap_shared,
            &bootstrap_private,
            &comment,
            &reply,
            &search_comment,
            &archived,
        ] {
            assert!(!bootstrap_rows.iter().any(|row| row["id"] == *excluded));
        }
        let source_world_get=call(&db,MEMBER,"get_record",json!({"ids":bootstrap_rows.iter().map(|r|r["id"].clone()).collect::<Vec<_>>(),"children_limit":0,"links_limit":0})).await;
        let bootstrap_interpretations = source_world_get["records"]
            .as_array()
            .expect("source world identity/interpretation")
            .iter()
            .map(|r| {
                assert_eq!(r["status"], "found");
                let interpreted = r
                    .get("lifecycle_interpretation")
                    .expect("source world full interpretation");
                lifecycle_carrier(interpreted);
                (r["id"].as_str().unwrap().to_owned(), interpreted.clone())
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let world_items=bootstrap_rows.iter().map(|row| {
            let id=row["id"].as_str().unwrap();
            assert!(id.len()<=256);assert!(row["name"].as_str().unwrap().chars().count()<=160);
            assert!(row["kind"].is_null() || row["kind"].as_str().unwrap().chars().count()<=64);
            let mut item=json!({"id":id,"name":row.get("name").expect("source world name"),"name_truncated":false,"type":row.get("type").expect("source world type"),"kind":row.get("kind").expect("source world kind"),"kind_truncated":false,"lifecycle_interpretation":bootstrap_interpretations[id],"last_activity_at":row.get("observed_activity_at").expect("source world activity")});
            let successor=if id==dashboard_ids["active"] {Some((&dashboard_successor,&dashboard_successor_reference))}else if id==lexical_ids["exact"] {Some((&search_successor,&lexical_references[&search_successor]))}else{None};
            // The main document is older than this bounded fixture window;
            // known actual visible source edges in the window are explicit.
            if let Some((successor,reference))=successor {item["superseded_by"]=json!({"items":[{"id":successor,"display_reference":reference}],"total_count":1});}
            assert!(serde_json::to_vec(&item).unwrap().len()<=1024);
            item
        }).collect::<Vec<_>>();
        let bootstrap_open = world_items
            .iter()
            .filter(|item| {
                item["type"] == "WorkItem"
                    && item["lifecycle_interpretation"]["status"] == "governed"
                    && item["lifecycle_interpretation"]["terminality"] == "open"
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(bootstrap_open.len(), 1);
        assert_eq!(bootstrap_open[0]["id"], dashboard_ids["active"]);
        let expected_world = json!({"freshness":"point-in-time slice preview; activity may have changed since the cut","scope":"bounded preview over the admitted member slice, not a complete dashboard or claim of omniscience","scan_limit":64,"scan_truncated":true,
            "recent_activity":{"items":world_items.iter().take(3).cloned().collect::<Vec<_>>(),"total_count":64,"limit":3,"truncated":true},
            "open_work":{"items":bootstrap_open,"total_count":1,"limit":2,"truncated":true},
            "resumability":{"assessed":false,"reason":"Bootstrap does not infer same-agent resumability from lifecycle alone; set_intent owns the purpose-relative resume briefing."},"omitted_unrepresentable_count":0});
        let bootstrap_counts=call(&db,MEMBER,"query_sql",json!({"sql":"SELECT COUNT(*) AS n FROM records r WHERE r.deleted_at IS NULL AND r.archived=0 AND NOT (r.type='Annotation' AND COALESCE(r.kind,'') IN ('attribution','acknowledgement','comment','suggestion','citation')) AND NOT (r.type='Entity' AND r.kind IS 'semantic-unit')"})).await["rows"][0]["n"].as_i64().unwrap();
        let bootstrap_people=call(&db,MEMBER,"query_sql",json!({"sql":"SELECT COUNT(DISTINCT r.id) AS n FROM records r JOIN bindings b ON b.record_id=r.id WHERE r.deleted_at IS NULL AND r.archived=0 AND r.type='Entity' AND r.kind='person' AND b.system='account' AND b.is_canonical=1"})).await["rows"][0]["n"].as_i64().unwrap();
        assert_eq!(
            bootstrap_people, 1,
            "caller-selected Person binding, never a directory roster"
        );
        let first = produce_ordinal(&db, MEMBER, dir.path(), 1).await;
        metadata_performance_proof::same_cut_metadata(&db, &first).await;
        let offered = dir.path().join("offered.db");
        first.persist(&offered).unwrap();
        let offered_bytes = std::fs::read(&offered).unwrap();
        for private in [
            "n3-preview-private",
            "malformed private schema",
            "Synthetic private structure payload",
            "Synthetic private search payload",
            "Synthetic private bootstrap instruction",
        ] {
            assert!(
                !offered_bytes
                    .windows(private.len())
                    .any(|bytes| bytes == private.as_bytes()),
                "private schema payload must not ship: {private}"
            );
        }
        let (physical_catalog, physical_ddl, physical_user_version) = {
            let offered_connection =
                Connection::open_with_flags(&offered, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let mut source_paths = BTreeSet::new();
            for (_, online) in &get_reads {
                for record in online["records"]
                    .as_array()
                    .expect("native source get rows")
                {
                    let id = record["id"].as_str().expect("source record id");
                    let expected = record
                        .get("containment_path_visible")
                        .expect("actual native path fact")
                        .as_bool()
                        .expect("path fact is boolean");
                    source_paths.insert(expected);
                    let selected:i64=offered_connection.query_row("SELECT containment_path_visible FROM member_record_metadata WHERE record_id=?1",[id],|row|row.get(0)).unwrap();
                    assert_eq!(
                        selected,
                        i64::from(expected),
                        "actual source path boolean is held on that exact selected record"
                    );
                }
            }
            assert_eq!(source_paths,BTreeSet::from([false,true]),"fixture covers actual native rooted records and the Direct's unfiled path, not an all-true default");
            let mut selected_owner_ids = BTreeSet::new();
            for (_, selected_owner) in facet_owners.values() {
                let id = selected_owner
                    .as_str()
                    .expect("captured selected owner record ID");
                let count: i64 = offered_connection
                    .query_row("SELECT COUNT(*) FROM records WHERE id=?1", [id], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(
                    count, 1,
                    "every captured selected owner closes over exactly one held record"
                );
                selected_owner_ids.insert(id);
            }
            for principal in &facet_raw_owners {
                if !selected_owner_ids.contains(principal.as_str()) {
                    let count: i64 = offered_connection
                        .query_row(
                            "SELECT COUNT(*) FROM records WHERE id=?1",
                            [principal],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert_eq!(
                        count, 0,
                        "distinct witnessed raw principals are not held ordinary records"
                    );
                }
            }
            // A visible saved-query facet explicitly authors private IDs as
            // input. That string is not a copied private identity/schema row.
            let authored_reference: bool = offered_connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM facet_values WHERE key='query' AND instr(value,?1)>0)",
                [&hidden_collection_member[1]], |row| row.get(0),
            ).unwrap();
            assert!(
                authored_reference,
                "fixture retains the actual caller-visible authored query reference"
            );
            for query in [
                "SELECT COUNT(*) FROM records WHERE id=?1",
                "SELECT COUNT(*) FROM member_record_metadata WHERE record_id=?1",
                "SELECT COUNT(*) FROM schema_config WHERE applies_to_collection_id=?1",
            ] {
                let count: i64 = offered_connection
                    .query_row(query, [&hidden_collection_member[1]], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    count, 0,
                    "private record, metadata and scoped schema rows must not ship"
                );
            }
            for query in [
                "SELECT COUNT(*) FROM records WHERE id=?1",
                "SELECT COUNT(*) FROM member_record_metadata WHERE record_id=?1",
            ] {
                let count: i64 = offered_connection
                    .query_row(query, [&dashboard_private], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    count, 0,
                    "private dashboard endpoint never enters the admitted closure"
                );
            }
            let source_context: String = offered_connection
                .query_row(
                    "SELECT source_context FROM main.member_context",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                source_context, "null",
                "fresh native has no selected legacy association"
            );
            let (principal, sources): (String, String) = offered_connection
                .query_row(
                    "SELECT principal,instruction_source_ids FROM main.member_context",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Json>(&principal).unwrap(),
                native_bootstrap["principal"]
            );
            let ordinary_root_count: i64 = offered_connection
                .query_row(
                    "SELECT COUNT(*) FROM main.records WHERE id IN ('kernel:root','native:root')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                ordinary_root_count, 0,
                "virtual authorization is not an inserted domain record"
            );
            let raw: String = offered_connection
                .query_row("SELECT virtual_root FROM main.member_context", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let selected: Json = serde_json::from_str(&raw).unwrap();
            let mut expected = native_root_tree["nodes"][0]
                .as_object()
                .expect("actual online virtual root")
                .clone();
            expected.remove("depth").expect("online root depth");
            expected
                .remove("child_count")
                .expect("online dynamic child count");
            expected.insert("kernel_root_id".into(), json!(KERNEL_ROOT_ID));
            expected.insert("virtual_root".into(), json!(true));
            assert_eq!(
                selected,
                Json::Object(expected),
                "only exact authorized descriptor/custody/path facts are captured"
            );
            let sources: Vec<String> = serde_json::from_str(&sources).unwrap();
            assert_eq!(
                sources
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>(),
                [bootstrap_shared.clone(), bootstrap_empty.clone()]
                    .into_iter()
                    .collect()
            );
            for query in [
                "SELECT COUNT(*) FROM records WHERE id=?1",
                "SELECT COUNT(*) FROM member_record_metadata WHERE record_id=?1",
            ] {
                assert_eq!(
                    offered_connection
                        .query_row(query, [&bootstrap_private], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    0
                );
            }
            let rows = offered_connection.prepare("SELECT name,sql FROM main.sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name").unwrap()
                .query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).unwrap()
                .collect::<std::result::Result<Vec<_>,_>>().unwrap();
            let mut catalog = Vec::new();
            let mut ddl = Vec::new();
            for (table, sql) in rows {
                let escaped = table.replace('"', "\"\"");
                let columns = offered_connection.prepare(&format!("PRAGMA main.table_xinfo(\"{escaped}\")")).unwrap()
                    .query_map([], |row| Ok(json!({"name":row.get::<_,String>(1)?,"type":row.get::<_,String>(2)?,"notnull":row.get::<_,i64>(3)?!=0,"pk":row.get::<_,i64>(5)?!=0}))).unwrap()
                    .collect::<std::result::Result<Vec<_>,_>>().unwrap();
                let columns = columns
                    .into_iter()
                    .map(|mut column| {
                        if let Some(metadata) = crate::schema::discovery::column_semantics(
                            &table,
                            column["name"].as_str().unwrap(),
                        ) {
                            column
                                .as_object_mut()
                                .unwrap()
                                .extend(metadata.as_object().unwrap().clone());
                        }
                        column
                    })
                    .collect::<Vec<_>>();
                assert!(
                    !columns.is_empty(),
                    "actual held physical tables have columns"
                );
                catalog.push(json!({"name":table,"role":"immutable member-profile projection or verification metadata; not canonical authority","columns":columns}));
                ddl.push(sql);
            }
            let version: i64 = offered_connection
                .pragma_query_value(Some(rusqlite::DatabaseName::Main), "user_version", |row| {
                    row.get(0)
                })
                .unwrap();
            (catalog, ddl, version)
        };
        let json = serde_json::to_vec(first.manifest()).unwrap();
        let context = context(MEMBER, first.manifest());
        let open = || {
            MemberCopyServing::open_unbound_routed(
                &root,
                Some(first.manifest().origin_database_id.clone()),
                "https://example.invalid".into(),
                "route-test".into(),
                test_consumer(),
            )
        };
        let mut owner = open().await.unwrap();
        owner
            .sign_in(
                MEMBER,
                ReconnectAnswer::Replace {
                    cut_at: first.manifest().captured_at.clone(),
                },
            )
            .await
            .unwrap();
        owner.bind_scope(&context).unwrap();
        owner
            .admit_candidate(&offered, &json, &context)
            .await
            .unwrap();
        assert!(
            owner.database().is_none(),
            "native files never acquire a v1 Db"
        );
        let registry = || {
            let mut r = ToolRegistry::new();
            crate::mcp::register_builtin_tools(&mut r).unwrap();
            crate::mcp::register_surface_tools(&mut r).unwrap();
            r
        };
        let reader = MemberServedSnapshot::from_serving(&owner, registry()).unwrap();
        let request = |name: &str, arguments: Json| json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}});
        let listed = reader
            .dispatch(request(
                "manage_attachments",
                json!({"action":"list","record_id":id,"format":"json"}),
            ))
            .await
            .unwrap();
        let record = reader
            .dispatch(request("get_record", json!({"ids":[id],"format":"json"})))
            .await
            .unwrap();
        assert_eq!(
            record["result"]["structuredContent"]["records"][0]["body"],
            "synthetic admitted body"
        );
        for (arguments, online) in &get_reads {
            let mut arguments = arguments.clone();
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("get_record", arguments))
                .await
                .unwrap();
            assert_get_member_parity(
                &got["result"]["structuredContent"],
                online,
                &child_references,
                &source_links,
            );
        }
        for (arguments, expected) in &resolution_cases {
            for modern in [false, true] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut request = request("resolve_many", arguments);
                if modern {
                    request["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(request).await.unwrap();
                let mut value = got["result"]["structuredContent"].clone();
                let footing = value
                    .as_object_mut()
                    .expect("resolve_many response object")
                    .remove("standby_context")
                    .expect("member footing");
                assert_eq!(
                    footing,
                    serde_json::to_value(&first.manifest().holding).unwrap()
                );
                assert_eq!(
                    &value, expected,
                    "member resolve_many modern={modern}: {got}"
                );
            }
        }
        let bootstrap_holding = serde_json::to_value(&first.manifest().holding).unwrap();
        let bootstrap_key = "scout-chair-a748b2";
        let mut held_bootstrap = None;
        for modern in [true, false] {
            let mut message = request(
                "bootstrap",
                json!({"run_key":bootstrap_key,"format":"json"}),
            );
            if modern {
                message["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
            }
            let before = chrono::Utc::now();
            let got = reader.dispatch(message).await.unwrap();
            let after = chrono::Utc::now();
            let value = got["result"]
                .get("structuredContent")
                .expect("native member bootstrap");
            let normalized = assert_native_member_bootstrap(
                value,
                &native_bootstrap,
                &expected_world,
                (bootstrap_counts, bootstrap_people),
                &bootstrap_holding,
                (before, after),
                Some(bootstrap_key),
            );
            if let Some(prior) = &held_bootstrap {
                assert_eq!(&normalized,prior,"full bootstrap envelope across modern/legacy, only strictly validated wall clock differs");
            } else {
                held_bootstrap = Some(normalized);
            }
            assert!(!value
                .to_string()
                .contains("Synthetic private bootstrap instruction"));
            assert!(!value.to_string().contains(&bootstrap_private));
            assert!(!value["current_world"]
                .to_string()
                .contains(&bootstrap_empty));
            let instruction_ids = value["instructions"]["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["source"]["record_id"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(instruction_ids, vec![bootstrap_shared.as_str()]);
            let list = reader
                .dispatch(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
                .await
                .unwrap();
            assert_eq!(
                value["tool_exposure"]["advertised_count"],
                list["result"]["tools"].as_array().unwrap().len()
            );
            let continuation = value["roots"]
                .get("continuation")
                .expect("generated root continuation");
            assert_eq!(continuation["tool"], "get_structure");
            let mut continuation_args = continuation.get("arguments").expect("root args").clone();
            continuation_args["format"] = json!("json");
            let mut continuation_request = request("get_structure", continuation_args);
            if modern {
                continuation_request["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
            }
            let continued = reader.dispatch(continuation_request).await.unwrap();
            let continued = continued["result"]
                .get("structuredContent")
                .expect("generated virtual root continuation executes");
            assert_structure_member_parity(
                continued,
                &native_root_tree,
                &bootstrap_holding,
                &tree_successions,
            );
            assert!(!continued.to_string().contains(&tree_private));
            assert!(!continued.to_string().contains(&bootstrap_private));
            let alias = reader.dispatch(request("get_structure",json!({"root_id":KERNEL_ROOT_ID,"max_depth":1,"max_children_per_node":2,"format":"json"}))).await.unwrap();
            assert_structure_member_parity(
                alias["result"]
                    .get("structuredContent")
                    .expect("kernel alias proof"),
                &native_kernel_root_tree,
                &bootstrap_holding,
                &tree_successions,
            );
            let next = value["next_steps"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["tool"] == "query_sql")
                .unwrap();
            let mut args = next["arguments"].clone();
            args["format"] = json!("json");
            let next_result = reader.dispatch(request("query_sql", args)).await.unwrap();
            assert_eq!(
                next_result["result"]["isError"], false,
                "generated next step executes: {next_result}"
            );
            assert_eq!(
                next_result["result"]["structuredContent"]["run_context"]["run_key"],
                bootstrap_key
            );
            let get=reader.dispatch(request("get_record",json!({"ids":[id],"run_key":bootstrap_key,"parent_key":bootstrap_key,"format":"json"}))).await.unwrap();
            assert_eq!(get["result"]["structuredContent"]["records"][0]["id"], id);
            let actor=reader.dispatch(request("query_sql",json!({"sql":"SELECT current_principal() AS actor","run_key":bootstrap_key,"parent_key":bootstrap_key,"format":"json"}))).await.unwrap();
            assert_eq!(
                actor["result"]["structuredContent"]["rows"][0]["actor"],
                member_principal
            );
        }
        for raw in [
            None,
            Some(Json::Null),
            Some(json!("new")),
            Some(json!("new:scout-chair")),
            Some(json!("malformed key")),
            Some(json!(7)),
        ] {
            let args = match &raw {
                None => json!({"format":"json"}),
                Some(raw) => json!({"run_key":raw,"parent_key":"new","format":"json"}),
            };
            let before = chrono::Utc::now();
            let got = reader.dispatch(request("bootstrap", args)).await.unwrap();
            let after = chrono::Utc::now();
            let value = got["result"]
                .get("structuredContent")
                .expect("bootstrap suppressed issuance/correlation contract");
            assert_native_member_bootstrap(
                value,
                &native_bootstrap,
                &expected_world,
                (bootstrap_counts, bootstrap_people),
                &bootstrap_holding,
                (before, after),
                None,
            );
            if let Some(raw) = &raw {
                if let Some(note) = crate::runkey::validate_value(Some(raw)).note() {
                    assert!(
                        value["run_context"]["notes"]
                            .as_array()
                            .unwrap()
                            .contains(&json!(note)),
                        "malformed explicit key diagnostic is retained"
                    );
                }
                let note = crate::runkey::validate_parent_key_value(Some(&json!("new")))
                    .parent_note()
                    .unwrap();
                assert!(value["run_context"]["notes"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(note)));
            }
        }
        for (tool, args) in [
            (
                "bootstrap",
                json!({"principal_id":owner_principal,"run_key":bootstrap_key}),
            ),
            (
                "get_record",
                json!({"id":id,"principal_id":owner_principal,"run_key":bootstrap_key}),
            ),
            (
                "query_sql",
                json!({"sql":"SELECT current_principal() AS actor","principal_id":owner_principal,"run_key":bootstrap_key}),
            ),
        ] {
            let got = reader.dispatch(request(tool, args)).await.unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "forged principal is not caller authority: {got}"
            );
        }
        assert_eq!(
            source_before_bootstrap,
            kernel::dump_all_kernel_tables(&db).await.unwrap(),
            "member bootstrap, correlation and generated reads never write the source"
        );
        for arguments in [
            json!({"names":[]}),
            json!({"names":vec!["x";101]}),
            json!({"names":[""]}),
            json!({"names":["x".repeat(513)]}),
            json!({"names":["Offline journey"],"type":"NotASpineType"}),
            json!({"names":["Offline journey"],"kind":""}),
            json!({"names":["Offline journey"],"ids":[id]}),
        ] {
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("resolve_many", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "existing strict resolver parser/bounds: {got}"
            );
        }
        for (arguments, online) in &archive_queries {
            let mut arguments = arguments.clone();
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("query_record", arguments))
                .await
                .unwrap();
            let value = &got["result"]["structuredContent"];
            assert_eq!(
                value.get("total").expect("member archive total"),
                online.get("total").expect("native archive total")
            );
            let ids = |value: &Json| {
                value
                    .get("records")
                    .expect("archive rows")
                    .as_array()
                    .expect("archive record array")
                    .iter()
                    .map(|r| r.get("id").expect("archive row id").clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                ids(value),
                ids(online),
                "actual native/member archive query: {got}"
            );
        }
        // ancestor_id is an existing member pipeline surface. Native online
        // has no equivalent handler option; pin the held hierarchy contract.
        for include in [false, true] {
            let got = reader.dispatch(request("query_record",json!({"steps":[{"step":"filter","ancestor_id":archived,"include_archived":include}],"format":"json"}))).await.unwrap();
            assert_eq!(
                got["result"]["structuredContent"]["total"],
                if include { 1 } else { 0 },
                "member archived subtree: {got}"
            );
            let rows = got["result"]["structuredContent"]["records"]
                .as_array()
                .expect("member subtree rows");
            assert_eq!(rows.len(), usize::from(include));
            if include {
                assert_eq!(rows[0]["id"], archived);
            }
        }
        let search_paths = |mut row: Json| {
            let record = row["id"].as_str().expect("lexical record id").to_owned();
            let reference = lexical_references
                .get(&record)
                .expect("source-selected lexical reference");
            row["display_reference"] = json!(reference);
            row["record_path"] = json!(format!("/{reference}"));
            row["record_path_full"] = json!(format!("/{record}"));
            row
        };
        let search_hit = |key: &str, score: f64, snippet: &str, strict: bool| {
            let source = &lexical_rows[&lexical_ids[key]];
            assert_eq!(source["type"], "Document");
            assert_eq!(source["kind"], "note");
            assert_eq!(source["home_id"], search_root);
            let mut hit = search_paths(
                json!({"id":source["id"],"type":source["type"],"kind":source["kind"],"name":source["name"],"home_id":source["home_id"],"score":score,"snippet":snippet}),
            );
            if strict && key == "exact" {
                hit["superseded_by"] = json!({"items":[{"id":search_successor,"name":"Search successor","display_reference":lexical_references[&search_successor]}],"total_count":1});
            }
            hit
        };
        let sibling = {
            let source = &lexical_rows[&lexical_ids["sibling"]];
            search_paths(
                json!({"id":source["id"],"type":source["type"],"kind":source["kind"],"name":source["name"],"home_id":source["home_id"]}),
            )
        };
        let exact = search_hit("exact", -31.0, "[n3quartz]", true);
        let title = search_hit("title", -15.0, "quiet", true);
        let body = search_hit("body", -2.0, "[n3quartz] [n3quartz]", true);
        let archive = search_hit("archive", -15.0, "quiet", true);
        let prefix = search_hit("prefix", -15.0, "n3quartzlater", false);
        let infix = search_hit("infix", 0.0, "Midn3quartzCase", false);
        let reformulate=" Consider reformulating: try synonyms or alternative phrasings, fewer or more specific terms, or query_record for structured filtering.";
        let near_guidance=" Near-miss candidates are listed under 'near_misses' — name_prefix (typed-prefix neighbours), name_infix (mid-word name matches, e.g. camelCase identifiers), and tree_siblings (records adjacent to the hits).";
        let build_search = |query: &str,
                            scope: Option<&str>,
                            limit: i64,
                            hits: Vec<Json>,
                            near: Option<Json>,
                            capped: bool,
                            guidance: String| {
            let mut output = json!({"query":query,"scope":scope,"hits":hits,"total":hits.len(),"returned":hits.len(),"limit":limit,"limit_reached":capped,"thin":near.is_some(),"guidance":guidance,"standby_context":serde_json::to_value(&first.manifest().holding).unwrap()});
            if let Some(near) = near {
                output["near_misses"] = near;
            }
            output
        };
        let near = json!({"name_prefix":[prefix],"name_infix":[infix],"tree_siblings":[sibling]});
        let mut search_cases = Vec::new();
        for scope in [None, Some(search_root.as_str())] {
            search_cases.push((json!({"query":"n3quartz","scope":scope}),build_search("n3quartz",scope,20,vec![exact.clone(),title.clone(),body.clone()],Some(near.clone()),false,format!("Only 3 full-text match(es) for \"n3quartz\" — likely not exhaustive.{reformulate}{near_guidance}"))));
        }
        search_cases.push((json!({"query":"n3quartz","scope":search_root,"include_archived":true}),build_search("n3quartz",Some(&search_root),20,vec![exact.clone(),archive.clone(),title.clone(),body.clone()],Some(near.clone()),false,format!("Only 4 full-text match(es) for \"n3quartz\" — likely not exhaustive.{reformulate}{near_guidance}"))));
        search_cases.push((json!({"query":"n3quartz","scope":search_root,"limit":1}),build_search("n3quartz",Some(&search_root),1,vec![exact.clone()],None,true,"This list may be incomplete. Use query_record with a filter step (types, kinds, ancestor_id, lifecycle) for a narrow, exhaustive answer.".into())));
        search_cases.push((json!({"query":"n3quartz","scope":search_root,"limit":999}),build_search("n3quartz",Some(&search_root),200,vec![exact.clone(),title.clone(),body.clone()],Some(near.clone()),false,format!("Only 3 full-text match(es) for \"n3quartz\" — likely not exhaustive.{reformulate}{near_guidance}"))));
        search_cases.push((json!({"query":"n3quart","scope":search_root}),build_search("n3quart",Some(&search_root),20,vec![],Some(json!({"name_prefix":[search_hit("exact",-16.0,"n3quartz",false),search_hit("title",-15.0,"n3quartz guide",false),search_hit("prefix",-15.0,"n3quartzlater",false)],"name_infix":[infix.clone()],"tree_siblings":[]})),false,format!("No full-text matches for \"n3quart\".{reformulate}{near_guidance}"))));
        for (query, near, extra) in [
            (
                "n3quartzCas",
                json!({"name_prefix":[],"name_infix":[infix.clone()],"tree_siblings":[]}),
                near_guidance,
            ),
            (
                "!!!",
                json!({"name_prefix":[],"name_infix":[],"tree_siblings":[]}),
                "",
            ),
        ] {
            search_cases.push((
                json!({"query":query,"scope":search_root}),
                build_search(
                    query,
                    Some(&search_root),
                    20,
                    vec![],
                    Some(near),
                    false,
                    format!("No full-text matches for {query:?}.{reformulate}{extra}"),
                ),
            ));
        }
        search_cases.push((json!({"query":"n3quartz","scope":lexical_references[&search_root]}),build_search("n3quartz",Some(&search_root),20,vec![exact.clone(),title.clone(),body.clone()],Some(near.clone()),false,format!("Only 3 full-text match(es) for \"n3quartz\" — likely not exhaustive.{reformulate}{near_guidance}"))));
        let mut held_searches = Vec::new();
        for (arguments, expected) in &search_cases {
            for modern in [false, true] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut message = request("search", arguments.clone());
                if modern {
                    message["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(message).await.unwrap();
                let value = got["result"]
                    .get("structuredContent")
                    .expect("member lexical contract");
                assert_eq!(value,expected,"exact existing member lexical response/ranking/guidance modern={modern}: {got}");
                assert!(!value.to_string().contains(&search_private));
                assert!(!value.to_string().contains(&search_comment));
                if modern {
                    held_searches.push((arguments, expected.clone()));
                }
            }
        }
        for arguments in [
            json!({"query":""}),
            json!({"query":"  "}),
            json!({"query":"n3quartz","limit":0}),
            json!({"query":"n3quartz","limit":-1}),
            json!({"query":"n3quartz","limit":"1"}),
            json!({"query":"n3quartz","extra":true}),
            json!({"query":"n3quartz","scope":search_private}),
            json!({"query":"n3quartz","scope":"missing lexical scope"}),
            json!({"query":"n3quartz","scope":"c01dcaf"}),
        ] {
            let got = reader.dispatch(request("search", arguments)).await.unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "existing lexical parser/visibility/ref refusal: {got}"
            );
        }
        let dashboard_entry = |key: &str, succession: bool| {
            let record = &dashboard_ids[key];
            let source = &dashboard_rows[record];
            let mut entry = json!({"id":record,"type":source.get("type").expect("source type"),"kind":source.get("kind").expect("source kind"),"name":source.get("name").expect("source name"),"lifecycle_interpretation":dashboard_interpretations[record],"maturity":source.get("maturity").expect("source maturity"),"last_activity_at":source.get("last_activity_at").expect("source activity")});
            if succession {
                entry["superseded_by"] = json!({"items":[{"id":dashboard_successor,"name":"Dashboard successor","display_reference":dashboard_successor_reference}],"total_count":1});
            }
            entry
        };
        let newest_first = |keys: &mut Vec<&str>| {
            keys.sort_by(|a, b| {
                let a = &dashboard_rows[&dashboard_ids[a]];
                let b = &dashboard_rows[&dashboard_ids[b]];
                b["last_activity_at"]
                    .as_str()
                    .unwrap()
                    .cmp(a["last_activity_at"].as_str().unwrap())
                    .then(a["id"].as_str().unwrap().cmp(b["id"].as_str().unwrap()))
            })
        };
        let mut held_dashboards = Vec::new();
        for (arguments, limit, days, single) in [
            (json!({"scope":dashboard_root}), 20, 14, false),
            (json!({"scope":dashboard_root,"limit":1}), 1, 14, false),
            (
                json!({"scope":dashboard_reference,"stale_after_days":1,"limit":100}),
                100,
                1,
                false,
            ),
            (json!({"scope":dashboard_ids["active"]}), 20, 14, true),
        ] {
            let mut active_keys = if single {
                vec!["active"]
            } else {
                vec!["active", "unclassified"]
            };
            newest_first(&mut active_keys);
            // Source witnesses bracket both sides of the threshold by years;
            // validate that fixture fact against the actual live clock.
            let now = chrono::Utc::now();
            for key in &active_keys {
                assert!(
                    chrono::DateTime::parse_from_rfc3339(
                        dashboard_rows[&dashboard_ids[*key]]["last_activity_at"]
                            .as_str()
                            .unwrap()
                    )
                    .unwrap()
                    .timestamp_millis()
                        > (now - chrono::Duration::days(1)).timestamp_millis()
                );
            }
            for key in ["oldest", "older"] {
                assert!(
                    chrono::DateTime::parse_from_rfc3339(
                        dashboard_rows[&dashboard_ids[key]]["last_activity_at"]
                            .as_str()
                            .unwrap()
                    )
                    .unwrap()
                    .timestamp_millis()
                        < (now - chrono::Duration::days(14)).timestamp_millis()
                );
            }
            let active = active_keys
                .iter()
                .take(limit)
                .map(|key| dashboard_entry(key, *key == "active"))
                .collect::<Vec<_>>();
            let stale = if single {
                vec![]
            } else {
                ["oldest", "older"]
                    .iter()
                    .take(limit)
                    .map(|key| dashboard_entry(key, false))
                    .collect::<Vec<_>>()
            };
            let mut blocked_keys = if single {
                vec!["active"]
            } else {
                vec!["active", "done", "waiting"]
            };
            newest_first(&mut blocked_keys);
            let blocked = blocked_keys
                .iter()
                .take(limit)
                .map(|key| {
                    let mut entry = dashboard_entry(key, *key == "active");
                    entry["blocked_by"] = match *key {
                        "active" => json!([{"id":dashboard_external,"relationship":"blocks"}]),
                        "done" => json!([{"id":dashboard_ids["older"],"relationship":"blocks"}]),
                        "waiting" => json!([]),
                        _ => panic!("unknown expected dashboard row"),
                    };
                    entry["waiting_on"] = if *key == "waiting" {
                        json!([{"id":dashboard_ids["older"],"relationship":"depends_on"}])
                    } else {
                        json!([])
                    };
                    entry
                })
                .collect::<Vec<_>>();
            let unclassified = if single {
                vec![]
            } else {
                let mut entry = dashboard_entry("unclassified", false);
                entry["reason"] = json!("no_governing_vocabulary");
                vec![entry]
            };
            let census = if single {
                json!({"shape":"counts","total":1,"buckets":[{"key":"open","count":1}]})
            } else {
                json!({"shape":"counts","total":9,"buckets":[{"key":null,"count":4},{"key":"open","count":3},{"key":"done","count":1},{"key":"mystery","count":1}]})
            };
            let expected = json!({"scope":if single {dashboard_ids["active"].clone()}else{dashboard_root.clone()},"stale_after_days":days,"limit":limit,"active":active,"active_total":if single{1}else{2},"stale":stale,"stale_total":if single{0}else{2},"blocked":blocked,"blocked_total":if single{1}else{3},"unclassified_lifecycle":{"note":"Diagnostic census, not a bucket: these records are ALSO reported in `active` or `stale`, bucketed on `last_activity_at` alone, because an uninterpretable lifecycle is a governance gap rather than evidence that the work is finished. Each entry names why interpretation failed.","items":unclassified,"total_count":if single{0}else{1},"truncated":false},"lifecycle_census":census,"claims":{"unavailable_offline":{"surface":"get_dashboard.claims","retry":"when_online"}},"runs":{"unavailable_offline":{"surface":"get_dashboard.runs","retry":"when_online"}},"standby_context":serde_json::to_value(&first.manifest().holding).unwrap()});
            for modern in [true, false] {
                let mut args = arguments.clone();
                args["format"] = json!("json");
                let mut message = request("get_dashboard", args);
                if modern {
                    message["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let before = chrono::Utc::now();
                let got = reader.dispatch(message).await.unwrap();
                let after = chrono::Utc::now();
                let value = got["result"]
                    .get("structuredContent")
                    .expect("member dashboard response");
                assert_eq!(dashboard_without_clock(value,before,after,days),expected,"full existing member dashboard contract modern={modern} arguments={arguments}: {got}");
                assert!(!value.to_string().contains(&dashboard_private));
                assert!(!value
                    .to_string()
                    .contains("Synthetic private dashboard payload"));
                let rendered = crate::mcp::render::render("get_dashboard", value)
                    .expect("existing dashboard text renderer");
                for section in ["get_dashboard.claims", "get_dashboard.runs"] {
                    assert!(rendered.contains(section));
                }
            }
            held_dashboards.push((arguments, expected, days));
        }
        for arguments in [
            json!({"scope":dashboard_private}),
            json!({"scope":"missing dashboard scope"}),
            json!({"scope":"c01dcaf"}),
            json!({"scope":dashboard_ids["archived"]}),
            json!({"scope":dashboard_root,"limit":0}),
            json!({"scope":dashboard_root,"limit":101}),
            json!({"scope":dashboard_root,"limit":-1}),
            json!({"scope":dashboard_root,"limit":"1"}),
            json!({"scope":dashboard_root,"stale_after_days":0}),
            json!({"scope":dashboard_root,"stale_after_days":36501}),
            json!({"scope":dashboard_root,"extra":true}),
        ] {
            let got = reader
                .dispatch(request("get_dashboard", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "dashboard parser/scope refusal arguments={arguments}: {got}"
            );
        }
        let scan_sample = |record: &str, evidence: Json| {
            let source = lexical_rows
                .get(record)
                .expect("authorised source sample row");
            let mut sample = json!({"id":record,"type":source["type"],"name":source["name"],"lifecycle_interpretation":scan_interpretations[record]});
            sample.as_object_mut().unwrap().extend(
                evidence
                    .as_object()
                    .expect("explicit metric evidence")
                    .clone(),
            );
            if record == lexical_ids["exact"] {
                sample["superseded_by"] = json!({"items":[{"id":search_successor,"name":"Search successor","display_reference":lexical_references[&search_successor]}],"total_count":1});
            }
            search_paths(sample)
        };
        // Literal member counts/qualities, with only sample timestamp order
        // taken from actual source heads. No nonexistent online scan oracle.
        let scan_cases = vec![
            json!({"scope":search_root,"query":"n3quartz","high_degree_min":1}),
            json!({"scope":search_root,"query":"n3quartz","high_degree_min":1,"include_archived":true}),
            json!({"scope":search_root,"query":"n3quartz","types":["Document"],"high_degree_min":1,"recent_window_days":1}),
            json!({"scope":search_root}),
            json!({"scope":search_root,"query":"n3quartz","types":["Collection"],"high_degree_min":1}),
            json!({"scope":lexical_references[&search_root],"authored_by":member_principal}),
            json!({"scope":search_root,"query":"n3quartz","types":["NotASpineType"]}),
        ];
        let mut held_scans = Vec::new();
        for (case, arguments) in scan_cases.into_iter().enumerate() {
            let include_archive = case == 1;
            let documents = case != 4 && case != 6;
            let collections = case != 2 && case != 6;
            let corpus_size = match case {
                1 => 8,
                2 => 6,
                4 => 1,
                6 => 0,
                _ => 7,
            };
            let days = if case == 2 { 1 } else { 14 };
            let minimum = if [0, 1, 2, 4].contains(&case) { 1 } else { 8 };
            let lexical = matches!(case, 0 | 1 | 2 | 4 | 6);
            let marker = |surface: &str| json!({"unavailable_offline":{"surface":surface,"retry":"when_online"}});
            let mut types = vec![];
            let mut kinds = vec![];
            if documents {
                types.push(json!({"key":"Document","count":if include_archive{7}else{6}}));
                kinds.push(json!({"key":"note","count":if include_archive{7}else{6}}));
            }
            if collections {
                types.push(json!({"key":"Collection","count":1}));
                kinds.push(json!({"key":"folder","count":1}));
            }
            let census = json!({"by_type":{"shape":"counts","total":corpus_size,"buckets":types},"by_kind":{"shape":"counts","total":corpus_size,"buckets":kinds},"by_lifecycle":{"shape":"counts","total":corpus_size,"buckets":if corpus_size==0 {vec![]}else{vec![json!({"key":null,"count":corpus_size})]}},"provenance":marker("scan.provenance")});
            let mut recent_ids = lexical_ids
                .values()
                .filter(|record| {
                    documents && (include_archive || **record != lexical_ids["archive"])
                })
                .cloned()
                .collect::<Vec<_>>();
            if collections {
                recent_ids.push(search_root.clone());
            }
            assert_eq!(recent_ids.len(), corpus_size);
            for record in &recent_ids {
                let time = chrono::DateTime::parse_from_rfc3339(
                    lexical_rows[record]["last_activity_at"]
                        .as_str()
                        .expect("actual source activity"),
                )
                .unwrap();
                assert!(
                    time > chrono::Utc::now() - chrono::Duration::days(1),
                    "fixture source heads are actually recent for every selected window"
                );
            }
            recent_ids.sort_by(|a, b| {
                lexical_rows[b]["last_activity_at"]
                    .as_str()
                    .unwrap()
                    .cmp(lexical_rows[a]["last_activity_at"].as_str().unwrap())
                    .then(a.cmp(b))
            });
            let recent_head = recent_ids.iter().take(3).cloned().collect::<Vec<_>>();
            let recent_samples = recent_head
                .iter()
                .map(|record| {
                    scan_sample(
                        record,
                        json!({"last_activity_at":lexical_rows[record]["last_activity_at"]}),
                    )
                })
                .collect::<Vec<_>>();
            let degree_ids = if documents && minimum == 1 {
                vec![lexical_ids["exact"].clone(), lexical_ids["title"].clone()]
            } else {
                vec![]
            };
            let degree_samples = degree_ids
                .iter()
                .enumerate()
                .map(|(i, record)| scan_sample(record, json!({"degree":if i==0{5}else{2}})))
                .collect::<Vec<_>>();
            let container_ids = if collections {
                vec![search_root.clone()]
            } else {
                vec![]
            };
            let container_samples = container_ids
                .iter()
                .map(|record| scan_sample(record, json!({"child_count":7})))
                .collect::<Vec<_>>();
            let mut axes = json!({"authored_by":marker("scan.authored_by"),"recent":{"count":corpus_size,"samples":recent_samples,"quality":if corpus_size==0{"empty"}else{"saturated"}},"high_degree":{"count":degree_ids.len(),"samples":degree_samples,"quality":if degree_ids.is_empty(){"empty"}else{"saturated"}},"containers":{"count":container_ids.len(),"samples":container_samples,"quality":if container_ids.is_empty(){"empty"}else{"saturated"}}});
            let lexical_ids_expected = if lexical && documents {
                if include_archive {
                    vec![
                        lexical_ids["exact"].clone(),
                        lexical_ids["archive"].clone(),
                        lexical_ids["title"].clone(),
                    ]
                } else {
                    vec![
                        lexical_ids["exact"].clone(),
                        lexical_ids["title"].clone(),
                        lexical_ids["body"].clone(),
                    ]
                }
            } else {
                vec![]
            };
            if lexical {
                let samples = lexical_ids_expected
                    .iter()
                    .map(|record| {
                        let (score, snippet) = if *record == lexical_ids["exact"] {
                            (-31.0, "[n3quartz]")
                        } else if *record == lexical_ids["body"] {
                            (-2.0, "[n3quartz] [n3quartz]")
                        } else {
                            (-15.0, "quiet")
                        };
                        scan_sample(record, json!({"score":score,"snippet":snippet}))
                    })
                    .collect::<Vec<_>>();
                axes["lexical"] = json!({"count":if documents{if include_archive{4}else{3}}else{0},"samples":samples,"quality":if documents{"saturated"}else{"empty"}});
                if include_archive {
                    assert_eq!(axes["lexical"]["count"], 4);
                    assert_eq!(
                        axes["lexical"]["samples"].as_array().unwrap().len(),
                        3,
                        "full pool count exceeds sample, never capped hits.len"
                    );
                }
            }
            let mut convergence = Vec::new();
            for record in [
                &search_root,
                &lexical_ids["exact"],
                &lexical_ids["title"],
                &lexical_ids["body"],
                &lexical_ids["archive"],
            ] {
                let mut memberships = Vec::new();
                if lexical_ids_expected.contains(record) {
                    memberships.push("lexical");
                }
                if recent_head.contains(record) {
                    memberships.push("recent");
                }
                if degree_ids.contains(record) {
                    memberships.push("high_degree");
                }
                if container_ids.contains(record) {
                    memberships.push("containers");
                }
                if memberships.len() < 2 {
                    continue;
                }
                let mut sample = scan_sample(record, json!({}));
                sample["axes"] = json!(memberships);
                sample["axis_count"] = json!(memberships.len());
                convergence.push(sample);
            }
            convergence.sort_by(|a, b| {
                b["axis_count"]
                    .as_u64()
                    .unwrap()
                    .cmp(&a["axis_count"].as_u64().unwrap())
                    .then(a["name"].as_str().unwrap().cmp(b["name"].as_str().unwrap()))
                    .then(a["id"].as_str().unwrap().cmp(b["id"].as_str().unwrap()))
            });
            let mut served = Vec::new();
            if lexical {
                served.push("lexical");
            }
            served.extend(["recent", "high_degree", "containers"]);
            let expected = json!({"corpus_size":corpus_size,"scope":search_root,"census":census,"axes":axes,"convergence":convergence,"thresholds":{"recent_window_days":days,"high_degree_min":minimum,"sample_limit":3,"saturation_threshold":0.1},"convergence_basis":{"kind":"served_axes","axes":served,"excluded_axes":["authored_by"]},"standby_context":serde_json::to_value(&first.manifest().holding).unwrap()});
            for modern in [false, true] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut message = request("scan", arguments.clone());
                if modern {
                    message["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let before = chrono::Utc::now();
                let got = reader.dispatch(message).await.unwrap();
                let after = chrono::Utc::now();
                let value = got["result"]
                    .get("structuredContent")
                    .expect("member scan response");
                assert_eq!(
                    scan_without_clock(value, before, after, days),
                    expected,
                    "exact member scan case={case} modern={modern}: {got}"
                );
                assert!(!value.to_string().contains(&search_private));
                assert!(!value.to_string().contains(&search_comment));
                if modern {
                    held_scans.push((arguments, expected.clone(), days));
                }
            }
        }
        for arguments in [
            json!({"scope":search_private}),
            json!({"scope":"missing scan scope"}),
            json!({"scope":"c01dcaf"}),
            json!({"scope":search_root,"recent_window_days":0}),
            json!({"scope":search_root,"recent_window_days":36501}),
            json!({"scope":search_root,"high_degree_min":0}),
            json!({"scope":search_root,"authored_by":OTHER}),
            json!({"scope":search_root,"recent_window_days":"1"}),
            json!({"scope":search_root,"extra":true}),
        ] {
            let got = reader
                .dispatch(request("scan", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "scan parser/selector/visibility refusal arguments={arguments}: {got}"
            );
            if arguments.get("authored_by").is_some() {
                assert!(got
                    .to_string()
                    .contains("scan: authored_by may name only the current caller"));
            }
        }
        let mut held_structures = Vec::new();
        for (arguments, online) in &structure_reads {
            for modern in [true, false] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut message = request("get_structure", arguments.clone());
                if modern {
                    message["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(message).await.unwrap();
                let value = got["result"]
                    .get("structuredContent")
                    .expect("member tree response");
                assert_structure_member_parity(
                    value,
                    online,
                    &serde_json::to_value(&first.manifest().holding).unwrap(),
                    &tree_successions,
                );
                assert!(!value.to_string().contains(&tree_private));
                assert!(!value.to_string().contains(&tree_private_child));
                if modern {
                    held_structures.push((arguments, value.clone()));
                }
            }
        }
        for arguments in [
            json!({"root_id":tree_private}),
            json!({"root_id":tree_private_child}),
            json!({"root_id":hidden_collection_member[1]}),
            json!({"root_id":"missing structure root"}),
            json!({"root_id":id,"max_depth":-1}),
            json!({"root_id":id,"max_children_per_node":-1}),
            json!({"root_id":id,"max_children_per_node":1001}),
            json!({"root_id":id,"exclude_types":["NotASpineType"]}),
            json!({"root_id":id,"extra":true}),
            json!({"root_id":id,"as_of":{"act":1}}),
            json!({"root_id":id,"max_depth":"1"}),
            json!({"root_id":"c01dcaf"}),
        ] {
            let got = reader
                .dispatch(request("get_structure", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "tree visibility/parser/safe-reference refusal: {got}"
            );
        }
        let safe_tree = reader
            .dispatch(request(
                "get_structure",
                json!({"root_id":source_reference,"max_depth":0,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            safe_tree["result"]["structuredContent"]["root_id"], reference_record,
            "stored source-safe reference: {safe_tree}"
        );
        let mut held_descriptions = Vec::new();
        for include_ddl in [None, Some(false), Some(true)] {
            for modern in [false, true] {
                let mut arguments = json!({"format":"json"});
                if let Some(include) = include_ddl {
                    arguments["include_ddl"] = json!(include);
                }
                let mut call = request("describe_schema", arguments.clone());
                if modern {
                    call["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(call).await.unwrap();
                assert_ne!(
                    got["result"]["isError"], true,
                    "actual member physical schema: {got}"
                );
                let value = got["result"]
                    .get("structuredContent")
                    .expect("describe structured response");
                let object = value.as_object().expect("describe object");
                let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
                keys.sort();
                let mut expected_keys = vec![
                    "logical_relations",
                    "engine",
                    "model",
                    "tables",
                    "standby_context",
                ];
                if include_ddl == Some(true) {
                    expected_keys.push("ddl_statements");
                }
                expected_keys.sort();
                assert_eq!(
                    keys, expected_keys,
                    "existing member response fields with actual native facts"
                );
                assert_eq!(
                    value["standby_context"],
                    serde_json::to_value(&first.manifest().holding).unwrap()
                );
                assert_eq!(value["tables"], json!(physical_catalog), "complete actual offered physical catalogue, not canonical tables or the SQL allowlist");
                assert_eq!(
                    value["engine"],
                    json!({
                        "name":crate::standby::kernel_v2::ENGINE,"version":crate::ENGINE_VERSION,"git_sha":crate::GIT_SHA,
                        "schema_version":0,"supported_schema_baseline":0,"user_version":physical_user_version,
                        "ddl_fingerprint":schema_digest(),"profile":"member_read_kernel_v2",
                    })
                );
                assert_eq!(physical_user_version, 0);
                assert_eq!(
                    crate::FULL_GIT_SHA.len(),
                    40,
                    "full build metadata is required for this qualification"
                );
                assert!(crate::FULL_GIT_SHA.bytes().all(|b| b.is_ascii_hexdigit()));
                assert_eq!(crate::GIT_SHA, &crate::FULL_GIT_SHA[..12]);
                assert!(value["logical_relations"]
                    .as_str()
                    .expect("logical relation guidance")
                    .contains("catalog_columns"));
                assert!(value["model"]
                    .as_str()
                    .expect("actual native model")
                    .contains("current-state member projection"));
                if include_ddl == Some(true) {
                    assert_eq!(value["ddl_statements"], json!(physical_ddl));
                }
                let names = physical_catalog
                    .iter()
                    .map(|table| table["name"].as_str().unwrap())
                    .collect::<BTreeSet<_>>();
                for excluded in [
                    "content_events",
                    "meta_events",
                    "policy_events",
                    "control_events",
                    "kernel_records",
                    "kernel_principals",
                    "record_policies",
                    "policy_entries",
                ] {
                    assert!(
                        !names.contains(excluded),
                        "no invented/excluded canonical table {excluded}"
                    );
                }
                assert!(names
                    .iter()
                    .all(|name| !name.starts_with("kernel_hcp_") && !name.contains("preferences")));
                for private in &hidden_collection_member {
                    assert!(!value.to_string().contains(private));
                }
                assert!(!value.to_string().contains("malformed private schema"));
                held_descriptions.push((arguments, value.clone()));
            }
        }
        for arguments in [json!({"unknown":true}), json!({"include_ddl":"true"})] {
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("describe_schema", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "existing strict describe parser: {got}"
            );
        }
        let internal_sql = reader
            .dispatch(request(
                "query_sql",
                json!({"sql":"SELECT principal_id FROM kernel_member_identity","format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            internal_sql["result"]["isError"], true,
            "describing a physical table grants no logical SQL authority: {internal_sql}"
        );
        let mut held_suggestions = Vec::new();
        for (arguments, online) in &suggestion_reads {
            for modern in [false, true] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut call = request("suggest_facet_values", arguments.clone());
                if modern {
                    call["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(call).await.unwrap();
                assert_ne!(
                    got["result"]["isError"], true,
                    "actual member suggestion dispatch: {got}"
                );
                let value = got["result"]
                    .get("structuredContent")
                    .expect("suggestion structured response");
                assert_suggestions_member_parity(
                    value,
                    online,
                    &serde_json::to_value(&first.manifest().holding).unwrap(),
                );
                held_suggestions.push((arguments, value.clone()));
            }
        }
        let selected_suggestion = reader.dispatch(request("suggest_facet_values", json!({"record_id":source_reference,"facet_key":"n3_suggest_priority","format":"json"}))).await.unwrap();
        assert_eq!(
            selected_suggestion["result"]["structuredContent"],
            held_suggestions
                .last()
                .expect("Message suggestion fixture")
                .1,
            "source-selected safe reference preserves suggestion context"
        );
        for arguments in [
            json!({"facet_key":"n3_suggest_priority"}),
            json!({"type":"Document"}),
            json!({"type":"Document","facet_key":7}),
            json!({"type":"Document","facet_key":"n3_suggest_priority","unknown":true}),
            json!({"type":"Document","record_id":id,"facet_key":"n3_suggest_priority"}),
            json!({"record_id":hidden_collection_member[1],"facet_key":"n3_suggest_priority"}),
            json!({"record_id":"c01dcaf","facet_key":"n3_suggest_priority"}),
        ] {
            if arguments["record_id"] != "c01dcaf" {
                let mut native_registry = registry();
                crate::mcp::kernel_v2::register_kernel_v2_tools(&mut native_registry).unwrap();
                assert!(
                    native_registry
                        .call_engine(
                            EngineHandle::KernelV2(db.clone()),
                            Caller::authenticated(MEMBER),
                            "suggest_facet_values",
                            arguments.clone()
                        )
                        .await
                        .is_err(),
                    "actual native parser/private target refusal: {arguments}"
                );
            }
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("suggest_facet_values", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "same suggestion parser/privacy or member safe-prefix refusal: {got}"
            );
        }
        let mut held_facets = Vec::new();
        for (arguments, online) in &facet_reads {
            for modern in [false, true] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut call = request("resolve_facets", arguments.clone());
                if modern {
                    call["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(call).await.unwrap();
                assert_ne!(
                    got["result"]["isError"], true,
                    "native facet dispatcher: {got}"
                );
                let value = got["result"]
                    .get("structuredContent")
                    .expect("facet structured response");
                assert_facets_member_parity(
                    value,
                    online,
                    &serde_json::to_value(&first.manifest().holding).unwrap(),
                    arguments
                        .get("record_id")
                        .and_then(Json::as_str)
                        .map(|id| facet_owners.get(id).expect("captured facet owner witness")),
                );
                held_facets.push((arguments, value.clone()));
            }
        }
        let selected_ref = reader
            .dispatch(request(
                "resolve_facets",
                json!({"record_id":source_reference,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            selected_ref["result"]["structuredContent"],
            held_facets.last().expect("Message facet fixture").1,
            "globally selected safe reference resolves to same held facts"
        );
        for arguments in [
            json!({}),
            json!({"record_id":id,"type":"Document"}),
            json!({"type":"Document","unknown":true}),
            json!({"record_id":hidden_collection_member[1]}),
            json!({"record_id":"c01dcaf"}),
        ] {
            if arguments["record_id"] != "c01dcaf" {
                // The short-reference safety rule is member-specific; parser
                // and exact private-ID refusals have an actual native oracle.
                let mut native_registry = registry();
                crate::mcp::kernel_v2::register_kernel_v2_tools(&mut native_registry).unwrap();
                assert!(
                    native_registry
                        .call_engine(
                            EngineHandle::KernelV2(db.clone()),
                            Caller::authenticated(MEMBER),
                            "resolve_facets",
                            arguments.clone()
                        )
                        .await
                        .is_err(),
                    "native facet parser/private identity refusal: {arguments}"
                );
            }
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("resolve_facets", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "strict facet parser/private identity/safe-prefix refusal: {got}"
            );
        }
        let mut held_previews = Vec::new();
        for (arguments, online) in &preview_reads {
            for modern in [false, true] {
                let mut arguments = arguments.clone();
                arguments["format"] = json!("json");
                let mut call = request("preview_record_shape", arguments.clone());
                if modern {
                    call["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(call).await.unwrap();
                assert_ne!(
                    got["result"]["isError"], true,
                    "preview actual dispatcher: {got}"
                );
                let value = got["result"]
                    .get("structuredContent")
                    .expect("preview structured response");
                assert_preview_member_parity(
                    value,
                    online,
                    &first.manifest().generation_id(),
                    &serde_json::to_value(&first.manifest().holding).unwrap(),
                );
                assert!(!value.to_string().contains("n3-preview-private"));
                assert!(!value.to_string().contains(&hidden_collection_member[1]));
                held_previews.push((arguments, value.clone()));
            }
        }
        for arguments in [
            json!({"kind":"note"}),
            json!({"type":"Unknown"}),
            json!({"facets":{}}),
            json!({"type":"Document","facets":null}),
            json!({"type":"Document","record_id":hidden_collection_member[1]}),
        ] {
            let mut native_registry = registry();
            crate::mcp::kernel_v2::register_kernel_v2_tools(&mut native_registry).unwrap();
            assert!(
                native_registry
                    .call_engine(
                        EngineHandle::KernelV2(db.clone()),
                        Caller::authenticated(MEMBER),
                        "preview_record_shape",
                        arguments.clone()
                    )
                    .await
                    .is_err(),
                "native parser must reject {arguments}"
            );
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("preview_record_shape", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "same supported closed preview parser: {got}"
            );
        }
        // Existing member list contract, against actual caller-authorised
        // public link staging (native online has no manage_links handler).
        let mut expected_links = source_links
            .iter()
            .filter(|row| row["source_id"] == id || row["target_id"] == id)
            .cloned()
            .collect::<Vec<_>>();
        expected_links.sort_by_key(|row| {
            (
                if row["source_id"] == id { 0 } else { 1 },
                row["relationship"]
                    .as_str()
                    .expect("source relationship")
                    .to_owned(),
                row["created_at"]
                    .as_str()
                    .expect("source link time")
                    .to_owned(),
                row["id"].as_str().expect("source link id").to_owned(),
            )
        });
        assert!(
            expected_links.len() > 1,
            "fixture must exercise continuation"
        );
        let mut retained_link_cursor = None;
        for modern in [false, true] {
            let mut cursor = None;
            let mut listed_links = Vec::new();
            for page in 0..=expected_links.len() {
                let mut arguments =
                    json!({"action":"list","record_id":id,"limit":1,"format":"json"});
                if let Some(token) = cursor.as_ref() {
                    arguments["cursor"] = json!(token);
                }
                let mut call = request("manage_links", arguments);
                if modern {
                    call["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(call).await.unwrap();
                assert_ne!(got["result"]["isError"], true, "{got}");
                let value = &got["result"]["structuredContent"];
                assert_eq!(
                    value.get("standby_context").expect("list holding"),
                    &serde_json::to_value(&first.manifest().holding).unwrap()
                );
                for (key, expected) in [
                    ("action", json!("list")),
                    ("format", json!("native.manage-links-list.v1")),
                    ("record_id", json!(id)),
                    ("viewer_relative", json!(true)),
                    ("query_basis", json!("live_at_each_page_read")),
                    ("scope", json!("opposite_endpoint_viewable_at_read_time")),
                    ("limit", json!(1)),
                    ("cursor", json!(cursor)),
                ] {
                    assert_eq!(
                        value.get(key).expect("required list field"),
                        &expected,
                        "{got}"
                    );
                }
                let outgoing = value["links_out"].as_array().expect("outgoing link array");
                let incoming = value["links_in"].as_array().expect("incoming link array");
                assert_eq!(value["returned"], outgoing.len() + incoming.len());
                listed_links.extend(outgoing.iter().chain(incoming).cloned());
                assert!(!value.to_string().contains(&hidden_collection_member[2]));
                assert!(!value.to_string().contains(&hidden_collection_member[0]));
                let has_more = value["has_more"].as_bool().expect("list has_more");
                if !has_more {
                    assert!(value.get("next_cursor").expect("cursor field").is_null());
                    assert!(value.get("next_call").expect("next call field").is_null());
                    break;
                }
                assert!(page < expected_links.len(), "bounded page progress");
                let token = value["next_cursor"].as_str().expect("opaque list token");
                assert!(uuid::Uuid::parse_str(token).is_ok());
                assert_eq!(
                    value["next_call"],
                    json!({"action":"list","record_id":id,"limit":1,"cursor":token})
                );
                cursor = Some(token.to_owned());
                retained_link_cursor = cursor.clone();
            }
            assert_eq!(
                listed_links, expected_links,
                "full source-selected rows and page order"
            );
        }
        let retained_link_cursor = retained_link_cursor.expect("continuation fixture");
        for arguments in [
            json!({"action":"list","record_id":id,"limit":2,"cursor":retained_link_cursor}),
            json!({"action":"list","record_id":archived,"limit":1,"cursor":retained_link_cursor}),
            json!({"action":"list","record_id":id,"cursor":"invalid"}),
            json!({"action":"list","record_id":id,"limit":0}),
            json!({"action":"list","record_id":id,"limit":201}),
            json!({"action":"list","record_id":hidden_collection_member[2]}),
            json!({"action":"list","record_id":id,"unknown":true}),
            json!({"action":"add","source_id":id,"target_id":archived,"relationship":"related_to"}),
            json!({"action":"remove","source_id":id,"target_id":archived,"relationship":"related_to"}),
        ] {
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("manage_links", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "list parser/cursor/privacy or write refusal: {got}"
            );
        }
        for selector in [reference_record.clone(), source_reference.clone()] {
            let got = reader
                .dispatch(request(
                    "manage_links",
                    json!({"action":"list","id":selector,"format":"json"}),
                ))
                .await
                .unwrap();
            let value = &got["result"]["structuredContent"];
            assert_eq!(
                value["record_id"], reference_record,
                "selected safe reference/selector alias: {got}"
            );
            let mut expected_reference_links = source_links
                .iter()
                .filter(|row| {
                    row["source_id"] == reference_record || row["target_id"] == reference_record
                })
                .cloned()
                .collect::<Vec<_>>();
            expected_reference_links.sort_by_key(|row| {
                (
                    if row["source_id"] == reference_record {
                        0
                    } else {
                        1
                    },
                    row["relationship"]
                        .as_str()
                        .expect("source reference relationship")
                        .to_owned(),
                    row["created_at"]
                        .as_str()
                        .expect("source reference link time")
                        .to_owned(),
                    row["id"]
                        .as_str()
                        .expect("source reference link id")
                        .to_owned(),
                )
            });
            let rows = value["links_out"]
                .as_array()
                .expect("reference outgoing")
                .iter()
                .chain(value["links_in"].as_array().expect("reference incoming"))
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(value["returned"], rows.len());
            assert_eq!(
                rows, expected_reference_links,
                "actual source-selected Message links: {got}"
            );
        }
        let short = reader
            .dispatch(request(
                "manage_links",
                json!({"action":"list","record_id":"c01dcaf","format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            short["result"]["isError"], true,
            "shorter-than-globally-safe reference refuses: {short}"
        );
        let mut rendered_records = Vec::new();
        for (selector, expected_id, interpretation) in [
            (id.clone(), id.clone(), true),
            (
                collection_reads[0].0.clone(),
                collection_reads[0].0.clone(),
                false,
            ),
            (comment.clone(), comment.clone(), true),
            (archived.clone(), archived.clone(), false),
            (mention_record.clone(), mention_record.clone(), false),
            (source_reference.clone(), reference_record.clone(), false),
        ] {
            let arguments =
                json!({"id":selector,"include_interpretation":interpretation,"format":"json"});
            let mut first_response = None;
            for modern in [false, true] {
                let mut request = request("render_record", arguments.clone());
                if modern {
                    request["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
                }
                let got = reader.dispatch(request).await.unwrap();
                let value = &got["result"]["structuredContent"];
                let object = value.as_object().expect("member render response object");
                assert_eq!(
                    object.len(),
                    if interpretation { 4 } else { 3 },
                    "exact existing render shape: {got}"
                );
                assert_eq!(object.get("id").expect("render id"), &json!(expected_id));
                assert_eq!(
                    object.get("standby_context").expect("render holding"),
                    &serde_json::to_value(&first.manifest().holding).unwrap()
                );
                if interpretation {
                    assert_eq!(
                        object
                            .get("interpretation")
                            .expect("render interpretation marker"),
                        &json!({"unavailable_offline":{"surface":"render_interpretation","retry":"when_online"}})
                    );
                } else {
                    assert!(!object.contains_key("interpretation"));
                }
                let markdown = object
                    .get("markdown")
                    .and_then(Json::as_str)
                    .expect("render markdown string");
                assert!(
                    markdown.contains(&format!("`{expected_id}`")),
                    "actual record identity: {got}"
                );
                if expected_id == id {
                    assert!(markdown.starts_with(&format!(
                        "# Offline journey\n\n**Document** / note — `{id}`\n"
                    )));
                    for text in [
                        "synthetic admitted body",
                        "## Links (incoming)",
                        "Imported attachment",
                        "## Mentioned by",
                        "Visible body mention witness",
                    ] {
                        assert!(
                            markdown.contains(text),
                            "member render section {text}: {got}"
                        );
                    }
                    assert!(markdown.contains(&attachment) && markdown.contains(&imported));
                    assert!(
                        markdown.contains(&format!(
                            "superseded by Renderer successor ({successor_reference})"
                        )),
                        "source-selected successor reference: {got}"
                    );
                } else if expected_id == collection_reads[0].0 {
                    // Existing RenderRecord defaults to a 200-child window;
                    // this 52-row fixture exercises every child and archive
                    // flag below that bound, rather than claiming truncation.
                    for text in [
                        "## Children",
                        "Collection member 000",
                        "Collection member 050",
                        "Resolver archived (Document / note",
                    ] {
                        assert!(markdown.contains(text), "render child {text}: {got}");
                    }
                    assert!(markdown
                        .lines()
                        .any(|line| line.contains("Resolver archived")
                            && line.ends_with("[archived]")));
                } else if expected_id == comment {
                    assert!(
                        markdown.contains("lifecycle: resolved")
                            && markdown.contains("> Synthetic resolution")
                            && markdown.contains("Synthetic root comment"),
                        "typed lifecycle retained for Markdown: {got}"
                    );
                } else if expected_id == archived {
                    assert!(
                        markdown.contains("ARCHIVED"),
                        "actual native archived state: {got}"
                    );
                } else if expected_id == mention_record {
                    assert!(
                        markdown.contains("## Mentions")
                            && markdown.contains("c01dcaf")
                            && markdown.contains(&reference_record)
                            && markdown.contains(&id),
                        "held body mention rendering: {got}"
                    );
                } else {
                    assert!(markdown.contains("Visible source-selected reference target"));
                }
                for hidden in &hidden_collection_member {
                    assert!(
                        !markdown.contains(hidden),
                        "private record never rendered: {got}"
                    );
                }
                if let Some(first_response) = &first_response {
                    assert_eq!(value, first_response, "protocol render parity");
                } else {
                    first_response = Some(value.clone());
                }
            }
            rendered_records.push((arguments, first_response.unwrap()));
        }
        for arguments in [
            json!({"id":"c01dcaf"}),
            json!({"id":hidden_collection_member[0]}),
            json!({"id":id,"resolve":false}),
            json!({"id":id,"include_interpretation":"yes"}),
        ] {
            let mut arguments = arguments;
            arguments["format"] = json!("json");
            let got = reader
                .dispatch(request("render_record", arguments))
                .await
                .unwrap();
            assert_eq!(
                got["result"]["isError"], true,
                "safe reference/presence/strict render parser: {got}"
            );
        }
        let exact = reader
            .dispatch(request(
                "get_record",
                json!({"record_id":reference_record,"format":"json"}),
            ))
            .await
            .unwrap();
        let exact = &exact["result"]["structuredContent"]["records"][0];
        assert_eq!(exact["display_reference"], source_reference);
        assert_eq!(
            exact.get("mentions_out").expect("Message companion marker"),
            &json!({"unavailable_offline":{"surface":"message_mentions","retry":"when_online"}})
        );
        let mention_read = reader
            .dispatch(request(
                "get_record",
                json!({"ids":[mention_record],"format":"json"}),
            ))
            .await
            .unwrap();
        let mention_read = &mention_read["result"]["structuredContent"]["records"][0];
        assert_eq!(
            mention_read
                .get("mentions_out_count")
                .expect("held body mention total"),
            &json!(3)
        );
        for mention in mention_read
            .get("mentions_out")
            .expect("held ordinary body mentions")
            .as_array()
            .expect("ordinary mention array")
        {
            // Shared mentions are caller-visible resolution, not globally safe
            // addresses. The hidden colliding sibling cannot become an oracle.
            assert_eq!(mention["resolution"]["state"], "resolved");
            let target = if mention["lookup_key"] == "c01dcaf" {
                &reference_record
            } else {
                &id
            };
            assert_eq!(&mention["resolution"]["id"], target);
            assert!(mention["resolution"].get("display_reference").is_none());
        }
        let mentions = reader
            .dispatch(request("get_record", json!({"ids":[id],"format":"json"})))
            .await
            .unwrap();
        assert_eq!(
            mentions["result"]["structuredContent"]["records"][0]["mentions_in_count"], 1,
            "private-body mentions never enter the member index: {mentions}"
        );
        for selector in [
            reference_record.clone(),
            source_reference.clone(),
            "c01dcaf".into(),
        ] {
            let got = reader
                .dispatch(request(
                    "get_record",
                    json!({"id":selector,"format":"json"}),
                ))
                .await
                .unwrap();
            let expected = if selector == "c01dcaf" {
                "not_found"
            } else {
                "found"
            };
            assert_eq!(
                got["result"]["structuredContent"]["records"][0]["status"], expected,
                "only stored safe prefix is an address, no global ambiguity claim: {got}"
            );
        }
        let bad_window = reader
            .dispatch(request(
                "get_record",
                json!({"ids":[id],"links_limit":1001,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            bad_window["result"]["isError"], true,
            "shared window guard: {bad_window}"
        );
        let attachment_read = reader
            .dispatch(request(
                "read_attachment",
                json!({"attachment_id":attachment,"offset":10,"length":6,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            attachment_read["result"]["structuredContent"]["content"], "inline",
            "{attachment_read}"
        );
        let listed_ids: Vec<_> = listed["result"]["structuredContent"]["attachments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["attachment_id"].as_str().unwrap())
            .collect();
        assert!(
            listed_ids.contains(&attachment.as_str()) && listed_ids.contains(&imported.as_str()),
            "{listed}"
        );
        let imported_read = reader
            .dispatch(request(
                "read_attachment",
                json!({"attachment_id":imported,"offset":10,"length":8,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            imported_read["result"]["structuredContent"]["content"], online_imported["content"],
            "{imported_read}"
        );
        assert_eq!(
            imported_read["result"]["structuredContent"]["blob"],
            online_imported["blob"]
        );
        let inspect = reader
            .dispatch(request(
                "manage_attachments",
                json!({"action":"inspect","attachment_id":attachment,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            inspect["result"]["structuredContent"]["blob"]["original_filename"],
            "member.txt"
        );
        let detach = reader
            .dispatch(request(
                "manage_attachments",
                json!({"action":"detach","attachment_id":attachment,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            detach["result"]["structuredContent"]["error_code"],
            "STANDBY_READ_ONLY"
        );
        let sql = reader.dispatch(request("query_sql", json!({"sql":"SELECT id,body FROM records WHERE id=?1","parameters":[id],"format":"json"}))).await.unwrap();
        assert_eq!(
            sql["result"]["structuredContent"]["rows"][0]["body"],
            "synthetic admitted body"
        );
        assert!(sql["result"]["structuredContent"]
            .get("as_of_seq")
            .is_none());
        for (query, online) in [
            (&ordinary_comments_query, &ordinary_online),
            (&explicit_comments_query, &comments_online),
        ] {
            let mut query = query.clone();
            query["format"] = json!("json");
            let offline = reader
                .dispatch(request("query_record", query))
                .await
                .unwrap();
            let offline = &offline["result"]["structuredContent"];
            let project = |value: &Json, member: bool| {
                let mut rows = value["records"]
                    .as_array()
                    .unwrap_or_else(|| panic!("query records missing: {value}"))
                    .iter()
                    .map(|r| {
                        let interpretation = r.get("lifecycle_interpretation").expect("supported query row must carry lifecycle_interpretation");
                        let carrier = lifecycle_carrier(interpretation);
                        if member {
                            assert!(r.get("lifecycle").is_none(), "member contract uses interpreted lifecycle");
                        } else {
                            assert_eq!(r.get("lifecycle").expect("native raw carrier must be present"), &json!(carrier));
                        }
                        if r["id"] == comment { assert_eq!(carrier, Some("resolved"), "resolved root state must survive"); }
                        if r["id"] == reply { assert_eq!(carrier, None, "reply has no lifecycle carrier"); }
                        json!({"id":r["id"],"body":r["body"],"lifecycle_interpretation":interpretation})
                    })
                    .collect::<Vec<_>>();
                rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
                rows
            };
            assert_eq!(
                offline["total"], online["total"],
                "native family parity, imported_governance={imported_governance}: {offline}"
            );
            assert_eq!(
                project(offline, true),
                project(online, false),
                "native comment integrity, imported_governance={imported_governance}"
            );
        }
        let pipeline_args = json!({"steps":[{"step":"filter","ids":[id,attachment,imported]}],"order":"name_asc","limit":1,"format":"json"});
        let mut modern_page = request("query_record", pipeline_args.clone());
        modern_page["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
        let page = reader.dispatch(modern_page).await.unwrap();
        let page_value = &page["result"]["structuredContent"];
        assert_eq!(page_value["total"], 3, "{page}");
        assert_eq!(page_value["returned"], 1, "{page}");
        assert_eq!(page_value["has_more"], true, "{page}");
        assert!(
            page_value["records"][0]["custody_boundary"].is_boolean(),
            "held custody is data: {page}"
        );
        assert!(
            page_value["records"][0]["record_path"].is_string(),
            "source-selected reference: {page}"
        );
        assert!(page_value.get("content_head_seq").is_none(), "{page}");
        let mut continuation = page_value["next_request"].clone();
        // Format is a dispatch presentation option, consumed before query
        // execution. Request JSON again for the legacy envelope assertions.
        continuation["format"] = json!("json");
        let continued = reader
            .dispatch(request("query_record", continuation.clone()))
            .await
            .unwrap();
        assert_eq!(
            continued["result"]["structuredContent"]["offset"], 1,
            "{continued}"
        );
        assert_ne!(
            continued["result"]["structuredContent"]["records"][0]["id"],
            page_value["records"][0]["id"]
        );
        let count=reader.dispatch(request("query_record",json!({"steps":[{"step":"filter","ids":[id,attachment,imported]}],"count_by":"type","format":"json"}))).await.unwrap();
        assert_eq!(count["result"]["structuredContent"]["total"], 3, "{count}");
        let traversed=reader.dispatch(request("query_record",json!({"steps":[{"step":"filter","ids":[id]},{"step":"traverse","target":"links","direction":"in","relationship":"part_of"}],"aggregate":{"op":"count"},"format":"json"}))).await.unwrap();
        assert_eq!(
            traversed["result"]["structuredContent"]["value"], 2,
            "{traversed}"
        );
        for (collection, online) in &collection_reads {
            let opened = reader
                .dispatch(request(
                    "open_collection",
                    json!({"record_id":collection,"format":"json"}),
                ))
                .await
                .unwrap();
            let value = &opened["result"]["structuredContent"];
            assert_eq!(value["status"], online["status"], "{opened}");
            assert_eq!(value["surface"], online["surface"]);
            assert_eq!(value["collection"], online["collection"]);
            assert_eq!(
                value["input"], online["input"],
                "collection parity imported_governance={imported_governance}: {opened}"
            );
            let renderer_labels = |value: &Json| {
                value["renderers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| json!({"id":r["id"],"name":r["name"]}))
                    .collect::<Vec<_>>()
            };
            assert_eq!(renderer_labels(value), renderer_labels(online));
            // Existing member renderer rows also expose their held runtime;
            // native online currently lists only id/name.
            for renderer in value["renderers"].as_array().unwrap() {
                assert_eq!(renderer["runtime"], "native.mdx.v2");
            }
            for hidden in &hidden_collection_member {
                assert!(!value.to_string().contains(hidden));
            }
        }
        let invalid = reader
            .dispatch(request("open_collection", json!({"id":id,"format":"json"})))
            .await
            .unwrap();
        assert_eq!(
            invalid["result"]["structuredContent"]["diagnostic"]["code"],
            "invalid_collection_shape",
            "{invalid}"
        );
        let hidden = reader
            .dispatch(request(
                "open_collection",
                json!({"id":hidden_collection_member[1],"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(hidden["result"]["isError"], true, "{hidden}");
        let unknown = reader
            .dispatch(request(
                "open_collection",
                json!({"id":id,"limit":2,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            unknown["result"]["isError"], true,
            "shared strict argument parser: {unknown}"
        );
        let write = reader
            .dispatch(request(
                "create_record",
                json!({"type":"Document","kind":"note","name":"refuse"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            write["result"]["structuredContent"]["error_code"],
            "STANDBY_READ_ONLY"
        );
        owner.quiesce().await;
        let retired = reader
            .dispatch(request("get_record", json!({"ids":[id],"format":"json"})))
            .await
            .unwrap();
        assert_eq!(
            retired["result"]["structuredContent"]["error_code"],
            "copy_unavailable"
        );
        drop(owner);
        // An unpinned restart may recover coordinates only from the current
        // credential and the exact native receipt/file. It must not activate.
        let receipt_path = root.join(crate::member_copy_serving::ADMISSION_FILENAME);
        let receipt_bytes = std::fs::read(&receipt_path).unwrap();
        let receipt_value: Json = serde_json::from_slice(&receipt_bytes).unwrap();
        let current = CredentialSelection::for_test(b"synthetic credential");
        for (field, value) in [
            ("scope_ref", "wrong-scope"),
            ("account_binding", "wrong-account"),
            ("server_origin", "https://foreign.invalid"),
            ("route_database_id", "foreign-route"),
        ] {
            let mut invalid = receipt_value.clone();
            invalid["binding"][field] = json!(value);
            let invalid = serde_json::to_vec(&invalid).unwrap();
            std::fs::write(&receipt_path, &invalid).unwrap();
            let mut refused = MemberCopyServing::open_unbound_routed(
                &root,
                None,
                "https://example.invalid".into(),
                "route-test".into(),
                test_consumer(),
            )
            .await
            .unwrap();
            assert!(refused.needs_native_receipt_metadata());
            assert!(
                !refused.restore_native_receipt_metadata(&current),
                "{field}"
            );
            assert!(refused.origin_database_id().is_none());
            assert!(!refused.is_serving());
            assert_eq!(
                std::fs::read(&receipt_path).unwrap(),
                invalid,
                "refusal never repairs or purges a receipt"
            );
            drop(refused);
        }
        std::fs::write(&receipt_path, &receipt_bytes).unwrap();
        let mut wrong_pin = MemberCopyServing::open_unbound_routed(
            &root,
            Some("foreign-origin".into()),
            "https://example.invalid".into(),
            "route-test".into(),
            test_consumer(),
        )
        .await
        .unwrap();
        assert!(!wrong_pin.restore_native_receipt_metadata(&current));
        assert_eq!(wrong_pin.origin_database_id(), Some("foreign-origin"));
        assert!(!wrong_pin.is_serving());
        drop(wrong_pin);
        let mut unpinned = MemberCopyServing::open_unbound_routed(
            &root,
            None,
            "https://example.invalid".into(),
            "route-test".into(),
            test_consumer(),
        )
        .await
        .unwrap();
        assert!(
            !unpinned.restore_native_receipt_metadata(&CredentialSelection::for_test(
                b"rotated synthetic credential"
            ))
        );
        assert!(unpinned.origin_database_id().is_none());
        assert!(!unpinned.is_serving());
        let snapshot_path = root
            .join("generations")
            .join(first.manifest().generation_id())
            .join(crate::member_copy_admission::SNAPSHOT_FILENAME);
        let snapshot_bytes = std::fs::read(&snapshot_path).unwrap();
        let mut corrupted = snapshot_bytes.clone();
        corrupted[0] ^= 1;
        std::fs::write(&snapshot_path, &corrupted).unwrap();
        assert!(
            !unpinned.restore_native_receipt_metadata(&current),
            "matching receipt/credential cannot restore metadata from invalid physical NKM2 bytes"
        );
        assert!(unpinned.origin_database_id().is_none());
        assert!(!unpinned.is_serving());
        assert_eq!(
            std::fs::read(&snapshot_path).unwrap(),
            corrupted,
            "verification refusal never repairs or purges the installed artifact"
        );
        std::fs::write(&snapshot_path, &snapshot_bytes).unwrap();
        assert!(unpinned.restore_native_receipt_metadata(&current));
        assert_eq!(
            unpinned.origin_database_id(),
            Some(first.manifest().origin_database_id.as_str())
        );
        assert_eq!(unpinned.bound_scope_ref(), Some("scope-one"));
        assert!(
            !unpinned.is_serving(),
            "metadata restoration never activates a lease"
        );
        assert_eq!(std::fs::read(&receipt_path).unwrap(), receipt_bytes);
        drop(unpinned);
        let mut owner = open().await.unwrap();
        assert!(owner.is_serving());
        let restarted = MemberServedSnapshot::from_serving(&owner, registry()).unwrap();
        let cold_list = restarted
            .dispatch(request(
                "manage_attachments",
                json!({"action":"list","record_id":id,"format":"json"}),
            ))
            .await
            .unwrap();
        let reset = restarted.dispatch(request("manage_links", json!({"action":"list","record_id":id,"limit":1,"cursor":retained_link_cursor,"format":"json"}))).await.unwrap();
        assert_eq!(
            reset["result"]["isError"], true,
            "process-local cursor reset on restart: {reset}"
        );
        assert!(
            reset.to_string().contains("cursor_reset_required"),
            "{reset}"
        );
        let fresh_links = restarted
            .dispatch(request(
                "manage_links",
                json!({"action":"list","record_id":id,"format":"json"}),
            ))
            .await
            .unwrap();
        let value = &fresh_links["result"]["structuredContent"];
        let rows = value["links_out"]
            .as_array()
            .expect("restart outgoing")
            .iter()
            .chain(value["links_in"].as_array().expect("restart incoming"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            rows, expected_links,
            "same admitted links after restart: {fresh_links}"
        );
        assert_eq!(value["has_more"], false);
        assert_eq!(value["limit"], 50);
        let cold_ids: Vec<_> = cold_list["result"]["structuredContent"]["attachments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["attachment_id"].as_str().unwrap())
            .collect();
        assert!(
            cold_ids.contains(&attachment.as_str()) && cold_ids.contains(&imported.as_str()),
            "{cold_list}"
        );
        let restarted_imported = restarted
            .dispatch(request(
                "read_attachment",
                json!({"attachment_id":imported,"offset":10,"length":8,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            restarted_imported["result"]["structuredContent"]["content"],
            online_imported["content"],
            "{restarted_imported}"
        );
        let raw_handle = restarted
            .dispatch(request(
                "read_attachment",
                json!({"attachment_id":imported_meta.id,"format":"json"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            raw_handle["result"]["isError"], true,
            "blob handle is not referencing-record authority: {raw_handle}"
        );
        let resumed_page = restarted
            .dispatch(request("query_record", continuation.clone()))
            .await
            .unwrap();
        assert_eq!(
            resumed_page["result"]["structuredContent"]["page_basis_digest"],
            page_value["page_basis_digest"],
            "{resumed_page}"
        );
        for (arguments, expected) in &resolution_cases {
            let mut arguments = arguments.clone();
            arguments["format"] = json!("json");
            let got = restarted
                .dispatch(request("resolve_many", arguments))
                .await
                .unwrap();
            let mut value = got["result"]["structuredContent"].clone();
            let footing = value
                .as_object_mut()
                .expect("restart resolver object")
                .remove("standby_context")
                .expect("restart member footing");
            assert_eq!(
                footing,
                serde_json::to_value(&first.manifest().holding).unwrap()
            );
            assert_eq!(
                &value, expected,
                "resolver survives same generation restart: {got}"
            );
        }
        for (arguments, online) in &archive_queries {
            let mut arguments = arguments.clone();
            arguments["format"] = json!("json");
            let got = restarted
                .dispatch(request("query_record", arguments))
                .await
                .unwrap();
            let value = &got["result"]["structuredContent"];
            assert_eq!(
                value.get("total").expect("restart archive total"),
                online.get("total").expect("source archive total")
            );
            let ids = |value: &Json| {
                value
                    .get("records")
                    .expect("archive rows")
                    .as_array()
                    .expect("archive array")
                    .iter()
                    .map(|r| r.get("id").expect("archive row id").clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                ids(value),
                ids(online),
                "archive query survives restart: {got}"
            );
        }
        let before_bootstrap = chrono::Utc::now();
        let got = restarted
            .dispatch(request(
                "bootstrap",
                json!({"run_key":bootstrap_key,"format":"json"}),
            ))
            .await
            .unwrap();
        let after_bootstrap = chrono::Utc::now();
        let normalized = assert_native_member_bootstrap(
            got["result"]
                .get("structuredContent")
                .expect("restart bootstrap"),
            &native_bootstrap,
            &expected_world,
            (bootstrap_counts, bootstrap_people),
            &bootstrap_holding,
            (before_bootstrap, after_bootstrap),
            Some(bootstrap_key),
        );
        assert_eq!(normalized,held_bootstrap.expect("full prior bootstrap envelope"),"same-generation footing/instructions/world through restart; carried key remains correlation only");
        let continued = restarted
            .dispatch(request(
                "get_structure",
                json!({"root_id":"native:root","format":"json"}),
            ))
            .await
            .unwrap();
        assert_structure_member_parity(
            continued["result"]
                .get("structuredContent")
                .expect("virtual root continuation survives restart"),
            &native_root_tree,
            &bootstrap_holding,
            &tree_successions,
        );
        for (arguments, expected, days) in &held_dashboards {
            let mut arguments = arguments.clone();
            arguments["format"] = json!("json");
            let before = chrono::Utc::now();
            let got = restarted
                .dispatch(request("get_dashboard", arguments))
                .await
                .unwrap();
            let after = chrono::Utc::now();
            let value = got["result"]
                .get("structuredContent")
                .expect("restart dashboard response");
            assert_eq!(
                dashboard_without_clock(value, before, after, *days),
                *expected,
                "same admitted dashboard after restart: {got}"
            );
        }
        for (arguments, expected, days) in &held_scans {
            let before = chrono::Utc::now();
            let got = restarted
                .dispatch(request("scan", arguments.clone()))
                .await
                .unwrap();
            let after = chrono::Utc::now();
            let value = got["result"]
                .get("structuredContent")
                .expect("restart member scan");
            assert_eq!(
                scan_without_clock(value, before, after, *days),
                *expected,
                "same admitted scan after restart, validated live-clock footing: {got}"
            );
        }
        for (arguments, expected) in &held_searches {
            let got = restarted
                .dispatch(request("search", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(got["result"].get("structuredContent").expect("restart member lexical response"),expected,"same-generation lexical indexes/ranking/near-misses/references after restart: {got}");
        }
        for (arguments, expected) in &held_structures {
            let got = restarted
                .dispatch(request("get_structure", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]
                    .get("structuredContent")
                    .expect("restarted tree"),
                expected,
                "complete same-generation structure after restart: {got}"
            );
        }
        for (arguments, expected) in &held_descriptions {
            let got = restarted
                .dispatch(request("describe_schema", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]
                    .get("structuredContent")
                    .expect("restart schema response"),
                expected,
                "same admitted physical schema/DDL after restart: {got}"
            );
        }
        for (arguments, expected) in &held_suggestions {
            let got = restarted
                .dispatch(request("suggest_facet_values", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]
                    .get("structuredContent")
                    .expect("restart suggestion response"),
                expected,
                "complete same-generation suggestion response after restart: {got}"
            );
        }
        for (arguments, expected) in &held_facets {
            let got = restarted
                .dispatch(request("resolve_facets", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]
                    .get("structuredContent")
                    .expect("restart facet response"),
                expected,
                "same admitted current facet facts after restart: {got}"
            );
        }
        for (arguments, expected) in &held_previews {
            let got = restarted
                .dispatch(request("preview_record_shape", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]
                    .get("structuredContent")
                    .expect("restart preview response"),
                expected,
                "complete same-generation preview survives restart: {got}"
            );
        }
        for (arguments, expected) in &rendered_records {
            let got = restarted
                .dispatch(request("render_record", arguments.clone()))
                .await
                .unwrap();
            assert_eq!(
                got["result"]
                    .get("structuredContent")
                    .expect("render restart response"),
                expected,
                "same admitted render generation survives restart: {got}"
            );
        }
        let restarted_mentions = restarted
            .dispatch(request(
                "get_record",
                json!({"ids":[mention_record],"format":"json"}),
            ))
            .await
            .unwrap();
        let restarted_mentions = &restarted_mentions["result"]["structuredContent"]["records"][0];
        for key in ["mentions_out", "mentions_out_count"] {
            assert_eq!(
                restarted_mentions
                    .get(key)
                    .expect("held mention field after restart"),
                mention_read
                    .get(key)
                    .expect("held mention field before restart"),
                "{key}"
            );
        }
        for (arguments, online) in &get_reads {
            let mut arguments = arguments.clone();
            arguments["format"] = json!("json");
            let got = restarted
                .dispatch(request("get_record", arguments))
                .await
                .unwrap();
            assert_get_member_parity(
                &got["result"]["structuredContent"],
                online,
                &child_references,
                &source_links,
            );
        }
        for (collection, online) in &collection_reads {
            let opened = restarted
                .dispatch(request(
                    "open_collection",
                    json!({"id":collection,"format":"json"}),
                ))
                .await
                .unwrap();
            assert_eq!(
                opened["result"]["structuredContent"]["input"], online["input"],
                "same-generation collection after restart: {opened}"
            );
        }
        let second = produce_ordinal(&db, MEMBER, dir.path(), 2).await;
        let newer = dir.path().join("newer.db");
        second.persist(&newer).unwrap();
        owner
            .admit_candidate(
                &newer,
                &serde_json::to_vec(second.manifest()).unwrap(),
                &context,
            )
            .await
            .unwrap();
        let newer_reader = MemberServedSnapshot::from_serving(&owner, registry()).unwrap();
        let stale_page = newer_reader
            .dispatch(request("query_record", continuation))
            .await
            .unwrap();
        assert_eq!(
            stale_page["result"]["isError"], true,
            "new generation refuses old page: {stale_page}"
        );
        assert!(
            stale_page["result"]["structuredContent"]["error"]
                .as_str()
                .unwrap()
                .contains("page basis changed"),
            "{stale_page}"
        );
        let latest = owner.generation_id().unwrap().to_owned();
        owner
            .admit_candidate(
                &newer,
                &serde_json::to_vec(second.manifest()).unwrap(),
                &context,
            )
            .await
            .unwrap();
        assert_eq!(
            owner.generation_id(),
            Some(latest.as_str()),
            "same pair redelivery keeps the admitted generation"
        );
        let mut conflict = second.manifest().clone();
        conflict.content_digest = if conflict.content_digest == "0".repeat(64) {
            "1".repeat(64)
        } else {
            "0".repeat(64)
        };
        assert_eq!(
            owner
                .admit_candidate(
                    &dir.path().join("must-not-open-missing.db"),
                    &serde_json::to_vec(&conflict).unwrap(),
                    &context
                )
                .await
                .unwrap_err(),
            crate::member_copy_admission::AdmissionError::RollbackRefused,
            "equal ordinal changed digest refuses before candidate access"
        );
        assert!(owner.recover_after_failed_candidate().await);
        assert_eq!(owner.generation_id(), Some(latest.as_str()));

        assert_eq!(
            owner
                .admit_candidate(&offered, &json, &context)
                .await
                .unwrap_err(),
            crate::member_copy_admission::AdmissionError::RollbackRefused
        );
        assert!(owner.recover_after_failed_candidate().await);
        assert_eq!(owner.generation_id(), Some(latest.as_str()));
        owner.quiesce().await;
        drop(owner);
        assert_eq!(std::fs::read(dir.path().join("source.db")).unwrap(), before);
        db.close().await;
    }
    source_context_proof::exercise().await;
}

#[tokio::test]
async fn native_profile_instructions_select_each_member_and_share_the_record_snapshot() {
    let (dir, db, owner, member) = fixture(false).await;
    let shared = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Workspace instructions","body":"synthetic shared instructions before","home_id":KERNEL_ROOT_ID})).await["id"].as_str().unwrap().to_owned();
    let empty=call(&db,OWNER,"create_record",json!({"type":"Document","kind":"note","name":"Empty member instruction source","home_id":KERNEL_ROOT_ID})).await["id"].as_str().unwrap().to_owned();
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&owner, "manage")]), &owner)
        .await
        .unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let pin = package.identity().unwrap();
    kernel::adopt_package_at(
        &db,
        &owner,
        &private,
        &package,
        Some(&pin),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let secret = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Owner instructions","body":"synthetic private owner instruction","home_id":private})).await["id"].as_str().unwrap().to_owned();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (id, scope, principal, source) in [
        ("workspace-visible", "database", None, shared.as_str()),
        ("workspace-hidden", "database", None, secret.as_str()),
        (
            "owner-only",
            "account",
            Some(owner.as_str()),
            secret.as_str(),
        ),
        (
            "member-only",
            "account",
            Some(member.as_str()),
            shared.as_str(),
        ),
        (
            "member-empty",
            "account",
            Some(member.as_str()),
            empty.as_str(),
        ),
    ] {
        kernel::import_instruction_binding_as(
            &db,
            &host,
            &kernel::ImportInstructionBinding {
                id: id.into(),
                scope_kind: scope.into(),
                scope_id: if scope == "database" {
                    "native:database".into()
                } else if principal == Some(owner.as_str()) {
                    OWNER.into()
                } else {
                    MEMBER.into()
                },
                account_principal: principal.map(str::to_owned),
                source_record_id: source.into(),
                position: 0,
                enabled: true,
                created_at: "2026-10-22T00:00:00Z".into(),
                actor: None,
            },
        )
        .await
        .unwrap();
    }
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    for account in [OWNER, MEMBER] {
        let file = produce(&db, account, dir.path()).await;
        let path = dir.path().join(format!("{account}.db"));
        file.persist(&path).unwrap();
        let admitted = AdmittedMemberFile::open(
            &path,
            dir.path(),
            &context(account, file.manifest()),
            file.manifest(),
        )
        .unwrap();
        let info = admitted.objects("member_context").unwrap();
        let selected: Vec<String> =
            serde_json::from_str(info[0]["instruction_source_ids"].as_str().unwrap()).unwrap();
        let selected_principal: Json =
            serde_json::from_str(info[0]["principal"].as_str().unwrap()).unwrap();
        assert_eq!(
            selected_principal["principal_id"],
            if account == MEMBER {
                member.as_str()
            } else {
                owner.as_str()
            }
        );
        if account == MEMBER {
            assert_eq!(
                selected
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
                [shared.clone(), empty.clone()].into_iter().collect()
            );
        } else {
            assert_eq!(
                selected
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
                [shared.clone(), secret.clone()].into_iter().collect()
            );
        }
        let instructions: Json =
            serde_json::from_str(info[0]["instructions"].as_str().unwrap()).unwrap();
        assert!(instructions
            .to_string()
            .contains("synthetic shared instructions before"));
        if account == MEMBER {
            assert!(!instructions.to_string().contains("owner-only"));
            assert!(!instructions.to_string().contains("workspace-hidden"));
            assert!(!instructions
                .to_string()
                .contains("synthetic private owner instruction"));
            assert!(!std::fs::read(&path)
                .unwrap()
                .windows(secret.len())
                .any(|bytes| bytes == secret.as_bytes()));
        } else {
            assert!(instructions
                .to_string()
                .contains("synthetic private owner instruction"));
        }
    }
    let mut connection = db.pool().acquire().await.unwrap();
    connection.close_on_drop();
    sqlx::query("BEGIN")
        .execute(&mut *connection)
        .await
        .unwrap();
    let generation = crate::standby::kernel_v2::coordinates(&mut connection)
        .await
        .unwrap();
    let origin = crate::standby::kernel_v2::origin(&mut connection, &generation)
        .await
        .unwrap();
    let cut =
        super::super::tests::ready(capture_in(&mut connection, &origin, MEMBER).await.unwrap());
    call(
        &db,
        OWNER,
        "update_record",
        json!({"id":shared,"body_set":"synthetic shared instructions after","if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some("synthetic shared instructions before")),"reason":"synthetic same-snapshot instruction proof"}),
    )
    .await;
    let declaration = manifest(&cut);
    let old = produce_in(&mut connection, cut, dir.path(), declaration)
        .await
        .unwrap();
    let path = dir.path().join("old-cut.db");
    old.persist(&path).unwrap();
    let admitted = AdmittedMemberFile::open(
        &path,
        dir.path(),
        &context(MEMBER, old.manifest()),
        old.manifest(),
    )
    .unwrap();
    let instructions = serde_json::to_string(&admitted.objects("member_context").unwrap()).unwrap();
    assert!(instructions.contains("synthetic shared instructions before"));
    assert!(!instructions.contains("synthetic shared instructions after"));
    let record = admitted
        .objects("records")
        .unwrap()
        .into_iter()
        .find(|row| row["id"] == shared)
        .unwrap();
    assert_eq!(record["body"], "synthetic shared instructions before");
    sqlx::query("ROLLBACK")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    db.close().await;
}
async fn produce(db: &crate::Db, account: &str, directory: &Path) -> ProducedMemberFile {
    produce_ordinal(db, account, directory, 1).await
}
async fn produce_ordinal(
    db: &crate::Db,
    account: &str,
    directory: &Path,
    ordinal: i64,
) -> ProducedMemberFile {
    let mut conn = db.pool().acquire().await.unwrap();
    conn.close_on_drop();
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    let generation = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    let origin = crate::standby::kernel_v2::origin(&mut conn, &generation)
        .await
        .unwrap();
    let cut = super::super::tests::ready(capture_in(&mut conn, &origin, account).await.unwrap());
    let mut declaration = manifest(&cut);
    declaration.ordering = ReplicaOrdering::Scoped { ordinal };
    declaration.holding = HoldingDisclosureV2::member("scope-one".into(), ordinal);
    let result = produce_in(&mut conn, cut, directory, declaration)
        .await
        .unwrap();
    let staged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        staged, 0,
        "physical source helpers must not see logical TEMP views"
    );
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    result
}
async fn fixture(activate: bool) -> (tempfile::TempDir, crate::Db, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    let member = kernel::create_principal(&db, "account", "Member", MEMBER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "edit")],
    )
    .await
    .unwrap();
    let other = kernel::create_principal(&db, "account", "Other", OTHER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "edit"), (&other, "view")],
    )
    .await
    .unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &owner, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let documents = crate::v2_standard::document4_package();
    let document_identity = kernel::install_package_as(&db, &owner, &documents)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &documents,
        Some(&document_identity),
        &documents.declared_reads,
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (id, principal) in [
        ("person:owner", owner.clone()),
        ("person:member", member.clone()),
        ("person:other", other.clone()),
    ] {
        kernel::import_record_as(
            &db,
            &host,
            id,
            KERNEL_ROOT_ID,
            Some(&owner),
            &kernel::ImportRecordState {
                message_principal: Some(principal),
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: package.definitions[0].family.clone(),
                        version: package.definitions[0].version,
                        digest: package.definitions[0].digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        "Entity",
                        "person",
                        Some(id),
                        None,
                        None,
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    if activate {
        super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    }
    (dir, db, owner, member)
}
#[tokio::test]
async fn native_profile_matches_live_current_relations_for_each_member() {
    let (dir, db, owner, member) = fixture(false).await;
    // Ordinary shared and private homes, plus owner-floor and hidden-home
    // placement, use kernel production primitives without projection edits.
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&owner, "manage")]), &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(&db, &owner, &private, &[(&owner, "manage")])
        .await
        .unwrap();
    for package in [
        crate::v2_standard::document4_package(),
        crate::v2_standard::v1_compat::package(),
    ] {
        let identity = package.identity().unwrap();
        kernel::adopt_package_at(
            &db,
            &owner,
            &private,
            &package,
            Some(&identity),
            &package.declared_reads,
        )
        .await
        .unwrap();
    }
    let shared = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Shared","body":"shared body","home_id":KERNEL_ROOT_ID})).await["id"].as_str().unwrap().to_owned();
    let secret = call(&db, OWNER, "create_record", json!({"type":"Document","kind":"note","name":"Secret","body":"private body","home_id":private})).await["id"].as_str().unwrap().to_owned();
    let comment = call(&db, OWNER, "create_record", json!({"type":"Annotation","kind":"comment","body":"synthetic private comment","links":[{"target_id":secret,"relationship":"part_of"}],"reason":"Synthetic member-copy derived proof"})).await["id"].as_str().unwrap().to_owned();
    let mut attachment_ids = vec![];
    for bearer in [&shared, &secret] {
        let result = call(&db, OWNER, "attach_text", json!({"record_id":bearer,"text":format!("attachment for {bearer}"),"filename":"proof.txt","mime":"text/plain"})).await;
        attachment_ids.push(result["attachment_id"].as_str().unwrap().to_owned());
    }
    // Other members' Directs remain hidden even from a root manager. This
    // tests both directions rather than assuming owner always sees everything.
    let mut direct_ids = vec![];
    for (account, person) in [(OWNER, "person:owner"), (MEMBER, "person:member")] {
        let result = call(&db, account,"manage_messages",json!({"action":"send","id":uuid::Uuid::new_v4().to_string(),"body":format!("synthetic direct {account}"),"addressed_to":["person:other"],"origin":{"type":"direct","participant_ids":[person,"person:other"]},"expectation":"reply","idempotency_key":format!("direct-{account}"),"reason":"Synthetic member-copy visibility proof"})).await;
        direct_ids.push(result["id"].as_str().unwrap().to_owned());
    }
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    // A stale shared home cannot make a hidden bearer's derived row visible.
    for (id, home, owner_id, typ, kind) in [
        (
            "derived-hidden",
            KERNEL_ROOT_ID,
            owner.as_str(),
            "Annotation",
            "highlight",
        ),
        (
            "owned-hidden-home",
            private.as_str(),
            member.as_str(),
            "Document",
            "note",
        ),
    ] {
        kernel::import_record_as(
            &db,
            &host,
            id,
            home,
            Some(owner_id),
            &kernel::ImportRecordState {
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: package.definitions[0].family.clone(),
                        version: package.definitions[0].version,
                        digest: package.definitions[0].digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        typ,
                        kind,
                        Some(id),
                        None,
                        None,
                    ),
                }),
                body: Some("synthetic derived body".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    kernel::import_generic_link_as(
        &db,
        &host,
        &kernel::GenericLink {
            link_id: uuid::Uuid::new_v4().to_string(),
            source_id: "derived-hidden".into(),
            target_id: secret.clone(),
            relationship: "part_of".into(),
            note: None,
            created_at: "2026-10-22T00:00:00Z".into(),
            actor: None,
        },
    )
    .await
    .unwrap();
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    for account in [OWNER, MEMBER, OTHER] {
        let produced = produce(&db, account, dir.path()).await;
        assert_eq!(
            produced.manifest().producer.name,
            crate::standby::kernel_v2::ENGINE
        );
        assert_eq!(produced.manifest().producer.schema_version, 0);
        let admitted = AdmittedMemberFile::open(
            produced.builder._file.path(),
            dir.path(),
            &context(account, produced.manifest()),
            produced.manifest(),
        )
        .unwrap();
        if account == MEMBER {
            let bytes = std::fs::read(produced.builder._file.path()).unwrap();
            assert!(!bytes
                .windows(private.len())
                .any(|w| w == private.as_bytes()));
            assert!(!bytes
                .windows(b"private body".len())
                .any(|w| w == b"private body"));
            let hidden = format!("synthetic direct {OWNER}");
            assert!(!bytes.windows(hidden.len()).any(|w| w == hidden.as_bytes()));
        }
        for sql in [
            "SELECT person_id,display_name FROM viewer",
            "SELECT count(*) AS n FROM viewer",
        ] {
            let offline = query::execute(&admitted, json!({"sql":sql})).unwrap();
            let online = call(&db, account, "query_sql", json!({"sql":sql})).await;
            assert_eq!(offline["rows"], online["rows"]);
            assert_eq!(offline["rows"].as_array().unwrap().len(), 1);
            if sql.contains("count(*)") {
                assert_eq!(offline["rows"][0]["n"], 1);
            }
        }
        let copied = admitted.relation("records").unwrap();
        let ids: BTreeSet<_> = copied
            .iter()
            .map(|r| match &r[0] {
                Value::Text(id) => id.clone(),
                _ => panic!("id"),
            })
            .collect();
        assert!(ids.contains(&shared));
        assert_eq!(ids.contains(&secret), account == OWNER);
        assert_eq!(ids.contains("derived-hidden"), account == OWNER);
        assert_eq!(ids.contains(&comment), account == OWNER);
        assert_eq!(
            ids.contains(&direct_ids[0]),
            account == OWNER || account == OTHER
        );
        assert_eq!(
            ids.contains(&direct_ids[1]),
            account == MEMBER || account == OTHER
        );
        let attachments = admitted.relation("member_attachments").unwrap();
        assert_eq!(attachments.len(), if account == OWNER { 2 } else { 1 });
        assert!(attachments
            .iter()
            .any(|r| r[0] == Value::Text(attachment_ids[0].clone())));
        // Also compare to public live query_sql, not just its staging helper.
        let online = call(
            &db,
            account,
            "query_sql",
            json!({"sql":"SELECT id,home_id FROM records ORDER BY id"}),
        )
        .await;
        let mut offline: Vec<_> = copied.iter().map(|row| { let Value::Text(id)=&row[0] else {panic!("id")};
            let columns=tables().into_iter().find(|(n,_)|n=="records").unwrap().1;
            let home=&row[columns.iter().position(|c|c=="home_id").unwrap()];
            json!({"id":id,"home_id":match home { Value::Text(s)=>Json::String(s.clone()), Value::Null=>Json::Null,_=>panic!("home") }})
        }).collect();
        offline.sort_by_key(|row| row["id"].as_str().unwrap().to_owned());
        assert_eq!(online["rows"], Json::Array(offline));
        let actor = kernel::resolve_principal_by_binding(&db, account)
            .await
            .unwrap()
            .unwrap()
            .0;
        let mut conn = db.pool().acquire().await.unwrap();
        conn.close_on_drop();
        sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
        let reads = tables()
            .into_iter()
            .filter(|(n, _)| {
                ![
                    "member_attachments",
                    "member_context",
                    "member_record_metadata",
                    "member_mentions",
                    "schema_config",
                    "facet_keys",
                ]
                .contains(&n.as_str())
            })
            .flat_map(|(n, c)| c.into_iter().map(move |c| (n.clone(), c)))
            .collect();
        crate::mcp::kernel_v2::sql::install(&mut conn, &actor, &reads)
            .await
            .unwrap();
        for (name, columns) in tables().into_iter().filter(|(n, _)| {
            ![
                "member_attachments",
                "member_context",
                "member_record_metadata",
                "member_mentions",
                "schema_config",
                "facet_keys",
            ]
            .contains(&n.as_str())
        }) {
            let rows = sqlx::query(&format!("SELECT {} FROM temp.{name}", quoted(&columns)))
                .fetch_all(&mut *conn)
                .await
                .unwrap();
            let mut live = rows
                .iter()
                .map(|row| {
                    (0..columns.len())
                        .map(|i| cell(row, i).unwrap())
                        .collect::<Vec<_>>()
                })
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>();
            let mut copy = admitted
                .relation(&name)
                .unwrap()
                .iter()
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>();
            live.sort();
            copy.sort();
            assert_eq!(copy, live, "{name}");
        }
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    }
    db.close().await;
}
#[tokio::test]
async fn native_profile_refuses_other_member_canonical_tamper_and_survives_candidate_replacement() {
    let (dir, db, _, _) = fixture(true).await;
    let produced = produce(&db, OWNER, dir.path()).await;
    let m = produced.manifest();
    let ctx = context(OWNER, m);
    assert!(AdmittedMemberFile::open(
        produced.builder._file.path(),
        dir.path(),
        &context(MEMBER, m),
        m
    )
    .is_err());
    // Match B's envelope and the offered A file's byte pin. The per-file
    // identity must still refuse independently of transport and byte hashes.
    let peer = produce(&db, MEMBER, dir.path()).await;
    let mut foreign_offer = peer.manifest().clone();
    foreign_offer.bytes = m.bytes.clone();
    assert!(matches!(
        AdmittedMemberFile::open(
            produced.builder._file.path(),
            dir.path(),
            &context(MEMBER, &foreign_offer),
            &foreign_offer
        ),
        Err(Refusal::Identity)
    ));
    // Close the canonical source before offering its standalone bytes. The
    // kernel writer fence intentionally refuses an ad-hoc pooled checkpoint.
    db.close().await;
    let source_path = dir.path().join("source.db");
    let bytes = std::fs::read(&source_path).unwrap();
    let mut canonical_offer = m.clone();
    canonical_offer.bytes.sha256 = hash(&bytes);
    canonical_offer.bytes.size_bytes = bytes.len() as u64;
    assert!(matches!(
        AdmittedMemberFile::open(&source_path, dir.path(), &ctx, &canonical_offer),
        Err(Refusal::Identity)
    ));

    let admitted =
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, m).unwrap();
    let before = admitted.relation("records").unwrap();
    produced
        .builder
        .connection
        .execute(
            "UPDATE kernel_member_identity SET generation_id='changed'",
            [],
        )
        .unwrap();
    assert!(AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, m).is_err());
    assert_eq!(admitted.relation("records").unwrap(), before);
    db.close().await;
}
#[tokio::test]
async fn native_profile_ranges_require_final_live_authority_and_catalog_check() {
    let (dir, db, owner, member) = fixture(true).await;
    let mut produced = produce(&db, MEMBER, dir.path()).await;
    assert!(produced.range(&db, 0, 128, || async { true }).await.is_ok());
    assert_eq!(
        produced.range(&db, 0, 128, || async { false }).await,
        Err(Refusal::Authorization)
    );
    kernel::replace_home_policy(&db, &owner, KERNEL_ROOT_ID, &[(&owner, "manage")])
        .await
        .unwrap();
    assert_eq!(
        produced.range(&db, 0, 128, || async { true }).await,
        Err(Refusal::Authorization)
    );
    assert!(
        !kernel::kernel_effective_capability(&db, &member, KERNEL_ROOT_ID)
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
    );
    db.close().await;
}

async fn call(db: &crate::Db, account: &str, name: &str, args: Json) -> Json {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(account),
            name,
            args,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn saved_tabs_member_files_and_vaults_exclude_other_accounts_private_state() {
    let (dir, db, owner, _) = fixture(true).await;
    let package = crate::v2_standard::saved_tabs::package();
    let identity = kernel::install_package_as(&db, &owner, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let mut tabs = Vec::new();
    for (account, secret) in [
        (OWNER, "owner-private-saved-tab-secret"),
        (MEMBER, "member-private-saved-tab-secret"),
    ] {
        let created = call(&db, account, "manage_saved_tabs", json!({"action":"create","creation_key":"private-working-slot","app":"agent.docs","initial_record_id":null,"reason":"export boundary proof"})).await;
        let tab = &created["tab"];
        let renamed = call(&db, account, "manage_saved_tabs", json!({"action":"rename","record_id":tab["record_id"],"expected_revision":tab["revision"],"operation_id":"private-title","custom_title":secret,"reason":"export boundary proof"})).await;
        tabs.push((
            account,
            renamed["tab"]["record_id"].as_str().unwrap().to_owned(),
            secret,
        ));
    }
    for (index, (account, own_id, _)) in tabs.iter().enumerate() {
        let (_, foreign_id, foreign_secret) = &tabs[1 - index];
        let produced = produce(&db, account, dir.path()).await;
        let physical = &produced.builder.connection;
        let own_count: i64 = physical
            .query_row("SELECT count(*) FROM records WHERE id=?", [own_id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(own_count, 1, "caller retains its own Configuration record");
        let foreign_count: i64 = physical
            .query_row(
                "SELECT count(*) FROM records WHERE id=?",
                [foreign_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(foreign_count, 0);
        for excluded in [
            "kernel_saved_tabs",
            "kernel_saved_tab_operations",
            "kernel_record_fields",
            "content_events",
        ] {
            let count: i64 = physical
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name=?",
                    [excluded],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 0,
                "member file excludes canonical relation {excluded}"
            );
        }
        let bytes = std::fs::read(produced.builder._file.path()).unwrap();
        for secret in [foreign_id.as_str(), *foreign_secret] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "foreign private state must not enter SQLite pages"
            );
        }
        let vault = crate::markdown_vault::kernel_v2::snapshot(&db, account)
            .await
            .unwrap();
        assert!(vault.records.contains_key(own_id));
        assert!(!vault.records.contains_key(foreign_id));
        let rendered = serde_json::to_string(&vault.records).unwrap();
        assert!(!rendered.contains(foreign_secret));
    }
    db.close().await;
}

#[tokio::test]
async fn native_profile_final_authorization_runs_after_the_catalog_await() {
    let (dir, db, owner, _) = fixture(true).await;
    let mut produced = produce(&db, MEMBER, dir.path()).await;
    let result = produced
        .range(&db, 0, 128, || async {
            kernel::replace_home_policy(&db, &owner, KERNEL_ROOT_ID, &[(&owner, "manage")])
                .await
                .unwrap();
            true
        })
        .await;
    assert_eq!(result, Err(Refusal::Authorization));
    db.close().await;
}

#[tokio::test]
async fn native_profile_checks_closed_schema_semantics_and_physical_readonly_handle() {
    let (dir, db, _, _) = fixture(true).await;
    let produced = produce(&db, OWNER, dir.path()).await;
    let mut m = produced.manifest().clone();
    let ctx = context(OWNER, &m);
    let admitted =
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &m).unwrap();
    for change in ["delta", "media", "v1"] {
        let mut wrong = m.clone();
        match change {
            "delta" => wrong.materialization = StandbyGenerationMaterialization::Delta,
            "media" => wrong.bytes.media_type = "text/plain".into(),
            _ => {
                wrong.producer.name = "native-ce".into();
                wrong.producer.schema_version = 90;
            }
        }
        assert!(matches!(
            AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &wrong),
            Err(Refusal::Schema)
        ));
    }
    assert!(admitted
        .connection
        .is_readonly(rusqlite::DatabaseName::Main)
        .unwrap());
    assert!(admitted
        .connection
        .execute("DELETE FROM main.records", [])
        .is_err());
    produced
        .builder
        .connection
        .execute("UPDATE main.records SET name='synthetic changed value'", [])
        .unwrap();
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    m.bytes.sha256 = hash(&bytes);
    m.bytes.size_bytes = bytes.len() as u64;
    assert!(matches!(
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &m),
        Err(Refusal::Content)
    ));
    produced
        .builder
        .connection
        .execute("CREATE TABLE unreviewed_payload(value TEXT)", [])
        .unwrap();
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    m.bytes.sha256 = hash(&bytes);
    m.bytes.size_bytes = bytes.len() as u64;
    assert!(matches!(
        AdmittedMemberFile::open(produced.builder._file.path(), dir.path(), &ctx, &m),
        Err(Refusal::Schema)
    ));
    db.close().await;
}

#[tokio::test]
async fn native_profile_admission_crash_residue_is_removed_by_member_purge() {
    use crate::member_copy_lifecycle::{MemberCopyLifecycle, ReconnectAnswer, RevokedCause};
    let (dir, db, _, _) = fixture(true).await;
    let produced = produce(&db, MEMBER, dir.path()).await;
    let admitted = AdmittedMemberFile::open(
        produced.builder._file.path(),
        dir.path(),
        &context(MEMBER, produced.manifest()),
        produced.manifest(),
    )
    .unwrap();
    let AdmittedMemberFile {
        connection,
        expected: _,
        principal: _,
        read_snapshots: _,
        _file,
    } = admitted;
    drop(connection);
    // Simulate process death: close the descriptor without running tempfile's
    // unlink cleanup. The real lifecycle must discover the plaintext residue.
    let (file, residue) = _file.keep().unwrap();
    drop(file);
    assert_eq!(residue.parent(), Some(dir.path()));
    assert!(residue.exists());
    let mut lifecycle = MemberCopyLifecycle::open(dir.path()).unwrap();
    lifecycle
        .sign_in(
            MEMBER,
            ReconnectAnswer::Replace {
                cut_at: "2026-10-22T00:00:00Z".into(),
            },
        )
        .unwrap();
    lifecycle
        .apply_reconnect(ReconnectAnswer::Revoked {
            cause: RevokedCause::MembershipEnded,
        })
        .unwrap();
    assert!(!residue.exists());
    db.close().await;
}

async fn assert_private_capsule_excluded(canvas: bool) {
    let (dir, db, owner, _) = fixture(false).await;
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&owner, "manage")]), &owner)
        .await
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    let id = if canvas {
        "private-canvas-proof"
    } else {
        "private-app-proof"
    };
    let secret = if canvas {
        "private-canvas-object-canary"
    } else {
        "private-app-state-canary"
    };
    kernel::import_record_as(
        &db,
        &host,
        id,
        &home,
        Some(&owner),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: package.definitions[0].family.clone(),
                    version: package.definitions[0].version,
                    digest: package.definitions[0].digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Document",
                    if canvas { "canvas" } else { "artifact" },
                    Some(secret),
                    None,
                    None,
                ),
            }),
            body: Some(secret.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut state = kernel::app_state::RetainedAppState::default();
    if canvas {
        state
            .canvas_objects
            .push(json!({"canvas_id":id,"object_id":"synthetic-object","props":secret}));
    } else {
        state
            .artifact_inputs
            .push(json!({"artifact_id":id,"slot":"synthetic-slot","value":secret}));
    }
    kernel::app_state::import_as(&db, &host, id, "synthetic-origin", &state)
        .await
        .unwrap();
    let retained: String =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id=?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(retained.contains(secret));
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER]).await;
    let sql = format!("SELECT id FROM records WHERE id='{id}'");
    assert_eq!(
        call(&db, OWNER, "query_sql", json!({"sql":sql})).await["rows"],
        json!([{"id":id}])
    );
    assert_eq!(
        call(&db, MEMBER, "query_sql", json!({"sql":sql})).await["rows"],
        json!([])
    );
    let produced = produce(&db, MEMBER, dir.path()).await;
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    for excluded in [id, secret, home.as_str()] {
        assert!(!bytes
            .windows(excluded.len())
            .any(|w| w == excluded.as_bytes()));
    }
    db.close().await;
}
#[tokio::test]
async fn native_profile_excludes_invisible_app_state() {
    assert_private_capsule_excluded(false).await;
}
#[tokio::test]
async fn native_profile_excludes_invisible_canvases_and_objects() {
    assert_private_capsule_excluded(true).await;
}

#[tokio::test]
async fn native_profile_bytes_exclude_other_members_emails_accounts_and_principals() {
    let (dir, db, owner, _) = fixture(false).await;
    let account = "acct_00000000000000000000000000000004";
    let email = "synthetic-private-member@example.test";
    let principal = kernel::create_principal(&db, "account", email, account, &owner)
        .await
        .unwrap();
    super::super::tests::activate(&db, OWNER, &[OWNER, MEMBER, OTHER, account]).await;
    let produced = produce(&db, MEMBER, dir.path()).await;
    let bytes = std::fs::read(produced.builder._file.path()).unwrap();
    let other = kernel::resolve_principal_by_binding(&db, OTHER)
        .await
        .unwrap()
        .unwrap()
        .0;
    for excluded in [
        email,
        account,
        principal.as_str(),
        OWNER,
        OTHER,
        owner.as_str(),
        other.as_str(),
    ] {
        assert!(!bytes
            .windows(excluded.len())
            .any(|w| w == excluded.as_bytes()));
    }
    db.close().await;
}

#[tokio::test]
async fn native_profile_registry_additive_reopen_and_concurrent_ordinals() {
    use crate::member_copy_registry::{MemberCopyRegistry, RegistryConfig, ScopeRefKey};
    async fn open(directory: &Path) -> MemberCopyRegistry {
        MemberCopyRegistry::open(RegistryConfig {
            store_dir: directory.to_owned(),
            scope_ref_key: ScopeRefKey::new([7; 32]),
            lease_ttl: std::time::Duration::from_secs(3600),
            hosted_route_database_id: "route-test".into(),
            consumer: test_consumer(),
        })
        .await
        .unwrap()
    }
    let dir = tempfile::tempdir().unwrap();
    let reg = open(dir.path()).await;
    drop(reg);
    let old = Connection::open(dir.path().join("registry.db")).unwrap();
    old.execute_batch("INSERT INTO member_copy_current VALUES ('legacy-scope','legacy-generation','retained'); DROP TABLE native_member_downloads; DROP TABLE native_member_ordinals;").unwrap();
    drop(old);
    let first = open(dir.path()).await;
    let connection = Connection::open(dir.path().join("registry.db")).unwrap();
    let retained: String = connection
        .query_row(
            "SELECT generation_id FROM member_copy_current WHERE scope_ref='legacy-scope'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, "legacy-generation");
    drop(connection);
    assert!(
        first
            .native_download("missing", "account", "scope", "route-test")
            .await
            .unwrap()
            .is_none(),
        "additive download DDL installed"
    );
    let second = open(dir.path()).await;
    let (left, right) = tokio::join!(
        first.allocate_native_ordinal("native-scope"),
        second.allocate_native_ordinal("native-scope")
    );
    let mut ordinals = [left.unwrap(), right.unwrap()];
    ordinals.sort();
    assert_eq!(ordinals, [1, 2]);
    drop((first, second));
    let reopened = open(dir.path()).await;
    assert_eq!(
        reopened
            .allocate_native_ordinal("native-scope")
            .await
            .unwrap(),
        3,
        "durable ordinal cannot regress after reopen"
    );
    let connection = Connection::open(dir.path().join("registry.db")).unwrap();
    let retained: String = connection
        .query_row(
            "SELECT generation_id FROM member_copy_current WHERE scope_ref='legacy-scope'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, "legacy-generation");
}
