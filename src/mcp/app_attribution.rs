//! Host-asserted app attribution for app contract v2 (task `50f5aca`).
//!
//! An installed v2 app acts with exactly the installing user's authority
//! (decision `48e1ff9`): there is no per-app scope. What changes is the
//! record. Every accepted action an app makes carries a row in
//! `provenance_action_app_attributions` beside its action attestation, so
//! "everything this app did" is a join through `provenance_action_outputs` to
//! the events, and a later undo can select it.
//!
//! At hosted ingress, the host (the alpha shell) sets
//! `X-Native-App` on a cookie-session, same-origin tool call; the frame can
//! never set headers. Hosting parses it with [`parse_header`] and attaches the
//! claim with [`crate::mcp::registry::Caller::with_host_asserted_app`]. No
//! tool argument can populate it. The engine then re-checks the claim against
//! the account's install table before dispatch ([`admit`]) and again inside
//! the write transaction that records it ([`record_in`]), so a claim naming
//! an install that is unknown, foreign, unadopted, removed, or not v2 never
//! reaches a handler and never lands in the table.
//!
//! The read-only owner standby also accepts the same identity string through
//! `tools/call` request metadata `native/app`. Desktop main owns the transport
//! and selected account; the engine runs the same install and app admission
//! against the admitted copy. This grants no writable-stdio ingress and never
//! widens a standby read, logical SQL relation, or account boundary.

use futures::future::BoxFuture;
use serde_json::Value;
use sqlx::{Sqlite, Transaction};

use crate::db::Db;
use crate::error::{Error, Result};

/// The header the host sets on an app's tool call:
/// `X-Native-App: <package>@<version>; install=<install_event_id>`.
pub const HEADER: &str = "x-native-app";

/// The only assertion kind recorded today: the hosted shell vouched for the
/// app over a cookie session with a same-host Origin.
pub const ASSERTION_HOST: &str = "host";

/// Operations refused for app-attributed calls, mirroring the host's final
/// list (`appHost`, PR #2038) as defence in depth. `(tool, None)` refuses
/// the whole tool; `(tool, Some(action))` refuses only a call whose
/// `arguments.action` is a string exactly equal to `action`.
///
/// - egress: the engine would carry data off the device on the app's behalf
///   (fetching an app-chosen URL, external connectors, invitations and guest
///   links to outside addresses);
/// - consent: installing, adopting or granting stays a human act;
/// - run lifecycle: the host owns the run, so an app cannot close it.
///
/// Names are registered tool names. Every path into a handler, including an
/// executor's inner operation, reaches [`admit`] with the source tool name.
pub const APP_REFUSED_OPERATIONS: [(&str, Option<&str>); 11] = [
    ("attach_from_url", None),
    ("resolve_external", None),
    ("observe_external", None),
    ("reach_connect", None),
    ("reach_read", None),
    ("manage_alpha_tabs", None),
    ("manage_artifact_module_grants", None),
    ("manage_artifact_inputs", None),
    ("close_run", None),
    ("manage_memberships", Some("invitations_send")),
    ("manage_memberships", Some("create_guest_link")),
];

/// Whether [`APP_REFUSED_OPERATIONS`] refuses this call.
pub fn app_refuses(operation: &str, arguments: &Value) -> bool {
    let action = arguments.get("action").and_then(Value::as_str);
    APP_REFUSED_OPERATIONS.iter().any(|(tool, refused_action)| {
        *tool == operation
            && match refused_action {
                None => true,
                Some(refused) => action == Some(*refused),
            }
    })
}

const MAX_PACKAGE_LEN: usize = 200;
const MAX_VERSION_LEN: usize = 64;
const MAX_EVENT_ID_LEN: usize = 128;

/// One app's claimed identity on one call: the exact install generation the
/// host launched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppAttribution {
    pub package: String,
    pub version: String,
    pub install_event_id: String,
}

impl AppAttribution {
    pub fn new(
        package: impl Into<String>,
        version: impl Into<String>,
        install_event_id: impl Into<String>,
    ) -> Result<Self> {
        let attribution = Self {
            package: package.into(),
            version: version.into(),
            install_event_id: install_event_id.into(),
        };
        if !token_ok(&attribution.package, MAX_PACKAGE_LEN, false)
            || !token_ok(&attribution.version, MAX_VERSION_LEN, false)
            || !token_ok(&attribution.install_event_id, MAX_EVENT_ID_LEN, true)
        {
            return Err(Error::engine("app attribution is malformed"));
        }
        Ok(attribution)
    }
}

/// A package, version or event id: printable ASCII, no whitespace, and none
/// of the header's own delimiters. `@` may appear in an event id only (the
/// package/version split is on the last `@`).
fn token_ok(value: &str, max_len: usize, allow_at: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b';' | b'=' | b',' | b'"' | b'\\')
                || (allow_at && byte == b'@')
        })
        && (allow_at || !value.contains('@'))
}

/// Parse `<package>@<version>; install=<install_event_id>`. Anything else,
/// including an unknown or repeated parameter, is malformed.
pub fn parse_header(raw: &str) -> Result<AppAttribution> {
    let malformed = || Error::engine("X-Native-App header is malformed");
    let mut parts = raw.split(';');
    let identity = parts.next().ok_or_else(malformed)?.trim();
    let (package, version) = identity.rsplit_once('@').ok_or_else(malformed)?;
    let mut install = None;
    for parameter in parts {
        let (key, value) = parameter.trim().split_once('=').ok_or_else(malformed)?;
        if key.trim() != "install" || install.is_some() {
            return Err(malformed());
        }
        install = Some(value.trim());
    }
    AppAttribution::new(package, version, install.ok_or_else(malformed)?).map_err(|_| malformed())
}

/// Shared install predicate: an installed, verified-adopted v2 install of
/// this account at exactly this package, version and install generation.
/// The install row's consented declaration, if this account holds an
/// installed, verified-adopted install at exactly this package, version and
/// install generation. Whether it is v2 is decided in Rust by
/// [`is_v2_declaration`], through I3's single contract rule.
const INSTALL_DECLARATION_SQL: &str = "SELECT consented_declaration FROM alpha_tab_installs
        WHERE account_id = ? AND package = ? AND version = ? AND event_id = ?
          AND status = 'installed'
          AND adoption IN ('shell_adopt.v1','shell_auto.v1')";

/// A stored consented declaration marks a v2 install: I3's
/// [`is_app_v2_declaration`](crate::mcp::tools::alpha_tabs::is_app_v2_declaration)
/// (`contract == APP_CONTRACT_V2`), with
/// [`validate_declaration_contract`](crate::alpha_tab_sessions::validate_declaration_contract)
/// re-run on the stored bytes as defence in depth. A missing row, unparsable
/// JSON, a v1 declaration or a v2 marker carrying declarations is not v2.
fn is_v2_declaration(stored: Option<&str>) -> bool {
    let Some(declaration) = stored.and_then(|raw| serde_json::from_str::<Value>(raw).ok()) else {
        return false;
    };
    crate::mcp::tools::alpha_tabs::is_app_v2_declaration(&declaration)
        && crate::alpha_tab_sessions::validate_declaration_contract(&declaration).is_ok()
}

/// Engine-side admission for an app-attributed call, before the handler.
///
/// Refuses an operation on [`APP_REFUSED_OPERATIONS`], refuses every
/// non-SQLite engine (only the SQLite store records attributions), and
/// refuses a claim that does not name a current, adopted v2 install of the
/// caller's own account.
///
/// Returns a boxed future built in this function's own frame, so the
/// dispatch poll frame that awaits it carries only a pointer: the dispatch
/// path sits close to the worker-stack budget in debug builds.
#[inline(never)]
pub(crate) fn admit<'a>(
    db: Option<&'a Db>,
    account_id: &'a str,
    operation: &'a str,
    arguments: &'a Value,
    attribution: &'a AppAttribution,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        if app_refuses(operation, arguments) {
            return Err(Error::engine(format!(
                "{operation} is not available to apps (app_operation_refused)"
            )));
        }
        let Some(db) = db else {
            return Err(Error::engine(
                "app attribution is recorded only by the SQLite store (app_attribution_unsupported)",
            ));
        };
        if !install_is_current(db, account_id, attribution).await? {
            return Err(unknown_install());
        }
        Ok(())
    })
}

/// Whether `account_id` holds a current, adopted v2 install of exactly this
/// package, version and install generation: the predicate [`admit`] enforces,
/// for callers that need the verdict rather than the tool-call error (a live
/// session classifies a lapsed install itself). Boxed for the same reason as
/// [`admit`].
#[inline(never)]
pub(crate) fn install_is_current<'a>(
    db: &'a Db,
    account_id: &'a str,
    attribution: &'a AppAttribution,
) -> BoxFuture<'a, Result<bool>> {
    Box::pin(async move {
        let stored: Option<String> = bind_install(
            sqlx::query_scalar(INSTALL_DECLARATION_SQL),
            account_id,
            attribution,
        )
        .fetch_optional(db.pool())
        .await?;
        Ok(is_v2_declaration(stored.as_deref()))
    })
}

fn unknown_install() -> Error {
    Error::engine(
        "X-Native-App does not name an adopted v2 install of this account (app_install_unknown)",
    )
}

/// Native apps act as their authenticated user. This dispatch check is only
/// preflight: admitted handlers repeat consent/source checks on their actual
/// read snapshot or mutation transaction, including accepted receipt retries.
#[cfg(feature = "v2-kernel-probe")]
#[inline(never)]
pub(crate) fn admit_kernel_v2<'a>(
    db: &'a Db,
    account: &'a str,
    operation: &'a str,
    arguments: &'a Value,
    attribution: &'a AppAttribution,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        if app_refuses(operation, arguments) {
            return Err(Error::engine(format!(
                "{operation} is not available to apps (app_operation_refused)"
            )));
        }
        // Each admitted write below owns native atomic attribution. Inbox
        // reads re-admit on their snapshot and derive the viewer from the
        // authenticated principal, preserving ordinary member visibility.
        // Keep unported handlers closed rather than returning un-attributed success.
        let messaging = operation == "manage_messages"
            && matches!(
                arguments["action"].as_str(),
                Some(
                    "send"
                        | "list_inbox"
                        | "list_message_state"
                        | "set_preference"
                        | "list_destinations"
                        | "set_destination"
                        | "mutate_human_awareness"
                        | "mark_no_longer_relevant"
                        | "unmark_no_longer_relevant"
                )
            );
        let package_read = cfg!(feature = "package-cel-dev")
            && matches!(
                operation,
                "describe_package_operations" | "call_package_operation"
            );
        if !messaging
            && !package_read
            && !matches!(
                operation,
                "get_record"
                    | "query_record"
                    | "whats_changed"
                    | "query_sql"
                    | "get_history"
                    | "search"
                    | "render_artifact"
                    | "invoke_artifact_interaction"
                    | "read_attachment"
                    | "manage_attachments"
                    | "read_canvas"
                    | "manage_canvas"
                    | "attach_text"
                    | "create_record"
                    | "update_record"
                    | "manage_links"
                    | "archive_record"
            )
        {
            return Err(Error::engine(format!(
                "{operation} is not yet available to native apps (app_operation_unsupported_on_v2)"
            )));
        }
        crate::kernel::app_installs::admit_account_app_as(db, account, attribution).await?;
        Ok(())
    })
}

fn bind_install<'q, O>(
    query: sqlx::query::QueryScalar<'q, Sqlite, O, sqlx::sqlite::SqliteArguments<'q>>,
    account_id: &'q str,
    attribution: &'q AppAttribution,
) -> sqlx::query::QueryScalar<'q, Sqlite, O, sqlx::sqlite::SqliteArguments<'q>> {
    query
        .bind(account_id.trim())
        .bind(&attribution.package)
        .bind(&attribution.version)
        .bind(&attribution.install_event_id)
}

/// Record the app beside one freshly inserted action attestation, inside the
/// same write transaction. The install is re-checked here so an install
/// removed between admission and commit aborts the write instead of
/// recording a stale claim.
///
/// Boxed in its own frame for the same reason as [`admit`]: every attestation
/// insert awaits it.
#[inline(never)]
pub(crate) fn record_in<'a>(
    tx: &'a mut Transaction<'static, Sqlite>,
    action_attestation_id: &'a str,
    account_id: &'a str,
    attribution: &'a AppAttribution,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let stored: Option<String> = bind_install(
            sqlx::query_scalar(INSTALL_DECLARATION_SQL),
            account_id,
            attribution,
        )
        .fetch_optional(&mut **tx)
        .await?;
        if !is_v2_declaration(stored.as_deref()) {
            return Err(unknown_install());
        }
        sqlx::query(
            "INSERT INTO provenance_action_app_attributions
                (action_attestation_id, package, version, install_event_id, assertion)
             VALUES (?,?,?,?,?)",
        )
        .bind(action_attestation_id)
        .bind(&attribution.package)
        .bind(&attribution.version)
        .bind(&attribution.install_event_id)
        .bind(ASSERTION_HOST)
        .execute(&mut **tx)
        .await?;
        Ok(())
    })
}

/// One output of an action a v2 app's call produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppActionOutput {
    pub action_attestation_id: String,
    /// `content` or `relationship`.
    pub output_domain: String,
    pub output_event_id: String,
    pub version: String,
    pub install_event_id: String,
    /// Act of the output event, the coordinate an undo rewinds to.
    pub act: Option<i64>,
}

/// Everything one account's installs of one app produced, content and
/// relationship outputs alike, ordered by act (then attestation and event id
/// for a stable order). This is the engine-side selector "undo everything
/// this app did" builds on (task `650d8700`).
///
/// Scoped to `(account, package)` through the attestation's principal, so
/// another account's install of the same package is never selected, and an
/// invalidated attestation attributes nothing (as in `content_event_apps`).
/// It applies no caller visibility beyond that: it reads the provenance
/// tables directly, so the undo path must authorize what it acts on. Callers
/// that need a caller-relative view use `query_sql`'s `content_event_apps`,
/// which is content-only. Relationship outputs are qualified by the
/// attestation's issuer origin exactly as `attested_act_in` does, so a
/// foreign relationship event that shares an id is never selected.
pub async fn app_action_outputs(
    db: &Db,
    account_id: &str,
    package: &str,
) -> Result<Vec<AppActionOutput>> {
    let mut conn = db.pool().acquire().await?;
    app_action_outputs_on(&mut conn, account_id, package).await
}

/// [`app_action_outputs`] on a caller-supplied connection, so undo can select
/// inside the same write transaction that reverts.
pub(crate) async fn app_action_outputs_on(
    conn: &mut sqlx::SqliteConnection,
    account_id: &str,
    package: &str,
) -> Result<Vec<AppActionOutput>> {
    let rows: Vec<(String, String, String, String, String, Option<i64>)> = sqlx::query_as(
        "WITH attributed AS (
             SELECT app.action_attestation_id, app.version, app.install_event_id,
                    a.issuer_origin_database_id
               FROM provenance_action_app_attributions AS app
               JOIN provenance_action_attestations AS a ON a.id = app.action_attestation_id
              WHERE app.package = ?1 AND a.principal = ?2
                AND NOT EXISTS (
                      SELECT 1 FROM provenance_attestation_validity_events AS v
                       WHERE v.attestation_id = a.id
                         AND v.status = 'invalidated'
                         AND v.ordinal = (SELECT MAX(v2.ordinal)
                                            FROM provenance_attestation_validity_events AS v2
                                           WHERE v2.attestation_id = v.attestation_id)))
         SELECT o.action_attestation_id, o.output_domain, o.output_event_id,
                t.version, t.install_event_id, e.act
           FROM attributed AS t
           JOIN provenance_action_outputs AS o
             ON o.action_attestation_id = t.action_attestation_id
           JOIN content_events AS e
             ON o.output_domain = 'content' AND e.id = o.output_event_id
         UNION ALL
         SELECT o.action_attestation_id, o.output_domain, o.output_event_id,
                t.version, t.install_event_id, e.act
           FROM attributed AS t
           JOIN provenance_action_outputs AS o
             ON o.action_attestation_id = t.action_attestation_id
           JOIN relationship_events AS e
             ON o.output_domain = 'relationship' AND e.id = o.output_event_id
            AND e.issuer_origin_db_id = t.issuer_origin_database_id
          ORDER BY 6, 1, 3",
    )
    .bind(package)
    .bind(account_id.trim())
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                action_attestation_id,
                output_domain,
                output_event_id,
                version,
                install_event_id,
                act,
            )| {
                AppActionOutput {
                    action_attestation_id,
                    output_domain,
                    output_event_id,
                    version,
                    install_event_id,
                    act,
                }
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refusal_list_matches_tools_and_exact_actions_only() {
        for tool in [
            "attach_from_url",
            "resolve_external",
            "observe_external",
            "reach_connect",
            "reach_read",
            "manage_alpha_tabs",
            "manage_artifact_module_grants",
            "manage_artifact_inputs",
            "close_run",
        ] {
            assert!(app_refuses(tool, &json!({})), "{tool}");
            assert!(app_refuses(tool, &json!({"action": "list"})), "{tool}");
        }
        for action in ["invitations_send", "create_guest_link"] {
            assert!(app_refuses(
                "manage_memberships",
                &json!({"action": action})
            ));
        }
        for args in [
            json!({}),
            json!({"action": "list"}),
            json!({"action": "invitations_send "}),
            json!({"action": "INVITATIONS_SEND"}),
            json!({"action": ["invitations_send"]}),
            json!({"action": {"name": "create_guest_link"}}),
        ] {
            assert!(!app_refuses("manage_memberships", &args), "{args}");
        }
        assert!(!app_refuses("manage_messages", &json!({"action": "send"})));
        assert!(!app_refuses("query_sql", &json!({})));
    }

    #[test]
    fn v2_declaration_follows_the_i3_contract_rule() {
        assert!(is_v2_declaration(Some(
            r#"{"contract":"native.app.v2","needs":[],"effects":[]}"#
        )));
        for stored in [
            None,
            Some("not json"),
            Some(r#"{"needs":[],"effects":[]}"#),
            Some(r#"{"contract":"native.app.v3","needs":[],"effects":[]}"#),
            Some(r#"{"contract":"native.app.v2","needs":["attention.query.v1"],"effects":[]}"#),
            Some(r#"{"contract":"native.app.v2","needs":[],"effects":[],"sessions":[]}"#),
        ] {
            assert!(!is_v2_declaration(stored), "{stored:?}");
        }
    }

    #[test]
    fn parses_the_agreed_header_shape() {
        let parsed = parse_header("agent.slack-workspace@0.4.0; install=evt-1").unwrap();
        assert_eq!(parsed.package, "agent.slack-workspace");
        assert_eq!(parsed.version, "0.4.0");
        assert_eq!(parsed.install_event_id, "evt-1");
        let spaced = parse_header("  a.b@1.0.0-rc.1 ;install = e  ").unwrap();
        assert_eq!(spaced.version, "1.0.0-rc.1");
        assert_eq!(spaced.install_event_id, "e");
    }

    #[test]
    fn refuses_malformed_headers() {
        for raw in [
            "",
            "a.b",
            "a.b@",
            "@1.0.0; install=e",
            "a.b@1.0.0",
            "a.b@1.0.0; install=",
            "a.b@1.0.0; install=e; install=f",
            "a.b@1.0.0; other=e",
            "a.b@1.0.0; install=e f",
            "a b@1.0.0; install=e",
            "a.b@1.0.0; install=\"e\"",
        ] {
            assert!(parse_header(raw).is_err(), "{raw:?} should be refused");
        }
        let long = format!("{}@1; install=e", "p".repeat(MAX_PACKAGE_LEN + 1));
        assert!(parse_header(&long).is_err());
    }
}
