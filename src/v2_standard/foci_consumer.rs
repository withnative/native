//! Consumer-side enforcement for `native.foci/foci@1` (gated increment 2).
//!
//! This module operates on plain values (serde_json values or small structs)
//! shaped like the stored v2 records. It adds no kernel primitives, no
//! storage or MCP wiring, and no hosted registration or migration.
//!
//! What this is: consumer-side enforcement, a **weaker contract** than v1's
//! store-level JSON-Schema validation. The `/5` store accepts structurally
//! valid values with malformed colours, ids or app strings that v1 refused
//! at the store; this module refuses them at read/write time instead. Full
//! parity needs host-defined text formats (Richard's decision A, §4.6):
//! the store-level string rules wait for G9, which is a prerequisite for
//! migrating real data. Until then no store-level string parity is claimed.
//!
//! No write-time graph invariant is claimed either: `member_of`/`parent`
//! cardinality, atomic create-with-link and cycle freedom across writers are
//! host-serialised concerns (G3/G5). The functions below check one
//! caller-supplied snapshot at a time; concurrent writers can still disagree.
//!
//! Personal-only: every rule here assumes one person's private Foci. No
//! sharing, audience or ownership check lives in this module.
//!
//! Stand-ins until G1: there is no archive primitive yet, so "archived" is
//! an explicit `bool` input on the consumer's view of a record, and
//! "invisible"/"unavailable" are explicit input sets. Callers supply them;
//! this module never reads record metadata or access policy.
//!
//! Deferred to app/host (rules 5.1.6-8 are app/host concerns):
//! - 5.1.6 Tracker acceptance (supported fields, one sort, `group_by`
//!   `"status"`): structural acceptance here is not app acceptance. A
//!   schema-maximal `query_view` (8 sorts, 16 terms) passes this module and
//!   is still refused by Tracker on open.
//! - 5.1.7 `record_view` open-time resolution (app install, target access):
//!   the target is data here, never authority.
//! - 5.1.8 archived-remove retry (event-free no-op after fresh proof):
//!   retry and CAS live in the host, not here.
//!
//! Name rule: v1 canonical form is copied from the shell/host, not
//! reinvented: collapse each run of whitespace to one space and trim, then
//! require the input to already equal that form, 1-60 code points, no
//! control characters. See [`canonical_name`] for the v1 line citations.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// A consumer refusal: which rule fired and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Short rule tag, e.g. `"name"`, `"order-duplicate"`, `"wire-version"`.
    pub rule: &'static str,
    /// Human-readable detail, including the value path where useful.
    pub message: String,
}

impl Refusal {
    pub(crate) fn new(rule: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.rule, self.message)
    }
}

impl std::error::Error for Refusal {}

/// Maximum live views in one Focus order, and maximum preference entries.
pub const MAX_ORDER: usize = 128;
/// Maximum filter terms in a `query_view` (structural; `/5` enforces it too).
pub const MAX_TERMS: usize = 16;
/// Maximum sorts in a `query_view` (structural; `/5` enforces it too).
pub const MAX_SORTS: usize = 8;

// ---------------------------------------------------------------------------
// Small hand-written matchers. Exact patterns come from the v1 evidence file
// `docs/evidence/foci-hosted-v1/configuration-shapes.json`; no regex crate
// is needed for these closed shapes.
// ---------------------------------------------------------------------------

/// `^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$`
/// (v1 evidence: focus ids, `view_order` items, preference `focus_id`).
/// Lowercase only, like v1: uppercase hex is refused.
pub fn is_uuid_v4v7(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            14 => {
                if *c != b'4' && *c != b'7' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() || c.is_ascii_uppercase() {
                    return false;
                }
            }
        }
    }
    true
}

/// `^#[0-9a-fA-F]{6}$` (v1 evidence: focus `colour`).
pub fn is_hex_colour(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 7 && b[0] == b'#' && b[1..].iter().all(|c| c.is_ascii_hexdigit())
}

fn is_app_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`, `≤128` (v1 evidence: `app`).
pub fn is_app_id(s: &str) -> bool {
    if s.is_empty() || s.chars().count() > 128 {
        return false;
    }
    let mut labels = s.split('.');
    match labels.next() {
        Some(first) if !first.is_empty() => {
            if !is_app_label(first) {
                return false;
            }
        }
        _ => return false,
    }
    let mut count = 1;
    for label in labels {
        count += 1;
        if label.is_empty() || !is_app_label(label) {
            return false;
        }
    }
    count >= 2
}

/// `^[a-z][a-z0-9-]*/[1-9][0-9]*$`, `≤64` (v1 evidence: query `format`).
pub fn is_format_id(s: &str) -> bool {
    if s.is_empty() || s.chars().count() > 64 {
        return false;
    }
    let Some((name, version)) = s.split_once('/') else {
        return false;
    };
    if version.is_empty() || !is_app_label(name) {
        return false;
    }
    let mut digits = version.bytes();
    match digits.next() {
        Some(b'1'..=b'9') => (),
        _ => return false,
    }
    digits.all(|c| c.is_ascii_digit())
}

/// `^[a-z][a-z0-9_]*$`, `≤64` (v1 evidence: term/sort `field`, `group_by`).
pub fn is_field_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// `^(uuid-v4v7|native:[a-z][a-z0-9-]*)$` (v1 evidence: `record_id` target).
pub fn is_record_locator(s: &str) -> bool {
    if is_uuid_v4v7(s) {
        return true;
    }
    let Some(token) = s.strip_prefix("native:") else {
        return false;
    };
    let b = token.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// V1's `\S` presence rule (v1 evidence: optional `text`, term `value`):
/// the string holds at least one character outside JS `\s` (see
/// [`is_v1_space`]). Rust's `char::is_whitespace` is close but not the
/// same set (notably U+0085): v1 parity needs the JS set.
pub fn has_nonblank(s: &str) -> bool {
    s.chars().any(|c| !is_v1_space(c))
}

// ---------------------------------------------------------------------------
// Names (§5.1.5). Canonical form matches v1 exactly:
// - `experiments/demo-shell/public/lib/fociPersistence.js` `validateFocusName`
//   (FP:424-429): `normal = name.trim().replace(/\s+/g, " ")`; refuse when
//   code-point length is 0 or >60, when `/[\u0000-\u001f\u007f]/` matches the
//   raw input, or when `normal !== name`.
// - `web/shell/src/fociDurable.ts` `cleanName` (FD:69-73): same rule as
//   `v.replace(/\s+/g, " ").trim()`, `cpLen(n) <= 60`, no controls, and the
//   input already canonical.
// JS `\s` is matched here as the explicit ASCII run plus the Unicode spaces
// in its class (see DECISIONS in the final report); controls are exactly
// U+0000-U+001F and U+007F, like v1.
// ---------------------------------------------------------------------------

/// Whitespace in v1's JS `\s` class, exactly: U+0009–U+000D, U+0020, U+00A0,
/// U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF.
/// Notably NOT U+0085 (NEL): in v1 `/\s/` never matches it, so an
/// NEL-only string is nonblank and a FEFF-only string is blank.
fn is_v1_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\x0B' | '\x0C' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// V1 canonical form: collapse each whitespace run to one space, trim ends.
pub fn canonical_name_form(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if is_v1_space(c) {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

fn is_v1_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}')
}

/// Validate a Focus or saved-view name: canonical form, 1-60 code points,
/// control characters refused. Returns the name unchanged on success.
pub fn validate_name(s: &str) -> Result<&str, Refusal> {
    if s.chars().any(is_v1_control) {
        return Err(Refusal::new("name", "name holds a control character"));
    }
    if s != canonical_name_form(s) {
        return Err(Refusal::new(
            "name",
            "name is not canonical: single spaces, no leading/trailing space",
        ));
    }
    let len = s.chars().count();
    if len == 0 || len > 60 {
        return Err(Refusal::new("name", "name is 1-60 code points"));
    }
    Ok(s)
}

#[cfg(test)]
mod string_tests {
    use super::*;

    #[test]
    fn uuid_accepts_v4_and_v7_lowercase_only() {
        assert!(is_uuid_v4v7("550e8400-e29b-41d4-a716-446655440000")); // v4
        assert!(is_uuid_v4v7("0193f9f2-7c1e-7f2a-9b3c-4d5e6f7a8b9c")); // v7
        assert!(!is_uuid_v4v7("550e8400-e29b-11d4-a716-446655440000")); // v1
        assert!(!is_uuid_v4v7("550E8400-E29B-41D4-A716-446655440000")); // upper
        assert!(!is_uuid_v4v7("550e8400e29b41d4a716446655440000")); // no dashes
        assert!(!is_uuid_v4v7("not-a-uuid"));
        assert!(!is_uuid_v4v7(""));
    }

    #[test]
    fn colour_is_hash_plus_six_hex() {
        assert!(is_hex_colour("#112233"));
        assert!(is_hex_colour("#aAbBcC"));
        assert!(!is_hex_colour("112233"));
        assert!(!is_hex_colour("#12345"));
        assert!(!is_hex_colour("#1234567"));
        assert!(!is_hex_colour("#gggggg"));
    }

    #[test]
    fn app_ids_need_two_labels() {
        assert!(is_app_id("agent.tracker"));
        assert!(is_app_id("fixture.docs-2"));
        assert!(!is_app_id("tracker")); // one label
        assert!(!is_app_id("Agent.tracker")); // capital
        assert!(!is_app_id(".tracker")); // empty label
        assert!(!is_app_id("agent.")); // trailing dot
        assert!(!is_app_id("agent..tracker"));
        assert!(!is_app_id("agent_tracker.x")); // underscore
        let long = format!("a.{}.b", "x".repeat(125));
        assert!(!is_app_id(&long)); // over 128 chars
    }

    #[test]
    fn formats_are_name_slash_positive_int() {
        assert!(is_format_id("tracker-query/1"));
        assert!(is_format_id("tracker-start/12"));
        assert!(!is_format_id("tracker-query/0"));
        assert!(!is_format_id("tracker-query/"));
        assert!(!is_format_id("tracker-query"));
        assert!(!is_format_id("Tracker-query/1"));
        assert!(!is_format_id("a/b/c"));
    }

    #[test]
    fn fields_are_snake() {
        assert!(is_field_name("status"));
        assert!(is_field_name("updated_by_2"));
        assert!(!is_field_name("Status"));
        assert!(!is_field_name("with-dash"));
        assert!(!is_field_name("with space"));
        assert!(!is_field_name(""));
        assert!(!is_field_name(&"f".repeat(65)));
    }

    #[test]
    fn locators_are_uuid_or_native_token() {
        assert!(is_record_locator("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_record_locator("native:root"));
        assert!(is_record_locator("native:my-token-2"));
        assert!(!is_record_locator("native:Root"));
        assert!(!is_record_locator("native:"));
        assert!(!is_record_locator("other:root"));
        assert!(!is_record_locator(""));
    }
    #[test]
    fn names_follow_v1_canonical_form() {
        assert_eq!(validate_name("Now"), Ok("Now"));
        assert_eq!(validate_name("My focus 2"), Ok("My focus 2"));
        assert!(validate_name("").is_err());
        assert!(validate_name("  Now").is_err()); // leading space
        assert!(validate_name("Now ").is_err()); // trailing space
        assert!(validate_name("My  focus").is_err()); // double space
        assert!(validate_name("a\tb").is_err()); // tab collapses
        assert!(validate_name("a\nb").is_err());
        assert!(validate_name("a\u{0}b").is_err()); // control
        assert!(validate_name("a\u{7f}b").is_err()); // DEL
        assert!(validate_name(&"x".repeat(60)).is_ok());
        assert!(validate_name(&"x".repeat(61)).is_err());
        // 60 code points in multibyte chars still fits.
        assert!(validate_name(&"é".repeat(60)).is_ok());
        assert!(validate_name(&"é".repeat(61)).is_err());
    }

    #[test]
    fn nonblank_matches_js_whitespace_not_rust() {
        // FEFF is JS `\s`: a FEFF-only string is blank, like v1.
        assert!(!has_nonblank("\u{feff}"));
        assert!(!has_nonblank(" \t\n\u{a0}\u{2003}\u{feff}"));
        // U+0085 (NEL) is not JS `\s`: an NEL-only string is nonblank,
        // like v1, even though Rust's `char::is_whitespace` says otherwise.
        assert!("\u{85}".chars().all(|c| c.is_whitespace()));
        assert!(has_nonblank("\u{85}"));
        assert!(has_nonblank("x"));
        assert!(!has_nonblank(""));
        assert!(!has_nonblank("   "));
        // Canonicalisation uses the same set: FEFF trims and collapses.
        assert_eq!(canonical_name_form("\u{feff}a\u{feff}"), "a");
        assert_eq!(canonical_name_form("a\u{2003}\u{2003}b"), "a b");
    }
}

// ---------------------------------------------------------------------------
// Order (§5.1.1). Writes refuse; reads repair. `live_members` is the set of
// live saved-view ids with a live `member_of` edge to this Focus, supplied
// by the caller; "archived" is an explicit input (stand-in until G1).
// ---------------------------------------------------------------------------

/// Check admitting one more saved view to a Focus: an archived Focus and a
/// Focus that already holds 128 live views both refuse (v1 LF:194-199).
/// The limit counts live membership, not order length.
pub fn check_view_admission(live_member_count: usize, focus_archived: bool) -> Result<(), Refusal> {
    if focus_archived {
        return Err(Refusal::new(
            "order-archived",
            "archived Focus cannot receive a saved view",
        ));
    }
    if live_member_count >= MAX_ORDER {
        return Err(Refusal::new(
            "view-limit",
            format!("Focus already holds {live_member_count} live views: limit reached"),
        ));
    }
    Ok(())
}

/// Check a Focus order write: duplicates, non-members, an archived Focus,
/// an over-long order, and over-limit live membership are all refused.
/// The membership limit applies to live members, not order length: even an
/// empty order refuses when the Focus already holds 129 live views.
pub fn check_order_write(
    order: &[String],
    live_members: &HashSet<String>,
    focus_archived: bool,
) -> Result<(), Refusal> {
    if focus_archived {
        return Err(Refusal::new(
            "order-archived",
            "archived Focus cannot receive a saved view",
        ));
    }
    if live_members.len() > MAX_ORDER {
        return Err(Refusal::new(
            "order-limit",
            format!(
                "Focus holds {} live views, over the {MAX_ORDER} limit",
                live_members.len()
            ),
        ));
    }
    if order.len() > MAX_ORDER {
        return Err(Refusal::new(
            "order-limit",
            format!(
                "order holds {} ids, over the {MAX_ORDER} limit",
                order.len()
            ),
        ));
    }
    let mut seen = HashSet::with_capacity(order.len());
    for id in order {
        if !seen.insert(id) {
            return Err(Refusal::new(
                "order-duplicate",
                format!("duplicate order id {id}"),
            ));
        }
        if !live_members.contains(id) {
            return Err(Refusal::new(
                "order-unknown",
                format!("order id {id} is not a live member of this Focus"),
            ));
        }
    }
    Ok(())
}

/// A repaired read order. `anomaly` is `Some` only when the repaired list
/// exceeded 128 and was truncated: the excess is reported, never dropped
/// silently (§5.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedOrder {
    pub order: Vec<String>,
    pub dropped: Vec<String>,
    pub appended: Vec<String>,
    pub anomaly: Option<String>,
}

/// Repair a stored order on read: refuse duplicate ids for this Focus only
/// (the caller scopes the failure; the refresh of other foci continues),
/// drop ids that are not live members, then append missing members sorted
/// by record id (v1 FD:271-278). Over 128, show the first 128 and report
/// the excess as an anomaly.
pub fn repair_order_read(
    stored: &[String],
    live_members: &HashSet<String>,
) -> Result<RepairedOrder, Refusal> {
    let mut seen = HashSet::with_capacity(stored.len());
    for id in stored {
        if !seen.insert(id) {
            return Err(Refusal::new(
                "order-duplicate",
                format!("duplicate order id {id}: this Focus is refused"),
            ));
        }
    }
    let mut order = Vec::new();
    let mut dropped = Vec::new();
    for id in stored {
        if live_members.contains(id) {
            order.push(id.clone());
        } else {
            dropped.push(id.clone());
        }
    }
    let mut appended = Vec::new();
    let mut missing: Vec<&String> = live_members
        .iter()
        .filter(|id| !seen.contains(*id))
        .collect();
    missing.sort();
    for id in missing {
        order.push((*id).clone());
        appended.push((*id).clone());
    }
    let mut anomaly = None;
    if order.len() > MAX_ORDER {
        let excess: Vec<String> = order.drain(MAX_ORDER..).collect();
        anomaly = Some(format!(
            "repaired membership holds {} views, over the {MAX_ORDER} limit; \
             showing the first {MAX_ORDER}, excess: {}",
            MAX_ORDER + excess.len(),
            excess.join(","),
        ));
    }
    Ok(RepairedOrder {
        order,
        dropped,
        appended,
        anomaly,
    })
}

// ---------------------------------------------------------------------------
// Membership (§5.1.2, Decision D settled): exactly one live `member_of` edge
// per view. A view with zero or two edges is hidden on its own and reported
// as an anomaly; the refresh does not fail (unlike v1 FP:388-391, which
// failed the whole refresh).
// ---------------------------------------------------------------------------

/// Where one view lands after membership resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Membership {
    /// Exactly one live edge: the view shows under this Focus.
    Shown(String),
    /// Zero or two+ edges: hidden on its own, with the anomaly to report.
    Hidden(String),
}

/// Resolve one view's live `member_of` targets.
pub fn resolve_membership(view_id: &str, live_targets: &[String]) -> Membership {
    match live_targets {
        [only] => Membership::Shown(only.clone()),
        [] => Membership::Hidden(format!("view {view_id} has no live member_of edge: hidden")),
        _ => Membership::Hidden(format!(
            "view {view_id} names {} member_of parents: hidden, never first-wins",
            live_targets.len()
        )),
    }
}

/// Resolve a whole refresh: shown views per Focus, hidden views aside.
/// Never fails; every anomaly is collected for the caller to report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MembershipRefresh {
    pub shown: HashMap<String, Vec<String>>,
    pub hidden: Vec<String>,
    pub anomalies: Vec<String>,
}

pub fn resolve_membership_refresh(views: &[(String, Vec<String>)]) -> MembershipRefresh {
    let mut out = MembershipRefresh::default();
    for (view_id, targets) in views {
        match resolve_membership(view_id, targets) {
            Membership::Shown(focus) => {
                out.shown.entry(focus).or_default().push(view_id.clone());
            }
            Membership::Hidden(anomaly) => {
                out.hidden.push(view_id.clone());
                out.anomalies.push(anomaly);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Parent (§5.1.3). At most one `parent` edge, depth ≤1, no cycles (including
// self). An absent or invisible parent makes the Focus a presentation root,
// and the parent's metadata is never read: when the parent is not in
// `visible`, its own edges are not consulted at all.
// ---------------------------------------------------------------------------

/// Where one Focus lands in presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationParent {
    /// Presentation root: no parent shown.
    Root { anomaly: Option<String> },
    /// Shown nested under this visible parent.
    Child(String),
}

/// Resolve one Focus's presentation parent.
///
/// `parents` maps every known Focus id to its `parent` edges; `visible` is
/// the set of Foci the caller may show. Unknown ids count as invisible.
pub fn resolve_parent(
    focus_id: &str,
    parents: &HashMap<String, Vec<String>>,
    visible: &HashSet<String>,
) -> PresentationParent {
    let edges: &[String] = parents.get(focus_id).map_or(&[], Vec::as_slice);
    if edges.len() > 1 {
        return PresentationParent::Root {
            anomaly: Some(format!(
                "focus {focus_id} names {} parents: shown as root",
                edges.len()
            )),
        };
    }
    let Some(parent) = edges.first() else {
        return PresentationParent::Root { anomaly: None };
    };
    if parent == focus_id {
        return PresentationParent::Root {
            anomaly: Some(format!("focus {focus_id} is its own parent: shown as root")),
        };
    }
    // Absent or invisible parent: presentation root, and the parent's
    // metadata is never read (its edges are not consulted below).
    if !visible.contains(parent) {
        return PresentationParent::Root { anomaly: None };
    }
    // Walk up from the visible parent: any revisit is a cycle, and any
    // chain longer than one edge is depth >1 (v1 FD:264-268 refuses
    // self-parents, cycles and grand-children alike). Both make this Focus
    // a root with an anomaly. Visibility is checked before every ancestor
    // lookup: an invisible or absent ancestor ends the chain there, and its
    // edges are never read. In particular an invisible grandparent means
    // the visible parent is itself a presentation root, so this Focus is
    // depth 1 and shows as its child.
    let mut chain = vec![focus_id.to_string()];
    let mut cursor = parent.clone();
    loop {
        if !visible.contains(&cursor) {
            break;
        }
        if chain.contains(&cursor) {
            return PresentationParent::Root {
                anomaly: Some(format!(
                    "focus {focus_id} sits in a parent cycle at {cursor}: shown as root"
                )),
            };
        }
        chain.push(cursor.clone());
        let next: &[String] = parents.get(&cursor).map_or(&[], Vec::as_slice);
        if next.len() != 1 {
            // No single onward edge: the chain ends here (an ancestor with
            // zero or two edges is its own violation, not this Focus's).
            break;
        }
        cursor = next[0].clone();
        // Bounded: a chain longer than every known Focus must repeat.
        if chain.len() > parents.len() + 1 {
            return PresentationParent::Root {
                anomaly: Some(format!(
                    "focus {focus_id} sits in a parent cycle at {cursor}: shown as root"
                )),
            };
        }
    }
    if chain.len() > 2 {
        return PresentationParent::Root {
            anomaly: Some(format!(
                "focus {focus_id} nests below {parent}, depth over 1: shown as root"
            )),
        };
    }
    PresentationParent::Child(parent.clone())
}

#[cfg(test)]
mod graph_tests {
    use super::*;

    fn set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn order_write_refuses_duplicates_unknown_archived_and_overflow() {
        let live = set(&["a", "b"]);
        assert!(check_order_write(&["a".into(), "b".into()], &live, false).is_ok());
        assert!(check_order_write(&[], &live, false).is_ok());
        let dup = check_order_write(&["a".into(), "a".into()], &live, false).unwrap_err();
        assert_eq!(dup.rule, "order-duplicate");
        let unknown = check_order_write(&["a".into(), "zzz".into()], &live, false).unwrap_err();
        assert_eq!(unknown.rule, "order-unknown");
        let archived = check_order_write(&["a".into()], &live, true).unwrap_err();
        assert_eq!(archived.rule, "order-archived");
        let big: Vec<String> = (0..129).map(|i| format!("v{i}")).collect();
        let big_live: HashSet<String> = big.iter().cloned().collect();
        let over = check_order_write(&big, &big_live, false).unwrap_err();
        assert_eq!(over.rule, "order-limit");
    }

    #[test]
    fn save_admission_and_live_membership_limits() {
        // Admission refuses at 128 live views, passes at 127 (v1 LF:194-199).
        assert!(check_view_admission(0, false).is_ok());
        assert!(check_view_admission(127, false).is_ok());
        assert_eq!(
            check_view_admission(128, false).unwrap_err().rule,
            "view-limit"
        );
        assert_eq!(
            check_view_admission(0, true).unwrap_err().rule,
            "order-archived"
        );
        // The order-write limit counts live members, not order length: an
        // empty order still refuses with 129 live members.
        let many: HashSet<String> = (0..129).map(|i| format!("v{i}")).collect();
        let refused = check_order_write(&[], &many, false).unwrap_err();
        assert_eq!(refused.rule, "order-limit");
        // 128 live members with a short order is fine.
        let full: HashSet<String> = (0..128).map(|i| format!("v{i}")).collect();
        assert!(check_order_write(&["v0".to_string()], &full, false).is_ok());
    }

    #[test]
    fn order_read_repairs_drop_append_and_reports_overflow() {
        // Drop unknown, append missing sorted by id.
        let live = set(&["b", "a", "c"]);
        let repaired = repair_order_read(&["b".into(), "gone".into()], &live).unwrap();
        assert_eq!(repaired.order, vec!["b", "a", "c"]);
        assert_eq!(repaired.dropped, vec!["gone"]);
        assert_eq!(repaired.appended, vec!["a", "c"]);
        assert_eq!(repaired.anomaly, None);
        // Duplicates refuse this Focus only.
        let dup = repair_order_read(&["a".into(), "a".into()], &live).unwrap_err();
        assert_eq!(dup.rule, "order-duplicate");
        // Repaired membership over 128: first 128 shown, excess reported.
        let many: HashSet<String> = (0..130).map(|i| format!("v{i:03}")).collect();
        let repaired = repair_order_read(&[], &many).unwrap();
        assert_eq!(repaired.order.len(), 128);
        assert_eq!(repaired.appended.len(), 130);
        let anomaly = repaired.anomaly.expect("overflow anomaly");
        assert!(
            anomaly.contains("v128") || anomaly.contains("v129"),
            "{anomaly}"
        );
        assert!(anomaly.contains("130"), "{anomaly}");
    }

    #[test]
    fn membership_zero_or_two_hides_only_that_view() {
        let out = resolve_membership_refresh(&[
            ("v1".into(), vec!["f1".into()]),
            ("v2".into(), vec![]),
            ("v3".into(), vec!["f1".into(), "f2".into()]),
            ("v4".into(), vec!["f2".into()]),
        ]);
        assert_eq!(out.shown.len(), 2);
        assert_eq!(out.shown["f1"], vec!["v1"]);
        assert_eq!(out.shown["f2"], vec!["v4"]);
        assert_eq!(out.hidden, vec!["v2", "v3"]);
        assert_eq!(out.anomalies.len(), 2);
    }

    #[test]
    fn parent_roots_absent_invisible_cycles_and_depth() {
        let visible = set(&["a", "b", "c", "d", "e", "f", "g", "h"]);
        let mut parents: HashMap<String, Vec<String>> = HashMap::new();
        parents.insert("a".into(), vec![]); // no parent: root, no anomaly
        parents.insert("b".into(), vec!["a".into()]); // child
        parents.insert("c".into(), vec!["missing".into()]); // absent: root
        parents.insert("d".into(), vec!["e".into()]); // self-parent
        parents.insert("e".into(), vec!["e".into()]);
        parents.insert("f".into(), vec!["g".into()]); // depth 2
        parents.insert("g".into(), vec!["a".into()]);
        parents.insert("h".into(), vec!["x".into(), "y".into()]); // two parents
        assert_eq!(
            resolve_parent("a", &parents, &visible),
            PresentationParent::Root { anomaly: None }
        );
        assert_eq!(
            resolve_parent("b", &parents, &visible),
            PresentationParent::Child("a".into())
        );
        assert_eq!(
            resolve_parent("c", &parents, &visible),
            PresentationParent::Root { anomaly: None }
        );
        assert!(matches!(
            resolve_parent("e", &parents, &visible),
            PresentationParent::Root { anomaly: Some(_) }
        ));
        assert!(matches!(
            resolve_parent("f", &parents, &visible),
            PresentationParent::Root { anomaly: Some(_) }
        ));
        assert!(matches!(
            resolve_parent("h", &parents, &visible),
            PresentationParent::Root { anomaly: Some(_) }
        ));
        // Invisible parent: root without anomaly, grandparent never consulted.
        let mut thin = HashMap::new();
        thin.insert("kid".into(), vec!["ghost".into()]);
        thin.insert("ghost".into(), vec!["kid".into()]); // cycle via ghost
        let narrow = set(&["kid"]);
        assert_eq!(
            resolve_parent("kid", &thin, &narrow),
            PresentationParent::Root { anomaly: None }
        );
        // Two-cycle between visible foci reports a cycle.
        let mut cyc = HashMap::new();
        cyc.insert("p".into(), vec!["q".into()]);
        cyc.insert("q".into(), vec!["p".into()]);
        let both = set(&["p", "q"]);
        let PresentationParent::Root { anomaly } = resolve_parent("p", &cyc, &both) else {
            panic!("expected root");
        };
        assert!(anomaly.expect("anomaly").contains("cycle"));
    }

    #[test]
    fn invisible_grandparent_ends_the_walk_unread() {
        // Visible a→b, b→invisible c. Whatever c's edges say (a cycle back
        // to a, an onward edge, or nothing), c is never read: a shows as
        // Child(b) at depth 1, and b is a clean root under its invisible
        // parent.
        let visible = set(&["a", "b"]);
        for c_edges in [
            vec!["a".to_string()],
            vec!["d".to_string()],
            vec![],
            vec!["x".to_string(), "y".to_string()],
        ] {
            let mut parents: HashMap<String, Vec<String>> = HashMap::new();
            parents.insert("a".into(), vec!["b".into()]);
            parents.insert("b".into(), vec!["c".into()]);
            parents.insert("c".into(), c_edges);
            assert_eq!(
                resolve_parent("a", &parents, &visible),
                PresentationParent::Child("b".into())
            );
            assert_eq!(
                resolve_parent("b", &parents, &visible),
                PresentationParent::Root { anomaly: None }
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Preferences (§5.1.4). No duplicate `focus_id`. A write refuses a newly
// supplied unavailable Focus id but drops previously known unavailable
// entries (v1 LF:214-217); reads ignore unavailable entries. Availability
// is a caller-supplied set (stand-in: no account or policy reads here).
// ---------------------------------------------------------------------------

/// One sidebar preference entry, mirroring the stored object shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferenceEntry {
    pub focus_id: String,
    pub tier: String,
    pub hidden: bool,
}

/// Check a preferences write. Returns the entries to store: unavailable ids
/// that were already known are dropped. Refuses duplicate `focus_id`,
/// over-long lists, and newly supplied unavailable ids.
pub fn check_preferences_write(
    entries: &[PreferenceEntry],
    available: &HashSet<String>,
    previously_known: &HashSet<String>,
) -> Result<Vec<PreferenceEntry>, Refusal> {
    if entries.len() > MAX_ORDER {
        return Err(Refusal::new(
            "preferences-limit",
            format!(
                "preferences hold {} entries, over the {MAX_ORDER} limit",
                entries.len()
            ),
        ));
    }
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        if !seen.insert(&entry.focus_id) {
            return Err(Refusal::new(
                "preferences-duplicate",
                format!("duplicate focus_id {}", entry.focus_id),
            ));
        }
        if !available.contains(&entry.focus_id) && !previously_known.contains(&entry.focus_id) {
            return Err(Refusal::new(
                "preferences-unavailable",
                format!("newly supplied focus {} is unavailable", entry.focus_id),
            ));
        }
    }
    Ok(entries
        .iter()
        .filter(|e| available.contains(&e.focus_id))
        .cloned()
        .collect())
}

/// Read preferences: ignore unavailable entries, keep sidebar order.
pub fn read_preferences(
    entries: &[PreferenceEntry],
    available: &HashSet<String>,
) -> Vec<PreferenceEntry> {
    entries
        .iter()
        .filter(|e| available.contains(&e.focus_id))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Stored-value string checks. These enforce the v1 string patterns and
// lengths that `/5` cannot express (§4.6; per Richard's decision A the
// store-level rules wait for G9, a prerequisite for migrating real data)
// on otherwise structurally valid stored values. Structure itself (required members,
// choices, bounds, no nested null) belongs to the `/5` validator; here a
// missing member or wrong JSON type is refused defensively with its path.
// ---------------------------------------------------------------------------

fn field_str<'a>(value: &'a Value, path: &str) -> Result<&'a str, Refusal> {
    value
        .as_str()
        .ok_or_else(|| Refusal::new("shape", format!("{path} is not a string")))
}

fn check_name(value: &Value, path: &str) -> Result<(), Refusal> {
    let name = field_str(value, path)?;
    validate_name(name)
        .map(|_| ())
        .map_err(|refusal| Refusal::new(refusal.rule, format!("{path}: {}", refusal.message)))
}

fn check_app(value: &Value, path: &str) -> Result<(), Refusal> {
    let app = field_str(value, path)?;
    if !is_app_id(app) {
        return Err(Refusal::new(
            "app",
            format!("{path} {app:?} is not a dotted app id of 128 or fewer chars"),
        ));
    }
    Ok(())
}

fn check_format(value: &Value, path: &str) -> Result<(), Refusal> {
    let format = field_str(value, path)?;
    if !is_format_id(format) {
        return Err(Refusal::new(
            "format",
            format!("{path} {format:?} is not name/version of 64 or fewer chars"),
        ));
    }
    Ok(())
}

fn check_field(value: &Value, path: &str) -> Result<(), Refusal> {
    let field = field_str(value, path)?;
    if !is_field_name(field) {
        return Err(Refusal::new(
            "field",
            format!("{path} {field:?} is not a snake field of 64 or fewer chars"),
        ));
    }
    Ok(())
}

/// Present optional `text`: 1-512 chars and nonblank (v1 evidence).
fn check_text(value: &Value, path: &str) -> Result<(), Refusal> {
    let text = field_str(value, path)?;
    let len = text.chars().count();
    if len == 0 || len > 512 || !has_nonblank(text) {
        return Err(Refusal::new(
            "text",
            format!("{path} is empty, over 512 chars, or blank"),
        ));
    }
    Ok(())
}

/// Term `value`: 1-256 chars and nonblank (v1 evidence).
fn check_term_value(value: &Value, path: &str) -> Result<(), Refusal> {
    let text = field_str(value, path)?;
    let len = text.chars().count();
    if len == 0 || len > 256 || !has_nonblank(text) {
        return Err(Refusal::new(
            "term-value",
            format!("{path} is empty, over 256 chars, or blank"),
        ));
    }
    Ok(())
}

fn get<'a>(value: &'a Value, key: &str, path: &str) -> Result<&'a Value, Refusal> {
    value
        .get(key)
        .ok_or_else(|| Refusal::new("shape", format!("{path} is missing")))
}

/// String rules for a stored `focus` value: name, optional colour, order ids.
pub fn validate_focus_strings(value: &Value) -> Result<(), Refusal> {
    check_name(get(value, "name", "/name")?, "/name")?;
    if let Some(colour) = value.get("colour") {
        let colour = field_str(colour, "/colour")?;
        if !is_hex_colour(colour) {
            return Err(Refusal::new(
                "colour",
                format!("/colour {colour:?} is not #RRGGBB"),
            ));
        }
    }
    let order = get(value, "view_order", "/view_order")?;
    let items = order
        .as_array()
        .ok_or_else(|| Refusal::new("shape", "/view_order is not a list".to_string()))?;
    for (i, item) in items.iter().enumerate() {
        let id = field_str(item, &format!("/view_order/{i}"))?;
        if !is_uuid_v4v7(id) {
            return Err(Refusal::new(
                "order-id",
                format!("/view_order/{i} {id:?} is not a v4/v7 uuid"),
            ));
        }
    }
    Ok(())
}

/// String rules for a stored `record_view` value.
pub fn validate_record_view_strings(value: &Value) -> Result<(), Refusal> {
    check_name(get(value, "name", "/name")?, "/name")?;
    let definition = get(value, "definition", "/definition")?;
    check_app(
        get(definition, "app", "/definition/app")?,
        "/definition/app",
    )?;
    let target = get(definition, "target", "/definition/target")?;
    let record_id = field_str(
        get(target, "record_id", "/definition/target/record_id")?,
        "/definition/target/record_id",
    )?;
    if !is_record_locator(record_id) {
        return Err(Refusal::new(
            "target",
            format!("/definition/target/record_id {record_id:?} is not a uuid or native: token"),
        ));
    }
    Ok(())
}

/// String rules for a stored `query_view` value: app, format, fields,
/// lengths, and nonblank present-optional `text`. Structural acceptance
/// here is not Tracker acceptance (deferred, §5.1.6).
pub fn validate_query_view_strings(value: &Value) -> Result<(), Refusal> {
    check_name(get(value, "name", "/name")?, "/name")?;
    let definition = get(value, "definition", "/definition")?;
    check_app(
        get(definition, "app", "/definition/app")?,
        "/definition/app",
    )?;
    check_format(
        get(definition, "format", "/definition/format")?,
        "/definition/format",
    )?;
    if let Some(text) = definition.get("text") {
        check_text(text, "/definition/text")?;
    }
    let filter = get(definition, "filter", "/definition/filter")?;
    let terms = get(filter, "terms", "/definition/filter/terms")?;
    let terms = terms.as_array().ok_or_else(|| {
        Refusal::new(
            "shape",
            "/definition/filter/terms is not a list".to_string(),
        )
    })?;
    for (i, term) in terms.iter().enumerate() {
        check_field(
            get(
                term,
                "field",
                &format!("/definition/filter/terms/{i}/field"),
            )?,
            &format!("/definition/filter/terms/{i}/field"),
        )?;
        check_term_value(
            get(
                term,
                "value",
                &format!("/definition/filter/terms/{i}/value"),
            )?,
            &format!("/definition/filter/terms/{i}/value"),
        )?;
    }
    let sort = get(definition, "sort", "/definition/sort")?;
    let sort = sort
        .as_array()
        .ok_or_else(|| Refusal::new("shape", "/definition/sort is not a list".to_string()))?;
    for (i, entry) in sort.iter().enumerate() {
        check_field(
            get(entry, "field", &format!("/definition/sort/{i}/field"))?,
            &format!("/definition/sort/{i}/field"),
        )?;
    }
    if let Some(group_by) = definition.get("group_by") {
        check_field(group_by, "/definition/group_by")?;
    }
    Ok(())
}

/// String rules plus duplicate `focus_id` for stored `focus_preferences`.
pub fn validate_preferences_strings(value: &Value) -> Result<(), Refusal> {
    let foci = get(value, "foci", "/foci")?;
    let foci = foci
        .as_array()
        .ok_or_else(|| Refusal::new("shape", "/foci is not a list".to_string()))?;
    let mut seen = HashSet::with_capacity(foci.len());
    for (i, entry) in foci.iter().enumerate() {
        let id = field_str(
            get(entry, "focus_id", &format!("/foci/{i}/focus_id"))?,
            &format!("/foci/{i}/focus_id"),
        )?;
        if !is_uuid_v4v7(id) {
            return Err(Refusal::new(
                "focus-id",
                format!("/foci/{i}/focus_id {id:?} is not a v4/v7 uuid"),
            ));
        }
        if !seen.insert(id) {
            return Err(Refusal::new(
                "preferences-duplicate",
                format!("duplicate focus_id {id}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod preferences_tests {
    use super::*;
    use serde_json::json;

    fn entry(id: &str) -> PreferenceEntry {
        PreferenceEntry {
            focus_id: id.into(),
            tier: "now".into(),
            hidden: false,
        }
    }

    fn set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn write_refuses_new_unavailable_but_drops_known() {
        let available = set(&["a", "b"]);
        let known = set(&["gone"]);
        // Newly supplied unavailable id refuses.
        let refused =
            check_preferences_write(&[entry("a"), entry("new-ghost")], &available, &set(&[]));
        assert_eq!(refused.unwrap_err().rule, "preferences-unavailable");
        // Previously known unavailable entry is dropped, order kept.
        let stored =
            check_preferences_write(&[entry("b"), entry("gone"), entry("a")], &available, &known)
                .unwrap();
        assert_eq!(stored, vec![entry("b"), entry("a")]);
        // Duplicates refuse even when available.
        let dup = check_preferences_write(&[entry("a"), entry("a")], &available, &set(&[]));
        assert_eq!(dup.unwrap_err().rule, "preferences-duplicate");
        // Reads ignore unavailable entries.
        let read = read_preferences(&[entry("a"), entry("gone")], &available);
        assert_eq!(read, vec![entry("a")]);
    }

    #[test]
    fn every_moved_string_rule_refuses_at_the_consumer() {
        let good_focus = json!({"name": "Now", "colour": "#112233", "view_order": []});
        assert!(validate_focus_strings(&good_focus).is_ok());
        assert!(validate_focus_strings(&json!({"name": "x", "view_order": []})).is_ok());
        for (value, rule) in [
            (json!({"name": "  x", "view_order": []}), "name"),
            (
                json!({"name": "x", "colour": "red", "view_order": []}),
                "colour",
            ),
            (
                json!({"name": "x", "colour": "#12345", "view_order": []}),
                "colour",
            ),
            (
                json!({"name": "x", "view_order": ["not-a-uuid"]}),
                "order-id",
            ),
            (
                json!({"name": "x", "view_order": ["550E8400-E29B-41D4-A716-446655440000"]}),
                "order-id",
            ),
        ] {
            assert_eq!(validate_focus_strings(&value).unwrap_err().rule, rule);
        }

        let good_record = json!({"name": "Plan",
            "definition": {"app": "agent.docs", "target": {"record_id": "native:root"}}});
        assert!(validate_record_view_strings(&good_record).is_ok());
        for (value, rule) in [
            (
                json!({"name": "Plan",
                "definition": {"app": "docs", "target": {"record_id": "native:root"}}}),
                "app",
            ),
            (
                json!({"name": "Plan",
                "definition": {"app": "agent.docs", "target": {"record_id": "other:root"}}}),
                "target",
            ),
            (
                json!({"name": "Plan",
                "definition": {"app": "agent.docs", "target": {"record_id": "native:Root"}}}),
                "target",
            ),
        ] {
            assert_eq!(validate_record_view_strings(&value).unwrap_err().rule, rule);
        }

        let good_query = json!({"name": "Work", "definition": {
            "app": "agent.tracker", "format": "tracker-query/1",
            "filter": {"combine": "all", "terms": []}, "sort": []}});
        assert!(validate_query_view_strings(&good_query).is_ok());
        let with_text = json!({"name": "Work", "definition": {
            "app": "agent.tracker", "format": "tracker-query/1", "text": "urgent",
            "filter": {"combine": "all", "terms": []}, "sort": []}});
        assert!(validate_query_view_strings(&with_text).is_ok());
        for (value, rule) in [
            (
                json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query",
                "filter": {"combine": "all", "terms": []}, "sort": []}}),
                "format",
            ),
            (
                json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query/1", "text": "   ",
                "filter": {"combine": "all", "terms": []}, "sort": []}}),
                "text",
            ),
            (
                json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query/1",
                "filter": {"combine": "all",
                    "terms": [{"field": "Status", "op": "eq", "value": "open"}]},
                "sort": []}}),
                "field",
            ),
            (
                json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query/1",
                "filter": {"combine": "all",
                    "terms": [{"field": "status", "op": "eq", "value": ""}]},
                "sort": []}}),
                "term-value",
            ),
            (
                json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query/1",
                "filter": {"combine": "all", "terms": []},
                "sort": [{"field": "with-dash", "direction": "asc"}]}}),
                "field",
            ),
            (
                json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query/1",
                "filter": {"combine": "all", "terms": []}, "sort": [],
                "group_by": "Status"}}),
                "field",
            ),
        ] {
            assert_eq!(validate_query_view_strings(&value).unwrap_err().rule, rule);
        }

        let v4 = "550e8400-e29b-41d4-a716-446655440000";
        let good_prefs = json!({"foci": [{"focus_id": v4, "tier": "now", "hidden": false}]});
        assert!(validate_preferences_strings(&good_prefs).is_ok());
        assert!(validate_preferences_strings(&json!({"foci": []})).is_ok());
        let dup = json!({"foci": [
            {"focus_id": v4, "tier": "now", "hidden": false},
            {"focus_id": v4, "tier": "background", "hidden": true}]});
        assert_eq!(
            validate_preferences_strings(&dup).unwrap_err().rule,
            "preferences-duplicate"
        );
        let bad_id = json!({"foci": [{"focus_id": "x", "tier": "now", "hidden": false}]});
        assert_eq!(
            validate_preferences_strings(&bad_id).unwrap_err().rule,
            "focus-id"
        );
    }
}
