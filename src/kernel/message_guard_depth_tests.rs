//! Message guard depth (Native task 11ef0d8b; boundaries review 0c6eef5 F1
//! row 8; proposal 078116d §12).
//!
//! The guard used to fail closed for every Annotation/Document `part_of`
//! chain deeper than 8, whether or not the chain reached a Message. In a
//! workspace with any Message, a comment thread more than 8 replies deep was
//! hidden from everyone, owners included; the single-record path hid it even
//! in a workspace with no Messages at all.
//!
//! The rule these tests hold:
//! * a record whose `part_of` bearer closure reaches **no** Message is not
//!   restricted by the guard at any depth: it gets exactly its ordinary
//!   bearer visibility;
//! * a record whose closure reaches a Message keeps today's guard exactly,
//!   at any depth, including failing closed beyond depth 8 for everyone.
//!
//! Unchanged cases are compared, in the same snapshot, against a verbatim
//! copy of the pre-fix guard (`legacy_guard`). Fixtures are raw rows in a
//! fresh v2 database, borrowed from spike B (`spike/visibility-anchor-model`).

use super::app_installs::scope::{with_scope_override, AppScope};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const ROOT: &str = KERNEL_ROOT_ID;
/// Today's guard walk depth.
const GUARD_DEPTH: usize = 8;
/// A comment thread comfortably past the guard depth.
const DEEP: usize = 12;
/// A plain (non-derived) Document chain past the derived-bearer ceiling.
const VERY_DEEP: usize = crate::authorization::MAX_DERIVED_BEARER_DEPTH + 5;

struct Fx {
    db: Db,
    _dir: tempfile::TempDir,
    p: BTreeMap<&'static str, String>,
}

impl Fx {
    async fn new() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("guard.db").display()),
            "account",
            "Admin",
            "admin",
        )
        .await
        .unwrap();
        let mut p = BTreeMap::new();
        p.insert("admin", admin);
        Fx { db, _dir: dir, p }
    }

    fn id(&self, label: &str) -> String {
        self.p[label].clone()
    }

    async fn principal(&mut self, label: &'static str) {
        let admin = self.id("admin");
        let id = create_principal(&self.db, "account", label, label, &admin)
            .await
            .unwrap();
        self.p.insert(label, id);
    }

    async fn exec(&self, sql: &str, binds: &[&str]) {
        let mut conn = self.db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(*b);
        }
        let result = q.execute(&mut *conn).await;
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *conn)
            .await
            .unwrap();
        result.unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    async fn home(&self, id: &str, parent: &str) {
        self.exec(
            "INSERT INTO kernel_roots(root_id,parent_id,owner_id,created_seq,created_at) VALUES(?1,?2,NULL,1,'2026-11-13T00:00:00Z')",
            &[id, parent],
        )
        .await;
    }

    async fn policy(&self, home: &str, rows: &[(&str, &str, &str)]) {
        self.exec(
            "INSERT OR IGNORE INTO kernel_policies(root_id,created_at) VALUES(?,'2026-11-13T00:00:00Z')",
            &[home],
        )
        .await;
        self.exec("DELETE FROM kernel_policy_entries WHERE root_id=?", &[home])
            .await;
        for (subject, effect, cap) in rows {
            self.exec(
                "INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) VALUES(?,'account',?,?,?)",
                &[home, subject, effect, cap],
            )
            .await;
        }
    }

    async fn rec(&self, id: &str, home: &str, owner: &str) {
        self.exec(
            "INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) VALUES(?,?,?,1,'2026-11-13T00:00:00Z')",
            &[id, home, owner],
        )
        .await;
    }

    async fn message_carrier(&self, id: &str, home: &str, owner: &str) {
        let accession = format!("acc:{id}");
        self.exec(
            "INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,created_seq,created_at) VALUES(?,?,?,'Message','k',?,'native.messaging',1,'d',1,'2026-11-13T00:00:00Z')",
            &[id, home, owner, &accession],
        )
        .await;
    }

    async fn sealed_message(&self, id: &str, home: &str, owner: &str) {
        self.message_carrier(id, home, owner).await;
        let state = serde_json::json!({
            "audience": { owner: "manage" },
            "author": owner,
            "origin": "native",
            "addressed_to": [],
            "conversations": [],
            "reply_to": null,
            "expectation": null,
            "reactions": {},
            "private": {},
            "source": {},
            "speaker": null,
        })
        .to_string();
        self.exec(
            "INSERT INTO kernel_messages(message_id,state,event_seq) VALUES(?,?,1)",
            &[id, &state],
        )
        .await;
    }

    async fn field(&self, id: &str, name: &str, value: &str) {
        let json = serde_json::to_string(value).unwrap();
        self.exec(
            "INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) VALUES(?,?,?,1) ON CONFLICT(record_id,name) DO UPDATE SET value_json=excluded.value_json",
            &[id, name, &json],
        )
        .await;
    }

    async fn part_of(&self, source: &str, target: &str) {
        let link = Uuid::new_v4().to_string();
        self.exec(
            "INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,note,created_at,actor,active,event_seq,imported) VALUES(?,?,?,'part_of',NULL,'2026-11-13T00:00:00Z',NULL,1,1,0)",
            &[&link, source, target],
        )
        .await;
    }

    async fn comment(&self, id: &str, home: &str, owner: &str, bearer: &str) {
        self.rec(id, home, owner).await;
        self.field(id, "v1_type", "Annotation").await;
        self.field(id, "v1_kind", "comment").await;
        self.part_of(id, bearer).await;
    }

    /// A plain Document page: not a derived artifact, so it keeps its own
    /// home authority, but the guard still walks through it.
    async fn page(&self, id: &str, home: &str, owner: &str) {
        self.rec(id, home, owner).await;
        self.field(id, "v1_type", "Document").await;
        self.field(id, "v1_kind", "page").await;
    }

    /// `prefix00 .. prefix{n-1}`, each a reply to the previous, the first on
    /// `bearer`.
    async fn thread(&self, prefix: &str, n: usize, home: &str, owner: &str, bearer: &str) {
        let mut bearer = bearer.to_owned();
        for i in 0..n {
            let id = format!("{prefix}{i:02}");
            self.comment(&id, home, owner, &bearer).await;
            bearer = id;
        }
    }

    async fn page_chain(&self, prefix: &str, n: usize, home: &str, owner: &str, bearer: &str) {
        let mut bearer = bearer.to_owned();
        for i in 0..n {
            let id = format!("{prefix}{i:03}");
            self.page(&id, home, owner).await;
            self.part_of(&id, &bearer).await;
            bearer = id;
        }
    }

    async fn event(&self, record: &str, event_type: &str, payload: serde_json::Value) {
        let id = Uuid::new_v4().to_string();
        let payload = payload.to_string();
        self.exec(
            "INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,?,NULL,1,'complete')",
            &[&id, record, event_type, &payload],
        )
        .await;
    }

    async fn frontier(&self, home: &str) -> i64 {
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')")
            .bind(home)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
}

/// The pre-fix guard, verbatim (prepared-read form): the oracle for every
/// case this change must leave alone.
fn legacy_guard(alias: &str, actor: &str, homes: &str) -> String {
    let type_index = " INDEXED BY idx_kernel_read_type";
    format!(
        r#"CASE WHEN NOT EXISTS(SELECT 1 FROM kernel_messages known WHERE known.message_id={alias}.id)
        AND NOT EXISTS(SELECT 1 FROM kernel_records carrier WHERE carrier.id={alias}.id AND
          ((carrier.pin_family='native.v1.record' AND carrier.pin_version=1 AND EXISTS(SELECT 1 FROM kernel_record_fields f{type_index} WHERE f.record_id=carrier.id AND f.name='v1_type' AND f.value_json='"Message"'))
           OR (carrier.primary_type='Message' AND NOT coalesce(carrier.pin_family='native.v1.record' AND carrier.pin_version=1,0))))
        AND NOT EXISTS(SELECT 1 FROM kernel_generic_links l JOIN kernel_record_fields f{type_index} ON f.record_id=l.source_id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"') WHERE l.source_id={alias}.id AND l.active=1 AND l.relationship='part_of')
        THEN 1 ELSE NOT EXISTS(
      WITH RECURSIVE bearers(id,depth) AS (
        SELECT {alias}.id,0 UNION ALL
        SELECT l.target_id,b.depth+1 FROM bearers b
        JOIN kernel_generic_links l ON l.source_id=b.id AND l.active=1 AND l.relationship='part_of'
        JOIN kernel_record_fields f{type_index} ON f.record_id=b.id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"')
        WHERE b.depth<8)
      SELECT 1 FROM bearers b WHERE
        ((EXISTS(SELECT 1 FROM kernel_messages known WHERE known.message_id=b.id)
          OR EXISTS(SELECT 1 FROM kernel_records carrier WHERE carrier.id=b.id AND
            ((carrier.pin_family='native.v1.record' AND carrier.pin_version=1 AND EXISTS(SELECT 1 FROM kernel_record_fields f{type_index} WHERE f.record_id=b.id AND f.name='v1_type' AND f.value_json='"Message"'))
             OR (carrier.primary_type='Message' AND NOT coalesce(carrier.pin_family='native.v1.record' AND carrier.pin_version=1,0)))))
         AND NOT EXISTS(
            SELECT 1 FROM kernel_messages m JOIN kernel_records mr ON mr.id=m.message_id
            JOIN ({homes}) current_home ON current_home.id=mr.home_id
            WHERE m.message_id=b.id
            AND (current_home.view OR mr.owner_id={actor})
            AND NOT EXISTS(SELECT 1 FROM kernel_principals service WHERE service.principal_id={actor} AND service.auth_binding='host:relates-to:transform')
            AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones tomb WHERE tomb.record_id=mr.id)))
        OR (b.depth=8
          AND EXISTS(SELECT 1 FROM kernel_record_fields f{type_index} WHERE f.record_id=b.id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"'))
          AND EXISTS(SELECT 1 FROM kernel_generic_links l WHERE l.source_id=b.id AND l.active=1 AND l.relationship='part_of'))
    ) END"#
    )
}

const HAS_MESSAGES_SQL: &str = "SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')";

/// The folder-scoped app exclusion `query_sql` applies after the gate.
const SCOPED_MESSAGE_CLOSURE_SQL: &str = "WITH RECURSIVE excluded(id) AS (
   SELECT id FROM main.kernel_records WHERE primary_type='Message'
   UNION SELECT message_id FROM main.kernel_messages
   UNION SELECT record_id FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"'
   UNION SELECT l.source_id FROM main.kernel_generic_links l JOIN excluded e ON e.id=l.target_id
         WHERE l.relationship='part_of' AND l.active=1
 ) SELECT id FROM excluded";

/// One caller's view of every record, all in one read snapshot.
struct Views {
    /// The product bulk gate, behind the workspace message probe.
    gate: BTreeSet<String>,
    /// Today's gate: the legacy guard over the same unguarded predicate.
    legacy: BTreeSet<String>,
    /// Ordinary bearer visibility with no message guard at all.
    unguarded: BTreeSet<String>,
    /// The single-record path (`kernel_effective_capability_on` allows View),
    /// for unscoped callers only.
    single: Option<BTreeSet<String>>,
}

async fn views(db: &Db, principal: &str, folders: Option<&[&str]>) -> Views {
    let scoped = folders.is_some();
    let work = async {
        let mut tx = db.write_pool().begin().await.unwrap();
        let scope = visible_home_anchors_as(&mut tx, principal).await.unwrap();
        sqlx::query(
            "CREATE TEMP TABLE _guard_scopes(home_id TEXT, valid INTEGER, policy_view INTEGER)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        for home in &scope.homes {
            sqlx::query("INSERT INTO temp._guard_scopes VALUES(?,?,?)")
                .bind(&home.home_id)
                .bind(home.policy_valid)
                .bind(home.policy_view)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let homes = "SELECT home_id AS id,policy_view AS view FROM temp._guard_scopes WHERE valid";
        let has_messages: bool = sqlx::query_scalar(HAS_MESSAGES_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let unguarded_gate = sql_record_visible("r", "?1", homes, false);
        let gates = [
            sql_record_visible("r", "?1", homes, has_messages),
            format!(
                "({}) AND ({unguarded_gate})",
                if has_messages {
                    legacy_guard("r", "?1", homes)
                } else {
                    "1".into()
                }
            ),
            unguarded_gate.clone(),
        ];
        let excluded: BTreeSet<String> = if scoped {
            sqlx::query_scalar::<_, String>(SCOPED_MESSAGE_CLOSURE_SQL)
                .fetch_all(&mut *tx)
                .await
                .unwrap()
                .into_iter()
                .collect()
        } else {
            BTreeSet::new()
        };
        let mut sets = Vec::new();
        for gate in gates {
            let ids: BTreeSet<String> = sqlx::query_scalar::<_, String>(&format!(
                "SELECT r.id FROM main.kernel_records r WHERE {gate}"
            ))
            .bind(principal)
            .fetch_all(&mut *tx)
            .await
            .unwrap()
            .into_iter()
            .filter(|id| !excluded.contains(id))
            .collect();
            sets.push(ids);
        }
        let single = if scoped {
            None
        } else {
            let all: Vec<String> =
                sqlx::query_scalar("SELECT id FROM main.kernel_records ORDER BY id")
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap();
            let mut seen = BTreeSet::new();
            for id in all {
                if kernel_effective_capability_on(&mut tx, principal, &id)
                    .await
                    .unwrap()
                    .allows(Capability::View)
                {
                    seen.insert(id);
                }
            }
            Some(seen)
        };
        tx.rollback().await.unwrap();
        let mut sets = sets.into_iter();
        Views {
            gate: sets.next().unwrap(),
            legacy: sets.next().unwrap(),
            unguarded: sets.next().unwrap(),
            single,
        }
    };
    match folders {
        Some(folders) => {
            let folders = folders.iter().map(|f| f.to_string()).collect();
            with_scope_override(principal, AppScope::Folders(folders), work).await
        }
        None => work.await,
    }
}

/// Records whose Annotation/Document `part_of` bearer closure (the guard's
/// walk, unbounded) reaches a Message carrier or sealed Message. Computed
/// here in Rust, independently of the SQL under test.
async fn message_bearing(db: &Db) -> BTreeSet<String> {
    let mut conn = db.pool().acquire().await.unwrap();
    let walks: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT record_id FROM kernel_record_fields WHERE name='v1_type' AND value_json IN ('\"Annotation\"','\"Document\"')",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let messages: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT message_id FROM kernel_messages UNION SELECT id FROM kernel_records WHERE primary_type='Message' UNION SELECT record_id FROM kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"'",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let mut links: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (source, target) in sqlx::query_as::<_, (String, String)>(
        "SELECT source_id,target_id FROM kernel_generic_links WHERE active=1 AND relationship='part_of'",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap()
    {
        links.entry(source).or_default().push(target);
    }
    let all: Vec<String> = sqlx::query_scalar("SELECT id FROM kernel_records")
        .fetch_all(&mut *conn)
        .await
        .unwrap();
    let mut out = BTreeSet::new();
    for id in all {
        let mut seen = BTreeSet::from([id.clone()]);
        let mut frontier = vec![id.clone()];
        while let Some(node) = frontier.pop() {
            if messages.contains(&node) {
                out.insert(id.clone());
                break;
            }
            if walks.contains(&node) {
                for next in links.get(&node).into_iter().flatten() {
                    if seen.insert(next.clone()) {
                        frontier.push(next.clone());
                    }
                }
            }
        }
    }
    out
}

/// The callers: a member with access, the bearer owner, a restricted member,
/// an admin, the transform service, and a folder-scoped app.
fn callers(fx: &Fx) -> Vec<(&'static str, String, Option<&'static [&'static str]>)> {
    vec![
        ("admin", fx.id("admin"), None),
        ("member", fx.id("member"), None),
        ("owner", fx.id("owner"), None),
        ("restricted", fx.id("restricted"), None),
        ("transform", fx.id("transform"), None),
        ("member@f1", fx.id("member"), Some(&["f:one"])),
    ]
}

async fn world() -> Fx {
    let mut fx = Fx::new().await;
    for label in ["member", "owner", "restricted"] {
        fx.principal(label).await;
    }
    let transform: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding='host:relates-to:transform'",
    )
    .fetch_one(fx.db.pool())
    .await
    .unwrap();
    fx.p.insert("transform", transform.clone());
    let (admin, member, owner) = (fx.id("admin"), fx.id("member"), fx.id("owner"));
    let members: BTreeMap<String, String> = ["admin", "member", "owner", "restricted"]
        .into_iter()
        .map(|label| (label.to_owned(), fx.id(label)))
        .collect();
    fx.event(
        ROOT,
        hosted_identity::ROSTER_EVENT,
        serde_json::json!({ "members": members, "catalog_accounts": {} }),
    )
    .await;
    // Root: admin manage and transform view; every roster member views.
    fx.policy(
        ROOT,
        &[(&admin, "allow", "manage"), (&transform, "allow", "view")],
    )
    .await;
    let seq = fx.frontier(ROOT).await;
    fx.event(
        ROOT,
        hosted_identity::POLICY_EVENT,
        serde_json::json!({
            "policy_seq": seq,
            "explicit": { admin.clone(): "manage", transform.clone(): "view" },
            "members": "view",
        }),
    )
    .await;
    // Team inherits root. Private: admin only, so members are valid without
    // View there and only its owners see their own records.
    fx.home("h:team", ROOT).await;
    fx.home("h:private", ROOT).await;
    fx.policy("h:private", &[(&admin, "allow", "manage")]).await;
    // Folder F1 inside team, for the folder-scoped app.
    fx.rec("f:one", "h:team", &admin).await;
    fx.field("f:one", "v1_type", "Collection").await;
    fx.field("f:one", "v1_kind", "folder").await;
    fx.home("h:f1", "h:team").await;
    fx.event(
        "h:f1",
        "kernel.home_created.v1",
        serde_json::json!({ "source_record_id": "f:one" }),
    )
    .await;

    // Ordinary bearers and deep comment threads on them.
    fx.rec("r:team", "h:team", &admin).await;
    fx.thread("c:t", DEEP, "h:team", &member, "r:team").await;
    fx.rec("r:own", "h:private", &owner).await;
    fx.thread("c:p", DEEP, "h:team", &member, "r:own").await;
    fx.rec("r:f1", "h:f1", &member).await;
    fx.thread("c:f", DEEP, "h:f1", &member, "r:f1").await;
    // Plain Documents keep their own home but are walked by the guard: a
    // chain past every depth bound, and a cycle.
    fx.page_chain("d:doc", VERY_DEEP, "h:team", &admin, "r:team")
        .await;
    fx.page("d:cyc_a", "h:team", &admin).await;
    fx.page("d:cyc_b", "h:team", &admin).await;
    fx.part_of("d:cyc_a", "d:cyc_b").await;
    fx.part_of("d:cyc_b", "d:cyc_a").await;
    fx
}

async fn add_messages(fx: &Fx) {
    let (admin, member) = (fx.id("admin"), fx.id("member"));
    fx.sealed_message("m:team", "h:team", &admin).await;
    fx.thread("c:mt", DEEP, "h:team", &member, "m:team").await;
    fx.sealed_message("m:private", "h:private", &admin).await;
    fx.thread("c:mp", DEEP, "h:team", &member, "m:private")
        .await;
    fx.sealed_message("m:f1", "h:f1", &member).await;
    fx.thread("c:mf", DEEP, "h:f1", &member, "m:f1").await;
    // An unsealed carrier fails closed for everyone.
    fx.message_carrier("m:unsealed", "h:team", &admin).await;
    fx.thread("c:mu", DEEP, "h:team", &member, "m:unsealed")
        .await;
    // A plain Document chain on a Message past every depth bound.
    fx.page_chain("d:mdoc", VERY_DEEP, "h:team", &admin, "m:team")
        .await;
    // Bears on a visible Message AND on a deep non-message chain.
    fx.page("d:mix", "h:team", &admin).await;
    fx.part_of("d:mix", "m:team").await;
    fx.part_of("d:mix", "d:doc010").await;
    // A cycle that also reaches a private Message.
    fx.page("d:cm_a", "h:team", &admin).await;
    fx.page("d:cm_b", "h:team", &admin).await;
    fx.part_of("d:cm_a", "d:cm_b").await;
    fx.part_of("d:cm_b", "d:cm_a").await;
    fx.part_of("d:cm_b", "m:private").await;
}

fn deepest(prefix: &str) -> String {
    format!("{prefix}{:02}", DEEP - 1)
}

/// Expected outcomes, stated per case rather than derived from any gate.
/// `(caller, record, visible)`; checked on the bulk gate and, for unscoped
/// callers, on the single-record path.
async fn expect(fx: &Fx, cases: &[(&str, &str, bool)]) {
    for (caller, folders) in callers(fx)
        .into_iter()
        .map(|(label, id, folders)| ((label, id), folders))
    {
        let mine: Vec<_> = cases.iter().filter(|(c, _, _)| *c == caller.0).collect();
        if mine.is_empty() {
            continue;
        }
        let v = views(&fx.db, &caller.1, folders).await;
        for (_, record, visible) in mine {
            assert_eq!(
                v.gate.contains(*record),
                *visible,
                "bulk gate: {} sees {record}",
                caller.0
            );
            if let Some(single) = &v.single {
                assert_eq!(
                    single.contains(*record),
                    *visible,
                    "single-record path: {} sees {record}",
                    caller.0
                );
            }
        }
    }
}

/// The rule, over every caller and every record, in one snapshot each:
/// message-bearing records are exactly today's gate; all others are exactly
/// ordinary bearer visibility; the single-record path agrees with the bulk.
async fn rule_holds(fx: &Fx) {
    let bearing = message_bearing(&fx.db).await;
    for (label, principal, folders) in callers(fx) {
        let v = views(&fx.db, &principal, folders).await;
        let all: BTreeSet<&String> = v.legacy.iter().chain(&v.unguarded).chain(&v.gate).collect();
        for id in all {
            let expected = if bearing.contains(id) {
                v.legacy.contains(id)
            } else {
                v.unguarded.contains(id)
            };
            assert_eq!(
                v.gate.contains(id),
                expected,
                "{label} {id}: message-bearing={}",
                bearing.contains(id)
            );
        }
        // Every message-bearing record is never wider than today.
        assert!(
            v.gate
                .iter()
                .filter(|id| bearing.contains(*id))
                .all(|id| v.legacy.contains(id)),
            "{label}: message-bearing visibility widened"
        );
        if let Some(single) = &v.single {
            assert_eq!(single, &v.gate, "{label}: single-record path vs bulk gate");
        }
    }
}

#[tokio::test]
async fn deep_threads_without_messages_follow_their_bearer() {
    let fx = world().await;
    let (t, p, f) = (deepest("c:t"), deepest("c:p"), deepest("c:f"));
    let doc = format!("d:doc{:03}", VERY_DEEP - 1);
    expect(
        &fx,
        &[
            ("member", &t, true),
            ("restricted", &t, true),
            ("owner", &p, true),
            ("member", &p, false),
            ("restricted", &p, false),
            ("admin", &p, true),
            ("member", &doc, true),
            ("member", "d:cyc_a", true),
            ("member@f1", &f, true),
            ("member@f1", &t, false),
        ],
    )
    .await;
    rule_holds(&fx).await;
}

#[tokio::test]
async fn deep_threads_on_ordinary_records_survive_any_message_in_the_workspace() {
    let fx = world().await;
    add_messages(&fx).await;
    let (t, p, f) = (deepest("c:t"), deepest("c:p"), deepest("c:f"));
    let doc = format!("d:doc{:03}", VERY_DEEP - 1);
    expect(
        &fx,
        &[
            // The bug: hidden from everyone once any Message existed.
            ("member", &t, true),
            ("restricted", &t, true),
            ("admin", &t, true),
            ("owner", &p, true),
            ("member", &p, false),
            ("restricted", &p, false),
            ("member", &doc, true),
            ("member", "d:cyc_a", true),
            ("member@f1", &f, true),
            ("member@f1", &t, false),
            ("member@f1", "r:f1", true),
        ],
    )
    .await;
    rule_holds(&fx).await;
}

#[tokio::test]
async fn message_bearing_chains_keep_todays_guard_at_any_depth() {
    let fx = world().await;
    add_messages(&fx).await;
    let last_shallow = |p: &str| format!("{p}{:02}", GUARD_DEPTH - 1);
    let first_deep = |p: &str| format!("{p}{:02}", GUARD_DEPTH);
    let mdoc_shallow = format!("d:mdoc{:03}", GUARD_DEPTH - 1);
    let mdoc_deep = format!("d:mdoc{:03}", GUARD_DEPTH);
    let mdoc_deepest = format!("d:mdoc{:03}", VERY_DEEP - 1);
    expect(
        &fx,
        &[
            // Within the walk: the Message's home policy governs.
            ("member", &last_shallow("c:mt"), true),
            ("admin", &last_shallow("c:mp"), true),
            ("member", "c:mp00", false),
            ("restricted", "c:mp00", false),
            ("member", &mdoc_shallow, true),
            // Beyond it: still fail closed, for everyone.
            ("member", &first_deep("c:mt"), false),
            ("admin", &first_deep("c:mt"), false),
            ("admin", &deepest("c:mt"), false),
            ("admin", &first_deep("c:mp"), false),
            ("member", &mdoc_deep, false),
            ("admin", &mdoc_deepest, false),
            // A visible Message on one branch and a deep chain on another.
            ("admin", "d:mix", false),
            // A cycle reaching a private Message.
            ("admin", "d:cm_a", false),
            ("member", "d:cm_a", false),
            // Unsealed carriers and the transform service fail closed.
            ("admin", "c:mu00", false),
            ("transform", "c:mt00", false),
            ("transform", "r:team", true),
            ("transform", &deepest("c:t"), true),
            // Folder-scoped apps never see Messages or what bears on them.
            ("member@f1", "m:f1", false),
            ("member@f1", "c:mf00", false),
            ("member@f1", &deepest("c:mf"), false),
        ],
    )
    .await;
    rule_holds(&fx).await;
}

// ---------------------------------------------------------------------------
// Bulk cost: the guard over a long chain must stay linear in the chain.
// ---------------------------------------------------------------------------

/// A `part_of` comment thread `{prefix}00000..` of length `n` on `bearer`,
/// written in three set statements so thousands of rows stay cheap to build.
async fn bulk_thread(fx: &Fx, prefix: &str, n: usize, home: &str, bearer: &str) {
    let owner = fx.id("admin");
    let series = format!(
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<{})",
        n - 1
    );
    fx.exec(
        &format!("{series} INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('{prefix}%05d',i),?1,?2,1,'2026-11-13T00:00:00Z' FROM n"),
        &[home, &owner],
    )
    .await;
    fx.exec(
        &format!("{series} INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT printf('{prefix}%05d',i),'v1_type','\"Annotation\"',1 FROM n UNION ALL SELECT printf('{prefix}%05d',i),'v1_kind','\"comment\"',1 FROM n"),
        &[],
    )
    .await;
    fx.exec(
        &format!("{series} INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,note,created_at,actor,active,event_seq,imported) SELECT printf('link:{prefix}%05d',i),printf('{prefix}%05d',i),CASE WHEN i=0 THEN ?1 ELSE printf('{prefix}%05d',i-1) END,'part_of',NULL,'2026-11-13T00:00:00Z',NULL,1,1,0 FROM n"),
        &[bearer],
    )
    .await;
}

/// SQLite VM steps (and wall time) to evaluate the prepared-read guard over
/// every record, in a workspace with a Message, with a thread of `n` on an
/// ordinary record and another of `n` on a Message.
async fn guard_cost(n: usize) -> (u64, std::time::Duration, i64) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let fx = Fx::new().await;
    let admin = fx.id("admin");
    fx.rec("r:bulk", ROOT, &admin).await;
    fx.sealed_message("m:bulk", ROOT, &admin).await;
    bulk_thread(&fx, "c:plain", n, ROOT, "r:bulk").await;
    bulk_thread(&fx, "c:msg", n, ROOT, "m:bulk").await;
    let guard = messaging::sql_guard(
        "r",
        "?1",
        "SELECT root_id AS id,1 AS view FROM kernel_roots",
        true,
    );
    let sql = format!("SELECT count(*) FROM kernel_records r WHERE {guard}");
    let mut conn = fx.db.pool().acquire().await.unwrap();
    let steps = Arc::new(AtomicU64::new(0));
    let meter = Arc::clone(&steps);
    {
        let mut handle = conn.lock_handle().await.unwrap();
        handle.remove_progress_handler();
        handle.set_progress_handler(1, move || {
            meter.fetch_add(1, Ordering::Relaxed);
            true
        });
    }
    let started = std::time::Instant::now();
    let visible: i64 = sqlx::query_scalar(&sql)
        .bind(&admin)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    let elapsed = started.elapsed();
    conn.lock_handle().await.unwrap().remove_progress_handler();
    (steps.load(Ordering::Relaxed), elapsed, visible)
}

#[tokio::test]
async fn guard_cost_is_linear_in_a_long_chain() {
    let (small_steps, small_time, small_visible) = guard_cost(1_000).await;
    let (large_steps, large_time, large_visible) = guard_cost(3_000).await;
    eprintln!(
        "message guard cost: 1k chains {small_steps} VM steps / {small_time:?}; 3k chains {large_steps} VM steps / {large_time:?}"
    );
    // The plain thread is visible at every depth; the Message thread only
    // within the guard's walk (plus the bearer, the Message and the root).
    assert_eq!(small_visible, 1_000 + GUARD_DEPTH as i64 + 2);
    assert_eq!(large_visible, 3_000 + GUARD_DEPTH as i64 + 2);
    // Tripling the chains must cost about three times as much, not nine.
    assert!(
        large_steps < small_steps * 9 / 2,
        "guard cost grows faster than linear: {small_steps} -> {large_steps} VM steps"
    );
}
