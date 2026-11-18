//! Equivalence of demand-scoped point reads with today's full-staging read,
//! on spike B's principal matrix (task 1d387440, note f819ab4) and spike A2's
//! body/Docs-page envelopes (note 85aa613). Fixtures write raw rows into a
//! real v2 schema; every comparison is a complete `query_sql` envelope.
use super::app_installs::scope::{with_scope_override, AppScope};
use super::demand_visibility as demand;
use super::*;
use crate::mcp::kernel_v2::sql;
use std::collections::{BTreeMap, BTreeSet};

const ROOT: &str = KERNEL_ROOT_ID;
const MAX_BEARER: usize = crate::authorization::MAX_DERIVED_BEARER_DEPTH;
const GUARD_DEPTH: usize = 8;

struct Fx {
    db: Db,
    _dir: tempfile::TempDir,
    admin: String,
    /// label -> principal id
    p: BTreeMap<&'static str, String>,
    /// roster members by label (binding == label)
    roster: BTreeSet<&'static str>,
}

impl Fx {
    async fn new() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("spike.db").display()),
            "account",
            "Admin",
            "admin",
        )
        .await
        .unwrap();
        let mut p = BTreeMap::new();
        p.insert("admin", admin.clone());
        Fx {
            db,
            _dir: dir,
            admin,
            p,
            roster: BTreeSet::new(),
        }
    }

    async fn principal(&mut self, label: &'static str) -> String {
        let id = create_principal(&self.db, "account", label, label, &self.admin)
            .await
            .unwrap();
        self.p.insert(label, id.clone());
        id
    }

    fn id(&self, label: &str) -> String {
        self.p[label].clone()
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

    async fn home(&self, id: &str, parent: Option<&str>) {
        self.exec(
            "INSERT INTO kernel_roots(root_id,parent_id,owner_id,created_seq,created_at) VALUES(?1,?2,NULL,1,'2026-11-13T00:00:00Z')",
            &[id, parent.unwrap_or("")],
        )
        .await;
        if parent.is_none() {
            self.exec(
                "UPDATE kernel_roots SET parent_id=NULL WHERE root_id=?",
                &[id],
            )
            .await;
        }
    }

    /// Replace the stored policy rows of `home` (creating the boundary).
    async fn policy(&self, home: &str, rows: &[(&str, &str, &str, &str)]) {
        self.exec(
            "INSERT OR IGNORE INTO kernel_policies(root_id,created_at) VALUES(?,'2026-11-13T00:00:00Z')",
            &[home],
        )
        .await;
        self.exec("DELETE FROM kernel_policy_entries WHERE root_id=?", &[home])
            .await;
        for (kind, subject, effect, cap) in rows {
            self.exec(
                "INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) VALUES(?,?,?,?,?)",
                &[home, kind, subject, effect, cap],
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

    /// A typed carrier (pin set), for `primary_type='Message'` carriers.
    async fn typed(&self, id: &str, home: &str, owner: &str, primary: &str, family: &str) {
        let accession = format!("acc:{id}");
        self.exec(
            "INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,created_seq,created_at) VALUES(?,?,?,?,'k',?,?,1,'d',1,'2026-11-13T00:00:00Z')",
            &[id, home, owner, primary, &accession, family],
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

    async fn typ(&self, id: &str, v1_type: &str, v1_kind: Option<&str>) {
        self.field(id, "v1_type", v1_type).await;
        if let Some(kind) = v1_kind {
            self.field(id, "v1_kind", kind).await;
        }
    }

    async fn set_owner(&self, id: &str, owner: &str) {
        self.exec(
            "UPDATE kernel_records SET owner_id=? WHERE id=?",
            &[owner, id],
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
        self.typ(id, "Annotation", Some("comment")).await;
        self.part_of(id, bearer).await;
    }

    async fn tomb(&self, id: &str) {
        self.exec(
            "INSERT OR REPLACE INTO kernel_import_tombstones(record_id,deleted_at,event_seq) VALUES(?,'2026-11-13T00:00:00Z',1)",
            &[id],
        )
        .await;
    }

    async fn seal(&self, id: &str, audience: &serde_json::Value) {
        // The single-record gate parses the complete canonical state. S1a's
        // audience-only stub was sufficient for bulk SQL, but is deliberately
        // malformed for that gate. Keep audience and visibility identical.
        let state = serde_json::to_string(&MessageState {
            audience: serde_json::from_value(audience.clone()).unwrap(),
            ..MessageState::default()
        })
        .unwrap();
        self.exec(
            "INSERT INTO kernel_messages(message_id,state,event_seq) VALUES(?,?,1) ON CONFLICT(message_id) DO UPDATE SET state=excluded.state",
            &[id, &state],
        )
        .await;
    }

    /// Append a raw content event (placement, roster, template, frontier).
    async fn event(&self, record: &str, event_type: &str, payload: serde_json::Value) {
        let id = Uuid::new_v4().to_string();
        let payload = payload.to_string();
        self.exec(
            "INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,?,NULL,1,'complete')",
            &[&id, record, event_type, &payload],
        )
        .await;
    }

    /// A folder record `folder` living in `container`, bound to child home
    /// `home` (parent `parent`), as `kernel.home_created.v1` records it.
    async fn folder(&self, folder: &str, container: &str, home: &str, parent: &str) {
        self.rec(folder, container, &self.admin).await;
        self.typ(folder, "Collection", Some("folder")).await;
        self.home(home, Some(parent)).await;
        self.event(
            home,
            "kernel.home_created.v1",
            serde_json::json!({ "source_record_id": folder }),
        )
        .await;
    }

    async fn write_roster(&self) {
        let members: BTreeMap<String, String> = self
            .roster
            .iter()
            .map(|label| ((*label).to_string(), self.id(label)))
            .collect();
        self.event(
            ROOT,
            hosted_identity::ROSTER_EVENT,
            serde_json::json!({ "members": members, "catalog_accounts": {} }),
        )
        .await;
    }

    /// A hosted member-policy template. `policy_seq` must equal the home's
    /// frontier for it to apply; `None` takes the current frontier.
    async fn template(
        &self,
        home: &str,
        explicit: &[(&str, &str)],
        members: Option<&str>,
        policy_seq: Option<i64>,
    ) {
        let seq = match policy_seq {
            Some(seq) => seq,
            None => self.frontier(home).await,
        };
        let explicit: BTreeMap<String, String> = explicit
            .iter()
            .map(|(id, cap)| ((*id).to_string(), (*cap).to_string()))
            .collect();
        self.event(
            home,
            hosted_identity::POLICY_EVENT,
            serde_json::json!({ "policy_seq": seq, "explicit": explicit, "members": members }),
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

    async fn move_frontier(&self, home: &str) {
        self.event(home, "kernel.import_home_delta.v1", serde_json::json!({}))
            .await;
    }
}

// ---------------------------------------------------------------------------

const HAS_MESSAGES_SQL: &str = "SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')";

const SCOPED_MESSAGE_CLOSURE_SQL: &str = "WITH RECURSIVE excluded(id) AS (
   SELECT id FROM main.kernel_records WHERE primary_type='Message'
   UNION SELECT message_id FROM main.kernel_messages
   UNION SELECT record_id FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"'
   UNION SELECT l.source_id FROM main.kernel_generic_links l JOIN excluded e ON e.id=l.target_id
         WHERE l.relationship='part_of' AND l.active=1
 ) SELECT id FROM excluded";

async fn oracle(db: &Db, principal: &str, folders: Option<&[String]>) -> BTreeSet<String> {
    let work = async {
        let mut tx = db.write_pool().begin().await.unwrap();
        let scope = visible_home_anchors_as(&mut tx, principal).await.unwrap();
        sqlx::query(
            "CREATE TEMP TABLE _spike_scopes(home_id TEXT, valid INTEGER, policy_view INTEGER)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        for home in &scope.homes {
            sqlx::query("INSERT INTO temp._spike_scopes VALUES(?,?,?)")
                .bind(&home.home_id)
                .bind(home.policy_valid)
                .bind(home.policy_view)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let has_messages: bool = sqlx::query_scalar(HAS_MESSAGES_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let gate = sql_record_visible(
            "r",
            "?1",
            "SELECT home_id AS id,policy_view AS view FROM temp._spike_scopes WHERE valid",
            has_messages,
        );
        let mut ids: BTreeSet<String> = sqlx::query_scalar::<_, String>(&format!(
            "SELECT r.id FROM main.kernel_records r WHERE {gate}"
        ))
        .bind(principal)
        .fetch_all(&mut *tx)
        .await
        .unwrap()
        .into_iter()
        .collect();
        if folders.is_some() {
            let excluded: Vec<String> = sqlx::query_scalar(SCOPED_MESSAGE_CLOSURE_SQL)
                .fetch_all(&mut *tx)
                .await
                .unwrap();
            for id in excluded {
                ids.remove(&id);
            }
        }
        tx.rollback().await.unwrap();
        ids
    };
    match folders {
        Some(folders) => {
            with_scope_override(principal, AppScope::Folders(folders.to_vec()), work).await
        }
        None => work.await,
    }
}

struct Matrix {
    /// (label, principal id, optional folder scope)
    callers: Vec<(String, String, Option<Vec<String>>)>,
}

async fn world() -> (Fx, Matrix) {
    let mut fx = Fx::new().await;
    for label in [
        "member",
        "grantee",
        "owner_nv",
        "owner_inv",
        "former",
        "outsider",
        "noperson",
    ] {
        fx.principal(label).await;
    }
    let host_import: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding='host:v1-import'",
    )
    .fetch_one(fx.db.pool())
    .await
    .unwrap();
    let transform: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding='host:relates-to:transform'",
    )
    .fetch_one(fx.db.pool())
    .await
    .unwrap();
    fx.p.insert("host_import", host_import);
    fx.p.insert("transform", transform);
    let (admin, member, grantee, owner_nv, owner_inv, outsider, transform) = (
        fx.id("admin"),
        fx.id("member"),
        fx.id("grantee"),
        fx.id("owner_nv"),
        fx.id("owner_inv"),
        fx.id("outsider"),
        fx.id("transform"),
    );

    // Roster: everyone except the outsider; "former" is offboarded later.
    fx.roster = [
        "admin",
        "member",
        "grantee",
        "owner_nv",
        "owner_inv",
        "former",
        "noperson",
    ]
    .into_iter()
    .collect();
    fx.write_roster().await;

    // Root: stored admin manage + transform view; hosted template members view.
    fx.policy(
        ROOT,
        &[
            ("account", &admin, "allow", "manage"),
            ("account", &transform, "allow", "view"),
        ],
    )
    .await;
    fx.template(
        ROOT,
        &[(&admin, "manage"), (&transform, "view")],
        Some("view"),
        None,
    )
    .await;

    // Topology.
    fx.home("h:team", Some(ROOT)).await;
    fx.home("h:team_sub", Some("h:team")).await;
    fx.home("h:private", Some(ROOT)).await; // valid, no view for owner_nv
    fx.policy("h:private", &[("account", &admin, "allow", "manage")])
        .await;
    fx.home("h:bad", Some(ROOT)).await; // invalid for owner_inv only
    fx.policy(
        "h:bad",
        &[
            ("account", &admin, "allow", "manage"),
            ("account", &owner_inv, "allow", "bogus"),
        ],
    )
    .await;
    fx.home("h:grant", Some(ROOT)).await; // explicit grants, no members
    fx.policy(
        "h:grant",
        &[
            ("account", &admin, "allow", "manage"),
            ("account", &grantee, "allow", "view"),
            ("account", &outsider, "allow", "view"),
        ],
    )
    .await;
    fx.template(
        "h:grant",
        &[(&admin, "manage"), (&grantee, "view"), (&outsider, "view")],
        None,
        None,
    )
    .await;
    fx.home("h:behind", Some(ROOT)).await; // template behind its frontier
    fx.policy("h:behind", &[("account", &admin, "allow", "manage")])
        .await;
    fx.template("h:behind", &[(&admin, "manage")], Some("view"), None)
        .await;
    fx.move_frontier("h:behind").await;
    fx.home("h:orphan_parent", None).await; // no anchor reachable
                                            // A 102-deep chain without policy: overflows MAX_HOME_DEPTH.
    let mut parent = ROOT.to_string();
    for i in 0..=MAX_HOME_DEPTH + 1 {
        let id = format!("h:deep{i:03}");
        fx.home(&id, Some(&parent)).await;
        parent = id;
    }
    // Folders for app scope: F1 in team -> HF1; F2 in HF1 -> HF2.
    fx.folder("f:one", "h:team", "h:f1", "h:team").await;
    fx.folder("f:two", "h:f1", "h:f2", "h:f1").await;
    // A self-policy private record inside F1.
    fx.home("h:self", Some("h:f1")).await;
    fx.policy("h:self", &[("account", &member, "allow", "manage")])
        .await;
    fx.event(
        "h:self",
        "kernel.home_created.v1",
        serde_json::json!({ "source_record_id": "r:selfpriv" }),
    )
    .await;
    // Its logical folder is F1 (as a move or private create records it).
    fx.event(
        "r:selfpriv",
        "kernel.record_rehomed.v2",
        serde_json::json!({ "new_home_id": "h:self", "logical_home_id": "f:one" }),
    )
    .await;
    // A stored `members` row: the kernel evaluates with is_member=false, so
    // it grants nothing (members only take effect through hosted templates).
    fx.home("h:members_row", Some(ROOT)).await;
    fx.policy(
        "h:members_row",
        &[
            ("account", &admin, "allow", "manage"),
            ("members", "", "allow", "view"),
        ],
    )
    .await;

    // Ordinary records.
    fx.rec("r:team", "h:team", &admin).await;
    fx.rec("r:team_member", "h:team", &member).await;
    fx.rec("r:sub", "h:team_sub", &admin).await;
    fx.rec("r:private_admin", "h:private", &admin).await;
    fx.rec("r:private_nv", "h:private", &owner_nv).await;
    fx.rec("r:bad_inv", "h:bad", &owner_inv).await;
    fx.rec("r:bad_admin", "h:bad", &admin).await;
    fx.rec("r:grant", "h:grant", &admin).await;
    fx.rec("r:behind", "h:behind", &admin).await;
    fx.rec("r:behind_member", "h:behind", &member).await;
    fx.rec("r:orphan_parent", "h:orphan_parent", &member).await;
    fx.rec("r:no_root_row", "h:missing", &member).await;
    fx.rec(
        "r:deep",
        &format!("h:deep{:03}", MAX_HOME_DEPTH + 1),
        &member,
    )
    .await;
    fx.rec(
        "r:deep_ok",
        &format!("h:deep{:03}", MAX_HOME_DEPTH - 1),
        &member,
    )
    .await;
    fx.rec("r:f1", "h:f1", &member).await;
    fx.rec("r:f2", "h:f2", &member).await;
    fx.rec("r:selfpriv", "h:self", &member).await;
    fx.rec("r:members_row", "h:members_row", &admin).await;
    fx.rec("r:tomb", "h:team", &member).await;
    fx.tomb("r:tomb").await;

    // Derived artifacts.
    fx.comment("c:team", "h:private", &member, "r:team").await; // own home ignored
    fx.comment("c:reply", "h:team", &member, "c:team").await;
    fx.comment("c:on_nv", "h:team", &member, "r:private_nv")
        .await; // terminal owner floor
    fx.comment("c:on_f1", "h:team", &member, "r:f1").await; // in scope via bearer
    fx.comment("c:two", "h:team", &member, "r:team").await;
    fx.part_of("c:two", "r:sub").await; // two bearers: broken
                                        // A duplicate active part_of (same triple) cannot exist: the schema's
                                        // partial unique index idx_kernel_generic_links_active_triple refuses it.
    fx.rec("c:none", "h:team", &member).await; // zero bearers: broken
    fx.typ("c:none", "Annotation", Some("comment")).await;
    fx.rec("a:attach", "h:team", &member).await; // attachment document
    fx.typ("a:attach", "Document", Some("attachment")).await;
    fx.part_of("a:attach", "r:private_admin").await;
    fx.rec("d:doc_part", "h:team", &member).await; // non-derived Document with part_of
    fx.typ("d:doc_part", "Document", Some("page")).await;
    fx.part_of("d:doc_part", "r:private_admin").await;
    // Tombstone mid-path.
    fx.comment("c:mid", "h:team", &member, "r:team").await;
    fx.comment("c:below_mid", "h:team", &member, "c:mid").await;
    fx.tomb("c:mid").await;
    // Chain of depth MAX_BEARER + 1 (overflow) and MAX_BEARER (ok).
    let mut bearer = "r:team".to_string();
    for i in 0..=MAX_BEARER {
        let id = format!("c:chain{i:03}");
        fx.comment(&id, "h:team", &member, &bearer).await;
        bearer = id;
    }
    // Ordinary record with a part_of (not derived; keeps own placement).
    fx.rec("r:part_plain", "h:team", &member).await;
    fx.part_of("r:part_plain", "r:private_admin").await;

    let callers: Vec<(String, String, Option<Vec<String>>)> = vec![
        ("admin".into(), admin.clone(), None),
        ("member".into(), member.clone(), None),
        ("grantee".into(), grantee.clone(), None),
        ("owner_nv".into(), owner_nv.clone(), None),
        ("owner_inv".into(), owner_inv.clone(), None),
        ("former".into(), fx.id("former"), None),
        ("outsider".into(), outsider.clone(), None),
        ("noperson".into(), fx.id("noperson"), None),
        ("transform".into(), transform.clone(), None),
        ("host_import".into(), fx.id("host_import"), None),
        (
            "member@f1".into(),
            member.clone(),
            Some(vec!["f:one".into()]),
        ),
        (
            "member@f2".into(),
            member.clone(),
            Some(vec!["f:two".into()]),
        ),
        ("admin@f1".into(), admin.clone(), Some(vec!["f:one".into()])),
    ];
    (fx, Matrix { callers })
}

async fn add_messages(fx: &Fx) {
    let (admin, member) = (fx.id("admin"), fx.id("member"));
    let audience = serde_json::json!({ admin.clone(): "manage" });
    // Sealed message in team, owned by admin; and one in F1.
    fx.typed("m:team", "h:team", &admin, "Message", "native.messaging")
        .await;
    fx.seal("m:team", &audience).await;
    fx.typed("m:f1", "h:f1", &member, "Message", "native.messaging")
        .await;
    fx.seal("m:f1", &serde_json::json!({ member.clone(): "manage" }))
        .await;
    // Sealed message in private: members cannot see it.
    fx.typed(
        "m:private",
        "h:private",
        &admin,
        "Message",
        "native.messaging",
    )
    .await;
    fx.seal("m:private", &audience).await;
    // Unsealed carriers: typed and v1-field forms.
    fx.typed(
        "m:unsealed",
        "h:team",
        &admin,
        "Message",
        "native.messaging",
    )
    .await;
    fx.rec("m:v1_unsealed", "h:team", &admin).await;
    fx.exec("UPDATE kernel_records SET primary_type='Note',kind='k',accession='acc:v1u',pin_family='native.v1.record',pin_version=1,pin_digest='d' WHERE id='m:v1_unsealed'", &[]).await;
    fx.typ("m:v1_unsealed", "Message", None).await;
    // Comments and documents bearing on messages.
    fx.comment("c:on_m_team", "h:team", &member, "m:team").await;
    fx.comment("c:on_m_private", "h:team", &member, "m:private")
        .await;
    fx.comment("c:on_m_f1", "h:f1", &member, "m:f1").await;
    fx.comment("c:on_unsealed", "h:team", &member, "m:unsealed")
        .await;
    // A non-derived Document part_of a private message: own authority AND guard.
    fx.rec("d:on_m_private", "h:team", &member).await;
    fx.typ("d:on_m_private", "Document", Some("page")).await;
    fx.part_of("d:on_m_private", "m:private").await;
    // An ordinary record part_of a message: no guard, but scoped closure.
    fx.rec("r:plain_on_m_f1", "h:f1", &member).await;
    fx.part_of("r:plain_on_m_f1", "m:f1").await;
    // A 10-deep thread on a member-visible message.
    let mut bearer = "m:team".to_string();
    for i in 0..10 {
        let id = format!("c:mt{i}");
        fx.comment(&id, "h:team", &member, &bearer).await;
        bearer = id;
    }
    // Guard depth 8: a 9-deep annotation chain on an ordinary record.
    let mut bearer = "r:team".to_string();
    for i in 0..=GUARD_DEPTH {
        let id = format!("c:g{i}");
        fx.comment(&id, "h:team", &member, &bearer).await;
        bearer = id;
    }
}

// ---------------------------------------------------------------------------
// Fixture witnesses: each fixture does, in the ORACLE, what it claims.
// ---------------------------------------------------------------------------

async fn sees(fx: &Fx, who: &str, folders: Option<&[&str]>, id: &str) -> bool {
    let folders: Option<Vec<String>> = folders.map(|f| f.iter().map(|s| s.to_string()).collect());
    oracle(&fx.db, &fx.id(who), folders.as_deref())
        .await
        .contains(id)
}

async fn witness(fx: &Fx, cases: &[(&str, Option<&[&str]>, &str, bool)]) {
    for (who, folders, id, expected) in cases {
        assert_eq!(
            sees(fx, who, *folders, id).await,
            *expected,
            "fixture witness: {who} {folders:?} {id}"
        );
    }
}

async fn witness_base(fx: &Fx) {
    let f1: &[&str] = &["f:one"];
    let deep_ok = format!("c:chain{:03}", MAX_BEARER - 1);
    let deep_over = format!("c:chain{MAX_BEARER:03}");
    witness(
        fx,
        &[
            ("member", None, "r:team", true), // members via hosted template
            ("member", None, "r:private_admin", false), // valid, no view
            ("owner_nv", None, "r:private_nv", true), // owner floor, valid scope
            ("owner_inv", None, "r:bad_inv", false), // owner, scope invalid for them only
            ("admin", None, "r:bad_inv", true), // same scope valid for admin
            ("grantee", None, "r:grant", true), // explicit account grant
            ("member", None, "r:grant", false),
            ("outsider", None, "r:grant", false), // grant without membership
            ("member", None, "r:behind", false),  // template behind frontier ignored
            ("member", None, "r:behind_member", true), // ...so owner floor only
            ("member", None, "r:members_row", false), // stored members row inert
            ("member", None, "r:orphan_parent", false), // broken walk, even for owner
            ("member", None, "r:no_root_row", false), // home with no root row
            ("member", None, "r:deep", false),    // walk overflow
            ("member", None, "r:deep_ok", true),
            ("member", None, "r:tomb", false),
            ("member", None, "c:team", true), // follows bearer, not own home
            ("member", None, "c:reply", true),
            ("member", None, "c:on_nv", false), // comment owner irrelevant
            ("owner_nv", None, "c:on_nv", true), // terminal owner floor
            ("member", None, "c:two", false),   // two bearers
            ("member", None, "c:none", false),  // zero bearers
            ("member", None, "a:attach", false), // attachment follows private bearer
            ("member", None, "d:doc_part", true), // non-derived Document: own home
            ("member", None, "c:below_mid", false), // tombstone mid-path
            ("member", None, &deep_ok, true),   // depth 100 terminal
            ("member", None, &deep_over, false), // depth 101 overflow
            ("member", None, "c:chain020", true), // deep chain visible: no messages yet
            ("member", Some(f1), "r:f1", true),
            ("member", Some(f1), "r:f2", true), // nested folder
            ("member", Some(f1), "r:selfpriv", true), // self-policy home, logical F1
            ("member", Some(f1), "c:on_f1", true), // comment follows in-scope bearer
            ("member", Some(f1), "r:team", false), // same anchor, out of scope
            ("member", Some(f1), "r:team_member", false), // owner floor does not leak out of scope
            ("transform", None, "r:team", true), // service principal, granted view
            ("host_import", None, "r:team", false),
        ],
    )
    .await;
}

async fn witness_messages(fx: &Fx) {
    let f1: &[&str] = &["f:one"];
    witness(
        fx,
        &[
            ("member", None, "m:team", true),
            ("member", None, "c:on_m_team", true),
            ("transform", None, "c:on_m_team", false), // service refused on guarded rows
            ("transform", None, "m:team", false),
            ("transform", None, "r:team", true), // ...but not elsewhere
            ("member", None, "c:on_m_private", false),
            ("member", None, "d:on_m_private", false), // own home visible, guard refuses
            ("admin", None, "d:on_m_private", true),
            ("admin", None, "m:unsealed", false), // unsealed carrier fails closed
            ("admin", None, "m:v1_unsealed", false),
            ("admin", None, "c:on_unsealed", false),
            ("member", None, "c:g7", true), // guard depth 8
            // Past the guard walk, a chain fails closed only if it reaches a
            // Message (task 11ef0d8b): these threads reach none.
            ("member", None, "c:g8", true),
            ("member", None, "c:chain020", true),
            // A thread on a visible message: visible within the walk, closed
            // past it.
            ("member", None, "c:mt6", true),
            ("member", None, "c:mt9", false),
            ("member", None, "r:plain_on_m_f1", true),
            ("member", Some(f1), "m:f1", false), // scoped apps never see messages
            ("member", Some(f1), "c:on_m_f1", false),
            ("member", Some(f1), "r:plain_on_m_f1", false), // ...nor any part_of descendant
            ("member", Some(f1), "r:f1", true),
        ],
    )
    .await;
}

fn declared(key: &str) -> String {
    let declaration: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("web/apps/src/apps/docs/declaration.json"),
        )
        .unwrap(),
    )
    .unwrap();
    declaration["needs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["key"] == key)
        .unwrap()["sql"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Run one read on the demand-scoped path and on today's full staging, under
/// the caller's app scope; return both envelopes and the path taken.
async fn both(
    db: &Db,
    principal: &str,
    folders: &Option<Vec<String>>,
    args: serde_json::Value,
) -> (
    std::result::Result<serde_json::Value, String>,
    std::result::Result<serde_json::Value, String>,
    sql::Stats,
) {
    sql::read_cost::with_comparison_budget(with_scope_override(
        principal,
        folders
            .clone()
            .map(AppScope::Folders)
            .unwrap_or(AppScope::All),
        async {
            let (actual, stats) = sql::measured(sql::query_sql(db, principal, args.clone())).await;
            let expected =
                sql::with_full_read_oracle(Box::pin(sql::query_sql(db, principal, args)))
                    .await
                    .map_err(|e| e.to_string());
            (actual.map_err(|e| e.to_string()), expected, stats)
        },
    ))
    .await
}

/// Every record of spike B's fixture, for all 13 callers, before or after the
/// first message, for one shape: envelopes equal full staging, and unscoped
/// callers actually take the demand-scoped path. Split four ways so the
/// halves of this (oracle-heavy) matrix run in parallel.
async fn principal_matrix(messages: bool, shape: &'static str, key: &str) {
    let (fx, matrix) = world().await;
    // Five real logical folder records, so every Docs ancestor join is live.
    let mut parent = ROOT.to_owned();
    for n in 1..=5 {
        let home = format!("h:a2:{n}");
        let folder = format!("f:a2:{n}");
        fx.folder(&folder, &parent, &home, &parent).await;
        fx.field(&folder, "title", &format!("Ancestor {n}")).await;
        parent = home;
    }
    fx.rec("r:a2:nested", &parent, &fx.admin).await;
    fx.typ("r:a2:nested", "Document", Some("note")).await;
    if messages {
        add_messages(&fx).await;
        witness_messages(&fx).await;
    } else {
        witness_base(&fx).await;
    }
    crate::kernel::sql_record_projection::catch_up(&fx.db)
        .await
        .unwrap();
    let statement = declared(key);
    let mut comparisons = 0;
    let mut demand_served = 0;
    // Every fixture record, plus both derived depth boundaries; the 101
    // intermediate thread nodes share the same principal inputs.
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM kernel_records WHERE id NOT LIKE 'c:chain%' UNION SELECT 'c:chain099' UNION SELECT 'c:chain100' ORDER BY 1").fetch_all(fx.db.pool()).await.unwrap();
    for (label, principal, folders) in &matrix.callers {
        for id in &ids {
            let args =
                serde_json::json!({"sql":statement,"parameters":[{"type":"text","value":id}]});
            let (actual, expected, stats) = both(&fx.db, principal, folders, args).await;
            if folders.is_none() {
                assert_eq!(stats.demand, Some(shape), "{label} {shape} {id}: path");
                assert_eq!(
                    stats.demand_fallbacks, 0,
                    "{label} {shape} {id}: unexpected fallback"
                );
                demand_served += 1;
            } else {
                assert_eq!(stats.demand, Some("scoped_app"), "{label} {shape} {id}");
            }
            if label == "member" && id == "r:a2:nested" && shape == "docs_page" {
                assert_eq!(
                    stats.staged_records, 6,
                    "five ancestor records plus the target, not full staging"
                );
                assert_eq!(actual.as_ref().unwrap()["row_count"], 1);
            }
            if label == "member" && !messages && id == "r:team" {
                assert_eq!(actual.as_ref().unwrap()["row_count"], 1, "{shape}");
            }
            assert_eq!(actual, expected, "messages={messages} {label} {shape} {id}");
            comparisons += 1;
        }
    }
    let unscoped = matrix.callers.iter().filter(|c| c.2.is_none()).count();
    assert_eq!(
        demand_served,
        unscoped * ids.len(),
        "every unscoped read took the demand path"
    );
    eprintln!("DEMAND_PRINCIPAL_MATRIX messages={messages} shape={shape} comparisons={comparisons} demand_served={demand_served}");
    fx.db.close().await;
}

#[tokio::test]
async fn demand_scoped_principal_matrix_exact_body() {
    principal_matrix(false, "exact_body", "docs.body").await;
}

#[tokio::test]
async fn demand_scoped_principal_matrix_exact_body_with_messages() {
    principal_matrix(true, "exact_body", "docs.body").await;
}

#[tokio::test]
async fn demand_scoped_principal_matrix_docs_page() {
    principal_matrix(false, "docs_page", "docs.page").await;
}

#[tokio::test]
async fn demand_scoped_principal_matrix_docs_page_with_messages() {
    principal_matrix(true, "docs_page", "docs.page").await;
}

/// Offboarding defeats the owner floor on the demand path too.
#[tokio::test]
async fn demand_scoped_offboarded_owner_body_and_page() {
    let (mut fx, _) = world().await;
    let former = fx.id("former");
    fx.set_owner("r:team", &former).await;
    for offboarded in [false, true] {
        if offboarded {
            fx.roster.remove("former");
            fx.write_roster().await;
        }
        for shape in ["docs.body", "docs.page"] {
            let args = serde_json::json!({"sql":declared(shape),"parameters":[{"type":"text","value":"r:team"}]});
            let (actual, expected, stats) = both(&fx.db, &former, &None, args).await;
            assert!(stats.demand.is_some_and(|d| d != "scoped_app"));
            assert_eq!(actual, expected, "offboarded={offboarded} {shape}");
            assert_eq!(actual.unwrap()["row_count"], if offboarded { 0 } else { 1 });
        }
    }
    fx.db.close().await;
}

/// A small world for placement-dependency witnesses: the root grants the
/// member View; `h:cont` holds a public folder record, `h:pub` holds a
/// public document, `h:acct` is an account-only home.
async fn placement_world() -> (Fx, String) {
    let mut fx = Fx::new().await;
    let member = fx.principal("member").await;
    let admin = fx.admin.clone();
    fx.policy(
        ROOT,
        &[
            ("account", &admin, "allow", "manage"),
            ("account", &member, "allow", "view"),
        ],
    )
    .await;
    fx.home("h:cont", Some(ROOT)).await;
    fx.home("h:pub", Some(ROOT)).await;
    fx.home("h:bare", Some(ROOT)).await;
    fx.home("h:acct", Some(ROOT)).await;
    fx.policy("h:acct", &[("account", &member, "allow", "manage")])
        .await;
    fx.folder("f:pub", "h:cont", "h:folder", "h:cont").await;
    fx.field("f:pub", "title", "Public folder").await;
    (fx, member)
}

async fn rehome(fx: &Fx, record: &str, logical: &str) {
    fx.event(
        record,
        "kernel.record_rehomed.v2",
        serde_json::json!({ "logical_home_id": logical }),
    )
    .await;
}

const PLAIN_HOME_READ: &str = "SELECT id,home_id FROM records WHERE id=?1";

/// Codex review of PR3463 (P1): a visible record whose logical home names an
/// unsealed, primary-type-only Message. There is no sealed message and no
/// v1 Message field anywhere, so only the full probe's `primary_type` arm
/// knows the guard is needed. The demand path must not admit the Message as
/// a placement dependency without the guard: `home_id` stays NULL, as in
/// full staging, for the plain read with no self-join and for the Docs page.
#[tokio::test]
async fn demand_scoped_placement_dependency_keeps_message_guard() {
    let (fx, member) = placement_world().await;
    let admin = fx.admin.clone();
    fx.typed("m:bare", "h:pub", &admin, "Message", "native.messaging")
        .await;
    fx.rec("r:doc", "h:pub", &admin).await;
    fx.typ("r:doc", "Document", Some("note")).await;
    rehome(&fx, "r:doc", "m:bare").await;
    witness(
        &fx,
        &[
            ("member", None, "r:doc", true),
            ("member", None, "m:bare", false),
        ],
    )
    .await;
    crate::kernel::sql_record_projection::catch_up(&fx.db)
        .await
        .unwrap();
    for statement in [PLAIN_HOME_READ.to_owned(), declared("docs.page")] {
        let args =
            serde_json::json!({"sql":statement,"parameters":[{"type":"text","value":"r:doc"}]});
        let (actual, expected, stats) = both(&fx.db, &member, &None, args).await;
        assert_eq!(stats.demand, Some("docs_page"), "{statement}");
        assert_eq!(actual, expected, "{statement}");
        let rows = actual.unwrap();
        assert_eq!(rows["row_count"], 1, "{statement}");
        assert!(
            !rows.to_string().contains("m:bare"),
            "the hidden Message must not surface as a home: {rows}"
        );
    }
    fx.db.close().await;
}

/// Codex review of PR3463 (P2): an account-only record filed in a visible
/// public folder, and one filed under a visible bare home with no record.
/// A plain finite read with no join must load the folder's own authority
/// home (and the bare home's row), so `home_id` names them exactly as full
/// staging does instead of masking them as NULL.
#[tokio::test]
async fn demand_scoped_plain_read_loads_placement_homes() {
    let (fx, member) = placement_world().await;
    fx.rec("r:acct", "h:acct", &member).await;
    fx.typ("r:acct", "Document", Some("note")).await;
    rehome(&fx, "r:acct", "f:pub").await;
    fx.rec("r:acct_bare", "h:acct", &member).await;
    fx.typ("r:acct_bare", "Document", Some("note")).await;
    rehome(&fx, "r:acct_bare", "h:bare").await;
    witness(
        &fx,
        &[
            ("member", None, "r:acct", true),
            ("member", None, "r:acct_bare", true),
            ("member", None, "f:pub", true),
        ],
    )
    .await;
    crate::kernel::sql_record_projection::catch_up(&fx.db)
        .await
        .unwrap();
    for (id, home) in [("r:acct", "f:pub"), ("r:acct_bare", "h:bare")] {
        for statement in [PLAIN_HOME_READ.to_owned(), declared("docs.page")] {
            let args =
                serde_json::json!({"sql":statement,"parameters":[{"type":"text","value":id}]});
            let (actual, expected, stats) = both(&fx.db, &member, &None, args).await;
            assert_eq!(stats.demand, Some("docs_page"), "{id}: {statement}");
            assert_eq!(actual, expected, "{id}: {statement}");
            if statement == PLAIN_HOME_READ {
                assert_eq!(actual.unwrap()["rows"][0]["home_id"], home, "{id}");
            }
        }
    }
    fx.db.close().await;
}

/// A historical fold can retain a recordless secondary alias for the
/// logical root, although live home admission requires a source record.
/// Full staging can use that alias's visibility when masking `home_id`.
/// Demand staging must use the census rather than silently losing it.
#[tokio::test]
async fn demand_scoped_recordless_root_secondary_alias_uses_census() {
    let (fx, member) = placement_world().await;
    fx.policy(ROOT, &[("account", &fx.admin, "allow", "manage")])
        .await;
    fx.home("h:root-alias", Some(ROOT)).await;
    fx.policy("h:root-alias", &[("account", &member, "allow", "view")])
        .await;
    fx.event(
        "h:root-alias",
        "kernel.home_created.v1",
        serde_json::json!({"source_record_id":"native:root"}),
    )
    .await;
    fx.rec("r:root-child", "h:acct", &member).await;
    fx.typ("r:root-child", "Document", Some("note")).await;
    rehome(&fx, "r:root-child", "native:root").await;
    fx.db.demand_root_aliases.invalidate();
    assert_eq!(
        demand_root_aliases::Check::settle(&fx.db).await,
        demand_root_aliases::State::HasAliases
    );
    for statement in [PLAIN_HOME_READ.to_owned(), declared("docs.page")] {
        let args = serde_json::json!({"sql":statement,"parameters":[{"type":"text","value":"r:root-child"}]});
        let (actual, expected, stats) = both(&fx.db, &member, &None, args).await;
        assert_eq!(stats.demand, Some("root_secondary_alias"));
        assert_eq!(actual, expected, "{statement}");
        if statement == PLAIN_HOME_READ {
            assert_eq!(actual.unwrap()["rows"][0]["home_id"], "native:root");
        }
    }
    fx.db.close().await;
}

/// The loader's home rows equal the census's rows for the same homes, for
/// every caller and every record, including broken, overflowing and
/// missing-root walks. This is the evaluator contract the staging relies on.
#[tokio::test]
async fn demand_scoped_homes_equal_census_rows() {
    let (fx, matrix) = world().await;
    add_messages(&fx).await;
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM kernel_records ORDER BY id")
        .fetch_all(fx.db.pool())
        .await
        .unwrap();
    let mut checked = 0;
    for (label, principal, folders) in &matrix.callers {
        if folders.is_some() {
            continue;
        }
        let mut tx = fx.db.write_pool().begin().await.unwrap();
        let census: BTreeMap<String, (bool, bool, bool)> =
            visible_home_anchors_as(&mut tx, principal)
                .await
                .unwrap()
                .homes
                .into_iter()
                .map(|h| (h.home_id, (h.policy_valid, h.policy_view, h.home_view)))
                .collect();
        for id in &ids {
            let demand::Demand::Scope(scope) = demand::demand_home_anchors_as(
                &mut tx,
                principal,
                std::slice::from_ref(id),
                &[],
                demand_root_aliases::State::Unknown,
            )
            .await
            .unwrap() else {
                panic!("{label} {id}: unexpected fallback");
            };
            assert!(scope.staged.contains(id));
            for home in scope.homes.homes {
                let row = (home.policy_valid, home.policy_view, home.home_view);
                assert_eq!(
                    census.get(&home.home_id),
                    Some(&row),
                    "{label} {id} {}",
                    home.home_id
                );
                checked += 1;
            }
        }
        tx.rollback().await.unwrap();
    }
    assert!(checked > 500, "{checked}");
}

// ---------------------------------------------------------------------------
// S1a: seven-axis cost matrix for live demand-scoped evaluation (73ad275 §6).
// Run: python3 scripts/read-cost-baseline.py --axes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, serde::Serialize)]
struct Axes {
    unrelated: usize,
    history: usize,
    roster: usize,
    width: usize,
    width_elsewhere: usize,
    depth: usize,
    chain: usize,
    guard: usize,
    policy_homes: usize,
    /// Sealed messages elsewhere in the workspace, each with one comment.
    messages: usize,
}
const BASE: Axes = Axes {
    unrelated: 1000,
    history: 1,
    roster: 10,
    width: 1,
    width_elsewhere: 1,
    depth: 1,
    chain: 1,
    guard: 0,
    policy_homes: 10,
    messages: 0,
};

/// A hosted workspace: roster, root and team anchors with templates, a
/// five-folder chain holding the target document, then one axis grown.
async fn axis_world(a: Axes) -> (Fx, String) {
    let mut fx = Fx::new().await;
    let reader = fx.principal("member").await;
    let admin = fx.admin.clone();
    // Roster: real admin and reader plus synthetic members (bindings only).
    let mut members = serde_json::Map::new();
    members.insert("admin".into(), admin.clone().into());
    members.insert("member".into(), reader.clone().into());
    for i in 2..a.roster {
        members.insert(format!("acct:m{i:05}"), format!("p:m{i:05}").into());
    }
    fx.event(
        ROOT,
        hosted_identity::ROSTER_EVENT,
        serde_json::json!({"members": members, "catalog_accounts": {}}),
    )
    .await;
    fx.policy(ROOT, &[("account", &admin, "allow", "manage")])
        .await;
    fx.template(ROOT, &[(&admin, "manage")], Some("view"), None)
        .await;
    // The path anchor, with `width` explicit grants (stored and template).
    fx.home("h:team", Some(ROOT)).await;
    let grants: Vec<(String, String)> = (0..a.width)
        .map(|i| (format!("p:w{i:04}"), "view".to_owned()))
        .chain([(admin.clone(), "manage".to_owned())])
        .collect();
    let rows: Vec<(&str, &str, &str, &str)> = grants
        .iter()
        .map(|(s, c)| ("account", s.as_str(), "allow", c.as_str()))
        .collect();
    fx.policy("h:team", &rows).await;
    let explicit: Vec<(&str, &str)> = grants
        .iter()
        .map(|(s, c)| (s.as_str(), c.as_str()))
        .collect();
    fx.template("h:team", &explicit, Some("view"), None).await;
    // Five folder records: the Docs page's full ancestor chain.
    let mut parent = "h:team".to_owned();
    for n in 1..=5 {
        let (home, folder) = (format!("h:f{n}"), format!("f:{n}"));
        fx.folder(&folder, &parent, &home, &parent).await;
        fx.field(&folder, "title", &format!("Folder {n}")).await;
        parent = home;
    }
    fx.rec("r:target", "h:f5", &admin).await;
    fx.typ("r:target", "Document", Some("note")).await;
    fx.field("r:target", "title", "Target").await;
    fx.field("r:target", "body", &"x".repeat(2048)).await;
    // Ancestry depth below the anchor, through plain homes.
    let mut parent = "h:team".to_owned();
    for d in 1..=a.depth {
        let home = format!("h:d{d:03}");
        fx.home(&home, Some(&parent)).await;
        parent = home;
    }
    fx.rec("r:deep", &parent, &admin).await;
    fx.field("r:deep", "title", "Deep").await;
    // Comment chain on the target; the read is its last comment.
    let mut bearer = "r:target".to_owned();
    for c in 1..=a.chain {
        let id = format!("c:k{c:03}");
        fx.comment(&id, "h:team", &reader, &bearer).await;
        bearer = id;
    }
    // Guard depth: messages exist, and an annotation chain of `guard` hops.
    if a.guard > 0 {
        fx.typed("m:any", "h:team", &admin, "Message", "native.messaging")
            .await;
        fx.seal("m:any", &serde_json::json!({ admin.clone(): "manage" }))
            .await;
        let mut bearer = "r:target".to_owned();
        for g in 1..=a.guard {
            let id = format!("c:g{g}");
            fx.comment(&id, "h:team", &reader, &bearer).await;
            bearer = id;
        }
    }
    // Unrelated messages elsewhere, each with one comment.
    for m in 0..a.messages {
        let (id, comment) = (format!("m:x{m:05}"), format!("c:x{m:05}"));
        fx.typed(&id, "h:team", &admin, "Message", "native.messaging")
            .await;
        fx.seal(&id, &serde_json::json!({ admin.clone(): "manage" }))
            .await;
        fx.comment(&comment, "h:team", &admin, &id).await;
    }
    // Same-record history: the target's own events and its anchor's policy
    // history (identical templates at the current frontier), plus events on
    // every ancestor home. Placement, policy and the envelope are unchanged.
    for _ in 0..a.history {
        fx.event(
            "r:target",
            "kernel.record_rehomed.v2",
            serde_json::json!({"new_home_id":"h:f5","logical_home_id":"f:5"}),
        )
        .await;
        fx.event("r:target", "kernel.test_history.v1", serde_json::json!({}))
            .await;
        fx.template("h:team", &explicit, Some("view"), None).await;
        for home in ["h:f1", "h:f2", "h:f3", "h:f4", "h:f5"] {
            fx.event(home, "kernel.test_history.v1", serde_json::json!({}))
                .await;
        }
    }
    // Policy homes elsewhere, each an anchor with grants and a template.
    fx.exec("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<CAST(?1 AS INTEGER)) INSERT INTO kernel_roots(root_id,parent_id,owner_id,created_seq,created_at) SELECT printf('h:p%05d',x),?2,NULL,1,'2026-11-13T00:00:00Z' FROM n", &[&a.policy_homes.to_string(), ROOT]).await;
    fx.exec("INSERT INTO kernel_policies(root_id,created_at) SELECT root_id,'2026-11-13T00:00:00Z' FROM kernel_roots WHERE root_id GLOB 'h:p*'", &[]).await;
    fx.exec("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<CAST(?1 AS INTEGER)) INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) SELECT h.root_id,'account',printf('p:e%04d',n.x),'allow','view' FROM kernel_roots h CROSS JOIN n WHERE h.root_id GLOB 'h:p*'", &[&a.width_elsewhere.to_string()]).await;
    fx.exec("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) SELECT 'ev:'||root_id,root_id,?1,json_object('policy_seq',0,'explicit',json_object('p:e0001','view'),'members','view'),NULL,1,'complete' FROM kernel_roots WHERE root_id GLOB 'h:p*'", &[hosted_identity::POLICY_EVENT]).await;
    // Unrelated records and events, in ten homes under the root.
    fx.exec("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10) INSERT INTO kernel_roots(root_id,parent_id,owner_id,created_seq,created_at) SELECT printf('h:u%02d',x),?1,NULL,1,'2026-11-13T00:00:00Z' FROM n", &[ROOT]).await;
    fx.exec("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<CAST(?1 AS INTEGER)) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('u:%06d',x),printf('h:u%02d',x%10+1),?2,1,'2026-11-13T00:00:00Z' FROM n", &[&a.unrelated.to_string(), &admin]).await;
    fx.exec("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'title',json_quote('Unrelated '||id),1 FROM kernel_records WHERE id GLOB 'u:*'", &[]).await;
    fx.exec("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4) INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) SELECT 'ue:'||r.id||':'||n.x,r.id,'kernel.test_history.v1','{}',NULL,1,'complete' FROM kernel_records r CROSS JOIN n WHERE r.id GLOB 'u:*'", &[]).await;
    crate::kernel::sql_record_projection::catch_up(&fx.db)
        .await
        .unwrap();
    (fx, reader)
}

#[derive(serde::Serialize)]
struct AxisSample {
    axis: &'static str,
    value: usize,
    shape: &'static str,
    target: String,
    path: Option<&'static str>,
    /// Warm maxima: [VM_STEP, FULLSCAN_STEP, SORT, AUTOINDEX].
    staging: [u64; 4],
    caller: [u64; 4],
    staged_rows: u64,
    roster_parses_per_read: u64,
    roster_parse_us_per_read: f64,
    row_count: u64,
    /// Total VM steps of today's path (census) for the same read.
    today_vm: u64,
}

async fn measure_axis(axis: &'static str, value: usize, a: Axes, target: &str) -> Vec<AxisSample> {
    let (fx, reader) = axis_world(a).await;
    let mut out = Vec::new();
    for (shape, key) in [("exact_body", "docs.body"), ("docs_page", "docs.page")] {
        let args =
            serde_json::json!({"sql":declared(key),"parameters":[{"type":"text","value":target}]});
        let expected =
            sql::with_full_read_oracle(Box::pin(sql::query_sql(&fx.db, &reader, args.clone())))
                .await
                .unwrap();
        let mut staging = [0u64; 4];
        let mut caller = [0u64; 4];
        let mut rows = 0;
        let mut path = None;
        let (mut parses, mut nanos) = (0, 0);
        let mut today_vm = 0;
        let repetitions = 3;
        for repetition in 0..=repetitions {
            let _ = hosted_identity::roster_parse_probe::take();
            let ((actual, stats), cost) =
                sql::read_cost::measure(sql::measured(sql::demand::with_enabled_for_test(
                    Box::pin(sql::query_sql(&fx.db, &reader, args.clone())),
                )))
                .await;
            let (p, n) = hosted_identity::roster_parse_probe::take();
            let actual = actual.unwrap();
            if repetition == repetitions {
                // Today's path for the same read: finite IDs over the census.
                let (_, today) = sql::read_cost::measure(Box::pin(sql::query_sql(
                    &fx.db,
                    &reader,
                    args.clone(),
                )))
                .await;
                today_vm = today.staging[0] + today.caller[0];
            }
            assert_eq!(actual, expected, "{axis}={value} {shape}: envelope");
            path = stats.demand;
            if repetition == 0 {
                continue;
            }
            for i in 0..4 {
                staging[i] = staging[i].max(cost.staging[i]);
                caller[i] = caller[i].max(cost.caller[i]);
            }
            rows = rows.max(cost.staged_rows);
            parses = parses.max(p);
            nanos += n;
        }
        out.push(AxisSample {
            axis,
            value,
            shape,
            target: target.to_owned(),
            path,
            staging,
            caller,
            staged_rows: rows,
            roster_parses_per_read: parses,
            roster_parse_us_per_read: nanos as f64 / 1000.0 / repetitions as f64,
            row_count: expected["row_count"].as_u64().unwrap(),
            today_vm,
        });
    }
    fx.db.close().await;
    out
}

#[tokio::test]
#[ignore = "S1a seven-axis demand-scoped cost matrix; scripts/read-cost-baseline.py --axes"]
async fn demand_scoped_axis_matrix() {
    let mut plan: Vec<(&'static str, usize, Axes, String)> = Vec::new();
    for n in [1000, 10000] {
        plan.push((
            "unrelated",
            n,
            Axes {
                unrelated: n,
                ..BASE
            },
            "r:target".into(),
        ));
    }
    for n in [1, 10, 100] {
        plan.push(("history", n, Axes { history: n, ..BASE }, "r:target".into()));
    }
    for n in [10, 100, 1000] {
        plan.push(("roster", n, Axes { roster: n, ..BASE }, "r:target".into()));
    }
    for n in [1, 10, 100] {
        plan.push((
            "width_on_path",
            n,
            Axes { width: n, ..BASE },
            "r:target".into(),
        ));
    }
    for n in [1, 100] {
        plan.push((
            "width_elsewhere",
            n,
            Axes {
                width_elsewhere: n,
                ..BASE
            },
            "r:target".into(),
        ));
    }
    for n in [1, 10, 50, 99] {
        plan.push(("depth", n, Axes { depth: n, ..BASE }, "r:deep".into()));
    }
    for n in [1, 10, 100] {
        plan.push((
            "comment_chain",
            n,
            Axes { chain: n, ..BASE },
            format!("c:k{n:03}"),
        ));
    }
    for n in 1..=8 {
        plan.push(("guard", n, Axes { guard: n, ..BASE }, format!("c:g{n}")));
    }
    // A thread deeper than the guard walk (depth 10 > 8) in a workspace with
    // messages: the guard then consults the workspace's message-bearing set.
    for n in [10, 100] {
        plan.push((
            "messages_deep_thread",
            n,
            Axes {
                messages: n,
                chain: 10,
                ..BASE
            },
            "c:k010".into(),
        ));
    }
    for n in [10, 100] {
        plan.push((
            "policy_homes",
            n,
            Axes {
                policy_homes: n,
                ..BASE
            },
            "r:target".into(),
        ));
    }
    let only = std::env::var("READ_COST_AXES").unwrap_or_default();
    for (axis, value, a, target) in plan {
        if !only.is_empty() && !only.split(',').any(|o| o == axis) {
            continue;
        }
        for sample in measure_axis(axis, value, a, &target).await {
            assert!(
                matches!(sample.path, Some("exact_body") | Some("docs_page")),
                "{axis}={value}: demand path not taken: {:?}",
                sample.path
            );
            eprintln!("DEMAND_AXIS {}", serde_json::to_string(&sample).unwrap());
        }
    }
}

/// Legacy/minimal sealed state can be accepted by bulk staging while the
/// independent point gate cannot deserialize it. Do not surface that fast
/// error: the old path must still answer exactly as before.
#[tokio::test]
async fn demand_scoped_malformed_message_recheck_falls_back_without_error() {
    let (fx, member) = placement_world().await;
    fx.typed(
        "m:legacy-minimal",
        "h:pub",
        &member,
        "Message",
        "native.messaging",
    )
    .await;
    fx.exec(
        "INSERT INTO kernel_messages(message_id,state,event_seq) VALUES(?,'{\"audience\":{}}',1)",
        &["m:legacy-minimal"],
    )
    .await;
    // Historical workspaces can be large. The legacy exact-ID fallback must
    // not expand this minimal-state carrier into a workspace-wide restage.
    fx.exec("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('r:unrelated:%d',x),'h:pub',?1,1,'2026-11-13T00:00:00Z' FROM n", &[&member]).await;
    for statement in [
        "SELECT id,body FROM records WHERE id=?1".to_owned(),
        declared("docs.page"),
    ] {
        let args = serde_json::json!({"sql":statement,"parameters":[{"type":"text","value":"m:legacy-minimal"}]});
        let (actual, expected, stats) = both(&fx.db, &member, &None, args.clone()).await;
        assert_eq!(actual, expected);
        assert_eq!(actual.unwrap()["row_count"], 1);
        assert_eq!(stats.demand_fallbacks, 1);
        if statement.contains("SELECT id,body") {
            assert_eq!(
                stats.staged_records, 1,
                "fallback retains the exact-ID legacy scope"
            );
        }
        let batch = vec![args.clone()];
        let (bound, stats) = sql::measured(sql::with_bound_query_read_session_for_test(
            &fx.db,
            &member,
            &batch,
            sql::query_sql(&fx.db, &member, args),
        ))
        .await;
        assert_eq!(bound.map_err(|e| e.to_string()), expected);
        assert_eq!(stats.demand_fallbacks, 1);
        assert_eq!(
            stats.staged_records, 1,
            "bound fallback retains exact candidates"
        );
    }
    fx.db.close().await;
}

async fn imported_root_world(unrelated: usize) -> (Fx, String) {
    let (fx, reader) = axis_world(Axes { unrelated, ..BASE }).await;
    // Imported workspaces have a logical root mapping but no root record.
    fx.event(ROOT, "kernel.import_home_policy.v1", serde_json::json!({}))
        .await;
    // The import event advances the policy frontier. Preserve the member's
    // root View with a template bound to that new frontier.
    fx.template(ROOT, &[(&fx.admin, "manage")], Some("view"), None)
        .await;
    // The top folder is logically filed in that root, independently of its
    // physical policy home. The shipped Docs query reaches it through h5.
    rehome(&fx, "f:1", "native:root").await;
    fx.db.demand_root_aliases.invalidate();
    assert_eq!(
        demand_root_aliases::Check::settle(&fx.db).await,
        demand_root_aliases::State::NoRecordlessRootAliases
    );
    (fx, reader)
}

#[tokio::test]
async fn demand_root_alias_unknown_never_blocks_and_falls_back() {
    let (fx, reader) = imported_root_world(10).await;
    let release = demand_root_aliases::Check::pause(&fx.db);
    let args = serde_json::json!({"sql":declared("docs.page"),"parameters":[{"type":"text","value":"r:target"}]});
    let (actual, expected, stats) = both(&fx.db, &reader, &None, args.clone()).await;
    assert_eq!(stats.demand, Some("root_alias_unknown"));
    assert_eq!(actual, expected);
    assert_eq!(actual.unwrap()["row_count"], 1);
    // An unknown root check does not affect reads with no root-cell dependency.
    let body = serde_json::json!({"sql":declared("docs.body"),"parameters":[{"type":"text","value":"r:target"}]});
    let (actual, expected, stats) = both(&fx.db, &reader, &None, body).await;
    assert_eq!(actual, expected);
    assert_eq!(stats.demand, Some("exact_body"));
    assert_eq!(
        fx.db.demand_root_aliases.state(),
        demand_root_aliases::State::Unknown
    );
    release.notify_one();
    assert_eq!(
        demand_root_aliases::Check::settle(&fx.db).await,
        demand_root_aliases::State::NoRecordlessRootAliases
    );
    let (actual, expected, stats) = both(&fx.db, &reader, &None, args).await;
    assert_eq!(actual, expected);
    assert_eq!(stats.demand, Some("docs_page"));
    fx.db.close().await;
}

#[tokio::test]
async fn demand_root_alias_generation_reopen_checks_new_copy() {
    let (fx, _) = imported_root_world(10).await;
    let old = fx.db.handle_id();
    // Simulate a newly adopted historical generation containing an alias.
    fx.event(
        "h:historic",
        "kernel.home_created.v1",
        serde_json::json!({"source_record_id":"native:root"}),
    )
    .await;
    let filename = fx.db.pool().connect_options().get_filename().to_path_buf();
    let reopened = open_v2_database(filename.to_str().unwrap()).await.unwrap();
    assert_ne!(old, reopened.handle_id());
    assert_eq!(
        demand_root_aliases::Check::settle(&reopened).await,
        demand_root_aliases::State::HasAliases
    );
    // A result from the prior incarnation is never reused for this open.
    assert_eq!(
        fx.db.demand_root_aliases.state(),
        demand_root_aliases::State::NoRecordlessRootAliases
    );
    reopened.close().await;
    fx.db.close().await;
}

/// The real shipped Docs SQL reaches a recordless imported root. After the
/// one background check, no history census remains on either read path:
/// both VM and full-scan counters stay identical with 10x unrelated records
/// and their events. Every answer is still checked against full staging.
#[tokio::test]
async fn demand_root_alias_imported_docs_reads_are_flat() {
    sql::read_cost::with_comparison_budget(imported_root_flatness()).await;
}

async fn imported_root_flatness() {
    let mut baseline = BTreeMap::new();
    for unrelated in [1000, 10000] {
        let (fx, reader) = imported_root_world(unrelated).await;
        // Witness the exact root-cell case, rather than a fixture that stops
        // at a bare physical home and never consults the root alias state.
        let home =
            serde_json::json!({"sql":PLAIN_HOME_READ,"parameters":[{"type":"text","value":"f:1"}]});
        let value = sql::query_sql(&fx.db, &reader, home).await.unwrap();
        assert_eq!(value["rows"][0]["home_id"], "native:root");
        for (shape, key) in [("exact_body", "docs.body"), ("docs_page", "docs.page")] {
            let args = serde_json::json!({"sql":declared(key),"parameters":[{"type":"text","value":"r:target"}]});
            let expected =
                sql::with_full_read_oracle(sql::query_sql(&fx.db, &reader, args.clone()))
                    .await
                    .unwrap();
            let mut counters = (0, 0);
            for _ in 0..3 {
                let ((actual, stats), cost) = sql::read_cost::measure(sql::measured(
                    sql::query_sql(&fx.db, &reader, args.clone()),
                ))
                .await;
                assert_eq!(actual.unwrap(), expected);
                assert_eq!(stats.demand, Some(shape));
                assert_eq!(stats.demand_fallbacks, 0);
                counters.0 = counters.0.max(cost.staging[0] + cost.caller[0]);
                counters.1 = counters.1.max(cost.staging[1] + cost.caller[1]);
            }
            assert!(
                counters.0 < 100_000,
                "{shape}: a root read must not run the census"
            );
            if unrelated == 1000 {
                baseline.insert(shape, counters);
            } else {
                assert_eq!(
                    counters, baseline[shape],
                    "{shape}: no event-history scan on the read path"
                );
            }
            eprintln!(
                "S1B_IMPORTED_ROOT_FLAT {}",
                serde_json::json!({"shape":shape,"unrelated":unrelated,"vm_steps":counters.0,"fullscan_steps":counters.1})
            );
        }
        fx.db.close().await;
    }
}

/// Census home_view includes recordless anchors, whereas the single-record
/// capability gate requires a root/record target. Substituting that gate for
/// home-cell masking would change existing View semantics.
#[tokio::test]
async fn demand_home_cells_cannot_use_single_record_gate_for_recordless_homes() {
    let (fx, member) = placement_world().await;
    fx.rec("r:bare-anchor", "h:recordless", &member).await;
    fx.policy("h:recordless", &[("account", &member, "allow", "view")])
        .await;
    let mut tx = fx.db.write_pool().begin().await.unwrap();
    let census = visible_home_anchors_as(&mut tx, &member).await.unwrap();
    assert!(census
        .homes
        .iter()
        .any(|h| h.home_id == "h:recordless" && h.home_view));
    assert!(
        kernel_effective_capability_on(&mut tx, &member, "h:recordless")
            .await
            .is_err()
    );
    assert!(
        kernel_effective_capability_on(&mut tx, &member, "native:root")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // Bind the physical root to the logical root, as imported workspaces do.
    fx.event(
        ROOT,
        "kernel.home_created.v1",
        serde_json::json!({"source_record_id":"native:root"}),
    )
    .await;
    fx.db.demand_root_aliases.invalidate();
    fx.rec("r:root-cell", "h:pub", &member).await;
    rehome(&fx, "r:root-cell", "native:root").await;
    demand_root_aliases::Check::settle(&fx.db).await;
    let args = serde_json::json!({"sql":PLAIN_HOME_READ,"parameters":[{"type":"text","value":"r:root-cell"}]});
    let (actual, expected, _) = both(&fx.db, &member, &None, args).await;
    assert_eq!(actual, expected);
    assert_eq!(actual.unwrap()["rows"][0]["home_id"], "native:root");
    fx.db.close().await;
}

/// The caller-error retry keeps a real placement fixpoint under the legacy
/// plan, including all five folder records reached by the shipped Docs SQL.
#[tokio::test]
async fn demand_bound_caller_retry_home_chain_matches_full_oracle() {
    let (fx, reader) = imported_root_world(20).await;
    let args = serde_json::json!({"sql":declared("docs.page"),"parameters":[{"type":"text","value":"r:target"}]});
    let expected = sql::with_full_read_oracle(sql::query_sql(&fx.db, &reader, args.clone()))
        .await
        .unwrap();
    let batch = vec![args.clone()];
    let (actual, stats) = sql::measured(sql::demand::with_failed_caller(
        sql::with_bound_query_read_session_for_test(
            &fx.db,
            &reader,
            &batch,
            sql::query_sql(&fx.db, &reader, args),
        ),
    ))
    .await;
    assert_eq!(actual.unwrap(), expected);
    assert_eq!(stats.demand_fallbacks, 1);
    assert_eq!(
        stats.staged_records, 6,
        "the target plus five real ancestors"
    );
    fx.db.close().await;
}
