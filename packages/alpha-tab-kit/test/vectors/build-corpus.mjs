#!/usr/bin/env node
// Regenerates corpus.json: cases the kit and the Rust install path must
// judge identically. The kit's tests assert the kit's verdict; the Rust
// drift test (src/mcp/tools/alpha_tab_kit_drift.rs) asserts the engine's.
// Boundary cases sit exactly at, and one past, every limit in limits.json.
import { writeFileSync } from "node:fs";

const need = (key, sql, params) => ({ need: "sql.snapshot.v1", key, label: "Kit corpus case", sql, ...(params ? { params } : {}) });
const ok = "SELECT id FROM records ORDER BY id LIMIT 1";
const text = (name, extra = {}) => ({ name, type: "text", ...extra });
const pad = (sql, bytes) => `${sql} /*${"x".repeat(bytes - Buffer.byteLength(sql) - 5)}*/`;

const sql = [
  // Admitted.
  { name: "ordered limit", sql: "SELECT id, name FROM records ORDER BY id LIMIT 5", admitted: true },
  { name: "one text param", sql: "SELECT id, body FROM records WHERE id = ?1", params: [text("id", { max_len: 64 })], admitted: true },
  { name: "join, ordered", sql: "SELECT r.id, l.relationship FROM records r JOIN links l ON l.source_id = r.id ORDER BY r.id, l.relationship LIMIT 10", admitted: true },
  { name: "cte with its own ordered limit", sql: "WITH recent AS (SELECT id FROM records ORDER BY last_activity_at_ms DESC, id LIMIT 20) SELECT id FROM recent ORDER BY id", admitted: true },
  { name: "aggregate", sql: "SELECT count(*) AS n FROM records", admitted: true },
  { name: "optional param and timestamp", sql: "SELECT id FROM records WHERE (?1 IS NULL OR kind = ?1) AND last_activity_at_ms >= ?2 ORDER BY id LIMIT 5", params: [text("kind", { required: false }), { name: "since", type: "timestamp_ms" }], admitted: true },
  { name: "like with a param", sql: "SELECT id FROM records WHERE name LIKE ?1 ORDER BY id LIMIT 5", params: [text("pattern")], admitted: true },
  { name: "now_ms()", sql: "SELECT id FROM records WHERE last_activity_at_ms > now_ms() - 86400000 ORDER BY id LIMIT 5", admitted: true },
  { name: "compound with trailing order", sql: "SELECT id FROM records WHERE kind = 'task' UNION SELECT id FROM records WHERE kind = 'epic' ORDER BY 1 LIMIT 10", admitted: true },
  // Refused.
  { name: "limit without order", sql: "SELECT id FROM records LIMIT 5", admitted: false, rule: "sql.limit-order" },
  { name: "nested limit without order", sql: "SELECT (SELECT target_id FROM links LIMIT 1) AS t FROM records ORDER BY id LIMIT 5", admitted: false, rule: "sql.limit-order" },
  { name: "outer limit without order", sql: "SELECT (SELECT target_id FROM links ORDER BY target_id LIMIT 1) AS t FROM records LIMIT 5", admitted: false, rule: "sql.limit-order" },
  { name: "group_concat", sql: "SELECT group_concat(name) AS names FROM records", admitted: false, rule: "sql.dropped-function" },
  { name: "json_extract", sql: "SELECT json_extract(body, '$.a') AS a FROM records ORDER BY id LIMIT 1", admitted: false, rule: "sql.dropped-function" },
  { name: "glob operator", sql: "SELECT id FROM records WHERE name GLOB 'a*' ORDER BY id LIMIT 1", admitted: false, rule: "sql.dropped-function" },
  { name: "lag window function", sql: "SELECT lag(id) OVER (ORDER BY id) AS prev FROM records", admitted: false, rule: "sql.unknown-function" },
  { name: "two-argument round", sql: "SELECT round(1.25, 1) AS r", admitted: false, rule: "sql.function-arity" },
  { name: "placeholder without params", sql: "SELECT id FROM records WHERE id = ?1", admitted: false, rule: "sql.placeholder-params" },
  { name: "placeholder gap", sql: "SELECT id FROM records WHERE id = ?2", params: [text("id")], admitted: false, rule: "sql.placeholder-params" },
  { name: "unused param", sql: ok, params: [text("id")], admitted: false, rule: "sql.placeholder-params" },
  { name: "named placeholder", sql: "SELECT id FROM records WHERE id = :id", params: [text("id")], admitted: false, rule: "sql.placeholder" },
  { name: "bare placeholder", sql: "SELECT id FROM records WHERE id = ?", params: [text("id")], admitted: false, rule: "sql.placeholder" },
  { name: "internal table", sql: "SELECT name FROM sqlite_master", admitted: false, rule: "sql.relation" },
  { name: "unknown relation", sql: "SELECT id FROM tasks ORDER BY id LIMIT 1", admitted: false, rule: "sql.relation" },
  { name: "write statement", sql: "DELETE FROM records", admitted: false, rule: "sql.first-word" },
  { name: "two statements", sql: "SELECT id FROM records; SELECT id FROM links", admitted: false, rule: "sql.single-statement" },
  { name: "clock keyword", sql: "SELECT current_timestamp AS t", admitted: false, rule: "sql.clock-keyword" },
  { name: "duplicate output label", sql: "SELECT r.id, l.source_id AS id FROM records r JOIN links l ON l.source_id = r.id ORDER BY r.id LIMIT 3", admitted: false, rule: "sql.duplicate-columns" },
  { name: "65 output columns", sql: `SELECT ${Array.from({ length: 65 }, (_, i) => `id AS c${i}`).join(", ")} FROM records ORDER BY id LIMIT 1`, admitted: false, rule: "sql.columns" },
];

const bound = (key, values, needKey = "kit.grid", extra = {}) => ({
  effect: "records.facet-set.v1", key, values, target: { need: needKey }, ...extra,
});
const cbound = (positions, max_body_bytes, needKey = "kit.grid", extra = {}) => ({
  effect: "comment.create.v1", positions, max_body_bytes, target: { need: needKey }, ...extra,
});
const gridNeed = need("kit.grid", ok);
const withBound = (effects, needs = [gridNeed]) => ({ needs, effects });

const eight = Array.from({ length: 8 }, (_, i) => need(`kit.n${i}`, ok));
const params = (n) => Array.from({ length: n }, (_, i) => ({ name: `p${i}`, type: "integer" }));
const paramSql = (n) => `SELECT id FROM records WHERE ${Array.from({ length: n }, (_, i) => `last_activity_at_ms > ?${i + 1}`).join(" AND ")} ORDER BY id LIMIT 1`;
const declaration = [
  { name: "minimal", declaration: { needs: [need("kit.a", ok)], effects: [] }, admitted: true },
  { name: "label 120 chars (multi-byte)", declaration: { needs: [{ ...need("kit.a", ok), label: "é".repeat(120) }], effects: [] }, admitted: true },
  { name: "label 121 chars", declaration: { needs: [{ ...need("kit.a", ok), label: "é".repeat(121) }], effects: [] }, admitted: false },
  { name: "empty label", declaration: { needs: [{ ...need("kit.a", ok), label: "" }], effects: [] }, admitted: false },
  { name: "key 40 chars", declaration: { needs: [need(`k${"a".repeat(39)}`, ok)], effects: [] }, admitted: true },
  { name: "key 41 chars", declaration: { needs: [need(`k${"a".repeat(40)}`, ok)], effects: [] }, admitted: false },
  { name: "key uppercase", declaration: { needs: [need("Kit", ok)], effects: [] }, admitted: false },
  { name: "key collides with a host need", declaration: { needs: [need("records.search.v1", ok)], effects: [] }, admitted: false },
  { name: "8 sql needs", declaration: { needs: eight, effects: [] }, admitted: true },
  { name: "9 sql needs", declaration: { needs: [...eight, need("kit.n8", ok)], effects: [] }, admitted: false },
  { name: "sql 4096 bytes", declaration: { needs: [need("kit.a", pad(ok, 4096))], effects: [] }, admitted: true },
  { name: "sql 4097 bytes", declaration: { needs: [need("kit.a", pad(ok, 4097))], effects: [] }, admitted: false },
  { name: "8 params", declaration: { needs: [need("kit.a", paramSql(8), params(8))], effects: [] }, admitted: true },
  { name: "9 params", declaration: { needs: [need("kit.a", paramSql(9), params(9))], effects: [] }, admitted: false },
  { name: "param name 32 chars", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [text(`p${"a".repeat(31)}`)])], effects: [] }, admitted: true },
  { name: "param name 33 chars", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [text(`p${"a".repeat(32)}`)])], effects: [] }, admitted: false },
  { name: "max_len 1024", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [text("id", { max_len: 1024 })])], effects: [] }, admitted: true },
  { name: "max_len 1025", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [text("id", { max_len: 1025 })])], effects: [] }, admitted: false },
  { name: "max_len 0", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [text("id", { max_len: 0 })])], effects: [] }, admitted: false },
  { name: "max_len on an integer param", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE last_activity_at_ms > ?1 ORDER BY id LIMIT 1", [{ name: "since", type: "integer", max_len: 10 }])], effects: [] }, admitted: false },
  { name: "unknown param type", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [{ name: "id", type: "uuid" }])], effects: [] }, admitted: false },
  { name: "required not boolean", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1", [text("id", { required: "yes" })])], effects: [] }, admitted: false },
  { name: "duplicate param", declaration: { needs: [need("kit.a", "SELECT id FROM records WHERE id = ?1 OR name = ?2", [text("id"), text("id")])], effects: [] }, admitted: false },
  { name: "extra key on a sql need", declaration: { needs: [{ ...need("kit.a", ok), note: "x" }], effects: [] }, admitted: false },
  { name: "duplicate sql key", declaration: { needs: [need("kit.a", ok), need("kit.a", ok)], effects: [] }, admitted: false },
  { name: "sql key duplicates a string need", declaration: { needs: ["kit.a", need("kit.a", ok)], effects: [] }, admitted: false },
  { name: "64 effects", declaration: { needs: [], effects: Array.from({ length: 64 }, (_, i) => `effect.e${i}.v1`) }, admitted: true },
  { name: "65 effects", declaration: { needs: [], effects: Array.from({ length: 65 }, (_, i) => `effect.e${i}.v1`) }, admitted: false },
  { name: "64 string needs", declaration: { needs: Array.from({ length: 64 }, (_, i) => `need.n${i}.v1`), effects: [] }, admitted: true },
  { name: "65 string needs", declaration: { needs: Array.from({ length: 65 }, (_, i) => `need.n${i}.v1`), effects: [] }, admitted: false },
  { name: "effect name 128 bytes", declaration: { needs: [], effects: ["e".repeat(128)] }, admitted: true },
  { name: "effect name 129 bytes", declaration: { needs: [], effects: ["e".repeat(129)] }, admitted: false },
  { name: "blank effect", declaration: { needs: [], effects: ["  "] }, admitted: false },
  { name: "numeric need entry", declaration: { needs: [7], effects: [] }, admitted: false },
  { name: "extra declaration key", declaration: { needs: [], effects: [], ports: [] }, admitted: false },
  { name: "missing effects", declaration: { needs: [] }, admitted: false },
  // records.facet-set.v1 object bounds (81372d1 slice): exact keys
  // effect/key/values/target{need}; the engine judges every case identically
  // (alpha_tab_kit_drift.rs kit_corpus_gets_the_same_verdict_from_the_engine).
  { name: "facet-set minimal", declaration: withBound([bound("priority", ["low"])]), admitted: true },
  { name: "facet-set empty-string value allowed", declaration: withBound([bound("priority", [""])]), admitted: true },
  { name: "facet-set 64 values", declaration: withBound([bound("priority", Array.from({ length: 64 }, (_, i) => `v${i}`))]), admitted: true },
  { name: "facet-set key 128 bytes", declaration: withBound([bound(`k${"a".repeat(127)}`, ["low"])]), admitted: true },
  { name: "facet-set value 128 bytes multi-byte", declaration: withBound([bound("priority", ["é".repeat(64)])]), admitted: true },
  { name: "facet-set bare string consents to nothing", declaration: withBound(["records.facet-set.v1"]), admitted: false },
  { name: "facet-set unknown object effect", declaration: withBound([bound("priority", ["low"], "kit.grid", { effect: "records.other.v1" })]), admitted: false },
  { name: "facet-set extra field", declaration: withBound([{ ...bound("priority", ["low"]), note: "x" }]), admitted: false },
  { name: "facet-set missing target", declaration: withBound([{ effect: "records.facet-set.v1", key: "priority", values: ["low"] }]), admitted: false },
  { name: "facet-set duplicate values", declaration: withBound([bound("priority", ["low", "low"])]), admitted: false },
  { name: "facet-set non-string value", declaration: withBound([bound("priority", [7])]), admitted: false },
  { name: "facet-set 65 values", declaration: withBound([bound("priority", Array.from({ length: 65 }, (_, i) => `v${i}`))]), admitted: false },
  { name: "facet-set value 129 bytes", declaration: withBound([bound("priority", ["e".repeat(129)])]), admitted: false },
  { name: "facet-set value 130 bytes multi-byte", declaration: withBound([bound("priority", ["é".repeat(65)])]), admitted: false },
  { name: "facet-set blank key", declaration: withBound([bound("  ", ["low"])]), admitted: false },
  { name: "facet-set key 129 bytes", declaration: withBound([bound(`k${"a".repeat(128)}`, ["low"])]), admitted: false },
  { name: "facet-set spine key refused", declaration: withBound([bound("lifecycle", ["open"])]), admitted: false },
  { name: "facet-set triage key refused", declaration: withBound([bound("triage", ["now"])]), admitted: false },
  { name: "facet-set dispatched key refused", declaration: withBound([bound("archived", ["true"])]), admitted: false },
  { name: "facet-set record-field key refused", declaration: withBound([bound("name", ["Board"])]), admitted: false },
  { name: "facet-set target without need", declaration: withBound([{ ...bound("priority", ["low"]), target: {} }]), admitted: false },
  { name: "facet-set target extra key", declaration: withBound([{ ...bound("priority", ["low"]), target: { need: "kit.grid", params: [] } }]), admitted: false },
  { name: "facet-set bad need key", declaration: withBound([bound("priority", ["low"], "Grid")]), admitted: false },
  { name: "facet-set undeclared need", declaration: withBound([bound("priority", ["low"], "kit.elsewhere")]), admitted: false },
  { name: "facet-set duplicate bound keys", declaration: withBound([bound("priority", ["low"]), bound("priority", ["high"])]), admitted: false },
  // comment.create.v1 object bounds (b9fb9fd family1): exact keys
  // effect/positions/max_body_bytes/target{need}; the engine judges every
  // case identically (alpha_tab_kit_drift.rs ...). Parameter/time gating
  // stays WRITE runtime; any syntactically valid need key parses here.
  { name: "comment minimal root", declaration: withBound([cbound(["root"], 100)]), admitted: true },
  { name: "comment reply", declaration: withBound([cbound(["reply"], 100)]), admitted: true },
  { name: "comment both positions", declaration: withBound([cbound(["root", "reply"], 300)]), admitted: true },
  { name: "comment positions unsorted admit", declaration: withBound([cbound(["reply", "root"], 300)]), admitted: true },
  { name: "comment cap 1", declaration: withBound([cbound(["root"], 1)]), admitted: true },
  { name: "comment cap 4096", declaration: withBound([cbound(["root"], 4096)]), admitted: true },
  { name: "comment split root reply different needs", declaration: { needs: [gridNeed, need("kit.other", ok)], effects: [cbound(["root"], 100), cbound(["reply"], 200, "kit.other")] }, admitted: true },
  { name: "comment with facet mixed", declaration: withBound([bound("priority", ["low"]), cbound(["root"], 100)]), admitted: true },
  { name: "comment bare string consents to nothing", declaration: withBound(["comment.create.v1"]), admitted: false },
  { name: "comment unknown object effect", declaration: withBound([{ ...cbound(["root"], 100), effect: "comment.other.v1" }]), admitted: false },
  { name: "comment extra field", declaration: withBound([{ ...cbound(["root"], 100), note: "x" }]), admitted: false },
  { name: "comment missing target", declaration: withBound([{ effect: "comment.create.v1", positions: ["root"], max_body_bytes: 100 }]), admitted: false },
  { name: "comment empty positions", declaration: withBound([cbound([], 100)]), admitted: false },
  { name: "comment three positions", declaration: withBound([cbound(["root", "reply", "root"], 100)]), admitted: false },
  { name: "comment duplicate positions", declaration: withBound([cbound(["root", "root"], 100)]), admitted: false },
  { name: "comment unknown position", declaration: withBound([cbound(["pinned"], 100)]), admitted: false },
  { name: "comment non-string position", declaration: withBound([cbound([7], 100)]), admitted: false },
  { name: "comment cap 0", declaration: withBound([cbound(["root"], 0)]), admitted: false },
  { name: "comment cap 4097", declaration: withBound([cbound(["root"], 4097)]), admitted: false },
  { name: "comment cap fractional", declaration: withBound([cbound(["root"], 100.5)]), admitted: false },
  { name: "comment cap negative", declaration: withBound([cbound(["root"], -4)]), admitted: false },
  { name: "comment cap boolean", declaration: withBound([cbound(["root"], true)]), admitted: false },
  { name: "comment cap string", declaration: withBound([cbound(["root"], "lots")]), admitted: false },
  { name: "comment target extra key", declaration: withBound([{ ...cbound(["root"], 100), target: { need: "kit.grid", other: 1 } }]), admitted: false },
  { name: "comment bad need key", declaration: withBound([cbound(["root"], 100, "Missing.Key")]), admitted: false },
  { name: "comment undeclared need", declaration: withBound([cbound(["root"], 100, "kit.absent")]), admitted: false },
  { name: "comment duplicate identical bounds", declaration: withBound([cbound(["root"], 100), cbound(["root"], 100)]), admitted: false },
  { name: "comment overlapping positions different needs", declaration: { needs: [gridNeed, need("kit.other", ok)], effects: [cbound(["root", "reply"], 100), cbound(["reply"], 200, "kit.other")] }, admitted: false },
  { name: "comment numeric effect entry", declaration: withBound([7]), admitted: false },
];

// Keep the existing reaction/title drift evidence when regenerating the corpus.
declaration.push(
  {"name": "react minimal thumbs-up", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["👍"], "target": {"need": "kit.grid"}}]}, "admitted": true},
  {"name": "react emoji unsorted admit", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["🎉", "👍"], "target": {"need": "kit.grid"}}]}, "admitted": true},
  {"name": "react bare string consents to nothing", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": ["message.react.v1"]}, "admitted": false},
  {"name": "react unknown emoji", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["nope"], "target": {"need": "kit.grid"}}]}, "admitted": false},
  {"name": "react duplicate emoji", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["👍", "👍"], "target": {"need": "kit.grid"}}]}, "admitted": false},
  {"name": "react extra field", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["👍"], "target": {"need": "kit.grid"}, "extra": 1}]}, "admitted": false},
  {"name": "react undeclared need", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["👍"], "target": {"need": "kit.absent"}}]}, "admitted": false},
  {"name": "react overlapping emoji different needs", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}, {"need": "sql.snapshot.v1", "key": "kit.other", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "message.react.v1", "emoji": ["👍", "🎉"], "target": {"need": "kit.grid"}}, {"effect": "message.react.v1", "emoji": ["🎉"], "target": {"need": "kit.other"}}]}, "admitted": false},
  {"name": "title minimal", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "records.title-set.v1", "target": {"need": "kit.grid"}}]}, "admitted": true},
  {"name": "title bare string consents to nothing", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": ["records.title-set.v1"]}, "admitted": false},
  {"name": "title extra field", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "records.title-set.v1", "target": {"need": "kit.grid"}, "extra": 1}]}, "admitted": false},
  {"name": "title missing target", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "records.title-set.v1"}]}, "admitted": false},
  {"name": "title undeclared need", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "records.title-set.v1", "target": {"need": "kit.absent"}}]}, "admitted": false},
  {"name": "title duplicate bounds", "declaration": {"needs": [{"need": "sql.snapshot.v1", "key": "kit.grid", "label": "Kit corpus case", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"}], "effects": [{"effect": "records.title-set.v1", "target": {"need": "kit.grid"}}, {"effect": "records.title-set.v1", "target": {"need": "kit.grid"}}]}, "admitted": false},
);

const packages = [
  { value: "agent.slack-workspace", admitted: true },
  { value: `a.${"b".repeat(32)}`, admitted: true },
  { value: `a.${"b".repeat(33)}`, admitted: false },
  { value: `${"a.".repeat(63)}ab`, admitted: true },
  { value: `${"a.".repeat(64)}a`, admitted: false },
  { value: "slack", admitted: false },
  { value: "agent.-slack", admitted: false },
  { value: "Agent.slack", admitted: false },
  { value: "agent..slack", admitted: false },
];
const versions = [
  { value: "0.1.1", admitted: true },
  { value: "12345678.0.0", admitted: true },
  { value: "123456789.0.0", admitted: false },
  { value: "1.2", admitted: false },
  { value: "1.2.3-beta", admitted: false },
];

writeFileSync(new URL("corpus.json", import.meta.url), `${JSON.stringify({
  note: "Generated by build-corpus.mjs. The kit (test/corpus.test.mjs) and the engine (src/mcp/tools/alpha_tab_kit_drift.rs) must both reach `admitted` for every case.",
  sql,
  declaration,
  packages,
  versions,
}, null, 2)}\n`);
