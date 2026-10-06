// The host-need rules and the fake host's read dispatcher, without a
// browser: `hostNeedRefusal` mirrors `parse_declared_read`, and the fake
// host answers each on-request host need from its own fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LIMITS } from "../src/limits.mjs";
import { hostNeedRefusal } from "../src/fake-host/rules.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";

const hex = (text) => Buffer.from(text, "utf8").toString("hex");
const cursor = hex(JSON.stringify(["a1", "n1"]));

test("canvas.scene.v1 params are bounded as the engine bounds them", () => {
  const ok = [
    { canvas_id: "c1" },
    { canvas_id: " c1 ", limit: 1 },
    { canvas_id: "c1", limit: LIMITS.reads.canvas_scene_limit_max, cursor },
    { canvas_id: "c1", cursor: null },
  ];
  for (const params of ok) assert.equal(hostNeedRefusal("canvas.scene.v1", params, LIMITS), null, JSON.stringify(params));
  const refused = [
    {},
    { canvas_id: "" },
    { canvas_id: 7 },
    { canvas_id: "c".repeat(LIMITS.reads.canvas_id_max_chars + 1) },
    { canvas_id: "c1", limit: 0 },
    { canvas_id: "c1", limit: LIMITS.reads.canvas_scene_limit_max + 1 },
    { canvas_id: "c1", limit: "10" },
    { canvas_id: "c1", cursor: "not-hex" },
    { canvas_id: "c1", cursor: hex('["a"]') },
    { canvas_id: "c1", cursor: hex(JSON.stringify(["", "n1"])) },
    { canvas_id: "c1", cursor: 3 },
    { canvas_id: "c1", port: "board" },
    { canvas_id: "c1", ops: [] },
  ];
  for (const params of refused) assert.equal(hostNeedRefusal("canvas.scene.v1", params, LIMITS), "invalid_params", JSON.stringify(params));
});

test("the fake host answers canvas.scene.v1 from the scene fixture", async () => {
  const scene = { version: "canvas.scene.v1", canvas_id: "c1", scene_token: "t:0", objects: [], live_objects: 0, limit: 500, truncated: false, next_cursor: null };
  const host = await startFakeHost({
    descriptor: { package: "agent.board", version: "0.1.0", declaration: { needs: ["canvas.scene.v1"], effects: [] } },
    html: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Board</title></head><body></body></html>",
    fixtures: { scene: ({ canvas_id }) => ({ ...scene, canvas_id }) },
    latencyMs: 0,
  });
  try {
    assert.deepEqual(host.plan.onRequestHost, ["canvas.scene.v1"]);
    const read = async (body) => (await fetch(`${host.origin}/__host/read`, { method: "POST", body: JSON.stringify(body) })).json();
    assert.deepEqual(await read({ need: "canvas.scene.v1", params: { canvas_id: "c9" } }), { result: { ...scene, canvas_id: "c9" } });
    assert.deepEqual(await read({ need: "canvas.scene.v1", params: { canvas_id: "c9", limit: 501 } }), { error: "invalid_params" });
    assert.deepEqual(await read({ need: "records.search.v1", params: { query: "x" } }), { error: "undeclared_need" });
  } finally {
    await host.close();
  }
});

test("records.changes.v1 params are bounded as the engine bounds them", () => {
  // The engine seals cursors; the host can only check their shape.
  const sealed = "ab".repeat(24) + "cd".repeat(36) + "ef".repeat(16);
  const ok = [
    { record_id: "r1" },
    { record_id: " r1 ", limit: 1 },
    { record_id: "r1", limit: LIMITS.reads.record_changes_limit_max, cursor: sealed },
    { record_id: "r1", cursor: null },
  ];
  for (const params of ok) assert.equal(hostNeedRefusal("records.changes.v1", params, LIMITS), null, JSON.stringify(params));
  const refused = [
    {},
    { record_id: "" },
    { record_id: 7 },
    { record_id: "r".repeat(LIMITS.reads.record_id_max_chars + 1) },
    { record_id: "r1", limit: 0 },
    { record_id: "r1", limit: LIMITS.reads.record_changes_limit_max + 1 },
    { record_id: "r1", limit: "10" },
    { record_id: "r1", cursor: "not-hex" },
    { record_id: "r1", cursor: 3 },
    { record_id: "r1", cursor: "ab".repeat(40) },
    { record_id: "r1", cursor: "abc".repeat(27) },
    { record_id: "r1", cursor: "f".repeat(LIMITS.reads.record_changes_cursor_max_chars + 2) },
    { record_id: "r1", after_seq: 5 },
    { record_id: "r1", detail: "full" },
  ];
  for (const params of refused) assert.equal(hostNeedRefusal("records.changes.v1", params, LIMITS), "invalid_params", JSON.stringify(params));
});

test("the fake host answers records.changes.v1 from the changes fixture", async () => {
  const page = { version: "records.changes.v1", record_id: "r1", order: "newest_first", events: [], limit: 50, complete: true, next_cursor: null };
  const host = await startFakeHost({
    descriptor: { package: "agent.history", version: "0.1.0", declaration: { needs: ["records.changes.v1"], effects: [] } },
    html: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>History</title></head><body></body></html>",
    fixtures: { changes: ({ record_id }) => ({ ...page, record_id }) },
    latencyMs: 0,
  });
  try {
    assert.deepEqual(host.plan.onRequestHost, ["records.changes.v1"]);
    const read = async (body) => (await fetch(`${host.origin}/__host/read`, { method: "POST", body: JSON.stringify(body) })).json();
    assert.deepEqual(await read({ need: "records.changes.v1", params: { record_id: "r9" } }), { result: { ...page, record_id: "r9" } });
    assert.deepEqual(await read({ need: "records.changes.v1", params: { record_id: "r9", limit: 51 } }), { error: "invalid_params" });
    assert.deepEqual(await read({ need: "canvas.scene.v1", params: { canvas_id: "c1" } }), { error: "undeclared_need" });
  } finally {
    await host.close();
  }
});

test("artifact.render.v1 params are bounded as the engine bounds them", () => {
  const id = "a7710000-0000-4000-8000-000000000033";
  assert.equal(hostNeedRefusal("artifact.render.v1", { artifact_id: id }, LIMITS), null);
  const refused = [
    {},
    { artifact_id: "" },
    { artifact_id: 7 },
    { artifact_id: "a771000" },
    { artifact_id: ` ${id} ` },
    { artifact_id: id.toUpperCase() },
    { artifact_id: id.replaceAll("-", "") },
    { artifact_id: `{${id}}` },
    { artifact_id: id, as_of: { event_id: "e1" } },
    { artifact_id: id, revalidate: {} },
    { artifact_id: id, include_timing: true },
    [id],
  ];
  for (const params of refused) assert.equal(hostNeedRefusal("artifact.render.v1", params, LIMITS), "invalid_params", JSON.stringify(params));
});

test("the fake host answers artifact.render.v1 from the render fixture", async () => {
  const id = "a7710000-0000-4000-8000-000000000033";
  const rendered = {
    version: "artifact.render.v1", status: "rendered", artifact_id: id, runtime: { id: "native.mdx.v2" },
    plan: { kind: "safe_tree", version: "1", tree: { type: "Fragment", props: {}, children: ["Hello"] }, provenance: { record_id: id } },
  };
  const host = await startFakeHost({
    descriptor: { package: "agent.docs", version: "0.1.0", declaration: { needs: ["artifact.render.v1"], effects: [] } },
    html: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Docs</title></head><body></body></html>",
    fixtures: {
      render: ({ artifact_id }) => {
        if (artifact_id !== id) throw new Error("live read refused [not_found]");
        return { ...rendered, artifact_id };
      },
    },
    latencyMs: 0,
  });
  try {
    assert.deepEqual(host.plan.onRequestHost, ["artifact.render.v1"]);
    const read = async (body) => (await fetch(`${host.origin}/__host/read`, { method: "POST", body: JSON.stringify(body) })).json();
    assert.deepEqual(await read({ need: "artifact.render.v1", params: { artifact_id: id } }), { result: rendered });
    assert.deepEqual(await read({ need: "artifact.render.v1", params: { artifact_id: "a771000" } }), { error: "invalid_params" });
    // A refusal is an ordinary refused read carrying the host's code.
    assert.deepEqual(await read({ need: "artifact.render.v1", params: { artifact_id: "a7710000-0000-4000-8000-0000000000ff" } }), { error: "not_found" });
    assert.deepEqual(await read({ need: "records.changes.v1", params: { record_id: "r1" } }), { error: "undeclared_need" });
  } finally {
    await host.close();
  }
});
