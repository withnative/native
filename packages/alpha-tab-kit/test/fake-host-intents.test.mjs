// The fake host's opt-in write answers (`options.intents`): no browser needed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { startFakeHost } from "../src/fake-host/server.mjs";

const descriptor = JSON.parse(readFileSync(new URL("fixtures/probe-descriptor.json", import.meta.url), "utf8"));
const html = readFileSync(new URL("fixtures/probe-queued.html", import.meta.url), "utf8");
const fixtures = { sql: { "probe.list": [{ id: "r1", name: "Task 1" }], "probe.body": () => [], "probe.links": () => [] } };
const post = (host, body) => fetch(`${host.origin}/__host/intent`, { method: "POST", body: JSON.stringify(body) }).then((r) => r.json());

test("without `intents` a write is refused unsupported_host and no write feature is advertised", async () => {
  const host = await startFakeHost({ descriptor, html, fixtures });
  try {
    assert.deepEqual(await post(host, { request_id: "a", entry_id: "e", slots: {}, values: {} }), { status: "rejected", code: "unsupported_host" });
    const page = await (await fetch(host.url)).text();
    assert.match(page, /"writes":false/);
  } finally {
    await host.close();
  }
});

test("with `intents` the handler's answer is the host's answer, and writes are advertised", async () => {
  const seen = [];
  const host = await startFakeHost({
    descriptor,
    html,
    fixtures,
    latencyMs: 0,
    intents: (intent) => {
      seen.push(intent);
      return intent.slots.task === "ok" ? { status: "committed" } : { status: "conflict", code: "conflict" };
    },
  });
  try {
    assert.deepEqual(await post(host, { request_id: "a", entry_id: "begin_work", slots: { task: "ok" }, values: {} }), { status: "committed" });
    assert.deepEqual(await post(host, { request_id: "b", entry_id: "begin_work", slots: { task: "no" }, values: {} }), { status: "conflict", code: "conflict" });
    assert.equal(seen.length, 2);
    assert.match(await (await fetch(host.url)).text(), /"writes":true/);
  } finally {
    await host.close();
  }
});
