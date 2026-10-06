// The JS half of the drift guard. The engine half is
// src/mcp/tools/alpha_tab_kit_drift.rs; this file checks what the engine
// test cannot: the vendored bridge's literals, and, when run inside
// native-ce, the demo shell source the kit's host rules mirror.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, cpSync, mkdtempSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { LIMIT_SOURCES } from "../src/limits.mjs";

const kit = new URL("../", import.meta.url);
const repo = new URL("../../", kit);
const bootstrap = readFileSync(new URL("src/fake-host/bridge-bootstrap.js", kit), "utf8");

test("the vendored bridge is the digest limits.json pins", () => {
  assert.equal(createHash("sha256").update(bootstrap).digest("hex"), LIMIT_SOURCES.bridge.bootstrap_sha256.value);
  const source = new URL("crates/artifact-html/src/html.rs", repo);
  if (existsSync(source)) {
    const engine = readFileSync(source, "utf8");
    const matches = [...engine.matchAll(/const BOOTSTRAP: &str = r#"([\s\S]*?)"#;/g)];
    assert.equal(matches.length, 1, "exactly one authoritative bootstrap template");
    assert.equal(bootstrap, matches[0][1], "the companion must equal governed production bytes");
  }
});

test("bridge limits are literal in the vendored bridge", () => {
  for (const [name, leaf] of Object.entries(LIMIT_SOURCES.bridge)) {
    if (!leaf.bootstrap_literal) continue;
    assert.ok(bootstrap.includes(leaf.bootstrap_literal), `bridge.${name}: ${leaf.bootstrap_literal}`);
    assert.ok(leaf.bootstrap_literal.includes(String(leaf.value)), `bridge.${name} value ${leaf.value}`);
  }
});

const inRepo = existsSync(new URL("experiments/demo-shell/public/views/pending.js", repo));
test("shell rules the fake host mirrors are still in the demo shell source", { skip: !inRepo && "not inside native-ce" }, () => {
  const leaves = [];
  const walk = (path, node) => {
    if (node && typeof node === "object" && "js_literal" in node) leaves.push([path, node]);
    else if (node && typeof node === "object") for (const [key, child] of Object.entries(node)) walk(`${path}.${key}`, child);
  };
  walk("", LIMIT_SOURCES);
  assert.ok(leaves.length >= 5);
  for (const [path, leaf] of leaves) {
    const file = leaf.source.split(":")[0];
    const text = readFileSync(new URL(file, repo), "utf8");
    assert.ok(text.includes(leaf.js_literal), `${path}: ${file} no longer contains ${leaf.js_literal}`);
    if (typeof leaf.value === "number") assert.ok(leaf.js_literal.replace(/_/g, "").includes(String(leaf.value)) || path.endsWith("reads_in_flight"), `${path} value ${leaf.value}`);
  }
});

test("the kit offers exactly the shell's on-request host needs", { skip: !inRepo && "not inside native-ce" }, async () => {
  // The opening literal above only proves the list still exists; compare
  // the list itself, so a need the shell gains cannot go missing here.
  const shell = await import(new URL("experiments/demo-shell/public/lib/pendingTabs.js", repo));
  assert.deepEqual(Object.keys(shell.ON_REQUEST_NEEDS), LIMIT_SOURCES.reads.on_request_host_needs.value);
});

test("the shell relays artifact.render.v1 like any consented on-request need", { skip: !inRepo && "not inside native-ce" }, async () => {
  const shell = await import(new URL("experiments/demo-shell/public/lib/pendingTabs.js", repo));
  const entry = (needs) => ({
    package: "agent.docs", event_id: "install-1", status: "installed", adoption: "shell_adopt.v1", target_resolves: true,
    launch_binding: { verdict: "refused", reason: "launch_request_required" },
    consented_declaration: { needs, effects: [] },
  });
  const consented = entry(["artifact.render.v1"]);
  const params = { artifact_id: "a7710000-0000-4000-8000-000000000033" };
  assert.deepEqual(shell.consentNeedItemsOf(consented), [
    { kind: "on-request", need: "artifact.render.v1", text: shell.ON_REQUEST_NEEDS["artifact.render.v1"] },
  ]);
  assert.match(shell.ON_REQUEST_NEEDS["artifact.render.v1"], /^Show MDX documents you can see/);
  assert.deepEqual(shell.onRequestNeedsOf(consented), ["artifact.render.v1"]);
  assert.deepEqual(shell.declaredReadArgsFor(consented, "artifact.render.v1", params), {
    action: "live_read", package: "agent.docs", expected_install_event_id: "install-1", need: "artifact.render.v1", params,
  });
  // Without consent the shell refuses before any network call; the backend
  // re-checks consent and bounds the params either way.
  assert.equal(shell.declaredReadRefusalFor(entry(["records.search.v1"]), "artifact.render.v1", params), "undeclared_need");
  assert.equal(shell.declaredReadRefusalFor(consented, "artifact.render.v1", ["x"]), "invalid_params");
});

test("the shell queues as many reads as the bridge lets a frame hold, and dispatches a bounded few", () => {
  // S2 of task 232e8f5: a queue deeper than the bridge cap is unreachable,
  // and a shallower one would answer busy to reads the frame may send. The
  // in-flight cap is the shell's own concurrency choice, below the queue cap
  // so the FIFO still absorbs bursts and `busy` stays unreachable through
  // the real bridge.
  assert.equal(LIMIT_SOURCES.shell.read_queue_max.value, LIMIT_SOURCES.bridge.pending_read_cap.value);
  assert.equal(LIMIT_SOURCES.shell.reads_in_flight.value, 4);
  assert.ok(LIMIT_SOURCES.shell.reads_in_flight.value < LIMIT_SOURCES.shell.read_queue_max.value);
});


test("browser icon catalogue is a byte-identical standalone-kit mirror", { skip: !inRepo && "not inside native-ce" }, () => {
  assert.equal(readFileSync(new URL("src/icons.mjs", kit), "utf8"),
    readFileSync(new URL("experiments/demo-shell/public/lib/appIcons.js", repo), "utf8"));
});

test("a copied standalone package imports its public icon and install API", async () => {
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { pathToFileURL } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "alpha-kit-standalone-"));
  try {
    cpSync(new URL("src/", kit), join(dir, "src"), { recursive: true });
    cpSync(new URL("limits.json", kit), join(dir, "limits.json"));
    cpSync(new URL("package.json", kit), join(dir, "package.json"));
    const copied = await import(pathToFileURL(join(dir, "src/index.mjs")));
    assert.ok(copied.SUPPORTED_ICON_NAMES.includes("BookOpen"));
    assert.equal(copied.isIconName("FutureIcon"), true);
    assert.deepEqual(copied.parseIconFacet("brand:airtable"), { kind: "brand", name: "airtable" });
    assert.equal(typeof copied.planInstall, "function");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
