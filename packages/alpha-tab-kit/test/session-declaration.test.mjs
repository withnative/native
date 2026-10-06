// Declared live-session consent (`session.body.v1`, contract §3): the shell
// must carry the optional `sessions` declaration through every copy path and
// keep legacy declarations byte-identical. Skips outside native-ce.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";

const kit = new URL("../", import.meta.url);
const repo = new URL("../../", kit);
const inRepo = existsSync(new URL("experiments/demo-shell/public/lib/pendingTabs.js", repo));
const skip = !inRepo && "not inside native-ce";

const row = (declaration) => ({
  package: "example.pkg",
  version: "1.0.0",
  digest: "sha256:" + "a".repeat(64),
  artifact_id: "artifact-1",
  consented_source_revision: "rev-1",
  declaration_digest: "b".repeat(64),
  consented_declaration: declaration,
  adoption: "shell_adopt.v1",
  status: "installed",
});

const session = {
  session: "session.body.v1",
  key: "doc",
  scope: { type: "Document", kind: "note" },
  mode: "edit",
  presence: true,
};

test("a declared session survives the pending copy and preview echo", { skip }, async () => {
  const shell = await import(new URL("experiments/demo-shell/public/lib/pendingTabs.js", repo));
  const normalized = shell.normalizePendingEntries({ installs: [row({ needs: [], effects: [], sessions: [session] })] });
  assert.equal(normalized.broken.length, 0);
  assert.deepEqual(normalized.entries[0].consented_declaration.sessions, [session]);
  assert.deepEqual(shell.previewArgsFor(normalized.entries[0], "test").declaration.sessions, [session]);
});

test("a legacy declaration keeps no sessions key", { skip }, async () => {
  const shell = await import(new URL("experiments/demo-shell/public/lib/pendingTabs.js", repo));
  const normalized = shell.normalizePendingEntries({ installs: [row({ needs: [], effects: [] })] });
  assert.equal(normalized.broken.length, 0);
  assert.equal("sessions" in normalized.entries[0].consented_declaration, false);
  assert.equal("sessions" in shell.previewArgsFor(normalized.entries[0], "test").declaration, false);
});

test("a malformed session declaration is rejected as a broken pin", { skip }, async () => {
  const shell = await import(new URL("experiments/demo-shell/public/lib/pendingTabs.js", repo));
  const bad = { ...session, mode: "write" };
  const normalized = shell.normalizePendingEntries({ installs: [row({ needs: [], effects: [], sessions: [bad] })] });
  assert.equal(normalized.entries.length, 0);
  assert.equal(normalized.broken[0]?.reason, "bad_pin_shape");
  assert.equal(shell.isSessionEntry(bad), false);
  assert.equal(shell.isSessionEntry({ ...session, presence: "yes" }), false);
  assert.equal(shell.isSessionEntry({ ...session, scope: { type: "Document", kind: "*" } }), true);
});

test("session consent item shows scope, permission and presence, and escapes author strings", { skip }, async () => {
  const el = () => ({
    style: {}, dataset: {}, innerHTML: "",
    append() {}, setAttribute() {}, querySelector: () => null,
    classList: { add() {}, remove() {} }, addEventListener() {}, removeEventListener() {},
  });
  globalThis.document = {
    querySelector: () => null, getElementById: () => null, createElement: el,
    addEventListener() {}, removeEventListener() {}, visibilityState: "hidden",
    body: el(), documentElement: el(),
  };
  const location = new URL("http://x");
  globalThis.location = location;
  globalThis.window = { addEventListener() {}, removeEventListener() {}, location };
  const view = await import(new URL("experiments/demo-shell/public/views/pending.js", repo));
  const escaped = [];
  const esc = (value) => { escaped.push(String(value)); return `<esc:${String(value)}>`; };
  const edit = view.sessionConsentItemHtml({ key: "doc", scope: { type: "Document", kind: "note" }, mode: "edit", presence: true }, esc);
  const watch = view.sessionConsentItemHtml({ key: "doc", scope: { type: "Document", kind: "*" }, mode: "view", presence: false }, esc);
  assert.match(edit, /read and edit this record's body/);
  assert.match(watch, /watch this record's body/);
  assert.match(edit, /presence <esc:shared>/);
  assert.match(watch, /presence <esc:off>/);
  assert.ok(escaped.includes("doc") && escaped.includes("Document/note") && escaped.includes("Document/*"));
});
