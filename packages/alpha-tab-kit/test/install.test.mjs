import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { planInstall, runInstall, chunkUtf8, encodeBody } from "../src/install.mjs";
import { computeDigests } from "../src/digest.mjs";

const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const descriptor = JSON.parse(readFileSync(new URL("fixtures/probe-descriptor.json", import.meta.url), "utf8"));
const html = readFileSync(new URL("fixtures/probe-queued.html", import.meta.url), "utf8");
const plan = (options = {}) => planInstall({ descriptor, html, homeId: "c59dffa3-a401-431a-a44b-c79cae9b8346", reason: "Install the kit probe", chunkBytes: 700, ...options });

// A stand-in for the Native tools, enforcing what the real ones enforce on
// this route: the if_body_digest guard, and whole-document validation only
// once the record is an artifact with the runtime facet.
function fakeNative({ corruptChunk, adoptionCarried = true } = {}) {
  const calls = [];
  const record = { id: "a0000000-0000-4000-8000-000000000001", body: "", kind: null, events: [] };
  let install = null;
  return {
    calls,
    record,
    async call(executor, operation, args) {
      calls.push({ executor, operation, args });
      if (operation === "create_record") {
        record.kind = args.kind;
        // The server decodes body_encoding at the tool boundary, before anything else.
        const bytes = args.body_encoding === "gzip+base64" ? gunzipSync(Buffer.from(args.body, "base64"))
          : args.body_encoding === "base64" ? Buffer.from(args.body, "base64") : null;
        record.body = bytes ? bytes.toString("utf8") : args.body;
        record.events.push({ id: `e${record.events.length}`, type: "record.created" });
        return { id: record.id, source_event_id: record.events[0].id, body_digest: sha256(record.body) };
      }
      if (operation === "update_record") {
        if (args.if_body_digest && args.if_body_digest !== sha256(record.body)) throw new Error("body changed [if_body_digest_mismatch]");
        if (args.body_append !== undefined) {
          // A transport that decodes one escape: the stored text loses a byte.
          const chunk = corruptChunk && calls.length === corruptChunk ? args.body_append.slice(1) : args.body_append;
          record.body += chunk;
          record.events.push({ id: `e${record.events.length}`, type: "record.updated" });
        }
        if (args.kind) {
          record.kind = args.kind;
          record.events.push({ id: `e${record.events.length}`, type: "record.updated" }, { id: `e${record.events.length + 1}`, type: "artifact.source_attested" });
        }
        return { id: record.id, body_digest: sha256(record.body) };
      }
      if (operation === "query_sql") {
        const last = record.events.filter((event) => event.type.startsWith("record.")).at(-1);
        return { rows: [{ id: last.id, type: last.type }] };
      }
      if (operation === "manage_alpha_tabs.install" || operation === "manage_alpha_tabs.update") {
        const digests = computeDigests(record.body, args.declaration, "native.html.v1");
        install = { package: args.package, version: args.version, digest: args.digest, declaration_digest: digests.declaration_digest, consented_source_revision: args.source_revision };
        return { changed: true, install, ...(operation === "manage_alpha_tabs.update" ? { idempotent_retry: false, update_event_id: "updated", adoption_carried: adoptionCarried, adoption_required: !adoptionCarried } : {}) };
      }
      if (operation === "manage_alpha_tabs.inspect") return { install };
      throw new Error(`unexpected ${operation}`);
    },
  };
}

test("chunks never split a code point and reassemble exactly", () => {
  const text = "a€😀b".repeat(50);
  const chunks = chunkUtf8(text, 7);
  assert.equal(chunks.join(""), text);
  for (const chunk of chunks) assert.ok(Buffer.byteLength(chunk) <= 7);
});

test("the plan is the proven route, each write guarded by the digest of the body so far", () => {
  const p = plan({ chunked: true });
  const ops = p.steps.map((step) => step.step);
  assert.equal(ops[0], "create-note");
  assert.deepEqual(ops.slice(-4), ["source-revision", "rekind-artifact", "install", "inspect"]);
  let body = "";
  for (const step of p.steps.filter((item) => item.step === "create-note" || item.step.startsWith("append-"))) {
    if (step.arguments.if_body_digest) assert.equal(step.arguments.if_body_digest, sha256(body));
    body += step.arguments.body ?? step.arguments.body_append;
    assert.equal(step.expect.body_digest, sha256(body));
  }
  assert.equal(body, html);
  assert.equal(p.steps.find((step) => step.step === "install").arguments.digest, computeDigests(html, descriptor.declaration).digest);
  assert.equal(p.steps[0].arguments.kind, "note");
  assert.equal("facets" in p.steps[0].arguments, false);
});

test("runInstall pins the last body-carrying event, not the re-kind", async () => {
  const native = fakeNative();
  const result = await runInstall(plan({ chunked: true }), native);
  const install = native.calls.find((call) => call.operation === "manage_alpha_tabs.install").args;
  assert.equal(install.artifact_id, native.record.id);
  const appendEvents = native.record.events.filter((event) => event.type === "record.updated");
  assert.equal(install.source_revision, result.source_revision);
  assert.notEqual(install.source_revision, appendEvents.at(-1).id, "the re-kind event carries no body");
  assert.equal(native.record.body, html);
  assert.ok(result.log.every((entry) => entry.ok));
});

test("a transport-altered chunk stops the route before the next write", async () => {
  const native = fakeNative({ corruptChunk: 2 });
  await assert.rejects(runInstall(plan({ chunked: true }), native), /append-2: body_digest/);
  assert.equal(native.calls.length, 2, "nothing after the mismatched write is sent");
});

test("a package that does not validate cannot be planned", () => {
  assert.throws(() => planInstall({ descriptor: { ...descriptor, version: "1.0" }, html, homeId: "x", reason: "r" }), /does not validate/);
});


test("icons are advisory presentation facets, outside consent and digests", async () => {
  const { validatePackage } = await import("../src/validate.mjs");
  const baseline = plan();
  for (const [icon, expected, warns] of [
    ["BookOpen", "BookOpen", false], ["FutureIcon", "FutureIcon", true],
    ["brand:airtable", "brand:airtable", false],
    ["brand:not-a-real-brand", "brand:not-a-real-brand", false],
    [`brand:${"a".repeat(64)}`, `brand:${"a".repeat(64)}`, false],
    ["brand:Airtable", undefined, true], ["brand:", undefined, true],
    [`brand:${"a".repeat(65)}`, undefined, true],
    ["simple-icons:airtable", undefined, true], ["brand:https://example.com/icon.svg", undefined, true],
    ["<svg/>", undefined, true], [{ kind: "brand", name: "airtable" }, undefined, true],
    ["file-text", undefined, true], [null, undefined, true],
    [{ kind: "lucide", name: "BookOpen" }, undefined, true],
    ["A".repeat(65), undefined, true],
  ]) {
    const authored = { ...descriptor, icon };
    const checked = validatePackage({ descriptor: authored, html });
    assert.equal(checked.ok, true);
    assert.equal(checked.findings.some(f => f.rule === "presentation.icon"), warns);
    for (const chunked of [false, true]) {
      const p = planInstall({ descriptor: authored, html, homeId: "home", reason: "Icon test", chunked });
      const facets = p.steps.find(s => s.step === (chunked ? "rekind-artifact" : "create-artifact")).arguments.facets;
      assert.equal(facets.app_icon, expected);
      assert.equal(Object.hasOwn(facets, "app_icon"), expected !== undefined);
      assert.deepEqual(p.digests, baseline.digests);
      // The install pin/declaration and all executable source writes stay identical.
      const sameRoute = planInstall({ descriptor, html, homeId: "home", reason: "Icon test", chunked });
      assert.deepEqual(p.steps.find(s => s.step === "install"), sameRoute.steps.find(s => s.step === "install"));
      assert.deepEqual(p.steps.filter(s => Object.hasOwn(s.arguments, "body") || Object.hasOwn(s.arguments, "body_append"))
        .map(s => [s.arguments.body, s.arguments.body_append]), sameRoute.steps
        .filter(s => Object.hasOwn(s.arguments, "body") || Object.hasOwn(s.arguments, "body_append"))
        .map(s => [s.arguments.body, s.arguments.body_append]));
    }
  }
  assert.equal(Object.hasOwn(baseline.steps[0].arguments.facets, "app_icon"), false);
});


test("new plans create the complete artifact once, without a stage retry key", () => {
  const p = plan();
  assert.deepEqual(p.steps.map(s => s.step), ["create-artifact", "install", "inspect"]);
  const args = p.steps[0].arguments;
  assert.equal(args.type, "Document");
  assert.equal(args.kind, "artifact");
  assert.deepEqual(args.facets, { runtime: "native.html.v1" });
  assert.equal(args.body_encoding, "gzip+base64");
  assert.equal(gunzipSync(Buffer.from(args.body, "base64")).toString("utf8"), html);
  assert.equal(args.response_mode, "summary");
  assert.equal(p.steps[0].expect.body_digest, sha256(html));
  assert.equal(Object.hasOwn(args, "idempotency_key"), false);
});

test("runInstall uses the whole-body create receipt's source event", async () => {
  const native = fakeNative();
  const result = await runInstall(plan(), native);
  assert.equal(result.source_revision, "e0");
  assert.equal(native.calls[1].args.source_revision, "e0");
  assert.equal(native.calls[1].args.artifact_id, native.record.id);
  assert.equal(native.calls.length, 3);
});

test("a bad or missing whole-body digest sends nothing after create", async () => {
  for (const body_digest of ["bad", undefined]) {
    const calls = [];
    await assert.rejects(runInstall(plan(), { async call(...args) {
      calls.push(args);
      return { write_receipt: { id: "r", source_event_id: "source", body_digest } };
    } }), /create-artifact: body_digest/);
    assert.equal(calls.length, 1);
  }
});

test("a missing create source event stops before install without a SQL fallback", async () => {
  const calls = [];
  await assert.rejects(runInstall(plan(), { async call(...args) {
    calls.push(args);
    return { id: "r", body_digest: sha256(html) };
  } }), /no source_event_id/);
  assert.equal(calls.length, 1);
});

test("replace removes only when explicitly selected, after source verification", async () => {
  assert.equal(plan().steps.some(s => s.operation === "manage_alpha_tabs.remove"), false);
  const p = plan({ replaceInstallEventId: "previous" });
  assert.deepEqual(p.steps.map(s => s.step), ["create-artifact", "remove-previous-install", "install", "inspect"]);
  const native = fakeNative();
  const call = native.call.bind(native);
  native.call = async (executor, operation, args) => {
    if (operation === "manage_alpha_tabs.remove") {
      native.calls.push({ executor, operation, args });
      assert.equal(args.expected_install_event_id, "previous");
      return { install: { event_id: "removed" } };
    }
    if (operation === "manage_alpha_tabs.install") assert.equal(args.expected_install_event_id, "removed");
    return call(executor, operation, args);
  };
  await runInstall(p, native);
  const calls = [];
  await assert.rejects(runInstall(p, { async call(...args) {
    calls.push(args);
    return { id: "r", source_event_id: "source", body_digest: "bad" };
  } }), /body_digest/);
  assert.equal(calls.length, 1, "mismatch must stop even the explicit removal");
});


test("a saved legacy plan still runs without a create source_event_id", async () => {
  const saved = JSON.parse(JSON.stringify(plan({ chunked: true })));
  const native = fakeNative();
  const call = native.call.bind(native);
  native.call = async (...args) => {
    const receipt = await call(...args);
    if (args[1] === "create_record") delete receipt.source_event_id;
    return receipt;
  };
  const result = await runInstall(saved, native);
  assert.ok(result.log.every(entry => entry.ok));
  assert.equal(native.calls.find(c => c.operation === "manage_alpha_tabs.install").args.source_revision,
    native.calls.filter(c => c.args.body_append !== undefined).length ? `e${saved.chunks - 1}` : "e0");
  assert.equal(native.record.body, html);
});

test("CLI defaults to whole-body and --chunked explicitly selects the old route", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const cli = fileURLToPath(new URL("../bin/alpha-tab-kit.mjs", import.meta.url));
  const fixture = fileURLToPath(new URL("fixtures/probe-descriptor.json", import.meta.url));
  const bundle = fileURLToPath(new URL("fixtures/probe-queued.html", import.meta.url));
  const args = [cli, "install-plan", fixture, "--html", bundle, "--home", "home", "--reason", "CLI test", "--chunk-bytes", "700"];
  const wholeRun = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.equal(wholeRun.status, 0);
  assert.match(wholeRun.stderr, /--chunk-bytes is ignored without --chunked/);
  const whole = JSON.parse(wholeRun.stdout);
  assert.deepEqual(whole, plan({ homeId: "home", reason: "CLI test" }));
  const chunkedRun = spawnSync(process.execPath, [...args, "--chunked"], { encoding: "utf8" });
  assert.equal(chunkedRun.status, 0);
  assert.equal(chunkedRun.stderr, "");
  const chunked = JSON.parse(chunkedRun.stdout);
  assert.deepEqual(chunked, plan({ homeId: "home", reason: "CLI test", chunked: true }));
  const rawRun = spawnSync(process.execPath, [...args.slice(0, -2), "--raw-body"], { encoding: "utf8" });
  assert.equal(rawRun.status, 0);
  assert.deepEqual(JSON.parse(rawRun.stdout), plan({ homeId: "home", reason: "CLI test", bodyEncoding: "utf8" }));
});


test("summary create receipts use only the receipt's own source pin", async () => {
  for (const wrapped of [false, true]) {
    for (const missing of [undefined, "source_event_id", "body_digest"]) {
      const native = fakeNative();
      const call = native.call.bind(native);
      native.call = async (...args) => {
        const result = await call(...args);
        if (args[1] !== "create_record") return result;
        const receipt = {
          id: result.id, type: "Document", kind: "artifact", name: "Kit probe",
          body_digest: sha256(html), source_event_id: "e0",
          lifecycle_interpretation: null, display_reference: "a000000", version: "rec:1",
          warnings: [{ id: "warning-id", body_digest: sha256(html) }],
          similar_existing: [{ id: "similar-id", name: "Other artifact" }],
          advisories: [{ id: "advisory-id", message: "Review source" }],
          artifact_input_continuity: { warning: { source_event_id: "decoy-event", body_digest: sha256(html) } },
        };
        if (missing) delete receipt[missing];
        return wrapped ? { write_receipt: receipt } : receipt;
      };
      if (missing) {
        await assert.rejects(runInstall(plan(), native), missing === "source_event_id" ? /no source_event_id/ : /create-artifact: body_digest/);
        assert.equal(native.calls.length, 1, "nested decoys cannot authorize install");
      } else {
        const result = await runInstall(plan(), native);
        assert.equal(result.record_id, native.record.id);
        assert.equal(result.source_revision, "e0");
        assert.equal(native.calls[1].args.source_revision, "e0");
        assert.equal(native.calls[1].args.artifact_id, native.record.id);
      }
    }
  }
});


test("after-removal chains install from the removal without removing again", async () => {
  for (const chunked of [false, true]) {
    const p = plan({ afterRemovalEventId: "removal-event", chunked });
    assert.equal(p.steps.some(s => s.operation === "manage_alpha_tabs.remove"), false);
    assert.equal(p.steps.find(s => s.step === "install").arguments.expected_install_event_id, "removal-event");
    const native = fakeNative();
    await runInstall(p, native);
    assert.equal(native.calls.find(c => c.operation === "manage_alpha_tabs.install").args.expected_install_event_id, "removal-event");
  }
  assert.equal(Object.hasOwn(plan().steps.find(s => s.step === "install").arguments, "expected_install_event_id"), false);
  assert.throws(() => plan({ afterRemovalEventId: "removed", replaceInstallEventId: "previous" }), /mutually exclusive/);
});

test("CLI plans after-removal and refuses combining it with replace", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const cli = fileURLToPath(new URL("../bin/alpha-tab-kit.mjs", import.meta.url));
  const fixture = fileURLToPath(new URL("fixtures/probe-descriptor.json", import.meta.url));
  const args = [cli, "install-plan", fixture, "--home", "home", "--reason", "Reinstall", "--after-removal", "removed"];
  const run = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.equal(run.status, 0);
  const p = JSON.parse(run.stdout);
  assert.equal(p.steps.some(s => s.operation === "manage_alpha_tabs.remove"), false);
  assert.equal(p.steps.find(s => s.step === "install").arguments.expected_install_event_id, "removed");
  const refused = spawnSync(process.execPath, [...args, "--replace", "previous"], { encoding: "utf8" });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /--replace and --after-removal are mutually exclusive/);
  assert.equal(refused.stdout, "");
});


test("removal options validate provided values and exclude each other by presence", () => {
  for (const [field, flag] of [["afterRemovalEventId", "--after-removal"], ["replaceInstallEventId", "--replace"]]) {
    for (const value of ["", "  ", "\t\n", null, false, 0]) {
      assert.throws(() => plan({ [field]: value }), { message: `${flag} needs a non-blank event id string` });
    }
    assert.deepEqual(plan({ [field]: undefined }), plan());
  }
  for (const [afterRemovalEventId, replaceInstallEventId] of [["", ""], ["", "previous"], ["removed", ""], [null, false]]) {
    assert.throws(() => plan({ afterRemovalEventId, replaceInstallEventId }), /mutually exclusive/);
  }
});


test("update plans stage the source then one guarded update, whole-body or chunked", async () => {
  for (const chunked of [false, true]) {
    const p = plan({ updateInstallEventId: "current", chunked });
    assert.deepEqual(p.steps.slice(-2).map(s => s.step), ["update", "inspect"]);
    assert.equal(p.steps.filter(s => s.executor === "artifacts_write").length, 1);
    const update = p.steps.at(-2);
    assert.equal(update.operation, "manage_alpha_tabs.update");
    assert.equal(update.arguments.expected_install_event_id, "current");
    assert.equal(update.arguments.source_revision, "{{source_revision}}");
    assert.equal(update.arguments.version, descriptor.version);
    assert.deepEqual(update.arguments.declaration, descriptor.declaration);
    const native = fakeNative();
    const result = await runInstall(p, native);
    const sent = native.calls.find(c => c.operation === "manage_alpha_tabs.update").args;
    assert.equal(sent.source_revision, result.source_revision);
    assert.equal(sent.artifact_id, result.record_id);
    assert.equal(sent.digest, p.digests.digest);
  }
});

test("update excludes replacement/removal options and rejects blank ids", () => {
  for (const field of ["replaceInstallEventId", "afterRemovalEventId"]) {
    for (const value of ["previous", "", null]) {
      assert.throws(() => plan({ updateInstallEventId: "current", [field]: value }), /mutually exclusive/);
    }
  }
  for (const value of ["", " ", "\t\n", null, false, 0]) {
    assert.throws(() => plan({ updateInstallEventId: value }), /--update needs a non-blank event id string/);
  }
});

test("update receipt uses only top-level adoption fields and reports them in result and log", async () => {
  for (const adoptionCarried of [true, false]) {
    const native = fakeNative({ adoptionCarried });
    const call = native.call;
    native.call = async (...args) => ({ decoy: { update_event_id: "fake", adoption_carried: !adoptionCarried, adoption_required: adoptionCarried }, ...await call(...args) });
    const entries = [];
    const result = await runInstall(plan({ updateInstallEventId: "current" }), native, { onStep: entry => entries.push(entry) });
    assert.equal(result.update_event_id, "updated");
    assert.equal(result.changed, true);
    assert.equal(result.idempotent_retry, false);
    assert.equal(result.adoption_carried, adoptionCarried);
    assert.equal(result.adoption_required, !adoptionCarried);
    assert.equal(entries.find(e => e.step === "update").adoption_carried, adoptionCarried);
    assert.deepEqual(entries, result.log);
  }
});

test("missing or inconsistent top-level update receipt fields stop before inspect", async () => {
  for (const key of ["update_event_id", "adoption_carried", "adoption_required", "changed", "idempotent_retry", "inconsistent"]) {
    const native = fakeNative();
    const call = native.call;
    native.call = async (...args) => {
      const result = await call(...args);
      if (args[1] === "manage_alpha_tabs.update") {
        result.decoy = { update_event_id: "nested", adoption_carried: true, adoption_required: false };
        if (key === "inconsistent") result.adoption_required = true;
        else delete result[key];
      }
      return result;
    };
    await assert.rejects(runInstall(plan({ updateInstallEventId: "current" }), native), /top-level/);
    assert.equal(native.calls.length, 2);
  }
});

test("unsupported update stops without inspect or destructive fallback", async () => {
  for (const message of ["unknown operation 'manage_alpha_tabs.update' for artifacts_write", "unknown (executor, operation)", "unknown variant `update`, expected `install`"]) {
    const calls = [];
    const native = fakeNative();
    await assert.rejects(runInstall(plan({ updateInstallEventId: "current" }), { async call(...args) {
      calls.push(args[1]);
      if (args[1] === "manage_alpha_tabs.update") throw new Error(message);
      return native.call(...args);
    } }), /Server predates manage_alpha_tabs.update; use --replace explicitly.*Staged source record a0000000-0000-4000-8000-000000000001 can be archived/);
    assert.deepEqual(calls, ["create_record", "manage_alpha_tabs.update"]);
  }
});

test("ordinary update refusals preserve the original error without replacement advice", async () => {
  for (const message of ["installation changed [cas_mismatch]", "transaction failed: unknown record", "interaction needs unknown key", "adoption_unverified", "unknown operation 'other' for artifacts_write"]) {
    const native = fakeNative();
    const calls = [];
    const original = new Error(message);
    await assert.rejects(runInstall(plan({ updateInstallEventId: "current" }), { async call(...args) {
      calls.push(args[1]);
      if (args[1] === "manage_alpha_tabs.update") throw original;
      return native.call(...args);
    } }), error => error === original);
    assert.deepEqual(calls, ["create_record", "manage_alpha_tabs.update"]);
  }
});

test("update expects pins only at the receipt install path, including wrapped receipts", async () => {
  for (const missing of ["install", "digest", "declaration_digest", undefined]) {
    const p = plan({ updateInstallEventId: "current" });
    const native = fakeNative();
    const call = native.call;
    native.call = async (...args) => {
      const result = await call(...args);
      if (args[1] !== "manage_alpha_tabs.update") return result;
      result.decoy = { digest: p.digests.digest, declaration_digest: p.digests.declaration_digest };
      if (missing === "install") delete result.install;
      else if (missing) delete result.install[missing];
      return { write_receipt: result };
    };
    if (missing) {
      await assert.rejects(runInstall(p, native), /update: (?:declaration_)?digest is undefined/);
      assert.equal(native.calls.length, 2);
    } else {
      const result = await runInstall(p, native);
      assert.equal(result.update_event_id, "updated");
      assert.equal(native.calls.length, 3);
    }
  }
});

test("update routes retain every digest fence", async () => {
  for (const chunked of [false, true]) {
    const native = fakeNative({ corruptChunk: chunked ? 2 : undefined });
    const call = native.call;
    if (!chunked) native.call = async (...args) => ({ ...await call(...args), body_digest: "wrong" });
    await assert.rejects(runInstall(plan({ updateInstallEventId: "current", chunked }), native), /body_digest/);
    assert.equal(native.calls.length, chunked ? 2 : 1);
  }
  const native = fakeNative();
  const call = native.call;
  native.call = async (...args) => {
    const result = await call(...args);
    if (args[1] === "manage_alpha_tabs.update") result.install.digest = "wrong";
    return result;
  };
  await assert.rejects(runInstall(plan({ updateInstallEventId: "current" }), native), /update: digest/);
  assert.equal(native.calls.length, 2);
});

test("whole-body plans send gzip+base64 by default and the server-side decode matches the local digest", async () => {
  const p = plan();
  const create = p.steps.find((step) => step.step === "create-artifact");
  assert.equal(create.arguments.body_encoding, "gzip+base64");
  assert.notEqual(create.arguments.body, html);
  assert.equal(gunzipSync(Buffer.from(create.arguments.body, "base64")).toString("utf8"), html);
  assert.deepEqual(create.expect, { body_digest: sha256(html), body_bytes: Buffer.byteLength(html, "utf8") });
  const native = fakeNative();
  await runInstall(p, native);
  assert.equal(native.record.body, html);
});

test("bodyEncoding utf8 falls back to the raw body with no body_encoding field; base64 is selectable", async () => {
  const raw = plan({ bodyEncoding: "utf8" }).steps.find((step) => step.step === "create-artifact").arguments;
  assert.equal(raw.body, html);
  assert.equal(Object.hasOwn(raw, "body_encoding"), false);
  const b64 = plan({ bodyEncoding: "base64" }).steps.find((step) => step.step === "create-artifact").arguments;
  assert.equal(b64.body_encoding, "base64");
  assert.equal(Buffer.from(b64.body, "base64").toString("utf8"), html);
  assert.throws(() => plan({ bodyEncoding: "rot13" }), /bodyEncoding must be one of utf8, base64, gzip\+base64/);
  const native = fakeNative();
  await runInstall(plan({ bodyEncoding: "utf8" }), native);
  assert.equal(native.record.body, html);
});

test("chunked plans stay raw and never carry body_encoding", () => {
  for (const step of plan({ chunked: true }).steps) assert.equal(Object.hasOwn(step.arguments, "body_encoding"), false);
});

test("encodeBody round-trips multibyte text and shrinks escape-heavy source", () => {
  const text = "<p>\"é€😀\"</p>\n".repeat(2000);
  for (const encoding of ["base64", "gzip+base64"]) {
    const { body, body_encoding } = encodeBody(text, encoding);
    const bytes = Buffer.from(body, "base64");
    assert.equal((body_encoding === "gzip+base64" ? gunzipSync(bytes) : bytes).toString("utf8"), text);
  }
  assert.ok(encodeBody(text).body.length < text.length / 10);
});

test("runInstall retries the encoded create once with the raw body when the server refuses body_encoding", async () => {
  for (const refusal of [
    "create_record: unknown field `body_encoding`, expected one of `type`, `reason`, `body`",
    "Invalid arguments: Additional properties are not allowed ('body_encoding' was unexpected)",
  ]) {
    const native = fakeNative();
    const call = native.call.bind(native);
    native.call = async (executor, operation, args) => {
      if (args.body_encoding) { native.calls.push({ executor, operation, args }); throw new Error(refusal); }
      return call(executor, operation, args);
    };
    const notices = [];
    const result = await runInstall(plan(), native, { onNotice: (message) => notices.push(message) });
    const creates = native.calls.filter((entry) => entry.operation === "create_record");
    assert.equal(creates.length, 2, "one refused encoded attempt, one raw retry");
    assert.equal(creates[0].args.body_encoding, "gzip+base64");
    assert.equal(creates[1].args.body, html);
    assert.equal(Object.hasOwn(creates[1].args, "body_encoding"), false);
    assert.deepEqual(creates[1].args, plan({ bodyEncoding: "utf8" }).steps[0].arguments);
    assert.equal(notices.length, 1);
    assert.match(notices[0], /does not support body_encoding/);
    assert.equal(result.log.find((entry) => entry.step === "create-artifact").fallback, "raw-body");
    assert.equal(native.record.body, html);
    assert.ok(result.log.every((entry) => entry.ok));
  }
});

test("runInstall does not fall back on a new server's own refusals or on other errors", async () => {
  for (const refusal of [
    "create_record: 'body' decodes to 600000 bytes, over the 524288-byte body limit [body_encoding_too_large]",
    "create_record: not valid gzip [body_encoding_invalid_gzip]",
    "create_record: html_policy_violation at line 3",
  ]) {
    const native = fakeNative();
    native.call = async (executor, operation, args) => { native.calls.push({ executor, operation, args }); throw new Error(refusal); };
    const notices = [];
    await assert.rejects(runInstall(plan(), native, { onNotice: (message) => notices.push(message) }), (error) => error.message === refusal);
    assert.equal(native.calls.length, 1, "no retry");
    assert.deepEqual(notices, []);
  }
});

test("raw and chunked plans carry no fallback", () => {
  for (const options of [{ bodyEncoding: "utf8" }, { chunked: true }]) {
    for (const step of plan(options).steps) assert.equal(Object.hasOwn(step, "fallback"), false);
  }
});

// A bundle whose manifest reads one input port, as Docs reads `pages`.
const manifest = { schema: "native.html.artifact.v1", capability_requests: [{ capability: "input.read", scope: { port: "pages" } }], inputs: { pages: { envelope: "native.collection-envelope.v1", expose_to_root: true, required: false } } };
const boundHtml = html.replace("</head>", `<script type="application/json" id="native-artifact-manifest">${JSON.stringify(manifest)}</script></head>`);
const boundPlan = (options = {}) => plan({ html: boundHtml, ...options });

test("a manifest's input.read ports are reported unbound unless bound", () => {
  assert.notEqual(boundHtml, html);
  assert.equal("unbound_inputs" in plan(), false, "plans without input ports stay byte-identical");
  assert.deepEqual(boundPlan().unbound_inputs, ["pages"]);
  assert.equal(boundPlan().steps.some((step) => step.step === "bind-inputs"), false);
  assert.equal("unbound_inputs" in boundPlan({ bindings: [{ port: "pages", collection_id: "c1" }] }), false);
  assert.throws(() => boundPlan({ bindings: [{ port: "items", collection_id: "c1" }] }), /does not request input\.read on that port/);
  assert.throws(() => boundPlan({ bindings: [{ port: "pages", collection_id: "c1" }, { port: "pages", collection_id: "c2" }] }), /bound once/);
  assert.throws(() => boundPlan({ chunked: true, bindings: [{ port: "pages", collection_id: "c1" }] }), /whole-body route/);
});

test("bindings bind and grant the exact new source before install", async () => {
  const p = boundPlan({ bindings: [{ port: "pages", collection_id: "c1" }] });
  assert.deepEqual(p.steps.map((step) => step.step), ["create-artifact", "bind-inputs", "grant-input-pages", "install", "inspect"]);
  const native = fakeNative();
  const base = native.call.bind(native);
  const executed = [];
  native.call = async (executor, operation, args) => {
    if (operation === "manage_artifact_inputs.bind_many") { native.calls.push({ executor, operation, args }); return { status: "bound" }; }
    if (operation === "manage_artifact_module_grants.grant") { native.calls.push({ executor, operation, args }); return { plan_id: "wpl1:p", target: "t", effect_summary: "e" }; }
    return base(executor, operation, args);
  };
  native.execute = async (executor, operation, prepared) => { executed.push({ executor, operation, prepared }); return { status: "granted" }; };
  const result = await runInstall(p, native);
  const bind = native.calls.find((call) => call.operation === "manage_artifact_inputs.bind_many").args;
  assert.deepEqual(bind, { artifact_id: native.record.id, bindings: [{ port_name: "pages", collection_id: "c1" }] });
  const grant = native.calls.find((call) => call.operation === "manage_artifact_module_grants.grant");
  assert.equal(grant.executor, "access_admin");
  assert.deepEqual(grant.args, {
    artifact_id: native.record.id, subject_kind: "artifact_source", subject_record_id: native.record.id,
    subject_event_id: result.source_revision, source_sha256: sha256(boundHtml),
    capability: "input.read", scope: { artifact_port: "pages" },
  });
  assert.deepEqual(executed, [{ executor: "access_admin", operation: "manage_artifact_module_grants.grant", prepared: { plan_id: "wpl1:p", target: "t", effect_summary: "e" } }]);
  const install = native.calls.find((call) => call.operation === "manage_alpha_tabs.install").args;
  assert.equal(install.source_revision, result.source_revision, "the grant names the source the install consents to");
});

test("a grant step stops before install when the client cannot execute a prepared plan", async () => {
  const native = fakeNative();
  const base = native.call.bind(native);
  native.call = async (executor, operation, args) => (operation === "manage_artifact_inputs.bind_many" ? { status: "bound" } : base(executor, operation, args));
  await assert.rejects(runInstall(boundPlan({ bindings: [{ port: "pages", collection_id: "c1" }] }), native), /client\.execute is missing/);
  assert.equal(native.calls.some((call) => call.operation === "manage_alpha_tabs.install"), false);
});
