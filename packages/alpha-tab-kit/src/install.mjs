// Whole-body, digest-guarded install by default. Explicit chunked mode keeps
// the legacy note/append/query/re-kind route for constrained transports.
// Saved plans execute their original steps through runInstall.
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { computeDigests } from "./digest.mjs";
import { validatePackage } from "./validate.mjs";
import { parseIconFacet } from "./icons.mjs";
import { LIMITS } from "./limits.mjs";

const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");

/** Whole-body source encodings the server's `body_encoding` accepts. */
export const BODY_ENCODINGS = Object.freeze([...LIMITS.install.body_encodings]);
export const DEFAULT_BODY_ENCODING = "gzip+base64";

/**
 * Encode the whole-body source for `create_record.body` + `body_encoding`.
 * `utf8` is the raw string and omits the field, so it is byte-identical to a
 * plan written before the field existed (use it against an older server).
 */
export function encodeBody(html, encoding = DEFAULT_BODY_ENCODING) {
  if (!BODY_ENCODINGS.includes(encoding)) throw new Error(`bodyEncoding must be one of ${BODY_ENCODINGS.join(", ")}, got ${JSON.stringify(encoding)}`);
  const bytes = Buffer.from(html, "utf8");
  if (encoding === "utf8") return { body: html };
  if (encoding === "base64") return { body: bytes.toString("base64"), body_encoding: encoding };
  return { body: gzipSync(bytes, { level: 9 }).toString("base64"), body_encoding: encoding };
}

/**
 * Root input ports the bundle's artifact manifest asks to read
 * (`capability_requests` of `input.read`). Each needs a Collection bound to
 * the exact new source, plus an `input.read` grant, before the tab can render:
 * bindings and grants are pinned to one source and never follow a reinstall.
 */
export function requestedInputPorts(html) {
  const match = /<script\b[^>]*\bid=["']native-artifact-manifest["'][^>]*>([\s\S]*?)<\/script>/i.exec(html);
  if (!match) return [];
  let manifest;
  try { manifest = JSON.parse(match[1]); } catch { return []; }
  const ports = (Array.isArray(manifest?.capability_requests) ? manifest.capability_requests : [])
    .filter((request) => request?.capability === "input.read" && typeof request.scope?.port === "string")
    .map((request) => request.scope.port);
  return [...new Set(ports)];
}

/** Split text into chunks of at most `maxBytes` UTF-8 bytes, never inside a code point. */
export function chunkUtf8(text, maxBytes) {
  const chunks = [];
  let current = "";
  let bytes = 0;
  for (const char of text) {
    const size = Buffer.byteLength(char, "utf8");
    if (bytes + size > maxBytes && current) { chunks.push(current); current = ""; bytes = 0; }
    current += char;
    bytes += size;
  }
  if (current || chunks.length === 0) chunks.push(current);
  return chunks;
}

/**
 * @param {object} p
 * @param {object} p.descriptor   package descriptor (package, version, runtime, declaration)
 * @param {string} p.html         exact bundle text
 * @param {string} p.homeId       folder for the source record
 * @param {string} p.reason       why (every write needs one; ≤1024 bytes for install)
 * @param {string} [p.name]       source record name
 * @param {string} [p.summary]
 * @param {Array}  [p.sources]    [{record_id, reason}] the writes rest on
 * @param {boolean} [p.chunked] opt in to the legacy chunked route
 * @param {"utf8"|"base64"|"gzip+base64"} [p.bodyEncoding] whole-body route only; default "gzip+base64". "utf8" sends the raw string (servers without body_encoding)
 * @param {number} [p.chunkBytes] chunked route only; default 8000
 * @param {object} [p.completenessBudget] overrides the advisory completeness lint bounds (tests)
 * @param {string} [p.replaceInstallEventId]  remove the current install of this package first
 * @param {string} [p.updateInstallEventId]  update the current install generation in place
 * @param {string} [p.afterRemovalEventId]  install against an existing removal event
 * @param {Array}  [p.bindings]   [{port, collection_id}] bind each input port of the new source to a
 *                                Collection and grant it input.read; whole-body route only
 */
export function planInstall(p) {
  const hasReplace = p.replaceInstallEventId !== undefined;
  const hasAfterRemoval = p.afterRemovalEventId !== undefined;
  const hasUpdate = p.updateInstallEventId !== undefined;
  if (hasUpdate && (hasReplace || hasAfterRemoval)) {
    throw new Error("--update, --replace and --after-removal are mutually exclusive");
  }
  if (hasReplace && hasAfterRemoval) {
    throw new Error("--replace and --after-removal are mutually exclusive");
  }
  for (const [field, flag] of [["replaceInstallEventId", "--replace"], ["afterRemovalEventId", "--after-removal"], ["updateInstallEventId", "--update"]]) {
    if (p[field] !== undefined && (typeof p[field] !== "string" || !p[field].trim())) {
      throw new Error(`${flag} needs a non-blank event id string`);
    }
  }
  const { descriptor, html, completenessBudget } = p;
  const bodyEncoding = p.bodyEncoding ?? DEFAULT_BODY_ENCODING;
  if (!BODY_ENCODINGS.includes(bodyEncoding)) throw new Error(`bodyEncoding must be one of ${BODY_ENCODINGS.join(", ")}, got ${JSON.stringify(bodyEncoding)}`);
  const validation = validatePackage({ descriptor, html, completenessBudget });
  if (!validation.ok) {
    const errors = validation.findings.filter((item) => item.severity === "error");
    const error = new Error(`package does not validate (${errors.length} error(s)); run alpha-tab-kit validate`);
    error.findings = errors;
    throw error;
  }
  if (!p.homeId || !p.reason) throw new Error("planInstall needs homeId and reason");
  if (Buffer.byteLength(p.reason) > LIMITS.install.reason_max_bytes) throw new Error(`reason exceeds ${LIMITS.install.reason_max_bytes} bytes`);
  const digests = computeDigests(html, descriptor.declaration, descriptor.runtime);
  const iconFacets = Object.hasOwn(descriptor, "icon") && parseIconFacet(descriptor.icon)
    ? { app_icon: descriptor.icon } : {};
  const bindings = p.bindings ?? [];
  const requestedPorts = requestedInputPorts(html);
  for (const binding of bindings) {
    if (!binding || typeof binding.port !== "string" || !binding.port || typeof binding.collection_id !== "string" || !binding.collection_id) {
      throw new Error("each binding needs a port and a collection_id");
    }
    if (!requestedPorts.includes(binding.port)) {
      throw new Error(`--bind ${binding.port}: the bundle's manifest does not request input.read on that port (requested: ${requestedPorts.join(", ") || "none"})`);
    }
  }
  if (new Set(bindings.map((binding) => binding.port)).size !== bindings.length) throw new Error("each port can be bound once");
  if (bindings.length && p.chunked) throw new Error("--bind needs the whole-body route; drop --chunked");
  const unboundInputs = requestedPorts.filter((port) => !bindings.some((binding) => binding.port === port));
  const chunks = p.chunked ? chunkUtf8(html, p.chunkBytes ?? 8000) : [html];
  const sources = p.sources ?? [];
  const steps = [];
  if (p.chunked) {
    let prefix = "";
    chunks.forEach((chunk, index) => {
      const before = prefix;
      prefix += chunk;
      const args = index === 0
        ? { type: "Document", kind: "note", name: p.name ?? `${descriptor.package} ${descriptor.version} (alpha tab source)`, home_id: p.homeId, summary: p.summary ?? `Source bytes of alpha tab ${descriptor.package} ${descriptor.version}; staged as a note, then switched to native.html.v1.`, body: chunk, reason: p.reason, sources }
        : { id: "{{record_id}}", body_append: chunk, if_body_digest: sha256(before), reason: `${p.reason} (chunk ${index + 1} of ${chunks.length})`, sources };
      steps.push({
        step: index === 0 ? "create-note" : `append-${index + 1}`,
        executor: "records_write",
        operation: index === 0 ? "create_record" : "update_record",
        arguments: args,
        expect: { body_digest: sha256(prefix), body_bytes: Buffer.byteLength(prefix, "utf8") },
      });
    });
    steps.push({
      step: "source-revision",
      executor: "sql_read",
      operation: "query_sql",
      // Same event types as resolve_alpha_tab_source_in (alpha_tabs.rs:2008):
      // artifact writes also append `artifact.source_attested` events.
      // The engine additionally requires json_type(payload,'$.body') IS NOT
      // NULL, but content_events exposes no payload column to query_sql. This
      // query therefore relies on an invariant of this plan: every write before
      // this step (create_record with `body`, update_record with `body_append`)
      // carries a body, and nothing else writes the record meanwhile (each
      // append is guarded by if_body_digest). Do not insert a body-less write
      // before this step.
      arguments: { sql: "SELECT id, type FROM content_events WHERE record_id = ?1 AND type IN ('record.created', 'record.updated', 'receipt.committed.v1') ORDER BY local_seq DESC, id LIMIT 1", parameters: [{ type: "text", value: "{{record_id}}" }] },
      capture: { source_revision: "rows[0].id" },
      note: "Run before any other write to the record: the newest event is the last body-carrying write.",
    });
    steps.push({
      step: "rekind-artifact",
      executor: "records_write",
      operation: "update_record",
      arguments: { id: "{{record_id}}", kind: "artifact", facets: { runtime: LIMITS.install.runtime, ...iconFacets }, if_body_digest: digests.bundle_sha256, reason: `${p.reason} (switch to native.html.v1; validates the complete document)`, sources },
      expect: { body_digest: digests.bundle_sha256 },
    });
  } else {
    const args = {
      type: "Document", kind: "artifact",
      name: p.name ?? `${descriptor.package} ${descriptor.version} (alpha tab source)`,
      home_id: p.homeId,
      summary: p.summary ?? `Source bytes of alpha tab ${descriptor.package} ${descriptor.version}.`,
      ...encodeBody(html, bodyEncoding),
      facets: { runtime: LIMITS.install.runtime, ...iconFacets },
      reason: p.reason, sources,
      response_mode: "summary",
    };
    steps.push({
      step: "create-artifact", executor: "records_write", operation: "create_record",
      arguments: args,
      // A server that predates `body_encoding` refuses the argument; runInstall
      // retries this one step with the raw body. Other refusals surface.
      ...(args.body_encoding ? { fallback: { reason: "server-without-body_encoding", arguments: (({ body_encoding, ...rest }) => ({ ...rest, body: html }))(args) } } : {}),
      expect: { body_digest: digests.bundle_sha256, body_bytes: Buffer.byteLength(html, "utf8") },
    });
  }
  if (bindings.length) {
    // Bind and grant the exact new source before install: a binding or grant
    // made for an earlier source does not carry to this one, and without them
    // render_artifact refuses (module_capability_denied), so every Save does too.
    steps.push({
      step: "bind-inputs",
      executor: "artifacts_write",
      operation: "manage_artifact_inputs.bind_many",
      arguments: { artifact_id: "{{record_id}}", bindings: bindings.map(({ port, collection_id }) => ({ port_name: port, collection_id })) },
    });
    for (const { port } of bindings) {
      steps.push({
        step: `grant-input-${port}`,
        executor: "access_admin",
        operation: "manage_artifact_module_grants.grant",
        // Plan-required: runInstall prepares, then executes the returned plan.
        prepare: true,
        arguments: {
          artifact_id: "{{record_id}}", subject_kind: "artifact_source", subject_record_id: "{{record_id}}",
          subject_event_id: "{{source_revision}}", source_sha256: digests.bundle_sha256,
          capability: "input.read", scope: { artifact_port: port },
        },
      });
    }
  }
  if (hasReplace) {
    steps.push({
      step: "remove-previous-install",
      executor: "artifacts_write",
      operation: "manage_alpha_tabs.remove",
      arguments: { package: descriptor.package, expected_install_event_id: p.replaceInstallEventId, reason: `${p.reason} (install refuses a package that is already installed)` },
    });
  }
  steps.push({
    step: hasUpdate ? "update" : "install",
    executor: "artifacts_write",
    operation: hasUpdate ? "manage_alpha_tabs.update" : "manage_alpha_tabs.install",
    arguments: {
      package: descriptor.package,
      version: descriptor.version,
      digest: digests.digest,
      artifact_id: "{{record_id}}",
      source_revision: "{{source_revision}}",
      declaration: descriptor.declaration,
      reason: p.reason,
      ...(hasUpdate ? { expected_install_event_id: p.updateInstallEventId } : hasReplace ? { expected_install_event_id: "{{removed_event_id}}" } : hasAfterRemoval ? { expected_install_event_id: p.afterRemovalEventId } : {}),
    },
    expect: { digest: digests.digest, declaration_digest: digests.declaration_digest },
  });
  steps.push({
    step: "inspect",
    executor: "artifacts_read",
    operation: "manage_alpha_tabs.inspect",
    arguments: { package: descriptor.package },
    expect: { digest: digests.digest, declaration_digest: digests.declaration_digest, version: descriptor.version },
    note: "Preview and adoption are the viewer's, in a signed-in browser at /alpha/: agents are refused preview receipts (preview_authority_missing).",
  });
  return { package: descriptor.package, version: descriptor.version, digests, chunks: chunks.length, ...(unboundInputs.length ? { unbound_inputs: unboundInputs } : {}), steps };
}

function fill(value, vars) {
  if (typeof value === "string") {
    return value.replace(/\{\{(\w+)\}\}/g, (match, name) => {
      if (vars[name] === undefined) throw new Error(`plan variable ${name} is not known yet`);
      return vars[name];
    });
  }
  if (Array.isArray(value)) return value.map((item) => fill(item, vars));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fill(item, vars)]));
  return value;
}

// Receipts differ by tool and response mode; find a field wherever it sits.
export function findField(value, key, depth = 0) {
  if (!value || typeof value !== "object" || depth > 6) return undefined;
  if (Object.prototype.hasOwnProperty.call(value, key) && value[key] !== null && typeof value[key] !== "object") return value[key];
  for (const child of Object.values(value)) {
    const found = findField(child, key, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

/**
 * True when a refusal is an older server rejecting the unknown `body_encoding`
 * argument (schema or strict-parse refusal). A new server's own refusals carry a
 * `[body_encoding_*]` code and must surface, not trigger a raw retry.
 */
export function refusesBodyEncoding(error) {
  const message = String(error?.message ?? error);
  return /body_encoding/.test(message) && !/\[body_encoding_[a-z_]+\]/.test(message);
}

/**
 * Execute a plan. `client.call(executor, operation, args)` must return the
 * parsed JSON result (throw on transport or tool errors). Stops at the first
 * mismatch; nothing after a failed digest check is sent.
 */
export async function runInstall(plan, client, options = {}) {
  const kind = Object.getOwnPropertyDescriptor(plan, "kind");
  if (kind && Object.hasOwn(kind, "value") && kind.value === "alpha-tab.body-feature-plan.v1") {
    throw new Error("body feature plans require a separately qualified Cookie host executor; runInstall refuses before source writes");
  }
  const { onStep } = options;
  const vars = {};
  const log = [];
  for (const step of plan.steps) {
    let rawBodyFallback = false;
    const args = fill(step.arguments, vars);
    let result;
    try {
      try {
        if (step.prepare) {
          if (typeof client.execute !== "function") throw new Error(`${step.step}: this client cannot execute a prepared plan (client.execute is missing)`);
          const prepared = await client.call(step.executor, step.operation, args);
          if (typeof prepared?.plan_id !== "string" || typeof prepared.target !== "string" || typeof prepared.effect_summary !== "string") {
            throw new Error(`${step.step}: preparation returned no plan_id/target/effect_summary`);
          }
          result = await client.execute(step.executor, step.operation, { plan_id: prepared.plan_id, target: prepared.target, effect_summary: prepared.effect_summary });
        } else {
          result = await client.call(step.executor, step.operation, args);
        }
      } catch (error) {
        if (!step.fallback || !refusesBodyEncoding(error)) throw error;
        (options.onNotice ?? ((message) => console.error(message)))(
          "Server does not support body_encoding yet; retrying the source write with the raw body.");
        result = await client.call(step.executor, step.operation, fill(step.fallback.arguments, vars));
        rawBodyFallback = true;
      }
    } catch (error) {
      if (step.operation === "manage_alpha_tabs.update" && /\bunknown operation ['"`]?manage_alpha_tabs\.update\b|\bunknown \(executor, operation\)|\bunknown variant [`'"]update[`'"]/i.test(error.message)) {
        throw new Error(`Server predates manage_alpha_tabs.update; use --replace explicitly for remove-then-install. Staged source record ${vars.record_id} can be archived. ${error.message}`, { cause: error });
      }
      throw error;
    }
    if (step.operation === "manage_alpha_tabs.update") result = result?.write_receipt ?? result;
    const entry = { step: step.step, ok: true, ...(rawBodyFallback ? { fallback: "raw-body" } : {}) };
    if (step.operation === "manage_alpha_tabs.update") {
      if (typeof result?.update_event_id !== "string" || !result.update_event_id.trim()
        || typeof result.adoption_carried !== "boolean" || typeof result.adoption_required !== "boolean"
        || result.adoption_carried === result.adoption_required
        || typeof result.changed !== "boolean" || typeof result.idempotent_retry !== "boolean") {
        throw new Error("update: missing or inconsistent top-level update_event_id/adoption_carried/adoption_required/changed/idempotent_retry; stopping before the next call");
      }
      for (const key of ["update_event_id", "adoption_carried", "adoption_required", "changed", "idempotent_retry"]) {
        vars[key] = result[key];
        entry[key] = result[key];
      }
      vars.install_status = result.install?.status;
      entry.install_status = vars.install_status;
    }
    // Summary receipts can contain unrelated source ids and digests in
    // warnings/advisories. Only the write receipt itself defines this pin.
    const createReceipt = step.step === "create-artifact" ? (result?.write_receipt ?? result) : undefined;
    if (step.step === "create-note" || step.step === "create-artifact") {
      vars.record_id = step.step === "create-artifact"
        ? createReceipt?.id
        : findField(result, "id") ?? findField(result, "record_id");
      if (!vars.record_id) throw new Error("create_record returned no record id");
      entry.record_id = vars.record_id;
    }
    if (step.step === "create-artifact") {
      vars.source_revision = createReceipt?.source_event_id;
      if (typeof vars.source_revision !== "string" || !vars.source_revision) throw new Error("create_record returned no source_event_id");
      entry.source_revision = vars.source_revision;
    }
    if (step.capture?.source_revision) {
      vars.source_revision = result?.rows?.[0]?.id;
      if (!vars.source_revision) throw new Error("could not read the source revision event id");
      entry.source_revision = vars.source_revision;
    }
    if (step.step === "remove-previous-install") {
      vars.removed_event_id = findField(result?.install ?? result, "event_id");
      entry.removed_event_id = vars.removed_event_id;
    }
    for (const [key, expected] of Object.entries(step.expect ?? {})) {
      if (key === "body_bytes") continue;
      const actual = step.step === "create-artifact" ? createReceipt?.[key] : step.operation === "manage_alpha_tabs.update" ? result?.install?.[key] : findField(result, key);
      if (actual !== expected) {
        entry.ok = false;
        entry.mismatch = { key, expected, actual };
        log.push(entry);
        onStep?.(entry);
        const error = new Error(`${step.step}: ${key} is ${actual}, expected ${expected}; stopping before the next write`);
        error.log = log;
        throw error;
      }
    }
    if (step.step === "create-artifact" && !createReceipt?.body_digest) {
      throw new Error("create-artifact: body_digest is absent; stopping before the next write");
    }
    log.push(entry);
    onStep?.(entry);
  }
  return { ...vars, log };
}
