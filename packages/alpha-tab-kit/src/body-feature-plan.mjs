// Pure author preparation. This module neither holds Cookie credentials nor
// calls the feature endpoint; current admission/consent remain server-owned.
import { randomUUID } from "node:crypto";
import { prepareSourceSteps } from "./body-feature-source.mjs";
import { validateBodyFeaturePackage } from "./validate.mjs";
import { LIMITS } from "./limits.mjs";
import { isRustBlank } from "./session-structure.mjs";

const members = ["descriptor", "html", "homeId", "reason", "name", "summary", "sources",
  "chunkBytes", "completenessBudget", "replaceInstallEventId"];

// Snapshot parsed JSON author data without invoking getters/toJSON. This does
// NOT detect duplicate decoded members in original JSON text. No normalization
// of declaration order, optional presence, SQL, sessions or source text occurs.
function snapshot(value, ancestors = new Set()) {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if ([...value].some((c) => c.codePointAt(0) >= 0xd800 && c.codePointAt(0) <= 0xdfff)) {
      throw new Error("feature planning requires Unicode scalar strings");
    }
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || ancestors.has(value)) throw new Error("feature planning requires acyclic JSON data");
  const array = Array.isArray(value);
  if (!array && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("feature planning requires plain JSON objects");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors).filter((key) => !(array && key === "length"));
  if (array && (keys.length !== value.length || keys.some((key, i) => key !== String(i)))) throw new Error("feature planning requires dense JSON arrays");
  const out = array ? [] : {};
  ancestors.add(value);
  for (const key of keys) {
    const d = descriptors[key];
    if (typeof key !== "string" || !d.enumerable || !Object.hasOwn(d, "value")) throw new Error("feature planning requires own JSON data members");
    Object.defineProperty(out, key, { value: snapshot(d.value, ancestors), enumerable: true });
  }
  ancestors.delete(value);
  return Object.freeze(out);
}

function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Closed, immutable host handoff. Retain THIS intent/key for explicit retry;
 * rerunning the planner creates a different intent, never historical recovery.
 * Other declared capabilities are retained in consent but withheld by this host.
 */
export function planBodyFeatureInstall(input) {
  const p = snapshot(input);
  if (!p || Array.isArray(p) || typeof p !== "object" || Object.keys(p).some((key) => !members.includes(key))) {
    throw new Error("unknown body feature planning member or invalid parameters");
  }
  for (const key of ["homeId", "reason"]) {
    if (typeof p[key] !== "string" || isRustBlank(p[key])) throw new Error(`planBodyFeatureInstall needs ${key}`);
  }
  if (typeof p.html !== "string") throw new Error("planBodyFeatureInstall needs exact HTML text");
  if (!p.descriptor || typeof p.descriptor !== "object" || Array.isArray(p.descriptor)) throw new Error("invalid descriptor");
  if (Object.hasOwn(p, "completenessBudget") && (!p.completenessBudget || Array.isArray(p.completenessBudget)
    || typeof p.completenessBudget !== "object" || Object.entries(p.completenessBudget).some(([key, value]) =>
      !["scriptBytes", "tokens", "steps"].includes(key) || !Number.isSafeInteger(value) || value < 0))) throw new Error("invalid completenessBudget");
  for (const key of ["name", "summary", "replaceInstallEventId"]) {
    if (Object.hasOwn(p, key) && (typeof p[key] !== "string" || (key === "replaceInstallEventId" && !p[key]))) throw new Error(`invalid ${key}`);
  }
  if (Object.hasOwn(p, "sources") && (!Array.isArray(p.sources) || p.sources.some((s) =>
    !s || Array.isArray(s) || Object.keys(s).length !== 2 || typeof s.record_id !== "string" || !s.record_id || typeof s.reason !== "string" || !s.reason))) throw new Error("invalid sources");
  if (Object.hasOwn(p, "chunkBytes") && (!Number.isSafeInteger(p.chunkBytes) || p.chunkBytes < 4)) throw new Error("chunkBytes must be a safe integer >=4");
  if (Buffer.byteLength(p.reason) > LIMITS.install.reason_max_bytes) throw new Error(`reason exceeds ${LIMITS.install.reason_max_bytes} bytes`);
  const validation = validateBodyFeaturePackage(p);
  if (!validation.ok) {
    const error = new Error("body feature package does not structurally validate; this is not admission");
    error.findings = validation.findings.filter((item) => item.severity === "error");
    throw error;
  }
  const { descriptor } = p;
  const { digests, steps } = prepareSourceSteps(p);
  return freeze({
    kind: "alpha-tab.body-feature-plan.v1",
    package: descriptor.package,
    version: descriptor.version,
    digests,
    sourceSteps: steps,
    hostInstall: {
      operation: "alpha-tabs.body-feature",
      method: "POST",
      pathTemplate: "/databases/{db_id}/alpha-tabs/body-feature",
      arguments: {
        action: "install", package: descriptor.package, version: descriptor.version,
        digest: digests.digest, artifact_id: "{{record_id}}", source_revision: "{{source_revision}}",
        declaration: descriptor.declaration, reason: p.reason, idempotency_key: randomUUID(),
        ...(p.replaceInstallEventId ? { expected_install_event_id: "{{removed_event_id}}" } : {}),
      },
    },
    hostAvailability: { body: "viewer-visible-current-bodies", otherReads: false, effects: false, sessions: false },
  });
}
