// Boundary cases for Attention's follow-up answers, run against BOTH validators so they cannot drift apart:
//   - the launcher's projection, `followupResultOf` in packages/native-launcher/src/appAgentSessions.mjs, and
//   - the frame bridge's `followupResultOf` in crates/artifact-html/src/html.rs (the vendored bridge-bootstrap.js).
// Each case is `{ name, kind, value, valid }`: `valid` means the answer is accepted as the Desktop contract allows it.
// Cases the two layers treat differently on purpose are not here: the launcher drops unknown keys while the frame refuses
// them, and the launcher also refuses control characters in identifiers.

const text = (n) => "a".repeat(n);
export const status = (patch = {}) => ({
  state: "paused", reason: "15 follow-ups started in 10 minutes.", limit: "burst", launchesToday: 15, dailyCeiling: 100,
  burst: { launches: 15, limit: 15, windowMs: 600000 }, running: 0, maxConcurrent: 2, queued: 3, queuedAt: 1760000000000,
  worker: { provider: "codex", model: "gpt-6.1", modeId: "auto", workspaceId: "w-1" }, executesOn: "this Desktop", updatedAt: 1760000000000, ...patch,
});
export const worker = (patch = {}) => ({ ...status().worker, ...patch });
export const view = (patch = {}) => ({
  configured: true, enabled: true, provider: "codex", model: "gpt-6.1", modeId: "auto", optionsReason: null,
  options: [{ provider: "codex", label: "Codex", modeId: "auto", models: [{ id: "gpt-6.1", label: "GPT 6.1" }] }], ...patch,
});
const option = (patch = {}) => ({ provider: "codex", label: "Codex", modeId: "auto", models: [{ id: "gpt-6.1", label: "GPT 6.1" }], ...patch });
const many = (n, make) => Array.from({ length: n }, (_, i) => make(i));

const c = (name, kind, value, valid) => ({ name, kind, value, valid });
export const followupBoundaryCases = [
  c("a healthy status", "status", status(), true),
  c("every state", "status", status({ state: "limit_reached" }), true),
  c("an unknown state", "status", status({ state: "sleeping" }), false),
  c("limit weekly", "status", status({ limit: "weekly" }), false),
  c("no limit", "status", status({ limit: null }), true),
  c("reason null", "status", status({ reason: null }), true),
  c("reason 2000 characters", "status", status({ reason: text(2000) }), true),
  c("reason 2001 characters", "status", status({ reason: text(2001) }), false),
  c("workspaceId 1 character", "status", status({ worker: worker({ workspaceId: "w" }) }), true),
  c("workspaceId 512 characters", "status", status({ worker: worker({ workspaceId: text(512) }) }), true),
  c("workspaceId 513 characters", "status", status({ worker: worker({ workspaceId: text(513) }) }), false),
  c("workspaceId empty", "status", status({ worker: worker({ workspaceId: "" }) }), false),
  c("provider 256 characters", "status", status({ worker: worker({ provider: text(256) }) }), true),
  c("provider 257 characters", "status", status({ worker: worker({ provider: text(257) }) }), false),
  c("model 256 characters", "status", status({ worker: worker({ model: text(256) }) }), true),
  c("model 257 characters", "status", status({ worker: worker({ model: text(257) }) }), false),
  c("modeId 257 characters", "status", status({ worker: worker({ modeId: text(257) }) }), false),
  c("no worker", "status", status({ worker: null }), true),
  c("a worker missing a field", "status", status({ worker: { provider: "codex", model: "m", modeId: "auto" } }), false),
  c("executesOn null", "status", status({ executesOn: null }), true),
  c("executesOn somewhere else", "status", status({ executesOn: "the cloud" }), false),
  c("negative count", "status", status({ launchesToday: -1 }), false),
  c("fractional count", "status", status({ running: 1.5 }), false),
  c("largest safe count", "status", status({ dailyCeiling: Number.MAX_SAFE_INTEGER }), true),
  c("count past the safe range", "status", status({ dailyCeiling: Number.MAX_SAFE_INTEGER + 1 }), false),
  c("fractional time", "status", status({ updatedAt: 1760000000000.5 }), false),
  c("queue not read yet", "status", status({ queued: null, queuedAt: null }), true),
  c("a count as text", "status", status({ maxConcurrent: "2" }), false),
  c("burst missing a field", "status", status({ burst: { launches: 1, limit: 15 } }), false),
  c("burst fractional", "status", status({ burst: { launches: 1, limit: 15, windowMs: 0.5 } }), false),
  c("a status missing a key", "status", (({ running, ...rest }) => rest)(status()), false),
  c("a status that is not an object", "status", [status()], false),

  c("settings not set up", "settingsGet", { configured: false, reason: "Follow-ups are not set up on this Mac yet." }, true),
  c("not-set-up reason 2000 characters", "settingsGet", { configured: false, reason: text(2000) }, true),
  c("not-set-up reason 2001 characters", "settingsGet", { configured: false, reason: text(2001) }, false),
  c("settings with one option", "settingsGet", view(), true),
  c("settings with no options", "settingsGet", view({ options: [], optionsReason: "The daemon is not running." }), true),
  c("optionsReason 2000 characters", "settingsGet", view({ optionsReason: text(2000) }), true),
  c("optionsReason 2001 characters", "settingsGet", view({ optionsReason: text(2001) }), false),
  c("16 providers", "settingsGet", view({ options: many(16, (i) => option({ provider: `p${i}` })) }), true),
  c("17 providers", "settingsGet", view({ options: many(17, (i) => option({ provider: `p${i}` })) }), false),
  c("64 models", "settingsGet", view({ options: [option({ models: many(64, (i) => ({ id: `m${i}`, label: `M ${i}` })) })] }), true),
  c("65 models", "settingsGet", view({ options: [option({ models: many(65, (i) => ({ id: `m${i}`, label: `M ${i}` })) })] }), false),
  c("model label 256 characters", "settingsGet", view({ options: [option({ models: [{ id: "m", label: text(256) }] })] }), true),
  c("model label 257 characters", "settingsGet", view({ options: [option({ models: [{ id: "m", label: text(257) }] })] }), false),
  c("model without a label", "settingsGet", view({ options: [option({ models: [{ id: "m" }] })] }), false),
  c("option label empty", "settingsGet", view({ options: [option({ label: "" })] }), false),
  c("enabled as text", "settingsGet", view({ enabled: "yes" }), false),
  c("provider 257 characters", "settingsGet", view({ provider: text(257) }), false),

  c("continue lifted a limit", "continue", { continued: true, message: "Continuing.", status: status() }, true),
  c("continue with a long message", "continue", { continued: false, message: text(2000), status: status() }, true),
  c("continue with a too-long message", "continue", { continued: false, message: text(2001), status: status() }, false),
  c("continue with a malformed status", "continue", { continued: true, message: "x", status: status({ state: "x" }) }, false),
  c("continue where continued is text", "continue", { continued: "yes", message: "x", status: status() }, false),

  c("settings applied", "settingsSet", { result: "applied", message: "Follow-ups are on.", settings: view(), status: status() }, true),
  c("settings saved, not yet applied", "settingsSet", { result: "saved", message: "Saved. It applies on the next pass.", settings: view(), status: status() }, true),
  c("settings unchanged", "settingsSet", { result: "unchanged", message: "Already set that way.", settings: view(), status: status() }, true),
  c("settings refused", "settingsSet", { result: "refused", message: "claude is not available.", status: status() }, true),
  c("a refusal that carries settings", "settingsSet", { result: "refused", message: "no", settings: view(), status: status() }, false),
  c("applied without settings", "settingsSet", { result: "applied", message: "ok", status: status() }, false),
  c("an unknown result", "settingsSet", { result: "pending", message: "ok", settings: view(), status: status() }, false),
  c("applied with a workspaceId of 512", "settingsSet", { result: "applied", message: "ok", settings: view(), status: status({ worker: worker({ workspaceId: text(512) }) }) }, true),
  c("applied with a workspaceId of 513", "settingsSet", { result: "applied", message: "ok", settings: view(), status: status({ worker: worker({ workspaceId: text(513) }) }) }, false),
];
