import { App } from "@modelcontextprotocol/ext-apps";
import "./style.css";
import { renderDiff } from "./diff";
import { el, errorText } from "./dom";
import {
  jsonCall,
  loadSuggestionData,
  refreshTarget,
  type Bridge,
  type ReviewTarget,
  type Suggestion,
} from "./suggestion-data";

type Bootstrap = {
  view: "suggestion_review";
  target: ReviewTarget;
  suggestion_count: number;
};

const root = document.getElementById("app")!;
const app = new App({ name: "Native suggestion review", version: "1.0.0" });
const bridge = app as unknown as Bridge;
let bootstrap: Bootstrap;
let suggestions: Suggestion[] = [];
const accepted: string[] = [];
const skipped = new Set<string>();
const preconditions = new Map<string, string>();
const status = el("div", "", "status");
let completed = false;
let commitInFlight = false;

function contextText(): string {
  return [
    `Suggestion triage for ${bootstrap.target.name} (${bootstrap.target.id}).`,
    `Revision: ${bootstrap.target.current_seq}.`,
    `Body digest: ${bootstrap.target.body_digest ?? "null-body"}.`,
    `Accepted in order: ${accepted.join(", ") || "none"}.`,
    `Skipped: ${[...skipped].join(", ") || "none"}.`,
    `State: ${completed ? "completed" : "staging"}.`,
  ].join(" ");
}

async function updateContext(): Promise<void> {
  try {
    await app.updateModelContext({
      content: [{ type: "text", text: contextText() }],
      structuredContent: {
        view: "suggestion_review",
        target: bootstrap.target,
        suggestions,
        accepted_in_order: [...accepted],
        skipped: [...skipped],
        completed,
      },
    });
  } catch {
    // Optional host capability: the App remains functional without it.
  }
}

function canAccept(id: string): boolean {
  if (completed || commitInFlight) return false;
  if (suggestions.find((value) => value.id === id)?.preview_status !== "would_accept") return false;
  const whole = preconditions.get(id) === "digest" || preconditions.get(id) === "none_whole";
  return accepted.length === 0 || (!whole && accepted.every((value) => !["digest", "none_whole"].includes(preconditions.get(value) ?? "")));
}

function draw(): void {
  root.replaceChildren();
  const head = el("div", undefined, "head");
  head.append(
    el("h1", bootstrap.target.name),
    el("span", `revision ${bootstrap.target.current_seq} · ${suggestions.length} open`, "muted"),
  );
  root.append(head, status);
  if (completed) {
    root.append(el("p", "The selected suggestions were committed. This review is complete."));
    return;
  }
  for (const suggestion of suggestions) {
    const card = el("article", undefined, "card");
    card.append(
      el("h2", suggestion.name),
      el("div", suggestion.preview_status === "would_accept" ? "Preview" : `Unavailable: ${suggestion.preview_status ?? "unknown"}`, "muted"),
    );
    const diff = el("div", undefined, "pane");
    renderDiff(diff, bootstrap.target.body ?? "", suggestion.preview_body ?? bootstrap.target.body ?? "");
    card.append(diff);
    const actions = el("div", undefined, "actions");
    const accept = el("button", accepted.includes(suggestion.id) ? "Accepted" : "Accept");
    accept.disabled = accepted.includes(suggestion.id) || !canAccept(suggestion.id);
    accept.addEventListener("click", async () => {
      accepted.push(suggestion.id);
      skipped.delete(suggestion.id);
      await updateContext();
      draw();
    });
    const skip = el("button", skipped.has(suggestion.id) ? "Skipped" : "Skip");
    skip.disabled = skipped.has(suggestion.id) || commitInFlight;
    skip.addEventListener("click", async () => {
      skipped.add(suggestion.id);
      const index = accepted.indexOf(suggestion.id);
      if (index >= 0) accepted.splice(index, 1);
      await updateContext();
      draw();
    });
    actions.append(accept, skip);
    card.append(actions);
    root.append(card);
  }
  const done = el("button", commitInFlight ? "Committing…" : "Done", "primary");
  done.disabled = accepted.length === 0 || commitInFlight;
  done.addEventListener("click", finish);
  root.append(done);
}

async function load(message?: string, refresh = false): Promise<void> {
  const selected = new Set(accepted);
  if (refresh) bootstrap.target = await refreshTarget(bridge, bootstrap.target.id);
  suggestions = await loadSuggestionData(bridge, bootstrap.target.id);
  preconditions.clear();
  for (const suggestion of suggestions) preconditions.set(suggestion.id, suggestion.precondition ?? "");
  accepted.splice(0, accepted.length, ...accepted.filter((id) => selected.has(id) && suggestions.some((suggestion) => suggestion.id === id)));
  for (const id of [...skipped]) if (!suggestions.some((suggestion) => suggestion.id === id)) skipped.delete(id);
  status.textContent = message ?? (suggestions.length ? "Stage suggestions, then commit the ordered selection once." : "No open suggestions.");
  await updateContext();
  draw();
}

async function finish(): Promise<void> {
  if (completed || commitInFlight || accepted.length === 0) return;
  commitInFlight = true;
  status.textContent = "Checking selection…";
  draw();
  const argumentsBase = {
    action: "accept",
    suggestion_ids: [...accepted],
    reason: "Accepted from the suggestion review App",
  };
  try {
    const preview = await jsonCall(bridge, "resolve_suggestions", { ...argumentsBase, dry_run: true });
    if (preview.status !== "would_accept") {
      commitInFlight = false;
      await load(`Preflight: ${String(preview.status ?? "failed")}. The target and open survivors were refreshed.`, true);
      return;
    }
    const outcome = await jsonCall(bridge, "resolve_suggestions", argumentsBase);
    if (outcome.status !== "accepted") {
      commitInFlight = false;
      await load(`Commit: ${String(outcome.status ?? "failed")}. The target and open survivors were refreshed.`, true);
      return;
    }
    completed = true;
    commitInFlight = false;
    status.textContent = "Committed successfully.";
    await updateContext();
    draw();
    try {
      const message = await app.sendMessage({
        role: "user",
        content: [{ type: "text", text: `Suggestion review complete for ${bootstrap.target.name}: accepted.` }],
      });
      if (message.isError) status.textContent = "Committed successfully. The host message could not be delivered.";
    } catch {
      status.textContent = "Committed successfully. The host message could not be delivered.";
    }
    draw();
  } catch (error) {
    commitInFlight = false;
    const failure = errorText(error);
    try {
      await load(`Commit failed: ${failure}. The target and open survivors were refreshed.`, true);
    } catch (refreshError) {
      status.textContent = `Commit failed: ${failure}. Refresh also failed: ${errorText(refreshError)}`;
      await updateContext();
      draw();
    }
  }
}

app.ontoolresult = (result) => {
  if (result.isError) {
    root.textContent = result.content?.find((block) => block.type === "text")?.text ?? "Launcher failed";
    return;
  }
  const value = result.structuredContent as Bootstrap;
  if (
    value?.view !== "suggestion_review" ||
    !value.target ||
    typeof value.target.current_seq !== "number" ||
    typeof value.target.body_is_null !== "boolean" ||
    !(typeof value.target.body_digest === "string" || value.target.body_digest === null)
  ) {
    root.textContent = "Unexpected App payload";
    return;
  }
  bootstrap = value;
  load().catch((error) => { root.textContent = errorText(error); });
};
app.connect();
