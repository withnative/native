import { App } from "@modelcontextprotocol/ext-apps";
import "./style.css";
import { renderDiff } from "./diff";
import { el, errorText } from "./dom";

type Payload = { view: "record_version_diff"; record_id: string; before: { as_of_seq: number; record: { name?: string; body?: string | null } }; after: { as_of_seq: number; record: { name?: string; body?: string | null } }; events: Array<{ seq: number; type: string; payload?: unknown }> };
type DisplayMode = "inline" | "fullscreen" | "pip";

const DISPLAY_MODES: DisplayMode[] = ["inline", "fullscreen", "pip"];
const DISPLAY_LABELS: Record<DisplayMode, string> = {
  inline: "Inline",
  fullscreen: "Fullscreen",
  pip: "Picture in picture",
};
const MAX_EVENT_DETAIL_CHARS = 4_000;
const root = document.getElementById("app")!;
const app = new App({ name: "Native record version diff", version: "1.0.0" });

function eventDetail(payload: unknown): string | undefined {
  if (payload === undefined) return undefined;
  let detail: string;
  try {
    detail = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) ?? String(payload);
  } catch {
    detail = "Event payload could not be displayed.";
  }
  return detail.length <= MAX_EVENT_DETAIL_CHARS
    ? detail
    : `${detail.slice(0, MAX_EVENT_DETAIL_CHARS)}\n… payload truncated`;
}

function displayModeControls(): HTMLElement | undefined {
  const context = app.getHostContext();
  const advertised = new Set(context?.availableDisplayModes ?? []);
  const available = DISPLAY_MODES.filter((mode) => advertised.has(mode));
  if (available.length === 0) return undefined;
  const controls = el("div", undefined, "actions display-modes");
  controls.setAttribute("aria-label", "Display mode");
  for (const mode of available) {
    const button = el("button", DISPLAY_LABELS[mode]);
    button.disabled = mode === context?.displayMode;
    button.addEventListener("click", async () => {
      try {
        await app.requestDisplayMode({ mode });
      } catch {
        // Display-mode negotiation is optional; the inline diff remains usable.
      }
    });
    controls.append(button);
  }
  return controls;
}

function render(payload: Payload) {
  root.replaceChildren(); const head = el("div", undefined, "head");
  const identity = el("div");
  identity.append(el("h1", payload.after.record.name ?? payload.record_id), el("span", `r${payload.before.as_of_seq} → r${payload.after.as_of_seq}`, "muted"));
  head.append(identity);
  const controls = displayModeControls();
  if (controls) head.append(controls);
  root.append(head);
  const diff = el("section", undefined, "pane"); renderDiff(diff, payload.before.record.body ?? "", payload.after.record.body ?? ""); root.append(diff);
  const details = el("details"); details.append(el("summary", `${payload.events.length} intervening event(s)`));
  const list = el("ol");
  for (const event of payload.events) {
    const item = el("li");
    item.append(el("div", `#${event.seq} ${event.type}`, "event-title"));
    const detail = eventDetail(event.payload);
    if (detail !== undefined) item.append(el("pre", detail, "event-payload"));
    list.append(item);
  }
  details.append(list); root.append(details);
}
app.ontoolresult = (result) => {
  try {
    if (result.isError) throw new Error(result.content?.[0]?.type === "text" ? result.content[0].text : "The launcher failed");
    const payload = result.structuredContent as Payload | undefined;
    if (
      payload?.view !== "record_version_diff" ||
      typeof payload.record_id !== "string" ||
      !payload.before?.record ||
      !payload.after?.record ||
      !Array.isArray(payload.events)
    ) throw new Error("Unexpected App payload");
    render(payload);
  } catch (error) {
    root.textContent = errorText(error);
  }
};
app.connect();
