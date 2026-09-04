// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from "vitest";

type ToolRequest = { name: string; arguments: Record<string, unknown> };
type ToolResult = { isError?: boolean; content?: Array<{ type: string; text?: string }>; structuredContent?: unknown };
type HostContext = { displayMode?: "inline" | "fullscreen" | "pip"; availableDisplayModes?: Array<"inline" | "fullscreen" | "pip"> };

const fixture = vi.hoisted(() => ({
  instances: [] as Array<{
    ontoolresult?: (result: ToolResult) => void;
    callServerTool: ReturnType<typeof vi.fn>;
    updateModelContext: ReturnType<typeof vi.fn>;
    sendMessage: ReturnType<typeof vi.fn>;
    requestDisplayMode: ReturnType<typeof vi.fn>;
    connect: ReturnType<typeof vi.fn>;
    receiveNotification(method: string, params: ToolResult): void;
  }>,
  toolHandler: async (_request: ToolRequest): Promise<ToolResult> => ({ structuredContent: {} }),
  displayHandler: async (params: { mode: string }): Promise<{ mode: string }> => params,
  hostContext: {} as HostContext,
}));

vi.mock("@modelcontextprotocol/ext-apps", () => ({
  App: class MockApp {
    ontoolresult?: (result: ToolResult) => void;
    callServerTool = vi.fn((request: ToolRequest) => fixture.toolHandler(request));
    updateModelContext = vi.fn(async () => ({}));
    sendMessage = vi.fn(async () => ({}));
    requestDisplayMode = vi.fn((params: { mode: string }) => fixture.displayHandler(params));
    connect = vi.fn(async () => ({}));
    getHostContext = () => fixture.hostContext;

    constructor() {
      fixture.instances.push(this);
    }

    receiveNotification(method: string, params: ToolResult): void {
      if (method === "ui/notifications/tool-result") this.ontoolresult?.(params);
    }
  },
}));

const target = {
  id: "target",
  name: "Target",
  type: "Document",
  body: "before",
  current_seq: 1,
  body_digest: "a".repeat(64),
  body_is_null: false,
  last_activity_at: null,
};

const suggestions = [
  { id: "span-1", name: "First span", body: "first", precondition: "span", anchor: "before" },
  { id: "span-2", name: "Second span", body: "second", precondition: "span", anchor: "before" },
  { id: "whole", name: "Whole body", body: "whole", precondition: "digest" },
];

async function settle(): Promise<void> {
  for (let index = 0; index < 4; index++) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
  for (let index = 0; index < 4; index++) await Promise.resolve();
}

async function waitUntil(predicate: () => boolean, message: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (predicate()) return;
    await settle();
  }
  throw new Error(message);
}

function appInstance() {
  const instance = fixture.instances.at(-1);
  if (!instance) throw new Error("App shell did not construct an App");
  return instance;
}

function notifyToolResult(app: ReturnType<typeof appInstance>, structuredContent: unknown): void {
  app.receiveNotification("ui/notifications/tool-result", { structuredContent });
}

function buttonInCard(name: string, label: string): HTMLButtonElement {
  const card = Array.from(document.querySelectorAll<HTMLElement>(".card"))
    .find((candidate) => candidate.querySelector("h2")?.textContent === name);
  const button = Array.from(card?.querySelectorAll("button") ?? [])
    .find((candidate) => candidate.textContent === label);
  if (!button) throw new Error(`Missing ${label} button for ${name}`);
  return button;
}

function button(label: string): HTMLButtonElement {
  const found = Array.from(document.querySelectorAll<HTMLButtonElement>("button"))
    .find((candidate) => candidate.textContent === label);
  if (!found) throw new Error(`Missing ${label} button`);
  return found;
}

function toolRequests(app: ReturnType<typeof appInstance>, name: string): ToolRequest[] {
  return app.callServerTool.mock.calls
    .map(([request]) => request as ToolRequest)
    .filter((request) => request.name === name);
}

function configureSuggestionTools() {
  const state = {
    finalPreviewStatus: "would_accept",
    commitStatus: "accepted",
    refreshedBody: "authoritative refresh",
    refreshedSeq: 9,
  };
  fixture.toolHandler = async ({ name, arguments: arguments_ }) => {
    if (name === "resolve_facets") {
      const suggestion = suggestions.find((value) => value.id === arguments_.record_id);
      return {
        structuredContent: {
          values: [
            { key: "proposal.precondition", value: suggestion?.precondition },
            ...(suggestion?.anchor ? [{ key: "anchor.old", value: suggestion.anchor }] : []),
          ],
        },
      };
    }
    if (name === "resolve_suggestions") {
      if (arguments_.reason === "Preview in the suggestion review App") {
        const id = (arguments_.suggestion_ids as string[])[0];
        return { structuredContent: { status: "would_accept", prospective_body: `preview ${id}` } };
      }
      return {
        structuredContent: arguments_.dry_run
          ? { status: state.finalPreviewStatus, prospective_body: "prospective" }
          : { status: state.commitStatus },
      };
    }
    if (name === "get_record") {
      if (arguments_.include_suggestions) {
        return {
          structuredContent: {
            records: [{ suggestions: suggestions.map(({ precondition: _precondition, anchor: _anchor, ...suggestion }) => suggestion) }],
          },
        };
      }
      return {
        structuredContent: {
          records: [{ status: "found", ...target, body: state.refreshedBody }],
        },
      };
    }
    if (name === "get_history") {
      return { structuredContent: { events: [{ seq: state.refreshedSeq }], next_after_seq: null } };
    }
    throw new Error(`Unexpected tool ${name}`);
  };
  return state;
}

async function openSuggestionShell() {
  await import("./suggestion-review");
  const app = appInstance();
  notifyToolResult(app, { view: "suggestion_review", target: { ...target }, suggestion_count: suggestions.length });
  await waitUntil(() => document.querySelectorAll(".card").length === suggestions.length, "suggestions did not render");
  return app;
}

beforeEach(() => {
  vi.resetModules();
  fixture.instances.length = 0;
  fixture.hostContext = {};
  fixture.toolHandler = async () => ({ structuredContent: {} });
  fixture.displayHandler = async (params) => params;
  document.body.innerHTML = '<main id="app"></main>';
});

describe("record-version App shell", () => {
  it("renders tool-result structuredContent safely, explains event payloads, and requests only advertised display modes", async () => {
    fixture.hostContext = { displayMode: "inline", availableDisplayModes: ["inline", "fullscreen"] };
    await import("./record-version-diff");
    const app = appInstance();
    notifyToolResult(app, {
      view: "record_version_diff",
      record_id: "record",
      before: { as_of_seq: 2, record: { name: "Versioned", body: "before" } },
      after: { as_of_seq: 7, record: { name: "Versioned", body: "after" } },
      events: [
        { seq: 5, type: "facet.set", payload: { key: "status", value: '<img src=x onerror="boom">' } },
        { seq: 6, type: "record.updated", payload: { summary: "x".repeat(5_000) } },
      ],
    });
    await settle();

    expect(document.querySelector("h1")?.textContent).toBe("Versioned");
    expect(document.querySelector(".event-title")?.textContent).toBe("#5 facet.set");
    expect(document.querySelector(".event-payload")?.textContent).toContain('"key": "status"');
    expect(document.querySelector(".event-payload")?.textContent).toContain("<img src=x");
    expect(document.querySelector("img")).toBeNull();
    const payloads = document.querySelectorAll<HTMLElement>(".event-payload");
    expect(payloads[1].textContent).toContain("… payload truncated");
    expect((payloads[1].textContent?.length ?? 0) < 4_100).toBe(true);
    expect(button("Inline").disabled).toBe(true);
    expect(Array.from(document.querySelectorAll("button")).some((value) => value.textContent === "Picture in picture")).toBe(false);

    button("Fullscreen").click();
    await settle();
    expect(app.requestDisplayMode).toHaveBeenCalledOnce();
    expect(app.requestDisplayMode).toHaveBeenCalledWith({ mode: "fullscreen" });

    fixture.displayHandler = async () => { throw new Error("unsupported"); };
    button("Fullscreen").click();
    await settle();
    expect(document.querySelector("h1")?.textContent).toBe("Versioned");
  });
});

describe("suggestion-review App shell", () => {
  it("stages full state locally, enforces accepted-alone rules, and commits the identical ordered selection once", async () => {
    configureSuggestionTools();
    const app = await openSuggestionShell();

    buttonInCard("Whole body", "Accept").click();
    await settle();
    expect(buttonInCard("First span", "Accept").disabled).toBe(true);
    buttonInCard("First span", "Accept").click();
    await settle();
    expect((app.updateModelContext.mock.calls.at(-1)?.[0] as { structuredContent: { accepted_in_order: string[] } }).structuredContent.accepted_in_order).toEqual(["whole"]);

    buttonInCard("Whole body", "Skip").click();
    await settle();
    buttonInCard("Second span", "Accept").click();
    await settle();
    expect(buttonInCard("Whole body", "Accept").disabled).toBe(true);
    buttonInCard("First span", "Accept").click();
    await settle();

    for (const [context] of app.updateModelContext.mock.calls) {
      const state = (context as { structuredContent: Record<string, unknown> }).structuredContent;
      expect(state).toEqual(expect.objectContaining({
        view: "suggestion_review",
        target: expect.objectContaining({ id: "target" }),
        suggestions: expect.any(Array),
        accepted_in_order: expect.any(Array),
        skipped: expect.any(Array),
        completed: expect.any(Boolean),
      }));
    }

    button("Done").click();
    await waitUntil(() => document.querySelector("main")?.textContent?.includes("review is complete") === true, "successful review did not complete");
    const finalCalls = toolRequests(app, "resolve_suggestions")
      .filter((request) => request.arguments.reason === "Accepted from the suggestion review App");
    const preflight = finalCalls.filter((request) => request.arguments.dry_run === true);
    const commits = finalCalls.filter((request) => request.arguments.dry_run !== true);
    expect(preflight).toHaveLength(1);
    expect(commits).toHaveLength(1);
    expect(preflight[0].arguments.suggestion_ids).toEqual(["span-2", "span-1"]);
    expect(commits[0].arguments.suggestion_ids).toEqual(preflight[0].arguments.suggestion_ids);
    expect(app.sendMessage).toHaveBeenCalledOnce();
    expect(document.querySelector("main")?.textContent).toContain("review is complete");
    expect(Array.from(document.querySelectorAll("button")).some((value) => value.textContent === "Done")).toBe(false);
    const finalContext = app.updateModelContext.mock.calls.at(-1)?.[0] as { structuredContent: { completed: boolean } };
    expect(finalContext.structuredContent.completed).toBe(true);
  });

  it.each([
    ["preflight would_conflict", "would_conflict", "accepted"],
    ["preflight would_stale", "would_stale", "accepted"],
    ["commit conflict", "would_accept", "conflict"],
    ["commit stale", "would_accept", "stale"],
  ])("refreshes and remains resubmittable after %s", async (_label, previewStatus, commitStatus) => {
    const state = configureSuggestionTools();
    state.finalPreviewStatus = previewStatus;
    state.commitStatus = commitStatus;
    const app = await openSuggestionShell();
    buttonInCard("First span", "Accept").click();
    await settle();
    button("Done").click();
    await waitUntil(() => toolRequests(app, "get_record").length === 3, "failed review did not refresh survivors");

    expect(app.sendMessage).not.toHaveBeenCalled();
    expect(toolRequests(app, "get_record")).toHaveLength(3);
    expect(toolRequests(app, "get_history")).toHaveLength(1);
    expect(toolRequests(app, "get_history")[0]?.arguments).toMatchObject({ detail: "metadata" });
    expect(toolRequests(app, "query_record")).toHaveLength(0);
    expect(document.querySelector(".head")?.textContent).toContain(`revision ${state.refreshedSeq}`);
    expect(button("Done").disabled).toBe(false);
    const failedAttemptCommits = toolRequests(app, "resolve_suggestions")
      .filter((request) => request.arguments.reason === "Accepted from the suggestion review App" && request.arguments.dry_run !== true);
    expect(failedAttemptCommits).toHaveLength(previewStatus === "would_accept" ? 1 : 0);

    state.finalPreviewStatus = "would_accept";
    state.commitStatus = "accepted";
    button("Done").click();
    await waitUntil(() => document.querySelector("main")?.textContent?.includes("review is complete") === true, "resubmitted review did not complete");
    expect(app.sendMessage).toHaveBeenCalledOnce();
    expect(document.querySelector("main")?.textContent).toContain("review is complete");
  });
});
