import { describe, expect, it } from "vitest";
import { loadSuggestionData, refreshTarget, type Bridge, type ToolResult } from "./suggestion-data";

function bridgeWith(handler: (name: string, args: Record<string, unknown>) => ToolResult): Bridge & { calls: Array<{ name: string; arguments: Record<string, unknown> }> } {
  const calls: Array<{ name: string; arguments: Record<string, unknown> }> = [];
  return {
    calls,
    async callServerTool(request) { calls.push(request); return handler(request.name, request.arguments); },
  };
}

describe("suggestion App bridge data", () => {
  it("requests JSON mode and loads rows, facets, and dry-run previews", async () => {
    const bridge = bridgeWith((name) => {
      if (name === "get_record") return { structuredContent: { records: [{ suggestions: [{ id: "s1", name: "Edit", body: "replacement" }] }] } };
      if (name === "resolve_facets") return { structuredContent: { values: [{ key: "proposal.precondition", value: "span" }, { key: "anchor.old", value: "before" }] } };
      if (name === "resolve_suggestions") return { structuredContent: { status: "would_accept", prospective_body: "after" } };
      throw new Error(name);
    });
    const suggestions = await loadSuggestionData(bridge, "target");
    expect(suggestions).toMatchObject([{ id: "s1", precondition: "span", preview_status: "would_accept", preview_body: "after" }]);
    expect(bridge.calls.map((call) => call.name)).toEqual(["get_record", "resolve_facets", "resolve_suggestions"]);
    expect(bridge.calls.every((call) => call.arguments.format === "json")).toBe(true);
  });

  it("refreshes a target and revision through JSON get_record/history calls", async () => {
    const bridge = bridgeWith((name) => name === "get_record"
      ? { structuredContent: { records: [{ status: "found", id: "target", name: "Target", type: "Document", body: "after" }] } }
      : { structuredContent: { events: [{ seq: 2 }, { seq: 7 }], next_after_seq: null } });
    const target = await refreshTarget(bridge, "target");
    expect(target.current_seq).toBe(7);
    expect(target.body_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(bridge.calls.map((call) => call.name)).toEqual(["get_record", "get_history"]);
    expect(bridge.calls.every((call) => call.arguments.format === "json")).toBe(true);
    expect(bridge.calls.find((call) => call.name === "get_history")?.arguments).toMatchObject({ detail: "metadata" });
  });

  it("rejects tool errors instead of treating them as empty results", async () => {
    const bridge = bridgeWith(() => ({ isError: true, content: [{ type: "text", text: "denied" }] }));
    await expect(loadSuggestionData(bridge, "target")).rejects.toThrow("get_record: denied");
  });

  it("rejects a nominal success without a structured object", async () => {
    const bridge = bridgeWith(() => ({ content: [{ type: "text", text: "not JSON" }] }));
    await expect(loadSuggestionData(bridge, "target")).rejects.toThrow("successful result omitted structuredContent");
  });
});
