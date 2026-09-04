export type ToolResult = {
  isError?: boolean;
  content?: Array<{ type: string; text?: string }>;
  structuredContent?: unknown;
};

export type Bridge = {
  callServerTool(request: { name: string; arguments: Record<string, unknown> }): Promise<ToolResult>;
};

export type ReviewTarget = {
  id: string;
  name: string;
  type: string;
  body: string | null;
  last_activity_at?: string | null;
  current_seq: number;
  body_digest: string | null;
  body_is_null: boolean;
};

export type Suggestion = {
  id: string;
  name: string;
  body?: string | null;
  summary?: string | null;
  created_at?: string;
  lifecycle?: string;
  preview_body?: string;
  preview_status?: string;
  precondition?: string;
};

function resultMessage(result: ToolResult): string {
  return result.content?.find((block) => block.type === "text")?.text ?? "tool call failed";
}

export async function jsonCall(
  bridge: Bridge,
  name: string,
  arguments_: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const result = await bridge.callServerTool({
    name,
    arguments: { ...arguments_, format: "json" },
  });
  if (result.isError) throw new Error(`${name}: ${resultMessage(result)}`);
  if (!result.structuredContent || typeof result.structuredContent !== "object" || Array.isArray(result.structuredContent)) {
    throw new Error(`${name}: successful result omitted structuredContent`);
  }
  return result.structuredContent as Record<string, unknown>;
}

function facetMap(payload: Record<string, unknown>): Map<string, unknown> {
  const values = payload.values;
  if (Array.isArray(values)) {
    return new Map(values.flatMap((row) => {
      if (!row || typeof row !== "object") return [];
      const value = row as Record<string, unknown>;
      return typeof value.key === "string" ? [[value.key, value.value] as [string, unknown]] : [];
    }));
  }
  return new Map(Object.entries((values && typeof values === "object" ? values : {}) as Record<string, unknown>));
}

export async function loadSuggestionData(bridge: Bridge, targetId: string): Promise<Suggestion[]> {
  const summaries: unknown[] = [];
  for (let offset = 0; ; offset += 100) {
    const page = await jsonCall(bridge, "get_record", {
      ids: [targetId],
      children_limit: 0,
      links_limit: 0,
      include_suggestions: true,
      suggestions_limit: 100,
      suggestions_offset: offset,
    });
    const record = Array.isArray(page.records) ? page.records[0] : undefined;
    if (!record || typeof record !== "object") throw new Error("get_record: target result is missing");
    const values = (record as Record<string, unknown>).suggestions;
    if (!Array.isArray(values)) throw new Error("get_record: suggestions must be an array");
    summaries.push(...values);
    if (values.length < 100) break;
  }
  const suggestions = summaries.map((value) => {
    if (!value || typeof value !== "object" || typeof (value as Record<string, unknown>).id !== "string") {
      throw new Error("get_record: malformed suggestion row");
    }
    return { ...(value as Suggestion) };
  });
  for (const suggestion of suggestions) {
    const facets = facetMap(await jsonCall(bridge, "resolve_facets", { record_id: suggestion.id }));
    const declared = String(facets.get("proposal.precondition") ?? "");
    suggestion.precondition = declared === "none" && !facets.get("anchor.old") ? "none_whole" : declared;
    const preview = await jsonCall(bridge, "resolve_suggestions", {
      action: "accept",
      suggestion_ids: [suggestion.id],
      reason: "Preview in the suggestion review App",
      dry_run: true,
    });
    suggestion.preview_status = typeof preview.status === "string" ? preview.status : undefined;
    suggestion.preview_body = typeof preview.prospective_body === "string" ? preview.prospective_body : undefined;
  }
  return suggestions;
}

async function bodyDigest(body: string | null): Promise<string | null> {
  if (body === null) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function refreshTarget(bridge: Bridge, targetId: string): Promise<ReviewTarget> {
  const get = await jsonCall(bridge, "get_record", { ids: [targetId] });
  if (!Array.isArray(get.records) || !get.records[0] || typeof get.records[0] !== "object") {
    throw new Error("get_record: target result is missing");
  }
  const record = get.records[0] as Record<string, unknown>;
  if (record.status !== "found" || typeof record.id !== "string" || typeof record.name !== "string" || typeof record.type !== "string") {
    throw new Error("get_record: target is not a live found record");
  }
  let cursor: number | undefined;
  let currentSeq = 0;
  do {
    const history = await jsonCall(bridge, "get_history", {
      record_id: targetId,
      limit: 500,
      detail: "metadata",
      ...(cursor === undefined ? {} : { after_seq: cursor }),
    });
    if (!Array.isArray(history.events)) throw new Error("get_history: events must be an array");
    for (const event of history.events) {
      if (!event || typeof event !== "object" || typeof (event as Record<string, unknown>).seq !== "number") {
        throw new Error("get_history: malformed event row");
      }
      currentSeq = Math.max(currentSeq, (event as Record<string, unknown>).seq as number);
    }
    cursor = typeof history.next_after_seq === "number" ? history.next_after_seq : undefined;
  } while (cursor !== undefined);
  if (currentSeq < 1) throw new Error("get_history: target has no revision");
  const body = typeof record.body === "string" ? record.body : null;
  return {
    id: record.id,
    name: record.name,
    type: record.type,
    body,
    last_activity_at: typeof record.last_activity_at === "string" ? record.last_activity_at : null,
    current_seq: currentSeq,
    body_digest: await bodyDigest(body),
    body_is_null: body === null,
  };
}
