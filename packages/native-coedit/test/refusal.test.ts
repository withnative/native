import * as Y from "yjs";
import { describe, expect, it } from "vitest";

import { CoeditClient, type CoeditEvent, type CoeditTransport } from "../src/client.js";
import type { ServerMsg } from "../src/protocol.js";
import { FakeHome } from "../src/testing/fakeHome.js";

/** Transport wrapper that records every server→client message. */
function tap(home: FakeHome): { seen: ServerMsg[]; transport: CoeditTransport } {
  const seen: ServerMsg[] = [];
  const inner = home.connect();
  let cb: ((m: ServerMsg) => void) | null = null;
  inner.onMessage((m) => {
    seen.push(m);
    cb?.(m);
  });
  return {
    seen,
    transport: {
      send: (m) => inner.send(m),
      onMessage: (c) => {
        cb = c;
      },
    },
  };
}

async function openClient(home: FakeHome, tapped: { seen: ServerMsg[]; transport: CoeditTransport } | null = null): Promise<CoeditClient> {
  const t = tapped !== null ? tapped.transport : home.connect();
  const client = new CoeditClient(t, { key: "k", record_id: "r", mode: "edit" });
  const live = new Promise<void>((resolve) => {
    const unsub = client.on((e) => {
      if (e.type === "status" && e.status === "live") {
        unsub();
        resolve();
      }
    });
  });
  client.open();
  await live;
  return client;
}

describe("FakeHome refusal", () => {
  it("refuses without applying: home and B never see BAD", async () => {
    const home = new FakeHome({ seed: 21, maxDelayMs: 3 });
    const tapped = tap(home);
    const a = await openClient(home, tapped);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "keep");
    await home.quiescent();
    expect(home.text).toBe("keep");
    expect(b.text.toString()).toBe("keep");

    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    await home.quiescent();

    // Never applied, never broadcast.
    expect(home.text).toBe("keep");
    expect(b.text.toString()).toBe("keep");

    // Refusal message shape: names the update_id, carries a sync diff.
    const msg = tapped.seen.find((m) => m.op === "session.refused");
    expect(msg).toMatchObject({ op: "session.refused", code: "forbidden" });
    if (msg === undefined || msg.op !== "session.refused") throw new Error("no refused");
    expect(msg.refused).toHaveLength(1);
    expect(typeof msg.refused[0]).toBe("string");
    expect(msg.sync).toBeInstanceOf(Uint8Array);

    // The sync is a diff against A's acked state ("keep"): applied to a
    // scratch doc it carries nothing new and no trace of BAD.
    const scratch = new Y.Doc();
    scratch.getText("body");
    Y.applyUpdate(scratch, msg.sync);
    expect(scratch.getText("body").toString()).toBe("");

    // B1 client surfaces the refusal; rebuild lands in B2b.
    const surfaced = events.find((e) => e.type === "refused");
    expect(surfaced).toMatchObject({ type: "refused", code: "forbidden", refused: msg.refused });
  }, 15000);
});

describe("CoeditClient refusal rebuild (B2b-i)", () => {
  it("drops refused text, replays surviving pending, and converges", async () => {
    const home = new FakeHome({ seed: 33, maxDelayMs: 3 });
    const a = await openClient(home);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "keep");
    await home.quiescent();
    expect(home.text).toBe("keep");

    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    await home.quiescent();

    // Independent pending edit, typed at the START so its origin is not BAD.
    a.text.insert(0, "more");
    await home.quiescent();

    const refused = events.find((e) => e.type === "refused");
    expect(refused).toMatchObject({ type: "refused", code: "forbidden", draft: "BAD" });
    expect(events.some((e) => e.type === "rebuilt")).toBe(true);

    expect(a.text.toString()).toBe("morekeep");
    expect(a.text.toString()).not.toContain("BAD");
    expect(home.text).toBe("morekeep");
    expect(b.text.toString()).toBe("morekeep");
    expect(a.text.toString()).toBe(b.text.toString());
    expect(a.pendingCount).toBe(0);
    expect(b.pendingCount).toBe(0);
  }, 15000);
});
