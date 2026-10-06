import { describe, expect, it } from "vitest";
import * as Y from "yjs";

import { CoeditClient, type CoeditEvent, type CoeditTransport } from "../src/client.js";
import type { ClientMsg, ServerMsg } from "../src/protocol.js";
import { FakeHome, type FakeHomeOptions } from "../src/testing/fakeHome.js";

/** Transport with independently holdable inbound and outbound queues. */
function link(home: FakeHome) {
  const inner = home.connect();
  const inQ: ServerMsg[] = [];
  const outQ: ClientMsg[] = [];
  const sent: ClientMsg[] = [];
  const received: ServerMsg[] = [];
  let cb: ((m: ServerMsg) => void) | null = null;
  let holdIn = false;
  let holdOut = false;
  inner.onMessage((m) => {
    received.push(m);
    if (holdIn) inQ.push(m);
    else cb?.(m);
  });
  return {
    transport: {
      send: (m: ClientMsg) => {
        sent.push(m);
        if (holdOut) outQ.push(m);
        else inner.send(m);
      },
      onMessage: (c: (m: ServerMsg) => void) => {
        cb = c;
      },
    } satisfies CoeditTransport,
    sent,
    received,
    holdIn: () => {
      holdIn = true;
    },
    holdOut: () => {
      holdOut = true;
    },
    deliverIn: (m: ServerMsg) => cb?.(m),
    releaseIn: (pred: (m: ServerMsg) => boolean) => {
      const out: ServerMsg[] = [];
      for (let i = inQ.length - 1; i >= 0; i--) if (pred(inQ[i])) out.unshift(inQ.splice(i, 1)[0]);
      for (const m of out) cb?.(m);
      return out;
    },
    releaseOut: (pred: (m: ClientMsg) => boolean) => {
      for (let i = outQ.length - 1; i >= 0; i--) if (pred(outQ[i])) inner.send(outQ.splice(i, 1)[0]);
    },
    releaseLastOut: () => {
      const m = outQ.pop();
      if (m !== undefined) inner.send(m);
    },
    flushOut: () => {
      holdOut = false;
      for (const m of outQ.splice(0)) inner.send(m);
    },
    flushIn: () => {
      holdIn = false;
      for (const m of inQ.splice(0)) cb?.(m);
    },
  };
}

async function openVia(transport: CoeditTransport): Promise<CoeditClient> {
  const client = new CoeditClient(transport, { key: "k", record_id: "r", mode: "edit" });
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

async function openClient(home: FakeHome): Promise<CoeditClient> {
  return openVia(home.connect());
}

function refusedEvent(events: CoeditEvent[]): Extract<CoeditEvent, { type: "refused" }> | undefined {
  return events.find((e) => e.type === "refused") as Extract<CoeditEvent, { type: "refused" }> | undefined;
}

const isUpdate = (m: ClientMsg): m is Extract<ClientMsg, { op: "session.update" }> => m.op === "session.update";

describe("F0: uncovered mid-span delete (outbound withheld)", () => {
  it("replays exactly the deleted items, not a widened span", async () => {
    const home = new FakeHome({ seed: 61, maxDelayMs: 0 });
    const l = link(home);
    const a = await openVia(l.transport);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(0, "abcde");
    await home.quiescent();

    l.holdOut();
    a.text.delete(1, 1); // delete "b" (:2); never sent to home
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD"); // :3
    await home.quiescent();

    // Release only the BAD update; the delete stays uncovered at home.
    l.releaseOut((m) => isUpdate(m) && m.update_id.endsWith(":3"));
    await home.quiescent();

    expect(refusedEvent(events)?.draft).toBe("BAD");
    expect(a.text.toString()).toBe("acde");
    expect(a.text.toString()).not.toContain("BAD");

    l.flushOut();
    await home.quiescent();
    expect(a.text.toString()).toBe("acde");
    expect(home.text).toBe("acde");
    expect(b.text.toString()).toBe("acde");
  }, 15000);
});

describe("F1: concurrent insert inside the deleted span survives", () => {
  it("deletes by item identity, not span endpoints", async () => {
    const home = new FakeHome({ seed: 62, maxDelayMs: 0 });
    const l = link(home);
    const a = await openVia(l.transport);
    const b = await openClient(home);

    a.text.insert(0, "abcdef");
    await home.quiescent();

    l.holdOut();
    a.text.delete(2, 3); // delete "cde"; withheld
    b.text.insert(3, "X"); // lands inside the to-be-deleted span
    await home.quiescent();
    expect(a.text.toString()).toBe("abXf");

    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    await home.quiescent();
    l.releaseOut((m) => isUpdate(m) && m.update_id.endsWith(":3"));
    await home.quiescent();

    expect(a.text.toString()).toBe("abXf");
    expect(a.text.toString()).toContain("X");

    l.flushOut();
    await home.quiescent();
    expect(a.text.toString()).toBe("abXf");
    expect(home.text).toBe("abXf");
    expect(b.text.toString()).toBe("abXf");
  }, 15000);
});

describe("F2: duplicate/stale refusal is idempotent", () => {
  it("rebuilds once and does not duplicate the replayed survivor", async () => {
    const home = new FakeHome({ seed: 63, maxDelayMs: 0, leasePoolSize: 3 });
    const l = link(home);
    const a = await openVia(l.transport);
    const b = await openClient(home);
    const opened = l.received.find((m) => m.op === "session.opened");
    if (opened?.op !== "session.opened") throw new Error("missing opened");
    const [initial, spare, confirmed] = opened.doc_client_ids;
    expect(opened.doc_client_ids).toHaveLength(3);
    expect(a.visible.clientID).toBe(initial);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(0, "keep");
    await home.quiescent();

    // A stale refusal naming an acknowledged update must leave the spare
    // available for the first genuine refusal.
    const acknowledged = l.sent.filter(isUpdate)[0];
    l.deliverIn({
      op: "session.refused",
      session: opened.session,
      code: "forbidden",
      refused: [acknowledged.update_id],
      sync: Y.encodeStateAsUpdate(a.visible),
    });
    expect(a.visible.clientID).toBe(initial);
    expect(events.filter((e) => e.type === "rebuilt")).toHaveLength(0);

    l.holdIn();
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD"); // :2
    a.text.insert(0, "more"); // :3, independent survivor
    await home.quiescent();

    const [refusal] = l.releaseIn((m) => m.op === "session.refused");
    expect(refusal?.op).toBe("session.refused");
    l.deliverIn(refusal as ServerMsg); // duplicate of the same refusal

    expect(events.filter((e) => e.type === "rebuilt")).toHaveLength(1);
    expect(a.visible.clientID).toBe(spare);
    expect(a.visible.clientID).not.toBe(confirmed);
    expect(a.connectionStatus).toBe("live");
    expect(refusedEvent(events)?.draft).toBe("BAD");
    expect(a.pendingCount).toBe(1);
    expect(a.text.toString()).toBe("morekeep");

    l.flushIn();
    await home.quiescent();
    expect(a.text.toString()).toBe("morekeep");
    expect(a.pendingCount).toBe(0);
    l.deliverIn(refusal as ServerMsg); // now stale as well as duplicate
    expect(a.visible.clientID).toBe(spare);
    expect(events.filter((e) => e.type === "rebuilt")).toHaveLength(1);
    a.text.insert(a.text.length, "!");
    await home.quiescent();
    expect(a.text.toString()).toBe("morekeep!");
    expect(home.text).toBe("morekeep!");
    expect(b.text.toString()).toBe("morekeep!");
    expect(events.some((e) => e.type === "exhausted")).toBe(false);
  }, 15000);
});

describe("F3: unreplayed deletion intent is surfaced", () => {
  it("counts a dependent delete instead of dropping it silently", async () => {
    const home = new FakeHome({ seed: 64, maxDelayMs: 0 });
    const a = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(0, "abcde");
    await home.quiescent();

    home.refuseNext("forbidden");
    const start = a.text.length;
    a.text.insert(start, "X"); // refused update
    a.text.delete(start, 1); // delete of the refused item: dependent
    await home.quiescent();

    const refused = refusedEvent(events);
    expect(refused?.draft).toBe("X");
    expect(refused?.unreplayedDeletes).toBeGreaterThanOrEqual(1);
    expect(a.text.toString()).toBe("abcde");
    expect(home.text).toBe("abcde");
  }, 15000);
});

describe("L1: post-exhaustion edits never send", () => {
  it("blocks authoring and preserves recovery text", async () => {
    const home = new FakeHome({ seed: 65, maxDelayMs: 0, leasePoolSize: 2 });
    const l = link(home);
    const a = await openVia(l.transport);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(0, "keep");
    await home.quiescent();

    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    a.text.insert(0, "more");
    await home.quiescent();

    expect(events.some((e) => e.type === "exhausted")).toBe(true);
    expect(a.connectionStatus).toBe("blocked");
    const before = l.sent.length;

    a.text.insert(0, "post");
    await home.quiescent();
    expect(l.sent.length).toBe(before); // no update sent under an unleased id
    expect(a.pendingCount).toBe(0);
    expect(home.text).toBe("keep");
  }, 15000);
});

/** Run an uncovered op through a refusal, then flush it and return the world. */
async function uncoveredReplay(seedText: string, act: (a: CoeditClient) => void, homeOpts: Partial<FakeHomeOptions> = {}) {
  const home = new FakeHome({ seed: 66, maxDelayMs: 0, ...homeOpts });
  const l = link(home);
  const a = await openVia(l.transport);
  const b = await openClient(home);
  const events: CoeditEvent[] = [];
  a.on((e) => events.push(e));
  a.text.insert(0, seedText);
  await home.quiescent();
  l.holdOut();
  act(a);
  home.refuseNext("forbidden");
  a.text.insert(a.text.length, "BAD");
  await home.quiescent();
  l.releaseLastOut(); // only BAD reaches home; the act stays uncovered
  await home.quiescent();
  l.flushOut();
  await home.quiescent();
  return { home, a, b, events };
}

/** Reference result of applying the same text ops to a plain yjs doc. */
function reference(seedText: string, act: (t: Y.Text) => void): string {
  const d = new Y.Doc();
  const t = d.getText("body");
  t.insert(0, seedText);
  d.transact(() => act(t));
  return t.toString();
}

describe("delete replay edge cases", () => {
  it("delete at document end", async () => {
    const { home, a, b } = await uncoveredReplay("abcde", (c) => c.text.delete(4, 1));
    expect(a.text.toString()).toBe("abcd");
    expect(home.text).toBe("abcd");
    expect(b.text.toString()).toBe("abcd");
  }, 15000);

  it("delete the whole document", async () => {
    const { home, a, b } = await uncoveredReplay("abcd", (c) => c.text.delete(0, 4));
    expect(a.text.toString()).toBe("");
    expect(home.text).toBe("");
    expect(b.text.toString()).toBe("");
  }, 15000);

  it("delete plus insert at the same index (replace)", async () => {
    const { home, a, b, events } = await uncoveredReplay("abcde", (c) => {
      c.visible.transact(() => {
        c.text.delete(2, 2);
        c.text.insert(2, "XY");
      });
    });
    const expected = reference("abcde", (t) => {
      t.delete(2, 2);
      t.insert(2, "XY");
    });
    expect(a.text.toString()).toBe(expected);
    expect(home.text).toBe(expected);
    expect(b.text.toString()).toBe(expected);
    expect(refusedEvent(events)?.draft).toBe("BAD");
  }, 15000);

  it("multiple deletes in one transaction", async () => {
    const { home, a, b } = await uncoveredReplay("abcdef", (c) => {
      c.visible.transact(() => {
        c.text.delete(1, 1);
        c.text.delete(2, 1);
      });
    });
    const expected = reference("abcdef", (t) => {
      t.delete(1, 1);
      t.delete(2, 1);
    });
    expect(a.text.toString()).toBe(expected);
    expect(home.text).toBe(expected);
    expect(b.text.toString()).toBe(expected);
  }, 15000);

  it("delete an astral and a CJK character", async () => {
    const seed = `a${String.fromCodePoint(0x1f600)}${String.fromCodePoint(0x4e2d)}b`;
    const { home, a, b } = await uncoveredReplay(seed, (c) => {
      c.text.delete(1, 2); // the emoji (surrogate pair)
      c.text.delete(1, 1); // the CJK char
    });
    expect(a.text.toString()).toBe("ab");
    expect(home.text).toBe("ab");
    expect(b.text.toString()).toBe("ab");
  }, 15000);
});

describe("E1: exhaustion ordering", () => {
  it("exhausted visible equals confirmed; resend text surfaces as draft (E1a)", async () => {
    const home = new FakeHome({ seed: 76, maxDelayMs: 0, leasePoolSize: 2 });
    const l = link(home);
    const a = await openVia(l.transport);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(0, "abc");
    await home.quiescent();

    l.holdOut();
    a.text.insert(a.text.length, "d"); // :2, integratable (clock == frontier)
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD"); // :3
    await home.quiescent();
    l.releaseLastOut(); // only BAD reaches home
    await home.quiescent();

    expect(events.some((e) => e.type === "exhausted")).toBe(true);
    expect(a.text.toString()).toBe("abc"); // resend not re-applied on exhaustion
    expect(a.connectionStatus).toBe("blocked");
    expect(refusedEvent(events)?.draft).toContain("d");
  }, 15000);

  it("counts clock-gap survivor delete intent on exhaustion (E1b)", async () => {
    const home = new FakeHome({ seed: 77, maxDelayMs: 0, leasePoolSize: 2 });
    const a = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(0, "abc");
    await home.quiescent();

    home.refuseNext("forbidden");
    const at = a.text.length;
    a.text.insert(at, "X"); // :2, refused
    a.text.delete(at, 1); // :3, deletes the refused item: clock-gap survivor
    await home.quiescent();

    expect(events.some((e) => e.type === "exhausted")).toBe(true);
    expect(refusedEvent(events)?.draft).toContain("X");
    expect(refusedEvent(events)?.unreplayedDeletes).toBe(1);
    expect(a.text.toString()).toBe("abc");
    expect(a.pendingCount).toBe(0);
  }, 15000);
});

describe("bounded three-ID pool", () => {
  it("blocks on the second real refusal and recovers all insert/delete intent plus close", async () => {
    const home = new FakeHome({ seed: 78, maxDelayMs: 0, leasePoolSize: 3 });
    const l = link(home);
    const a = await openVia(l.transport);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));
    const opened = l.received.find((m) => m.op === "session.opened");
    if (opened?.op !== "session.opened") throw new Error("missing opened");
    const [initial, spare, confirmed] = opened.doc_client_ids;
    expect(opened.doc_client_ids).toHaveLength(3);
    expect(a.visible.clientID).toBe(initial);

    a.text.insert(0, "abc");
    await home.quiescent();
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "FIRST");
    await home.quiescent();
    expect(a.visible.clientID).toBe(spare);
    expect(a.connectionStatus).toBe("live");
    expect(refusedEvent(events)?.draft).toBe("FIRST");
    expect(a.text.toString()).toBe("abc");

    l.holdOut();
    a.text.insert(a.text.length, "d"); // integratable unsent survivor
    a.text.delete(1, 1); // integratable unsent delete of confirmed b
    a.text.insert(a.text.length, "BAD");
    const bad = l.sent.filter(isUpdate).at(-1)!;
    a.text.delete(a.text.length - 3, 3); // clock-gap delete of refused BAD
    a.text.insert(0, "more"); // independent clock-gap insert survivor
    home.refuseNext("forbidden");
    l.releaseOut((m) => isUpdate(m) && m.update_id === bad.update_id);
    await home.quiescent();

    const refusals = events.filter((e) => e.type === "refused");
    expect(refusals).toHaveLength(2);
    const second = refusals[1];
    if (second.type !== "refused") throw new Error("missing refusal");
    expect(second.draft).toContain("BAD");
    expect(second.draft).toContain("d");
    expect(second.draft).toContain("more");
    expect(second.unreplayedDeletes).toBe(4);
    const exhausted = events.find((e) => e.type === "exhausted");
    expect(exhausted?.type === "exhausted" ? exhausted.draft : undefined).toBe(second.draft);
    expect(a.connectionStatus).toBe("blocked");
    expect(a.pendingCount).toBe(0);
    expect(a.visible.clientID).toBe(confirmed);
    // No pending structs were reapplied: visible equals acknowledged home.
    expect(a.text.toString()).toBe("abc");
    expect(home.text).toBe("abc");
    expect(b.text.toString()).toBe("abc");
    const updatesBefore = l.sent.filter(isUpdate).length;
    a.text.insert(0, "post");
    a.text.delete(4, 1); // blocked delete intent of confirmed a
    await home.quiescent();
    expect(l.sent.filter(isUpdate)).toHaveLength(updatesBefore);
    a.close();
    const closed = events.find((e) => e.type === "closed");
    expect(closed?.type === "closed" ? closed.draft : undefined).toBe("post");
    expect(closed?.type === "closed" ? closed.unreplayedDeletes : undefined).toBe(1);
    expect(l.sent.at(-1)?.op).toBe("session.close");
    l.releaseOut((m) => m.op === "session.close");
    await home.quiescent();
    a.close();
    expect(events.filter((e) => e.type === "closed")).toHaveLength(1);
    expect(a.connectionStatus).toBe("closed");
    expect(home.text).toBe("abc");
    expect(b.text.toString()).toBe("abc");
  }, 15000);
});
