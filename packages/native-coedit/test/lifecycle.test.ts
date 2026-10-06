import { describe, expect, it } from "vitest";
import * as Y from "yjs";

import { CoeditClient, type CoeditEvent, type CoeditTransport } from "../src/client.js";
import type { ClientMsg, ServerMsg } from "../src/protocol.js";
import { FakeHome } from "../src/testing/fakeHome.js";

/** Transport with holdable inbound/outbound queues that records both directions. */
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
    flushIn: () => {
      holdIn = false;
      for (const m of inQ.splice(0)) cb?.(m);
    },
    flushOut: () => {
      holdOut = false;
      for (const m of outQ.splice(0)) inner.send(m);
    },
  };
}

function client(home: FakeHome, mode: "edit" | "view" = "edit", t = home.connect()) {
  return { c: new CoeditClient(t, { key: "k", record_id: "r", mode }), t };
}

async function live(a: CoeditClient, home: FakeHome): Promise<void> {
  const p = new Promise<void>((res) => {
    const unsub = a.on((e) => {
      if (e.type === "status" && e.status === "live") {
        unsub();
        res();
      }
    });
  });
  a.open();
  await home.quiescent();
  await p;
}

const isUpdate = (m: ClientMsg): m is Extract<ClientMsg, { op: "session.update" }> => m.op === "session.update";

describe("A1: open is single-use", () => {
  it("ignores repeated open calls", async () => {
    const home = new FakeHome({ seed: 71, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    a.open();
    a.open();
    a.open();
    await home.quiescent();

    expect(l.sent.filter((m) => m.op === "session.open")).toHaveLength(1);
    a.text.insert(0, "x");
    await home.quiescent();
    expect(l.sent.filter(isUpdate)).toHaveLength(1);
    expect(a.pendingCount).toBe(0);
    expect(home.text).toBe("x");
  }, 15000);
});

describe("A2: pre-live edits are never raw-sent", () => {
  it("holds intent and re-authors under the leased id on opened", async () => {
    const home = new FakeHome({ seed: 72, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    l.holdIn();
    a.open();
    a.text.insert(0, "hi"); // before live
    await home.quiescent();

    expect(l.sent.filter(isUpdate)).toHaveLength(0); // nothing raw sent
    expect(a.connectionStatus).toBe("connecting");

    l.flushIn(); // deliver session.opened
    await home.quiescent();
    expect(a.connectionStatus).toBe("live");
    expect(a.text.toString()).toBe("hi");
    expect(home.text).toBe("hi"); // authored under the leased id, accepted
    expect(a.pendingCount).toBe(0);
  }, 15000);
});

describe("A4: session and status validation", () => {
  it("ignores foreign-session, duplicate-opened and post-close frames", async () => {
    const home = new FakeHome({ seed: 73, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    await live(a, home);
    a.text.insert(0, "base");
    await home.quiescent();

    const opened = l.received.find((m) => m.op === "session.opened");
    if (opened === undefined || opened.op !== "session.opened") throw new Error("no opened");

    const foreign = new Y.Doc();
    foreign.getText("body").insert(0, "XXX");
    l.deliverIn({ op: "session.remote", session: "other", update: Y.encodeStateAsUpdate(foreign), from: { person_ref: null, kind: "peer" } });
    expect(a.text.toString()).toBe("base");

    // Duplicate opened handshake is ignored.
    l.deliverIn(opened);
    expect(a.connectionStatus).toBe("live");

    a.close();
    l.deliverIn({ op: "session.remote", session: opened.session, update: Y.encodeStateAsUpdate(foreign), from: { person_ref: null, kind: "peer" } });
    expect(a.text.toString()).toBe("base");
    expect(a.connectionStatus).toBe("closed");
  }, 15000);
});

describe("A5: close preserves recovery intent and cannot reopen", () => {
  it("emits a draft of unconfirmed text and clears pending", async () => {
    const home = new FakeHome({ seed: 74, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    await live(a, home);

    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));
    l.holdIn();
    a.text.insert(0, "draft");
    await home.quiescent();
    expect(a.pendingCount).toBe(1);

    const opensBefore = l.sent.filter((m) => m.op === "session.open").length;
    a.close();
    const closed = events.find((e) => e.type === "closed") as Extract<CoeditEvent, { type: "closed" }> | undefined;
    expect(closed?.draft).toBe("draft");
    expect(a.pendingCount).toBe(0);
    expect(a.connectionStatus).toBe("closed");

    a.open(); // ignored: single-use
    expect(l.sent.filter((m) => m.op === "session.open")).toHaveLength(opensBefore);
  }, 15000);
});

describe("A3: confirmed is not public", () => {
  it("has no public confirmed surface", () => {
    const home = new FakeHome({ seed: 75 });
    const a = new CoeditClient(home.connect(), { key: "k", record_id: "r", mode: "edit" });
    // @ts-expect-error `confirmed` is private and must not be reachable.
    void a.confirmed;
    expect(a.text).toBeDefined();
  });
});

describe("E2/L3/V4: blocked recovery, closed-before-opened, stale sync", () => {
  it("blocked typing is preserved for close recovery and close still sends (E2)", async () => {
    const home = new FakeHome({ seed: 78, maxDelayMs: 0, leasePoolSize: 2 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    await live(a, home);
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

    a.text.insert(0, "post"); // blocked: must not send
    await home.quiescent();
    expect(l.sent.length).toBe(before);

    a.close();
    expect(l.sent.some((m) => m.op === "session.close")).toBe(true);
    const closed = events.find((e) => e.type === "closed") as Extract<CoeditEvent, { type: "closed" }> | undefined;
    expect(closed?.draft).toContain("post");
    expect(a.connectionStatus).toBe("closed");

    a.close(); // idempotent: no second session.close
    expect(l.sent.filter((m) => m.op === "session.close")).toHaveLength(1);
  }, 15000);

  it("a late opened after closed before handshake is ignored (L3)", async () => {
    const home = new FakeHome({ seed: 79, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    l.holdIn();
    a.open();
    a.close(); // closed while connecting; no session.close (no session yet)
    expect(a.connectionStatus).toBe("closed");
    expect(l.sent.some((m) => m.op === "session.close")).toBe(false);

    l.flushIn(); // deliver the delayed session.opened
    expect(a.connectionStatus).toBe("closed");
    expect(a.text.toString()).toBe("");
  }, 15000);

  it("a stale/unknown refusal mirrors trusted sync to visible (V4)", async () => {
    const home = new FakeHome({ seed: 80, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    await live(a, home);
    a.text.insert(0, "base");
    await home.quiescent();

    const opened = l.received.find((m) => m.op === "session.opened");
    if (opened === undefined || opened.op !== "session.opened") throw new Error("no opened");
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    const foreign = new Y.Doc();
    foreign.getText("body").insert(0, "Z");
    l.deliverIn({
      op: "session.refused",
      session: opened.session,
      code: "stale",
      refused: ["ghost:99"],
      sync: Y.encodeStateAsUpdate(foreign),
    });

    expect(a.text.toString()).toContain("Z");
    expect(events.some((e) => e.type === "rebuilt")).toBe(false);
    expect(a.connectionStatus).toBe("live");
  }, 15000);
});

/** Net plaintext of applying `act` to an initially empty text. */
function netOf(act: (t: Y.Text) => void): string {
  const d = new Y.Doc();
  const t = d.getText("body");
  act(t);
  return t.toString();
}

describe("L2: pre-live net snapshot (no self-delete resurrection)", () => {
  it("type then delete sends nothing and leaves home unchanged", async () => {
    const home = new FakeHome({ seed: 81, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    l.holdIn();
    a.open();
    a.text.insert(0, "abc");
    a.text.delete(0, 3);
    l.flushIn();
    await home.quiescent();

    expect(l.sent.filter(isUpdate)).toHaveLength(0);
    expect(a.connectionStatus).toBe("live");
    expect(a.text.toString()).toBe("");
    expect(home.text).toBe("");
    expect(a.pendingCount).toBe(0);
  }, 15000);

  it("collapses several transactions (replace + CJK/astral) to exact net text", async () => {
    const home = new FakeHome({ seed: 82, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    l.holdIn();
    a.open();
    a.text.insert(0, "abc");
    a.text.delete(0, 1);
    a.text.insert(1, `${String.fromCodePoint(0x4e2d)}${String.fromCodePoint(0x1f600)}`);
    a.visible.transact(() => {
      a.text.delete(1, 2);
      a.text.insert(1, "Z");
    });
    const expected = netOf((t) => {
      t.insert(0, "abc");
      t.delete(0, 1);
      t.insert(1, `${String.fromCodePoint(0x4e2d)}${String.fromCodePoint(0x1f600)}`);
      t.delete(1, 2);
      t.insert(1, "Z");
    });
    expect(a.text.toString()).toBe(expected);

    l.flushIn();
    await home.quiescent();
    expect(l.sent.filter(isUpdate)).toHaveLength(1);
    expect(a.text.toString()).toBe(expected);
    expect(home.text).toBe(expected);
    expect(a.pendingCount).toBe(0);
  }, 15000);

  it("empty net yields no phantom draft or delete intent", async () => {
    const home = new FakeHome({ seed: 83, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    l.holdIn();
    a.open();
    a.text.insert(0, "xyz");
    a.text.delete(0, 3);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));
    a.close();
    const closed = events.find((e) => e.type === "closed") as Extract<CoeditEvent, { type: "closed" }> | undefined;
    expect(closed?.draft).toBe("");
    expect(closed?.unreplayedDeletes).toBe(0);
  }, 15000);

  it("close before handshake recovers the pre-live net text", async () => {
    const home = new FakeHome({ seed: 84, maxDelayMs: 0 });
    const l = link(home);
    const a = new CoeditClient(l.transport, { key: "k", record_id: "r", mode: "edit" });
    l.holdIn();
    a.open();
    a.text.insert(0, "hello");
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));
    a.close();
    const closed = events.find((e) => e.type === "closed") as Extract<CoeditEvent, { type: "closed" }> | undefined;
    expect(closed?.draft).toBe("hello");
  }, 15000);
});
