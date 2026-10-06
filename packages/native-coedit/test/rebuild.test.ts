import { describe, expect, it } from "vitest";

import { CoeditClient, type CoeditEvent, type CoeditTransport } from "../src/client.js";
import type { ServerMsg } from "../src/protocol.js";
import { FakeHome } from "../src/testing/fakeHome.js";

async function openVia(transport: CoeditTransport, key = "k"): Promise<CoeditClient> {
  const client = new CoeditClient(transport, { key, record_id: "r", mode: "edit" });
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

function openClient(home: FakeHome): Promise<CoeditClient> {
  return openVia(home.connect());
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Code-point boundaries, so an edit never splits a surrogate pair. */
function boundaries(s: string): number[] {
  const out = [0];
  let i = 0;
  while (i < s.length) {
    i += (s.codePointAt(i) as number) > 0xffff ? 2 : 1;
    out.push(i);
  }
  return out;
}

/** A transport whose server→client messages can be held and released selectively. */
function gated(home: FakeHome): {
  transport: CoeditTransport;
  hold: () => void;
  queue: ServerMsg[];
  flush: () => void;
  deliver: (pred: (m: ServerMsg) => boolean) => ServerMsg[];
} {
  const inner = home.connect();
  const queue: ServerMsg[] = [];
  let cb: ((m: ServerMsg) => void) | null = null;
  let holding = false;
  inner.onMessage((m) => {
    if (holding) queue.push(m);
    else cb?.(m);
  });
  return {
    transport: {
      send: (m) => inner.send(m),
      onMessage: (c) => {
        cb = c;
      },
    },
    hold: () => {
      holding = true;
    },
    queue,
    flush: () => {
      holding = false;
      const all = queue.splice(0);
      for (const m of all) cb?.(m);
    },
    deliver: (pred) => {
      const take: ServerMsg[] = [];
      for (let i = queue.length - 1; i >= 0; i--) {
        if (pred(queue[i])) take.unshift(...queue.splice(i, 1));
      }
      for (const m of take) cb?.(m);
      return take;
    },
  };
}

function refusedEvent(events: CoeditEvent[]): Extract<CoeditEvent, { type: "refused" }> | undefined {
  return events.find((e) => e.type === "refused") as Extract<CoeditEvent, { type: "refused" }> | undefined;
}

describe("B2b-ii: dependent pending and draft fidelity", () => {
  it("a pending insert anchored in refused structs becomes recovery draft", async () => {
    const home = new FakeHome({ seed: 51, maxDelayMs: 0 });
    const a = await openClient(home);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "keep");
    await home.quiescent();

    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    a.text.insert(a.text.length, "!"); // anchored on BAD's last item
    await home.quiescent();

    const refused = refusedEvent(events);
    expect(refused?.draft).toBe("BAD!");
    expect(a.text.toString()).toBe("keep");
    expect(a.text.toString()).not.toContain("BAD");
    expect(a.text.toString()).not.toContain("!");
    expect(home.text).toBe("keep");
    expect(b.text.toString()).toBe("keep");
    expect(a.pendingCount).toBe(0);
  }, 15000);

  it("preserves astral and CJK characters in the recovery draft exactly", async () => {
    const home = new FakeHome({ seed: 52, maxDelayMs: 0 });
    const a = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "keep");
    await home.quiescent();

    const cjk = String.fromCodePoint(0x4e2d, 0x6587, 0x1f600, 0x0301, 0x61);
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, cjk);
    await home.quiescent();

    expect(refusedEvent(events)?.draft).toBe(cjk);
    expect(a.text.toString()).toBe("keep");
  }, 15000);
});

describe("B2b-ii: coverage and ordering regressions", () => {
  it("a pending delete survives a refusal (delete-only update is not dropped)", async () => {
    const home = new FakeHome({ seed: 53, maxDelayMs: 0 });
    const gate = gated(home);
    const a = await openVia(gate.transport);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "hello world");
    await home.quiescent();
    expect(home.text).toBe("hello world");

    gate.hold();
    a.text.delete(6, 5); // delete "world": a delete-only yjs update
    await home.quiescent(); // home applies it; its ack is held (still pending)
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    await home.quiescent();

    // Release only the refusal, leaving the delete's ack still delayed.
    gate.deliver((m) => m.op === "session.refused");
    // The delete is still pending and uncovered, so it was replayed.
    expect(a.text.toString()).toBe("hello ");
    expect(home.text).toBe("hello "); // home had applied the delete
    expect(b.text.toString()).toBe("hello ");
    expect(refusedEvent(events)?.draft).toBe("BAD");

    gate.flush();
    await home.quiescent();
    expect(a.text.toString()).toBe("hello ");
    expect(a.pendingCount).toBe(0);
  }, 15000);

  it("a delayed old ack cannot delete a re-authored pending entry", async () => {
    const home = new FakeHome({ seed: 54, maxDelayMs: 0 });
    const gate = gated(home);
    const a = await openVia(gate.transport);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "keep");
    await home.quiescent();

    gate.hold();
    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    a.text.insert(0, "more"); // independent pending edit, sent after BAD
    await home.quiescent();

    // Deliver only the refusal first: "more" is re-authored under a new id.
    gate.deliver((m) => m.op === "session.refused");
    gate.deliver((m) => m.op === "session.ack"); // the stale ack, naming the retired id
    expect(a.pendingCount).toBe(1); // the re-authored entry survives the old ack
    expect(refusedEvent(events)?.draft).toBe("BAD");

    gate.flush();
    await home.quiescent();
    expect(a.text.toString()).toBe("morekeep");
    expect(a.pendingCount).toBe(0);
  }, 15000);
});

describe("B2b-ii: lease exhaustion fails closed", () => {
  it("preserves all unconfirmed text as draft and never reuses an id", async () => {
    // Pool of 2: one author id plus the reserved confirmed id.
    const home = new FakeHome({ seed: 55, maxDelayMs: 0, leasePoolSize: 2 });
    const a = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    a.text.insert(a.text.length, "keep");
    await home.quiescent();

    home.refuseNext("forbidden");
    a.text.insert(a.text.length, "BAD");
    a.text.insert(0, "more");
    await home.quiescent();

    const exhausted = events.find((e) => e.type === "exhausted") as Extract<CoeditEvent, { type: "exhausted" }> | undefined;
    expect(exhausted).toBeDefined();
    expect(exhausted?.draft).toContain("BAD");
    expect(exhausted?.draft).toContain("more");
    expect(a.text.toString()).toBe("keep"); // nothing replayed under a reused id
    expect(a.pendingCount).toBe(0);
    expect(home.text).toBe("keep");
  }, 15000);
});

describe("B2b-ii: concurrent run with a mid-run refusal", () => {
  it("converges over 50 rounds and never resurrects refused text", async () => {
    const home = new FakeHome({ seed: 77, maxDelayMs: 2 });
    const a = await openClient(home);
    const b = await openClient(home);
    const events: CoeditEvent[] = [];
    a.on((e) => events.push(e));

    const rng = mulberry32(20260930);
    const alphabet = [
      "x",
      "y",
      " ",
      String.fromCodePoint(0x4e2d),
      String.fromCodePoint(0x1f600),
      String.fromCodePoint(0x0301),
    ];
    const marker = "ZZREFUSEZZ";

    for (let round = 0; round < 50; round++) {
      const client = rng() < 0.5 ? a : b;
      if (round === 25) {
        // Settle, then carry out the refusal on a peek of A only.
        await home.quiescent();
        home.refuseNext("forbidden");
        a.text.insert(a.text.length, marker);
        await home.quiescent();
        continue;
      }
      const at = boundaries(client.text.toString());
      const pos = at[Math.floor(rng() * at.length)];
      const ch = alphabet[Math.floor(rng() * alphabet.length)];
      client.text.insert(pos, ch);
    }
    await home.quiescent();

    expect(a.text.toString()).toBe(b.text.toString());
    expect(a.text.toString()).toBe(home.text);
    expect(a.text.toString()).not.toContain(marker);
    expect(b.text.toString()).not.toContain(marker);
    expect(home.text).not.toContain(marker);
    expect(refusedEvent(events)?.draft).toBe(marker);
    expect(a.pendingCount).toBe(0);
    expect(b.pendingCount).toBe(0);
  }, 20000);
});
