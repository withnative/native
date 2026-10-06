import { describe, expect, it } from "vitest";

import { CoeditClient } from "../src/client.js";
import { FakeHome } from "../src/testing/fakeHome.js";

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

/** Code-point boundary offsets (never splits a surrogate pair). */
function boundaries(s: string): number[] {
  const out = [0];
  let i = 0;
  while (i < s.length) {
    i += (s.codePointAt(i) as number) > 0xffff ? 2 : 1;
    out.push(i);
  }
  return out;
}

async function openClient(home: FakeHome): Promise<CoeditClient> {
  const client = new CoeditClient(home.connect(), { key: "k", record_id: "r", mode: "edit" });
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

describe("two clients over delayed delivery", () => {
  it("converge over 200 seeded rounds and drain pending", async () => {
    const home = new FakeHome({ seed: 42, maxDelayMs: 3 });
    const a = await openClient(home);
    const b = await openClient(home);

    const rng = mulberry32(1234);
    const alphabet = [
      "a",
      "b",
      "c",
      " ",
      String.fromCharCode(0x4e2d), // CJK, 3 UTF-8 bytes
      String.fromCodePoint(0x1f600), // astral, surrogate pair
      String.fromCharCode(0x0301), // combining mark
    ];
    let expectedLength = 0;
    for (let round = 0; round < 200; round++) {
      const client = rng() < 0.5 ? a : b;
      const at = boundaries(client.text.toString());
      const pos = at[Math.floor(rng() * at.length)];
      const ch = alphabet[Math.floor(rng() * alphabet.length)];
      client.text.insert(pos, ch);
      expectedLength += ch.length;
    }

    await home.quiescent();
    expect(a.text.toString()).toBe(b.text.toString());
    expect(a.text.toString()).toBe(home.text);
    expect(a.text.length).toBe(expectedLength);
    expect(a.pendingCount).toBe(0);
    expect(b.pendingCount).toBe(0);
  }, 15000);
});
