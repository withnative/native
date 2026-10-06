import * as Y from "yjs";
import { describe, expect, it } from "vitest";

import { CoeditClient, type CoeditEvent } from "../src/client.js";
import type { ServerMsg } from "../src/protocol.js";
import { FakeHome } from "../src/testing/fakeHome.js";

interface RawSession {
  send: (msg: Parameters<ReturnType<FakeHome["connect"]>["send"]>[0]) => void;
  seen: ServerMsg[];
  session: string;
  leased: number[];
}

async function openRaw(home: FakeHome, mode: "edit" | "view" = "edit"): Promise<RawSession> {
  const seen: ServerMsg[] = [];
  const t = home.connect();
  t.onMessage((m) => seen.push(m));
  t.send({ op: "session.open", key: "k", record_id: "r", mode });
  await home.quiescent();
  const opened = seen.find((m) => m.op === "session.opened");
  if (opened === undefined || opened.op !== "session.opened") throw new Error("no opened");
  return { send: (msg) => t.send(msg), seen, session: opened.session, leased: opened.doc_client_ids };
}

function refused(seen: ServerMsg[]): ServerMsg & { op: "session.refused" } {
  const m = seen.find((x) => x.op === "session.refused");
  if (m === undefined || m.op !== "session.refused") throw new Error("no refused");
  return m;
}

describe("FakeHome validation", () => {
  it("refuses a foreign client id without applying it", async () => {
    const home = new FakeHome({ seed: 7 });
    const raw = await openRaw(home);
    const evil = new Y.Doc(); // random unleased clientID
    evil.getText("body").insert(0, "evil");
    raw.send({ op: "session.update", session: raw.session, update: Y.encodeStateAsUpdate(evil), update_id: "u1" });
    await home.quiescent();
    expect(refused(raw.seen).code).toBe("foreign_client_id");
    expect(home.text).toBe("");
  });

  it("refuses a bad doc shape (extra root) even with a leased id", async () => {
    const home = new FakeHome({ seed: 8 });
    const raw = await openRaw(home);
    const evil = new Y.Doc();
    evil.clientID = raw.leased[0];
    evil.getText("body").insert(0, "hi");
    evil.getMap("other").set("x", 1);
    raw.send({ op: "session.update", session: raw.session, update: Y.encodeStateAsUpdate(evil), update_id: "u1" });
    await home.quiescent();
    expect(refused(raw.seen).code).toBe("bad_doc_shape");
    expect(home.text).toBe("");
  });

  it("refuses oversized updates", async () => {
    const home = new FakeHome({ seed: 9, maxUpdateBytes: 8 });
    const raw = await openRaw(home);
    const big = new Y.Doc();
    big.clientID = raw.leased[0];
    big.getText("body").insert(0, "x".repeat(32));
    raw.send({ op: "session.update", session: raw.session, update: Y.encodeStateAsUpdate(big), update_id: "u1" });
    await home.quiescent();
    expect(refused(raw.seen).code).toBe("too_large");
    expect(home.text).toBe("");
  });

  it("refuses updates from view-mode peers as forbidden", async () => {
    const home = new FakeHome({ seed: 10 });
    const events: CoeditEvent[] = [];
    const viewer = new CoeditClient(home.connect(), { key: "k", record_id: "r", mode: "view" });
    viewer.on((e) => events.push(e));
    const live = new Promise<void>((resolve) => {
      const unsub = viewer.on((e) => {
        if (e.type === "status" && e.status === "live") {
          unsub();
          resolve();
        }
      });
    });
    viewer.open();
    await live;
    viewer.text.insert(0, "nope");
    await home.quiescent();
    const r = events.find((e) => e.type === "refused");
    expect(r).toMatchObject({ type: "refused", code: "forbidden" });
    expect(home.text).toBe("");
  });
});
