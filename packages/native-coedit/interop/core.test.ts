import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as Y from "yjs";

import { CoeditClient, type CoeditEvent } from "../src/client.js";
import type { ClientMsg, ServerMsg } from "../src/protocol.js";
import { CoreFixture, type FixtureLink } from "./coreFixture.js";

const isUpdate = (m: ClientMsg): m is Extract<ClientMsg, { op: "session.update" }> => m.op === "session.update";
const isRefused = (e: CoeditEvent): e is Extract<CoeditEvent, { type: "refused" }> => e.type === "refused";
let fixture: CoreFixture | undefined;

beforeEach(async () => { fixture = await CoreFixture.start(); });
afterEach(async () => {
  const current = fixture;
  fixture = undefined;
  if (current) await current.stop();
});
function home(): CoreFixture {
  if (!fixture) throw new Error("missing core fixture");
  return fixture;
}
async function open(database = "db-a", mode: "edit" | "view" = "edit", existing?: FixtureLink) {
  const f = home();
  const link = existing ?? await f.attach(database);
  const client = new CoeditClient(link.transport, { key: database, record_id: f.recordId, mode });
  client.open();
  await f.idle();
  expect(client.connectionStatus).toBe("live");
  return { client, link };
}
async function converged(expected: string, ...peers: Awaited<ReturnType<typeof open>>[]): Promise<void> {
  await home().idle();
  for (const { client, link } of peers) {
    const core = await home().inspect(link);
    expect(core.body).toBe(expected);
    expect(client.text.toString()).toBe(expected);
    expect(Buffer.from(client.text.toString(), "utf8")).toEqual(Buffer.from(core.body, "utf8"));
    expect(client.pendingCount).toBe(0);
    // Rust full sync must also decode as exact plaintext in an independent Yjs doc.
    const doc = new Y.Doc();
    try { Y.applyUpdate(doc, core.sync); expect(doc.getText("body").toString()).toBe(expected); }
    finally { doc.destroy(); }
  }
}
function authors(update: Uint8Array): number[] {
  return [...new Set(Y.decodeUpdate(update).structs.map((s) => s.id.client))];
}
function receiveRefusal(link: FixtureLink): Extract<ServerMsg, { op: "session.refused" }> {
  const frame = link.received.filter((m) => m.op === "session.refused").at(-1);
  if (frame?.op !== "session.refused") throw new Error("core did not refuse");
  return frame;
}

describe("actual Rust registry ↔ SDK (opt-in, ephemeral)", () => {
  it("consumes a Rust seed and exchanges exact astral/CJK/combining/CRLF insert/delete bytes", async () => {
    const a = await open(), b = await open();
    expect(Object.keys(home().sourceHashes).sort()).toEqual(["src/coedit/refusal.rs", "src/coedit/registry.rs"]);
    expect(a.link.opened.session).toBe(b.link.opened.session);
    expect(a.link.opened.peer).not.toBe(b.link.opened.peer);
    await converged("A😀漢e\u0301\r\nZ", a, b);

    const ids = [...a.link.opened.doc_client_ids, ...b.link.opened.doc_client_ids];
    expect(a.link.opened.doc_client_ids).toHaveLength(3);
    expect(b.link.opened.doc_client_ids).toHaveLength(3);
    expect(new Set(ids).size).toBe(6);
    for (const id of ids) { expect(Number.isInteger(id)).toBe(true); expect(id).toBeGreaterThan(0); expect(id).toBeLessThan(2 ** 31); }
    const seedAuthors = authors(a.link.opened.sync);
    expect(seedAuthors).toHaveLength(1);
    for (const id of seedAuthors) { expect(id).toBeGreaterThanOrEqual(2 ** 31); expect(id).toBeLessThanOrEqual(0xffffffff); expect(ids).not.toContain(id); }
    expect(a.client.visible.clientID).toBe(a.link.opened.doc_client_ids[0]);

    a.client.text.insert(1, "界🦊");
    await converged("A界🦊😀漢e\u0301\r\nZ", a, b);
    b.client.text.delete(b.client.text.toString().indexOf("😀"), 2);
    await converged("A界🦊漢e\u0301\r\nZ", a, b);
    b.client.text.insert(b.client.text.toString().indexOf("Z"), "中o\u0308\r\n");
    await converged("A界🦊漢e\u0301\r\n中o\u0308\r\nZ", a, b);
    a.client.text.delete(a.client.text.toString().indexOf("e\u0301"), 2);
    await converged("A界🦊漢\r\n中o\u0308\r\nZ", a, b);
    const accepted = a.link.sent.filter(isUpdate)[0];
    const remote = b.link.received.find((m) => m.op === "session.remote");
    if (remote?.op !== "session.remote") throw new Error("no core broadcast");
    expect(remote.update).toEqual(accepted.update); // no re-encoding in the adapter
  });

  it("shares one DB across links, isolates a second DB, and really refuses a View peer", async () => {
    const a = await open(), b = await open(), isolated = await open("db-b"), view = await open("db-a", "view");
    const events: CoeditEvent[] = [];
    view.client.on((event) => events.push(event));
    expect(view.link.opened.session).toBe(a.link.opened.session);
    expect(isolated.link.opened.session).not.toBe(a.link.opened.session);
    const leases = [...a.link.opened.doc_client_ids, ...b.link.opened.doc_client_ids, ...view.link.opened.doc_client_ids];
    expect(new Set(leases).size).toBe(9);
    a.client.text.insert(0, "同😀");
    await converged("同😀" + home().seed, a, b, view);
    await converged(home().seed, isolated);
    view.client.text.insert(0, "NOT-A-GRANT");
    await home().idle();
    expect(receiveRefusal(view.link).code).toBe("forbidden");
    expect(events.filter(isRefused).at(-1)?.draft).toBe("NOT-A-GRANT");
    await converged("同😀" + home().seed, a, b, view);
    await converged(home().seed, isolated);
  });

  it("uses real size refusals, replays a clock-gap survivor once, then exhausts without losing intent", async () => {
    const a = await open(), b = await open();
    const [initial, spare, confirmed] = a.link.opened.doc_client_ids;
    const events: CoeditEvent[] = [];
    a.client.on((event) => events.push(event));
    const huge = "X".repeat(a.link.opened.limits.max_update_bytes + 1);
    const survivor = "s😀漢";
    a.link.holdOut();
    a.client.text.insert(a.client.text.length, huge);
    a.client.text.insert(0, survivor); // its original author has a refused clock gap
    const [oversized, dependent] = a.link.sent.filter(isUpdate);
    expect(oversized.update.byteLength).toBeGreaterThan(a.link.opened.limits.max_update_bytes);
    expect(dependent.update.byteLength).toBeLessThan(a.link.opened.limits.max_update_bytes);
    a.link.releaseOut((m) => isUpdate(m) && m.update_id === oversized.update_id);
    await home().idle();
    const refusal = receiveRefusal(a.link);
    expect(refusal.code).toBe("too_large");
    expect(refusal.refused).toEqual([oversized.update_id]);
    expect((await home().inspect(a.link)).body).toBe(home().seed);
    expect(events.filter(isRefused).at(-1)?.draft).toBe(huge);
    expect(a.client.text.toString()).toBe(survivor + home().seed);
    expect(a.client.visible.clientID).toBe(spare);
    expect(a.client.visible.clientID).not.toBe(confirmed);
    expect(a.client.pendingCount).toBe(1);
    const replay = a.link.sent.filter(isUpdate).at(-1)!;
    expect(replay.update_id).not.toBe(dependent.update_id);
    expect(authors(replay.update)).toEqual([spare]);
    expect(authors(oversized.update)).toEqual([initial]);

    // Repeat only the actual core frame. Original dependent bytes remain
    // withheld by the link; deliver the SDK's fresh replay, not those old bytes.
    a.link.deliverIn(refusal);
    expect(events.filter((e) => e.type === "rebuilt")).toHaveLength(1);
    expect(a.client.visible.clientID).toBe(spare);
    a.link.releaseOut((m) => isUpdate(m) && m.update_id === replay.update_id);
    await converged(survivor + home().seed, a, b);
    a.link.deliverIn(refusal); // also stale now; still no additional lease used
    expect(events.filter((e) => e.type === "rebuilt")).toHaveLength(1);
    expect(a.client.visible.clientID).toBe(spare);

    const huge2 = "Q".repeat(a.link.opened.limits.max_update_bytes + 1);
    const extra = "余🦊";
    a.client.text.insert(a.client.text.length, huge2);
    const second = a.link.sent.filter(isUpdate).at(-1)!;
    a.client.text.insert(0, extra);
    a.client.text.delete(a.client.text.toString().indexOf("Z"), 1); // pending delete intent too
    const beforeRefusal = a.link.sent.length;
    a.link.releaseOut((m) => isUpdate(m) && m.update_id === second.update_id);
    await home().idle();
    expect(receiveRefusal(a.link).code).toBe("too_large");
    expect(a.client.connectionStatus).toBe("blocked");
    expect(a.client.pendingCount).toBe(0);
    expect(a.link.sent.length).toBe(beforeRefusal); // exhaustion cannot send under confirmed/retired IDs
    expect(events.filter((e) => e.type === "exhausted")).toHaveLength(1);
    expect(events.filter(isRefused).at(-1)?.draft).toBe(huge2 + extra);
    expect(events.filter(isRefused).at(-1)?.unreplayedDeletes).toBeGreaterThanOrEqual(1);
    await converged(survivor + home().seed, a, b);
    const sentBeforeBlockedEdit = a.link.sent.length;
    a.client.text.insert(0, "post");
    expect(a.link.sent.length).toBe(sentBeforeBlockedEdit);
    expect((await home().inspect(a.link)).body).toBe(survivor + home().seed);
    a.client.close();
    const closed = events.find((e) => e.type === "closed");
    expect(closed?.type === "closed" ? closed.draft : undefined).toBe("post");
    a.link.releaseOut((m) => m.op === "session.close");
    await home().idle();
    expect(a.link.received.at(-1)).toMatchObject({ op: "session.closed", reason: "left" });
    await expect(home().inspect(a.link)).rejects.toThrow("no live peer");
  });

  it("rejects malformed/binding/version requests without touching state, and really leaves/reseeds", async () => {
    const a = await open(), otherDb = await open("db-b");
    const invalidOpen = await home().attach("db-a");
    await expect(home().rawMessage(invalidOpen, { op: "session.open", key: "db-b", record_id: home().recordId, mode: "edit" })).rejects.toThrow("database binding mismatch");
    await expect(home().rawMessage(invalidOpen, { op: "session.open", key: "db-a", record_id: "unknown", mode: "edit" })).rejects.toThrow("unknown fixture record");
    const b = await open("db-a", "edit", invalidOpen);
    expect(b.link.opened.doc_client_ids[0]).toBe(a.link.opened.doc_client_ids[2] + 1); // rejected opens allocated nothing
    await expect(home().rawMessage(a.link, { op: "session.update", session: otherDb.link.opened.session, update: [0, 0], update_id: "wrong" })).rejects.toThrow("session binding mismatch");
    await expect(home().rawMessage(a.link, { op: "session.update", session: a.link.opened.session, update: [256], update_id: "bad-byte" })).rejects.toThrow("malformed session message");
    await expect(home().rawMessage(a.link, { op: "session.update", session: a.link.opened.session, update: [-1], update_id: "signed-byte" })).rejects.toThrow("malformed session message");
    await expect(home().rawMessage(a.link, { op: "session.close", session: a.link.opened.session, peer: b.link.opened.peer })).rejects.toThrow("malformed session message");
    await expect(home().rawMessage(a.link, { op: "session.version", session: a.link.opened.session, reason: "not supported" })).rejects.toThrow("no persistence/version authority");
    await converged(home().seed, a, b, otherDb);
    a.client.text.insert(0, "ephemeral");
    await converged("ephemeral" + home().seed, a, b);
    a.client.close(); await home().idle();
    expect(a.link.received.at(-1)).toMatchObject({ op: "session.closed", reason: "left" });
    await expect(home().inspect(a.link)).rejects.toThrow("no live peer");
    await converged("ephemeral" + home().seed, b);
    b.client.close(); await home().idle();
    const reopened = await open();
    expect(reopened.link.opened.session).not.toBe(a.link.opened.session);
    expect(reopened.link.opened.doc_client_ids[0]).toBeGreaterThan(b.link.opened.doc_client_ids[2]);
    await converged(home().seed, reopened, otherDb); // last leave dropped the live doc, no durability implied
  });
});
