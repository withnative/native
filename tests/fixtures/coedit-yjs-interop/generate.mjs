#!/usr/bin/env node
// Generates vectors.json: Yjs (JS) update vectors with the text they must
// produce, and relative positions with the UTF-8 byte offsets they must
// resolve to. The engine applies them with yrs (OffsetKind::Bytes) to prove the
// two agree on the wire format the kit client sends (0a700a3, contract B2).
//
//   npm ci --prefix web/apps                                   # provides yjs 13.6.33
//   node tests/fixtures/coedit-yjs-interop/generate.mjs        # rewrite vectors.json
//   node tests/fixtures/coedit-yjs-interop/generate.mjs --check  # fail if it would change
//
// Every client id is fixed, so the output is deterministic for a given yjs.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const appsYjs = join(here, "../../../web/apps/node_modules/yjs");
const Y = await import(join(appsYjs, "dist/yjs.mjs"));
const yjsVersion = JSON.parse(readFileSync(join(appsYjs, "package.json"), "utf8")).version;

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const utf8 = (text) => Buffer.byteLength(text, "utf8");
/** UTF-8 byte offset of a UTF-16 index. */
const byteOffset = (text, index) => utf8(text.slice(0, index));

/** The home's author id (FakeHome's), two leased peer ids, and a reader that never authors. */
const HOME = 0x7ff00001, ADA = 0x1010, BEN = 0x1020, READER = 0x7ff000ff;

function doc(clientID) {
  const d = new Y.Doc();
  d.clientID = clientID;
  return d;
}

/** Run `edit` on `d` and return exactly the update it produced. */
function step(d, edit) {
  const before = Y.encodeStateVector(d);
  d.transact(() => edit(d.getText("body")));
  return Y.encodeStateAsUpdate(d, before);
}

function check(condition, message) {
  if (!condition) throw new Error(`vector self-check failed: ${message}`);
}

function finish(name, description, updates, d, extra = {}) {
  const text = d.getText("body").toString();
  // Self-check: a fresh doc applying the updates in order reaches the same text.
  const replay = doc(READER + 2);
  for (const u of updates) Y.applyUpdate(replay, u);
  check(replay.getText("body").toString() === text, `${name} replays`);
  return {
    name,
    description,
    updates: updates.map(b64),
    expected_text: text,
    expected_utf8_length: utf8(text),
    expected_utf16_length: text.length,
    full_state_update: b64(Y.encodeStateAsUpdate(d)),
    ...extra,
  };
}

const cases = [];

// 1. Seed text, then an insert.
{
  const d = doc(HOME);
  const seed = step(d, (t) => t.insert(0, "Hello world\n"));
  d.clientID = ADA;
  const insert = step(d, (t) => t.insert(6, "brave new "));
  check(d.getText("body").toString() === "Hello brave new world\n", "seed+insert text");
  cases.push(finish("seed_then_insert", "The home seeds the body; a peer inserts ASCII in the middle.", [seed, insert], d));
}

// 2. Emoji, CJK, combining marks and CRLF: inserts and deletes, one update each.
{
  const d = doc(HOME);
  const updates = [step(d, (t) => t.insert(0, "Café 😀 中文 é end.\r\nline two\r\n"))];
  d.clientID = ADA;
  const t = d.getText("body");
  const at = (needle) => {
    const i = t.toString().indexOf(needle);
    check(i >= 0, `find ${needle}`);
    return i;
  };
  updates.push(step(d, (x) => x.insert(at("😀"), "🎉 ")));                    // astral insert before an astral char
  updates.push(step(d, (x) => x.delete(at("中文"), 2)));                       // delete two BMP CJK chars (6 bytes)
  updates.push(step(d, (x) => x.insert(at(" é"), "日本")));               // CJK insert where they were
  updates.push(step(d, (x) => x.delete(at("́"), 1)));                      // delete only the combining mark
  updates.push(step(d, (x) => x.insert(at("\r\nline two"), "\r\nnew line")));   // insert a CRLF line
  updates.push(step(d, (x) => x.delete(at("😀"), 2)));                         // delete a whole surrogate pair
  updates.push(step(d, (x) => x.delete(at("line two\r\n") + 8, 2)));          // delete the final CRLF
  check(t.toString() === "Café 🎉  日本 e end.\r\nnew line\r\nline two", "unicode text");
  cases.push(finish("unicode_inserts_and_deletes", "Emoji (4 bytes, 2 UTF-16 units), CJK (3 bytes), a combining mark and CRLF, inserted and deleted one update at a time.", updates, d));
}

// 3. Two concurrent clients from one seed; the result is independent of order.
{
  const home = doc(HOME);
  const seed = step(home, (t) => t.insert(0, "base 😀 text\r\n"));
  const a = doc(ADA), b = doc(BEN);
  Y.applyUpdate(a, seed);
  Y.applyUpdate(b, seed);
  const ua = step(a, (t) => { t.insert(5, "Ada中 "); t.delete(t.toString().indexOf("text"), 4); });
  const ub = step(b, (t) => { t.insert(5, "Ben🧪 "); t.delete(t.toString().indexOf("😀"), 2); t.insert(t.length, "tail\r\n"); });
  const merged = doc(READER);
  for (const u of [seed, ua, ub]) Y.applyUpdate(merged, u);
  const other = doc(READER + 1);
  for (const u of [seed, ub, ua]) Y.applyUpdate(other, u);
  check(other.getText("body").toString() === merged.getText("body").toString(), "order independence");
  cases.push(finish("concurrent_two_clients", "Ada and Ben edit the same seed concurrently, including inserts at the same index and overlapping deletes. Applying the last two updates in either order must give expected_text.", [seed, ua, ub], merged, { order_independent_from: 1 }));
}

// 4. Relative positions around an emoji, resolved to UTF-8 byte offsets after later edits.
{
  const d = doc(HOME);
  const seed = step(d, (t) => t.insert(0, "a😀b中c\r\n"));
  const t = d.getText("body");
  const marks = [
    { name: "before_emoji_assoc_right", index: 1, assoc: 0, note: "Sticks to the emoji: text inserted at this spot lands before the position." },
    { name: "before_emoji_assoc_left", index: 1, assoc: -1, note: "Sticks to 'a': text inserted at this spot lands after the position." },
    { name: "after_emoji", index: 3, assoc: 0 },
    { name: "after_cjk", index: 5, assoc: 0 },
    { name: "after_crlf", index: 8, assoc: -1 },
  ].map((m) => ({ ...m, rel: Y.createRelativePositionFromTypeIndex(t, m.index, m.assoc) }));
  d.clientID = ADA;
  const updates = [seed, step(d, (x) => x.insert(0, "→")), step(d, (x) => x.insert(2, "!"))];
  const text = t.toString();
  check(text === "→a!😀b中c\r\n", "relative text");
  const relative_positions = marks.map(({ rel, ...m }) => {
    const abs = Y.createAbsolutePositionFromRelativePosition(rel, d);
    check(abs !== null, `${m.name} resolves`);
    return {
      ...m,
      encoded: b64(Y.encodeRelativePosition(rel)),
      encoded_against_update_count: 1,
      expected_utf16_index: abs.index,
      expected_utf8_offset: byteOffset(text, abs.index),
      seed_utf8_offset: byteOffset("a😀b中c\r\n", m.index),
    };
  });
  const offsets = Object.fromEntries(relative_positions.map((p) => [p.name, p.expected_utf8_offset]));
  // Independent expectations: "→" is 3 bytes, "!" 1 byte, "😀" 4, "中" 3.
  check(offsets.before_emoji_assoc_right === 3 + 1 + 1, "assoc right moves past the '!' inserted at its spot");
  check(offsets.before_emoji_assoc_left === 3 + 1, "assoc left stays before the '!'");
  check(offsets.after_emoji === 3 + 1 + 1 + 4, "after emoji");
  check(offsets.after_cjk === 3 + 1 + 1 + 4 + 1 + 3, "after CJK");
  check(offsets.after_crlf === utf8(text), "after CRLF is the end");
  cases.push(finish("relative_positions_around_emoji", "Relative positions encoded against the seed (the first update only), then resolved after all updates. assoc follows Yjs: 0 or more sticks to the item on the right, below 0 to the item on the left. expected_utf8_offset is what yrs with OffsetKind::Bytes must report.", updates, d, { relative_positions }));
}

const out = JSON.stringify({
  format: "native.coedit-yjs-interop.v1",
  generator: "tests/fixtures/coedit-yjs-interop/generate.mjs",
  yjs_version: yjsVersion,
  encoding: "Yjs update v1, base64. Relative positions: Y.encodeRelativePosition, base64.",
  doc_shape: "One root Y.Text named \"body\".",
  apply: "For each case: a fresh doc, apply `updates` in order; the body text must equal expected_text, with expected_utf8_length bytes. full_state_update alone must give the same text.",
  cases,
}, null, 2) + "\n";

const target = join(here, "vectors.json");
if (process.argv.includes("--check")) {
  const current = readFileSync(target, "utf8");
  if (current !== out) {
    console.error("vectors.json is out of date: run generate.mjs");
    process.exit(1);
  }
  console.log("vectors.json is current");
} else {
  writeFileSync(target, out);
  console.log(`wrote ${cases.length} cases to ${target}`);
}
