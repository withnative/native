import { describe, expect, it } from "vitest";

import { utf16OffsetToUtf8, utf8Length, utf8OffsetToUtf16 } from "../src/offsets.js";

// A(1B,1U) e(1B,1U) U+0301(2B,1U) 中(3B,1U) U+1F600(4B,2U) \r(1B,1U) \n(1B,1U)
const TEXT = "Aé中😀\r\n";
const EXPECTED_UTF16_LEN = 8;
const EXPECTED_BYTE_LEN = 13;

// [utf16 offset, utf8 offset] at every grapheme/code-point boundary.
const BOUNDARIES: Array<[number, number]> = [
  [0, 0],
  [1, 1], // after A
  [2, 2], // after e
  [3, 4], // after combining acute
  [4, 7], // after 中
  [6, 11], // after 😀
  [7, 12], // after \r
  [8, 13], // after \n
];

describe("utf16OffsetToUtf8", () => {
  it("maps every boundary", () => {
    for (const [u16, bytes] of BOUNDARIES) {
      expect(utf16OffsetToUtf8(TEXT, u16)).toBe(bytes);
    }
  });

  it("floors a mid-surrogate-pair offset to the pair start", () => {
    expect(utf16OffsetToUtf8(TEXT, 5)).toBe(7);
  });

  it("clamps out-of-range offsets", () => {
    expect(utf16OffsetToUtf8(TEXT, -3)).toBe(0);
    expect(utf16OffsetToUtf8(TEXT, 999)).toBe(EXPECTED_BYTE_LEN);
    expect(utf16OffsetToUtf8("", 5)).toBe(0);
  });

  it("encodes a lone surrogate as U+FFFD (3 bytes), like TextEncoder", () => {
    const lone = `a${String.fromCharCode(0xd800)}b`;
    expect(utf16OffsetToUtf8(lone, 3)).toBe(1 + 3 + 1);
    expect(utf8OffsetToUtf16(lone, 2)).toBe(1);
  });
});

describe("utf8OffsetToUtf16", () => {
  it("maps every boundary", () => {
    for (const [u16, bytes] of BOUNDARIES) {
      expect(utf8OffsetToUtf16(TEXT, bytes)).toBe(u16);
    }
  });

  it("floors byte offsets inside multi-byte sequences", () => {
    expect(utf8OffsetToUtf16(TEXT, 3)).toBe(2); // inside combining acute
    expect(utf8OffsetToUtf16(TEXT, 5)).toBe(3); // inside 中
    expect(utf8OffsetToUtf16(TEXT, 6)).toBe(3); // inside 中
    expect(utf8OffsetToUtf16(TEXT, 8)).toBe(4); // inside emoji
    expect(utf8OffsetToUtf16(TEXT, 10)).toBe(4); // inside emoji
  });

  it("clamps out-of-range offsets", () => {
    expect(utf8OffsetToUtf16(TEXT, -1)).toBe(0);
    expect(utf8OffsetToUtf16(TEXT, 999)).toBe(EXPECTED_UTF16_LEN);
    expect(utf8OffsetToUtf16("", 1)).toBe(0);
  });
});

describe("round trip", () => {
  it("is the identity on boundary-aligned offsets", () => {
    for (const [u16, bytes] of BOUNDARIES) {
      expect(utf8OffsetToUtf16(TEXT, utf16OffsetToUtf8(TEXT, u16))).toBe(u16);
      expect(utf16OffsetToUtf8(TEXT, utf8OffsetToUtf16(TEXT, bytes))).toBe(bytes);
    }
  });

  it("holds for a mixed string with CRLF line endings", () => {
    const doc = "第一行\r\n第二行 😀 done\r\n";
    // Round trip is the identity on code-point boundaries only: a mid-pair
    // offset floors to the pair start on the way back (tested below).
    let u16 = 0;
    while (u16 <= doc.length) {
      const bytes = utf16OffsetToUtf8(doc, u16);
      expect(utf8OffsetToUtf16(doc, bytes)).toBe(u16);
      if (u16 === doc.length) break;
      u16 += (doc.codePointAt(u16) as number) > 0xffff ? 2 : 1;
    }
    const pairAt = doc.indexOf("😀");
    const pairBytes = utf16OffsetToUtf8(doc, pairAt);
    expect(utf16OffsetToUtf8(doc, pairAt + 1)).toBe(pairBytes);
    expect(utf8OffsetToUtf16(doc, pairBytes)).toBe(pairAt);
  });
});

describe("utf8Length", () => {
  it("counts wire bytes", () => {
    expect(utf8Length(TEXT)).toBe(EXPECTED_BYTE_LEN);
    expect(utf8Length("")).toBe(0);
    expect(utf8Length("hello")).toBe(5);
  });
});
