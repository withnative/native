import { describe, expect, it } from "vitest";
import { lineDiff, wordDiff } from "./diff";
describe("diff", () => {
  it("preserves context and identifies changes", () => { expect(lineDiff("a\nb", "a\nc").map((line) => line.kind)).toEqual(["same", "add", "del"]); });
  it("marks only changed intra-line words", () => {
    expect(wordDiff("alpha beta", "alpha gamma", "del").filter((part) => part.changed).map((part) => part.text)).toEqual(["beta"]);
    expect(wordDiff("alpha beta", "alpha gamma", "add").filter((part) => part.changed).map((part) => part.text)).toEqual(["gamma"]);
  });
  it("falls back to a bounded, lossless coarse diff for large bodies", () => {
    const before = ["shared start", ...Array.from({ length: 800 }, (_, index) => `before ${index}`), "shared end"].join("\n");
    const after = ["shared start", ...Array.from({ length: 800 }, (_, index) => `after ${index}`), "shared end"].join("\n");
    const result = lineDiff(before, after);
    expect(result.filter((line) => line.kind !== "add").map((line) => line.text).join("\n")).toBe(before);
    expect(result.filter((line) => line.kind !== "del").map((line) => line.text).join("\n")).toBe(after);
    expect(result[0].kind).toBe("same");
    expect(result.at(-1)?.kind).toBe("same");
  });
  it("falls back to a lossless whole-line token for large intra-line changes", () => {
    const before = Array.from({ length: 200 }, (_, index) => `before-${index}`).join(" ");
    const after = Array.from({ length: 200 }, (_, index) => `after-${index}`).join(" ");
    expect(wordDiff(before, after, "del")).toEqual([{ changed: true, text: before }]);
    expect(wordDiff(before, after, "add")).toEqual([{ changed: true, text: after }]);
  });
});
