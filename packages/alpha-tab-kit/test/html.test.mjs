import { test } from "node:test";
import assert from "node:assert/strict";
import { validateHtml } from "../src/html.mjs";

const doc = (body, head = "") => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>T</title>${head}</head><body>${body}</body></html>`;
const rules = (source, options) => validateHtml(source, options).filter((item) => item.severity === "error").map((item) => item.rule);
const warnings = (source, options) => validateHtml(source, options).filter((item) => item.severity === "warning").map((item) => item.rule);

test("a minimal document passes clean", () => {
  assert.deepEqual(validateHtml(doc("<main><h1>T</h1><h2>S</h2></main>")), []);
});

test("preamble: exact doctype, then <html>, then an attribute-free <head> (html.rs:1131)", () => {
  assert.deepEqual(rules("<html lang=en><head><title>T</title></head><body></body></html>"), ["document-preamble"]);
  assert.deepEqual(rules('<!doctype html><!-- c --><html lang="en"><head><title>T</title></head><body></body></html>'), ["document-preamble"]);
  assert.deepEqual(rules('<!doctype html><html lang="en"><head class="x"><title>T</title></head><body></body></html>'), ["bootstrap-order"]);
});

test("tag counts are textual, like the engine: a <body inside a comment counts", () => {
  assert.deepEqual(rules(doc("<main><h1>T</h1><!-- <body> --></main>")), ["body-count"]);
});

test("envelope: html[lang] and one non-empty title", () => {
  assert.deepEqual(rules('<!doctype html><html><head><title>T</title></head><body><main><h1>T</h1></main></body></html>'), ["document-envelope"]);
  assert.deepEqual(rules('<!doctype html><html lang="en"><head><title> </title></head><body><main><h1>T</h1></main></body></html>'), ["document-envelope"]);
});

test("isolation rules stay hard errors", () => {
  assert.deepEqual(rules(doc("<main><h1>T</h1></main><script src=x.js></script>")), ["external-script"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1></main>", '<link rel="stylesheet" href="x.css">')), ["external-link-resource"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1><iframe></iframe></main>")), ["forbidden-element"]);
  assert.deepEqual(rules(doc('<main><h1>T</h1><a href="https://example.com">x</a></main>')), ["url-attribute"]);
  assert.deepEqual(rules(doc('<main><h1>T</h1><a href="#s">x</a><img alt="" src="data:image/png;base64,aQ=="></main>')), []);
  assert.deepEqual(rules(doc('<main><h1>T</h1><img alt="" src="https://example.com/a.png"></main>')), ["data-url"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1></main>", "<style>a{background:url(https://x/y.png)}</style>")), ["css-url", "css-url"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1></main>", "<style>@import 'x.css';</style>")), ["css-import"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1></main>", '<meta http-equiv="refresh" content="1">')), ["meta-http-equiv"]);
  assert.deepEqual(rules(doc('<main><h1>T</h1><button data-native-record-id="">x</button></main>')), ["host-navigation"]);
});

test("script text is not parsed as markup", () => {
  assert.deepEqual(rules(doc('<main><h1>T</h1></main><script>const s = "<iframe src=x>";</script>')), []);
});

test("size limit (html.rs:1557)", () => {
  assert.deepEqual(rules(doc(`<main><h1>T</h1><p>${"x".repeat(524288)}</p></main>`)), ["body-size"]);
});

test("accessibility rules: errors by default (hosted 28 Sep behaviour), warnings with strict: false (current source)", () => {
  const noMain = doc("<h1>T</h1>");
  assert.deepEqual(rules(noMain), ["landmarks"]);
  assert.deepEqual(rules(noMain, { strict: false }), []);
  assert.deepEqual(warnings(noMain, { strict: false }), ["landmarks"]);
  const skip = doc("<main><h1>T</h1><h3>S</h3></main>");
  assert.deepEqual(rules(skip), ["heading-order"]);
  assert.deepEqual(warnings(skip, { strict: false }), ["heading-order"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1><h1>U</h1></main>")), ["single-h1"]);
  assert.deepEqual(rules(doc("<main><h1>T</h1><h1>U</h1></main>"), { strict: false }), []);
  assert.deepEqual(warnings(doc("<main><h1>T</h1><h1>U</h1></main>"), { strict: false }), ["single-h1"]);
  assert.deepEqual(warnings(doc('<main><h1>T</h1><img src="data:image/png;base64,aQ=="><div tabindex="2">x</div></main>')), ["image-alt", "positive-tabindex"]);
});
