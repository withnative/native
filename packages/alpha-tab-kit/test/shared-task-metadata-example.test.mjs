// Static package checks for the shared-task-metadata authoring example
// (examples/shared-task-metadata.html): the actual HTML plus the actual
// declaration. No Playwright and no fixture here; the required R5b browser
// proof mounts this exact source for behavior.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDeclaration } from "../src/declaration.mjs";
import { validateHtml } from "../src/html.mjs";
import { validatePackage } from "../src/validate.mjs";

const example = readFileSync(new URL("../examples/shared-task-metadata.html", import.meta.url), "utf8");
const declaration = JSON.parse(readFileSync(new URL("../examples/shared-task-metadata.declaration.json", import.meta.url), "utf8"));

test("shared-task-metadata example is a complete package: no validator errors, one h1, clean declaration, admission true", () => {
  assert.deepEqual(validateHtml(example).filter((item) => item.severity === "error"), []);
  assert.equal((example.match(/<h1/g) || []).length, 1);
  assert.deepEqual(parseDeclaration(declaration).findings, []);
  const admission = validatePackage({
    descriptor: { package: "agent.shared-task-metadata-example", version: "0.1.0", runtime: "native.html.v1", declaration },
    html: example,
  });
  assert.equal(admission.ok, true);
  assert.deepEqual(admission.findings.filter((item) => item.severity === "error"), []);
});
