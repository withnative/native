// Author validation and exact fixture bundle; no installation or authority.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validatePackage } from "../../../../packages/alpha-tab-kit/src/validate.mjs";
const out = resolve(process.argv[2] || "target/package-ui-bundle");
const descriptor = JSON.parse(await readFile(new URL("package.descriptor.json", import.meta.url)));
const html = await readFile(new URL("package.html", import.meta.url), "utf8");
const result = validatePackage({ descriptor, html });
if (!result.ok) throw new Error(JSON.stringify(result.findings));
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "package.html"), html);
await writeFile(resolve(out, "manifest.json"), JSON.stringify([{package:descriptor.package,version:descriptor.version,file:"package.html",...result.digests}], null, 2) + "\n");
console.log(JSON.stringify({out, findings:result.findings, digests:result.digests}));
