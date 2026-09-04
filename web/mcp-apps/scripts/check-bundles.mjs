import { readFile } from "node:fs/promises";
for (const file of ["dist/record-version-diff.html", "dist/suggestion-review.html"]) {
  const html = await readFile(new URL(`../${file}`, import.meta.url), "utf8");
  for (const forbidden of [
    /<script[^>]+src=/i,
    /<link[^>]+stylesheet/i,
    /<(?:img|iframe|source)[^>]+src=["']https?:/i,
    /from ["']@modelcontextprotocol/,
    /querySelectorAll\([^)]*modulepreload/i,
    /\bfetch\s*\(/i,
  ]) if (forbidden.test(html)) throw new Error(`${file} is not self-contained: ${forbidden}`);
  if (/[\t ]+$/mu.test(html)) throw new Error(`${file} contains trailing whitespace`);
  if (!html.includes("ui/notifications/tool-result")) throw new Error(`${file} does not contain the bundled Apps bridge listener`);
}
