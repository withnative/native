import { readFile, writeFile } from "node:fs/promises";

for (const file of ["dist/record-version-diff.html", "dist/suggestion-review.html"]) {
  const url = new URL(`../${file}`, import.meta.url);
  const html = await readFile(url, "utf8");
  const normalized = html
    .split(/\r?\n/)
    .map((line) => line.replace(/[\t ]+$/u, ""))
    .join("\n");
  if (normalized !== html) await writeFile(url, normalized, "utf8");
}
