// The one place the kit reads the backend's numbers from. `limits.json` is
// checked by a Rust test (`src/mcp/tools/alpha_tab_kit_drift.rs`) against
// the constants and behaviour it mirrors, so a backend change that moves a
// limit fails the backend's own CI until this file moves with it.
import { readFileSync } from "node:fs";

const raw = JSON.parse(readFileSync(new URL("../limits.json", import.meta.url), "utf8"));

// Flatten `{ value, rust }` leaves to their values; keep the raw form for
// messages that cite the source.
function values(node) {
  if (node && typeof node === "object" && !Array.isArray(node)) {
    if ("value" in node && ("rust" in node || "source" in node)) return node.value;
    return Object.fromEntries(Object.entries(node).map(([key, child]) => [key, values(child)]));
  }
  return node;
}

export const LIMITS = values(raw);
export const LIMIT_SOURCES = raw;

// `source("declaration.label_max_chars")` → "src/mcp/tools/alpha_tabs.rs SQL_SNAPSHOT_LABEL_MAX_CHARS"
export function source(path) {
  let node = raw;
  for (const part of path.split(".")) node = node?.[part];
  if (!node || typeof node !== "object") return "limits.json";
  return [node.source, node.rust].filter(Boolean).join(" ");
}
