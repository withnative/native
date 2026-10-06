// Canonical finite host icon catalogue. Browser mirror: public/lib/appIcons.js.
// Keep the mirror byte-identical; alpha-tab-kit test/drift-js.test.mjs checks it.
export const ICON_LIBRARY_VERSION = "0.544.0";
// Brand marks come from a second, host-pinned catalogue (web/shell's
// brandIcons module reads @iconify-json/simple-icons). This file validates the
// descriptor shape only; it never carries brand artwork, so the mirror stays
// small and the artwork stays host-owned.
export const BRAND_LIBRARY = "simple-icons";
export const BRAND_LIBRARY_VERSION = "1.2.98";
export const ICON_NAME_MAX_BYTES = 64;
export const SUPPORTED_ICON_NAMES = Object.freeze([
  "Activity", "BookOpen", "Briefcase", "Building2", "CalendarDays",
  "Camera", "ChartNoAxesCombined", "CircleCheck", "Code2", "FileText",
  "FolderOpen", "Gamepad2", "Gem", "GitPullRequest", "Globe",
  "GraduationCap", "Headset", "Heart", "Image", "ListTodo",
  "Mail", "MapPin", "MessagesSquare", "Milestone", "Music",
  "Notebook", "PanelsTopLeft", "Search", "Settings", "Shield",
  "ShoppingCart", "Table2", "Terminal", "Users", "Wallet",
  "Wrench",
]);
const names = new Set(SUPPORTED_ICON_NAMES);
export function isIconName(value) {
  return typeof value === "string" && value.length <= ICON_NAME_MAX_BYTES
    && value === value.trim() && /^[A-Z][A-Za-z0-9]*$/.test(value);
}
export function isSupportedIconName(value) {
  return typeof value === "string" && names.has(value);
}
// A brand name is a collection slug: lower-case, hyphen-separated.
export function isBrandName(value) {
  return typeof value === "string" && value.length <= ICON_NAME_MAX_BYTES
    && value === value.trim() && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value);
}
// Scalar authoring contract for descriptor.icon and the open app_icon facet.
// The prefix fixes the catalogue identity; the host alone resolves artwork.
// Unknown bounded names survive parsing and render the host's monogram.
export function parseIconFacet(value) {
  if (typeof value !== "string") return null;
  if (value.startsWith("brand:")) {
    const name = value.slice(6);
    return isBrandName(name) ? { kind: "brand", name } : null;
  }
  return isIconName(value) ? { kind: "lucide", name: value } : null;
}
export function normalizeIcon(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (value.kind === "lucide" && isIconName(value.name)) return { kind: "lucide", name: value.name };
  if (value.kind === "brand" && isBrandName(value.name)) return { kind: "brand", name: value.name };
  return null;
}
export const DEFAULT_APP_ICONS = Object.freeze({
  "agent.calendar-week": { kind: "brand", name: "googlecalendar" },
  "agent.database": { kind: "brand", name: "airtable" },
  "agent.datadog-agents": { kind: "brand", name: "datadog" },
  "agent.docs": "FileText",
  "agent.github-review": { kind: "brand", name: "github" },
  "agent.linear": { kind: "brand", name: "linear" },
  "agent.miro-board": { kind: "brand", name: "miro" },
  "agent.notion-pages": { kind: "brand", name: "notion" },
  "agent.preact-cbeae17.database": { kind: "brand", name: "airtable" },
  "agent.prism": "Gem",
  "agent.roadmap-base": { kind: "brand", name: "airtable" },
  "agent.salesforce-crm": { kind: "brand", name: "salesforce" },
  "agent.slack-workspace": { kind: "brand", name: "slack" },
  "agent.task-invaders": "Gamepad2",
  "agent.task-reader-v4": "ListTodo",
  "agent.tracker": "CircleCheck",
  "agent.zendesk-queue": { kind: "brand", name: "zendesk" },
  "agent.messages": "MessagesSquare",
  "agent.hello-records": "ListTodo",
});
// The outer freeze does not reach the descriptor objects, so freeze them too;
// an importer cannot mutate a shared curated default.
for (const value of Object.values(DEFAULT_APP_ICONS)) {
  if (value !== null && typeof value === "object") Object.freeze(value);
}
// Presence is separate from value: an explicit invalid/custom choice must not
// be replaced by a curated default. This helper never writes to the source.
export function appIconFor(packageId, explicitValue, hasExplicit = false) {
  const value = hasExplicit ? explicitValue
    : Object.hasOwn(DEFAULT_APP_ICONS, packageId) ? DEFAULT_APP_ICONS[packageId] : null;
  return typeof value === "string"
    ? parseIconFacet(value)
    : normalizeIcon(value);
}
const colours = Object.freeze(["#80563d", "#526747", "#426c79", "#665a86", "#86576a", "#706126"]);
export function appMonogram(packageId) {
  const text = typeof packageId === "string" ? packageId : "";
  const label = text.split(".").at(-1)?.replace(/^[^a-z0-9]+/i, "") ?? "";
  let hash = 2166136261;
  for (const char of text) hash = Math.imul(hash ^ char.codePointAt(0), 16777619) >>> 0;
  return { initial: label.charAt(0).toUpperCase() || "?", colour: colours[hash % colours.length] };
}
