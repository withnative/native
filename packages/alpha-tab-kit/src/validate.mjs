import { parseBodyFeatureDeclaration } from "./body-feature-grammar.mjs";
// One entry point: every install-time rule the kit can run locally, for one
// package descriptor plus its HTML bundle.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { LIMITS } from "./limits.mjs";
import { finding, warning } from "./findings.mjs";
import { parseDeclaration } from "./declaration.mjs";
import { lintSql, NOT_MIRRORED } from "./sql-lint.mjs";
import { validateHtml, STRICT_DEFAULT } from "./html.mjs";
import { completenessAnalysis } from "./completeness-lint.mjs";
import { computeDigests } from "./digest.mjs";

import { parseIconFacet, isSupportedIconName } from "./icons.mjs";

const AT = "src/mcp/tools/alpha_tabs.rs";
const I = LIMITS.install;

// Mirrors `require_package` (alpha_tabs.rs:1715).
export function packageFindings(pkg) {
  const out = [];
  if (typeof pkg !== "string" || pkg.length === 0 || Buffer.byteLength(pkg) > I.package_max_bytes) {
    out.push(finding("install.package", `${AT}:1716 require_package`, `package must be 1..${I.package_max_bytes} characters`));
    return out;
  }
  const labels = pkg.split(".");
  if (labels.length < 2 || labels.some((label) => label.length === 0 || label.length > I.package_label_max_bytes || label.startsWith("-") || label.endsWith("-") || !/^[a-z0-9-]+$/.test(label))) {
    out.push(finding("install.package", `${AT}:1734 require_package`, `package '${pkg}' is not a reverse-dns id (two or more dot-separated labels of [a-z0-9-], 1..${I.package_label_max_bytes} each)`));
  }
  return out;
}

// Mirrors `require_version` (alpha_tabs.rs:1740).
export function versionFindings(version) {
  const parts = typeof version === "string" ? version.split(".") : [];
  if (typeof version !== "string" || version.length > I.version_max_bytes || parts.length !== 3
    || parts.some((part) => part.length === 0 || part.length > I.version_part_max_digits || !/^[0-9]+$/.test(part))) {
    return [finding("install.version", `${AT}:1749 require_version`, `version '${version}' is not semver X.Y.Z`)];
  }
  return [];
}

// Mirrors `require_digest` (alpha_tabs.rs:1755).
export function digestFormatFindings(digest) {
  if (typeof digest !== "string" || !digest.startsWith("sha256:")) return [finding("install.digest", `${AT}:1758 require_digest`, "digest must start with 'sha256:'")];
  if (!/^[0-9a-f]{64}$/.test(digest.slice(7))) return [finding("install.digest", `${AT}:1767 require_digest`, "digest must be 'sha256:' plus 64 lowercase hex characters")];
  return [];
}

function topLevelLimit(sql) {
  // The last `LIMIT <n>` at paren depth 0, or null.
  let depth = 0;
  let found = null;
  const re = /\(|\)|'(?:[^']|'')*'|"(?:[^"]|"")*"|--[^\n]*|\/\*[\s\S]*?\*\/|\bLIMIT\s+(\d+)/gi;
  for (const match of sql.matchAll(re)) {
    if (match[0] === "(") depth += 1;
    else if (match[0] === ")") depth -= 1;
    else if (match[1] !== undefined && depth === 0) found = Number(match[1]);
  }
  return found;
}

/**
 * Validate a descriptor object and its HTML. Returns
 * `{ ok, findings, digests, notMirrored }`; `ok` is false when any finding
 * is an error. `completenessBudget` overrides the advisory completeness
 * lint's work bounds (`LINT_BUDGET`); exhausting them is only a warning.
 */
export function validatePackage(input) {
  return validatePackageWith(input, parseDeclaration);
}

// Explicit pure author feature validation, never host admission.
export function validateBodyFeaturePackage(input) {
  return validatePackageWith(input, parseBodyFeatureDeclaration);
}

function validatePackageWith({ descriptor, html, strict = STRICT_DEFAULT, completenessBudget }, parse) {
  const findings = [];
  const d = descriptor ?? {};
  for (const key of ["package", "version", "runtime", "declaration"]) {
    if (!(key in d)) findings.push(finding("descriptor.shape", "kit descriptor (manage_alpha_tabs.install arguments, alpha_tabs.rs:1652)", `descriptor is missing '${key}'`));
  }
  findings.push(...packageFindings(d.package), ...versionFindings(d.version));
  if (d.runtime !== I.runtime) {
    findings.push(finding("descriptor.runtime", "src/mcp/tools/alpha_tabs.rs launch_binding_in (runtime_present requires native.html.v1)", `runtime must be '${I.runtime}', got '${d.runtime}'`));
  }

  const icon = parseIconFacet(d.icon);
  if (Object.hasOwn(d, "icon") && (!icon || (icon.kind === "lucide" && !isSupportedIconName(icon.name)))) {
    findings.push(warning("presentation.icon", "alpha-tab-kit icon authoring contract", "Unsupported Lucide or malformed icon; bounded PascalCase names and brand:<slug> are preserved, malformed values are omitted. Unknown names render a monogram. Run alpha-tab-kit icons for supported Lucide names; brand artwork availability is resolved by the host's pinned Simple Icons catalogue."));
  }

  const parsed = parse(d.declaration);
  findings.push(...parsed.findings);
  for (const need of parsed.sqlNeeds) {
    findings.push(...lintSql(need.sql, need.params, `needs[key=${need.key}].sql`));
    const limit = topLevelLimit(need.sql);
    // Parameterised reads are usually keyed lookups, so only an explicit
    // over-cap LIMIT is flagged for them.
    const overCap = limit !== null && limit > LIMITS.reads.sql_snapshot_row_cap;
    if (overCap || (limit === null && need.params.length === 0)) {
      findings.push(warning("reads.row-cap", `${AT}:130 SQL_SNAPSHOT_ROW_CAP`, limit === null
        ? `no top-level LIMIT: the host delivers at most ${LIMITS.reads.sql_snapshot_row_cap} rows and truncates the rest (truncated: true, row_count = full count)`
        : `LIMIT ${limit} exceeds the ${LIMITS.reads.sql_snapshot_row_cap}-row delivery cap; rows past ${LIMITS.reads.sql_snapshot_row_cap} are truncated`, { where: `needs[key=${need.key}]` }));
    }
  }

  let digests = null;
  if (typeof html === "string") {
    findings.push(...validateHtml(html, { strict }));
    findings.push(...completenessAnalysis(html, parsed.sqlNeeds, completenessBudget).findings);
    try {
      digests = computeDigests(html, d.declaration, d.runtime ?? I.runtime);
    } catch (error) {
      findings.push(error.finding ?? finding("digest", `${AT}:770 alpha_tab_canonical_declaration`, error.message));
    }
  }
  if (digests) {
    for (const key of ["bundle_sha256", "declaration_digest", "digest"]) {
      if (key in d && d[key] !== digests[key]) {
        findings.push(finding("descriptor.digest-stale", `${AT}:851 alpha_tab_digest`, `descriptor ${key} ${d[key]} does not match the bundle (${digests[key]}); run \`alpha-tab-kit digest --write\``));
      }
    }
    if ("digest" in d) findings.push(...digestFormatFindings(d.digest));
    if (d.digest_version !== undefined && d.digest_version !== LIMITS.digest.version) {
      findings.push(finding("descriptor.digest-version", `${AT}:73 ALPHA_TAB_DIGEST_VERSION`, `digest_version must be '${LIMITS.digest.version}'`));
    }
  }
  return {
    ok: !findings.some((item) => item.severity === "error"),
    findings,
    digests,
    notMirrored: NOT_MIRRORED,
  };
}

/** Load `<descriptor>.json` and the bundle it names (relative to it). */
export function loadPackage(descriptorPath, htmlPath) {
  const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8"));
  const bundlePath = htmlPath ?? (descriptor.bundle ? resolve(dirname(descriptorPath), descriptor.bundle) : null);
  const html = bundlePath ? readFileSync(bundlePath, "utf8") : null;
  return { descriptor, html, bundlePath };
}
