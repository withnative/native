// native.html.v1 write policy, mirroring `native_artifact_html::html::validate`
// (crates/artifact-html/src/html.rs:1554), which the server runs on every
// write of a Document/artifact with `runtime: native.html.v1`
// (src/mcp/tools/artifacts.rs:7771 validate_prospective_html, :3492
// validate_prospective_artifact).
//
// Rust parses with html5ever; this module uses a small dependency-free tag
// scanner (comments and script/style/title/textarea contents are skipped the
// way an HTML parser treats them). The preamble, doctype and tag-count rules
// are byte/regex rules in Rust too and are mirrored exactly; element,
// attribute, CSS and asset rules are mirrored on the scanned tags.
// Not mirrored: no-quirks detection beyond the doctype, exact DOM node count
// (elements are counted, text nodes are not), slide-deck structure, and the
// named-input manifest declaration grammar.
import { LIMITS } from "./limits.mjs";
import { finding, warning } from "./findings.mjs";

const H = "crates/artifact-html/src/html.rs";
const L = LIMITS.html;
const ADVISORY_COMMIT = "ffd9c76cd";

// 28 Sep 2026: strict stays the default because hosted production still runs
// the validator from before ffd9c76cd. render_artifact reported
// adapter_revision 1 and validator version 1; main is at 3, which is where
// the accessibility rules became advisory. See README "When to flip the
// strict default": flipping is this one line, once `alpha-tab-kit hosted`
// reports validator version >= 3.
export const STRICT_DEFAULT = true;

const RAW_TEXT = new Set(["script", "style", "textarea", "title", "xmp", "noembed", "noframes"]);
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
const SKIPPED_ATTRIBUTES = new Set(["style", "class", "id", "lang", "title", "alt", "role", "hidden", "tabindex", "type", "charset", "content", "name", "http-equiv", "width", "height", "controls", "autoplay", "loop", "muted", "playsinline", "value", "min", "max", "step", "placeholder", "for", "disabled", "checked", "selected", "readonly", "required", "scope", "colspan", "rowspan"]);

function decodeEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#[0-9]+|amp|lt|gt|quot|apos|nbsp);/gi, (match, body) => {
    const lower = body.toLowerCase();
    if (lower[0] === "#") {
      const code = lower[1] === "x" ? parseInt(lower.slice(2), 16) : parseInt(lower.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : match;
    }
    return { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " }[lower];
  });
}

function position(source, offset) {
  let line = 1;
  let last = -1;
  for (let index = source.indexOf("\n"); index !== -1 && index < offset; index = source.indexOf("\n", index + 1)) {
    line += 1;
    last = index;
  }
  return `line ${line}, column ${offset - last}`;
}

/** Scan start tags in document order, as an HTML tokenizer sees them. */
export function scanTags(source) {
  const elements = [];
  let i = 0;
  while (i < source.length) {
    const lt = source.indexOf("<", i);
    if (lt < 0) break;
    if (source.startsWith("<!--", lt)) {
      const end = source.indexOf("-->", lt + 4);
      i = end < 0 ? source.length : end + 3;
      continue;
    }
    if (source[lt + 1] === "!" || source[lt + 1] === "?" || source[lt + 1] === "/") {
      const end = source.indexOf(">", lt + 1);
      i = end < 0 ? source.length : end + 1;
      continue;
    }
    const nameMatch = /^[A-Za-z][A-Za-z0-9-]*/.exec(source.slice(lt + 1, lt + 64));
    if (!nameMatch) { i = lt + 1; continue; }
    const tag = nameMatch[0].toLowerCase();
    let j = lt + 1 + nameMatch[0].length;
    const attributes = new Map();
    // Attribute tokenizer: name[=value] with ', " or unquoted values.
    while (j < source.length) {
      while (j < source.length && /[\s/]/.test(source[j])) j += 1;
      if (source[j] === ">" || j >= source.length) break;
      const attrMatch = /^[^\s"'>/=]+/.exec(source.slice(j, j + 256));
      if (!attrMatch) { j += 1; continue; }
      const name = attrMatch[0].toLowerCase();
      j += attrMatch[0].length;
      while (/\s/.test(source[j] ?? "")) j += 1;
      let value = "";
      if (source[j] === "=") {
        j += 1;
        while (/\s/.test(source[j] ?? "")) j += 1;
        const quote = source[j];
        if (quote === '"' || quote === "'") {
          const end = source.indexOf(quote, j + 1);
          value = source.slice(j + 1, end < 0 ? source.length : end);
          j = end < 0 ? source.length : end + 1;
        } else {
          const unquoted = /^[^\s>]*/.exec(source.slice(j))[0];
          value = unquoted;
          j += unquoted.length;
        }
      }
      if (!attributes.has(name)) attributes.set(name, decodeEntities(value));
    }
    const end = j + 1;
    const element = { tag, attributes, offset: lt, text: null };
    elements.push(element);
    i = end;
    if (RAW_TEXT.has(tag) && !VOID.has(tag)) {
      const close = source.slice(end).search(new RegExp(`</${tag}[\\s>/]`, "i"));
      const stop = close < 0 ? source.length : end + close;
      element.text = source.slice(end, stop);
      if (tag === "title" || tag === "textarea") element.text = decodeEntities(element.text);
      i = stop;
    }
  }
  return elements;
}

// Mirrors `bootstrap_insertion_offset` (html.rs:1131): BOM, whitespace, the
// exact doctype, `<html` + space or `>`, then an attribute-free `<head>`.
// Returns the injection offset, or a finding.
export function bootstrapInsertionOffset(source) {
  const tagEnd = (start) => {
    let quote = null;
    for (let index = start; index < source.length; index += 1) {
      const c = source[index];
      if (quote === null && (c === "'" || c === '"')) quote = c;
      else if (quote !== null && c === quote) quote = null;
      else if (quote === null && c === ">") return index + 1;
    }
    return -1;
  };
  const skipSpace = (offset) => { while (offset < source.length && /[\t\n\f\r ]/.test(source[offset])) offset += 1; return offset; };
  let offset = source.startsWith("﻿") ? 1 : 0;
  offset = skipSpace(offset);
  const doctypeEnd = tagEnd(offset);
  if (doctypeEnd < 0 || source.slice(offset, doctypeEnd).trim().toLowerCase() !== "<!doctype html>") {
    return { error: finding("document-preamble", `${H}:1136 bootstrap_insertion_offset`, "document must begin with an HTML5 doctype (exactly `<!doctype html>`)", { code: "html_invalid_document" }) };
  }
  offset = skipSpace(doctypeEnd);
  const htmlEnd = tagEnd(offset);
  const htmlOpen = htmlEnd < 0 ? "" : source.slice(offset, htmlEnd);
  if (htmlEnd < 0 || htmlOpen.slice(0, 5).toLowerCase() !== "<html" || !/[\s>]/.test(htmlOpen[5] ?? "")) {
    return { error: finding("document-preamble", `${H}:1162 bootstrap_insertion_offset`, "doctype must be followed directly by the html element", { code: "html_invalid_document", where: position(source, offset) }) };
  }
  offset = skipSpace(htmlEnd);
  const headEnd = tagEnd(offset);
  if (headEnd < 0 || source.slice(offset, headEnd).toLowerCase() !== "<head>") {
    return { error: finding("bootstrap-order", `${H}:1186 bootstrap_insertion_offset`, "html start tag must be followed directly by an attribute-free head start tag", { code: "html_invalid_document", where: position(source, offset) }) };
  }
  return { offset: headEnd };
}

function decodeDataUrl(raw) {
  if (!raw.startsWith("data:")) return { error: "asset URL must be data:" };
  const comma = raw.indexOf(",");
  if (comma < 0) return { error: "malformed data URL" };
  const parts = raw.slice(5, comma).split(";");
  const mime = (parts.shift() ?? "").toLowerCase();
  if (!L.data_mime_types.includes(mime)) return { error: `data asset MIME '${mime}' is not permitted` };
  const payload = raw.slice(comma + 1);
  if (parts.some((part) => part.toLowerCase() === "base64")) {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(payload) || payload.length % 4 !== 0) return { error: "invalid base64 data asset" };
    return { bytes: Buffer.from(payload, "base64").length };
  }
  return { bytes: Buffer.byteLength(decodeURIComponent(payload), "utf8") };
}

/**
 * Validate one HTML body. `strict` (default true) escalates the accessibility
 * advisories that hosted builds before ffd9c76cd refused — one <main>, an
 * <h1>, and heading order as seen by the 28 Sep 2026 install run — to errors.
 */
export function validateHtml(source, { strict = STRICT_DEFAULT } = {}) {
  const findings = [];
  const where = (element) => (element ? position(source, element.offset) : undefined);
  const error = (rule, line, message, element, code = "html_policy_violation") => findings.push(finding(rule, `${H}:${line}`, message, { code, where: where(element) }));
  // `mirrors` overrides the source citation for a rule current source does
  // not state as such (single-h1).
  const advise = (rule, line, message, element, legacyRefusal = false, mirrors = `${H}:${line}`) => {
    const extra = { where: where(element) };
    if (legacyRefusal && strict) {
      findings.push(finding(rule, `${mirrors} (advisory since ${ADVISORY_COMMIT}; refused by the hosted server on 28 Sep 2026)`, message, extra));
    } else {
      findings.push(warning(rule, mirrors, message, extra));
    }
  };

  const bytes = Buffer.byteLength(source, "utf8");
  if (bytes > L.body_max_bytes) {
    error("body-size", 1557, `HTML source is ${bytes} bytes; the UTF-8 body limit is ${L.body_max_bytes}`, null, "html_source_too_large");
    return findings;
  }
  const preamble = bootstrapInsertionOffset(source);
  if (preamble.error) { findings.push(preamble.error); return findings; }
  const body = source.startsWith("﻿") ? source.slice(1) : source;
  if (!/^<!doctype\s+html\s*>/is.test(body)) { error("doctype", 1566, "complete HTML must begin with an HTML5 doctype", null, "html_invalid_document"); return findings; }
  for (const tag of ["html", "head", "body"]) {
    const count = (body.match(new RegExp(`<\\s*${tag}(?:\\s|>)`, "gis")) ?? []).length;
    if (count !== 1) {
      // Textual, like Rust: a `<body` inside a comment or a script string counts.
      error(`${tag}-count`, 1574, `document must contain exactly one <${tag}> start tag (found ${count} textual matches, including any in comments or script strings)`, null, "html_invalid_document");
      return findings;
    }
  }

  const elements = scanTags(body);
  if (elements.length > L.dom_node_max) error("dom-node-limit", 1203, `static DOM node limit exceeded (${elements.length} elements > ${L.dom_node_max})`);
  let lang = false;
  const titles = [];
  const css = [];
  const assets = [];
  let charset = false;
  let viewport = false;
  let profile = null;
  let profileCount = 0;
  let mains = 0;
  let h1 = 0;
  const headings = [];
  for (const element of elements) {
    const { tag, attributes } = element;
    const attr = (name) => attributes.get(name);
    let rejectedByName = false;
    switch (tag) {
      case "html": lang = (attr("lang") ?? "").trim() !== ""; break;
      case "title": titles.push(element.text ?? ""); break;
      case "main": mains += 1; break;
      case "style": css.push(element.text ?? ""); break;
      case "meta": {
        if (attributes.has("charset") && attr("charset").trim().toLowerCase() === "utf-8") charset = true;
        const metaName = attr("name")?.toLowerCase();
        if (metaName === "viewport" && (attr("content") ?? "").toLowerCase().includes("width=device-width")) viewport = true;
        if (metaName === "native-artifact-profile") {
          profileCount += 1;
          if (profileCount > 1) error("profile-count", 1265, "profile meta must occur at most once", element);
          else profile = (attr("content") ?? "").trim().toLowerCase();
        }
        const httpEquiv = attr("http-equiv")?.toLowerCase();
        if (httpEquiv === "content-security-policy" || httpEquiv === "refresh") error("meta-http-equiv", 1286, "authored CSP and refresh meta are forbidden", element);
        break;
      }
      case "script":
        if (attributes.has("src")) { error("external-script", 1306, "script[src] is forbidden", element); rejectedByName = true; }
        if (attr("type")?.toLowerCase() === "importmap") error("import-map", 1316, "import maps are forbidden", element);
        break;
      case "link": error("external-link-resource", 1340, "link elements are forbidden; artifacts are self-contained", element); rejectedByName = true; break;
      case "form": if (attributes.has("action")) { error("form-action", 1347, "form[action] is forbidden", element); rejectedByName = true; } break;
      case "img": if (!attributes.has("alt")) advise("image-alt", 1350, "image has no alt; describe it, or use alt=\"\" if it is decorative", element); break;
      default:
        if (L.forbidden_elements.includes(tag)) { error("forbidden-element", 1299, `<${tag}> is forbidden`, element); rejectedByName = true; }
    }
    if (/^h[1-6]$/.test(tag)) {
      headings.push({ level: Number(tag[1]), element });
      if (tag === "h1") h1 += 1;
    }
    const tabindex = Number.parseInt((attr("tabindex") ?? "").trim(), 10);
    if (Number.isInteger(tabindex) && tabindex > 0) advise("positive-tabindex", 1366, `<${tag}> has a positive tabindex, which overrides the natural focus order; use 0 or -1`, element);
    if (attributes.has("style")) css.push(attr("style"));
    for (const [key, value] of attributes) {
      if (key.startsWith("on") || key.startsWith("aria-") || key.startsWith("data-") || SKIPPED_ATTRIBUTES.has(key)) continue;
      if (key === "src" && tag === "img") { assets.push(value); continue; }
      if (key === "href" && tag === "a" && value.startsWith("#")) continue;
      if (L.url_attributes.includes(key) && !rejectedByName) error("url-attribute", 1446, `URL-bearing attribute ${key} on <${tag}> is forbidden`, element);
    }
    if (attributes.has("data-native-record-id") && (attr("data-native-record-id").trim() === "" || attributes.has("data-native-external-url"))) {
      error("host-navigation", 1460, "host-mediated navigation must name exactly one non-empty destination", element);
    }
    if (attributes.has("data-native-external-url")) {
      let parsed = null;
      try { parsed = new URL(attr("data-native-external-url")); } catch { /* reported below */ }
      if (!parsed) error("host-navigation", 1473, "data-native-external-url must be an absolute http(s) URL", element);
      else if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) error("host-navigation", 1484, "data-native-external-url must be an absolute http(s) URL without credentials", element);
    }
  }

  if (!lang || titles.length !== 1 || titles[0].trim() === "") {
    error("document-envelope", 1598, `document requires one html[lang], head, body and non-empty title (lang ${lang ? "present" : "missing"}, ${titles.length} title element(s))`, null, "html_invalid_document");
  }
  if (!charset) advise("document-charset", 1614, "head has no <meta charset=\"utf-8\">");
  if (!viewport) advise("document-viewport", 1621, "head has no <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
  if (profile !== null && profile !== "document" && profile !== "slides") error("profile", 1634, `unknown native artifact profile '${profile}'`);
  if (mains !== 1) advise("landmarks", 1642, mains === 0 ? "artifact has no <main> landmark" : `artifact has ${mains} <main> elements; keep exactly one visible <main>`, null, true);
  if (h1 === 0) advise("missing-h1", 1655, "artifact has no <h1>", null, true);
  if (h1 > 1) advise("single-h1", 2512, `artifact has ${h1} <h1> elements; keep exactly one`, null, true, `kit rule: current source accepts several <h1> (${H}:2512 test)`);
  for (let index = 1; index < headings.length; index += 1) {
    const [before, after] = [headings[index - 1], headings[index]];
    if (after.level > before.level + 1) {
      advise("heading-order", 1047, `heading levels skip from h${before.level} to h${after.level}; review the hierarchy`, after.element, true);
    }
  }

  let cssRules = 0;
  for (const text of css) {
    const normalized = text.replace(/\/\*[\s\S]*?\*\//g, "").toLowerCase();
    if (normalized.includes("@import")) error("css-import", 1669, "CSS @import is forbidden");
    if (normalized.includes("image-set(") || normalized.includes("-webkit-image-set(")) error("css-image-set", 1674, "CSS image-set is forbidden; use a single quota-checked data URL");
    if (normalized.includes("http:") || normalized.includes("https:") || normalized.includes("url(//")) error("css-url", 1684, "external CSS authority is forbidden (the text `http:`/`https:` anywhere in CSS outside comments is refused)");
    cssRules += (text.match(/\{/g) ?? []).length;
    for (const match of text.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gis)) {
      const value = match[1].trim();
      if (value.startsWith("data:")) assets.push(value);
      else if (!value.startsWith("#")) error("css-url", 1695, `CSS url(${[...value].slice(0, 80).join("")}) is not a permitted data asset or fragment`);
    }
  }
  if (cssRules > L.css_rule_max) error("css-rules", 1706, `CSS rule limit exceeded (${cssRules} > ${L.css_rule_max})`);
  let assetTotal = 0;
  for (const asset of assets) {
    const decoded = decodeDataUrl(asset);
    if (decoded.error) { error("data-url", 1503, decoded.error, null, "html_asset_invalid"); continue; }
    if (decoded.bytes > L.data_asset_max_bytes) error("data-asset-size", 1544, "decoded data asset exceeds per-asset limit", null, "html_asset_too_large");
    assetTotal += decoded.bytes;
  }
  if (assetTotal > L.data_assets_total_max_bytes) error("data-asset-total", 1714, "decoded data assets exceed aggregate limit", null, "html_asset_too_large");
  return findings;
}
