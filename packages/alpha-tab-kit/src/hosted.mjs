// Compare a hosted server's native.html.v1 runtime descriptor with what the
// kit mirrors (main). The descriptor comes from `render_artifact` on any
// native.html.v1 artifact the caller can view (artifacts_execute; it writes
// no record): `result.runtime` is `native_artifact_html::html::descriptor()`
// as that server was built (crates/artifact-html/src/html.rs:1879).
import { LIMITS } from "./limits.mjs";
import { STRICT_DEFAULT } from "./html.mjs";

/** The validator version at which <main>, <h1> and heading order became advisory (ffd9c76cd). */
export const ADVISORY_VALIDATOR_VERSION = 3;

export function compareHosted(renderResult) {
  const runtime = renderResult?.runtime ?? renderResult;
  if (runtime?.id !== LIMITS.install.runtime) throw new Error("not a native.html.v1 render_artifact result: expected result.runtime.id = native.html.v1");
  const validator = runtime.validator?.version;
  const adapter = runtime.adapter_revision;
  const bridgeDigest = runtime.delivery_transform?.digest;
  const limitKeys = { body_utf8_bytes: "body_max_bytes", data_asset_decoded_bytes_each: "data_asset_max_bytes", data_asset_decoded_bytes_total: "data_assets_total_max_bytes", static_dom_nodes: "dom_node_max", css_rules: "css_rule_max", input_json_bytes: "input_json_max_bytes", input_records: "input_records_max", bridge_message_bytes: "bridge_message_max_bytes" };
  const limitDiffs = Object.entries(limitKeys)
    .filter(([hosted, kit]) => runtime.limits?.[hosted] !== undefined && runtime.limits[hosted] !== LIMITS.html[kit])
    .map(([hosted, kit]) => ({ limit: hosted, hosted: runtime.limits[hosted], kit: LIMITS.html[kit] }));
  const accessibilityAdvisory = Number.isInteger(validator) && validator >= ADVISORY_VALIDATOR_VERSION;
  return {
    hosted: { adapter_revision: adapter, validator_version: validator, bridge_digest: bridgeDigest },
    kit: { adapter_revision: LIMITS.bridge.adapter_revision, validator_version: LIMITS.bridge.validator_version, bridge_digest: LIMITS.bridge.bootstrap_sha256 },
    matches_main: adapter === LIMITS.bridge.adapter_revision && validator === LIMITS.bridge.validator_version && bridgeDigest === LIMITS.bridge.bootstrap_sha256 && limitDiffs.length === 0,
    bridge_matches: bridgeDigest === LIMITS.bridge.bootstrap_sha256,
    limit_diffs: limitDiffs,
    accessibility_rules: accessibilityAdvisory ? "advisory" : "refused",
    strict_default: STRICT_DEFAULT,
    advice: accessibilityAdvisory
      ? (STRICT_DEFAULT ? "hosted validator is at or past ffd9c76cd: the strict default can flip (STRICT_DEFAULT in src/html.mjs)" : "strict default already matches hosted")
      : (STRICT_DEFAULT ? "hosted still refuses <main>/<h1>/heading-order problems: keep the strict default" : "hosted refuses <main>/<h1>/heading-order problems but the kit is not strict: flip STRICT_DEFAULT back to true"),
  };
}
