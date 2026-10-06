// @withnative/alpha-tab-kit: the public entry points. See README.md.
export { SUPPORTED_ICON_NAMES, ICON_LIBRARY_VERSION, BRAND_LIBRARY, BRAND_LIBRARY_VERSION, isIconName, isSupportedIconName, isBrandName, parseIconFacet } from "./icons.mjs";
export { LIMITS, LIMIT_SOURCES } from "./limits.mjs";
export { bundleSha256, declarationDigest, installDigest, computeDigests, canonicalDeclaration, DIGEST_VERSION } from "./digest.mjs";
export { validatePackage, loadPackage, packageFindings, versionFindings, digestFormatFindings } from "./validate.mjs";
export { parseDeclaration, parseFacetSetBound, parseCommentCreateBound, parseCommentCreateBounds, parseMessageReactBound, parseMessageReactBounds, parseTitleSetBound, parseTitleSetBounds, splitNeeds, FACET_SET_EFFECT, COMMENT_CREATE_EFFECT, COMMENT_CREATE_MAX_BODY_BYTES, COMMENT_CREATE_POSITIONS, MESSAGE_REACT_EFFECT, MESSAGE_REACT_EMOJIS, TITLE_SET_EFFECT } from "./declaration.mjs";
// Dormant BodySet shape/digest only; no engine/host Save capability asserted.
export { parseBodySetBound, parseBodySetBounds, BODY_SET_EFFECT, BODY_SET_MAX_BODY_BYTES } from "./declaration.mjs";
export { lintSql, NOT_MIRRORED } from "./sql-lint.mjs";
export { validateHtml, STRICT_DEFAULT } from "./html.mjs";
export { completenessFindings, completenessAnalysis, LINT_BUDGET } from "./completeness-lint.mjs";
export { compareHosted, ADVISORY_VALIDATOR_VERSION } from "./hosted.mjs";
export { planInstall, runInstall, chunkUtf8 } from "./install.mjs";
export { requestCode, verifyCode, readBearer, createMcpClient, DEFAULT_ORIGIN, DEFAULT_BEARER_FILE } from "./remote.mjs";
export { formatFinding } from "./findings.mjs";
export { buildMessageReactProposal, messageReactOutcomeText, MESSAGE_REACT_MANIFEST_EFFECT } from "./message-react.mjs";

// Node-only feature author preparation; generic admission remains refused.
export { planBodyFeatureInstall } from "./body-feature-plan.mjs";
