// A finding names the rule, the source location it mirrors, and whether the
// hosted path refuses (`error`) or only advises (`warning`).

export function finding(rule, mirrors, message, extra = {}) {
  return { severity: "error", rule, mirrors, message, ...extra };
}

export function warning(rule, mirrors, message, extra = {}) {
  return { severity: "warning", rule, mirrors, message, ...extra };
}

export function formatFinding(item) {
  const where = item.where ? ` (${item.where})` : "";
  return `${item.severity === "error" ? "✗" : "!"} [${item.rule}] ${item.message}${where}\n    mirrors ${item.mirrors}`;
}
