export type DiffLine = { kind: "same" | "add" | "del"; text: string; before?: number; after?: number };
export type DiffToken = { changed: boolean; text: string };

const MAX_LINE_CELLS = 250_000;
const MAX_WORD_CELLS = 10_000;

function exceedsCellBudget(left: number, right: number, budget: number): boolean {
  return left > Math.floor(budget / Math.max(1, right));
}

function coarseLineDiff(before: string[], after: string[]): DiffLine[] {
  let prefix = 0;
  while (prefix < before.length && prefix < after.length && before[prefix] === after[prefix]) prefix++;

  let suffix = 0;
  while (
    suffix < before.length - prefix &&
    suffix < after.length - prefix &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  ) suffix++;

  const out: DiffLine[] = [];
  for (let index = 0; index < prefix; index++) {
    out.push({ kind: "same", text: before[index], before: index + 1, after: index + 1 });
  }
  for (let index = prefix; index < before.length - suffix; index++) {
    out.push({ kind: "del", text: before[index], before: index + 1 });
  }
  for (let index = prefix; index < after.length - suffix; index++) {
    out.push({ kind: "add", text: after[index], after: index + 1 });
  }
  for (let offset = suffix; offset > 0; offset--) {
    const beforeIndex = before.length - offset;
    const afterIndex = after.length - offset;
    out.push({ kind: "same", text: before[beforeIndex], before: beforeIndex + 1, after: afterIndex + 1 });
  }
  return out;
}

export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before.split("\n"), b = after.split("\n");
  if (exceedsCellBudget(a.length + 1, b.length + 1, MAX_LINE_CELLS)) return coarseLineDiff(a, b);
  const table = Array.from({ length: a.length + 1 }, () => Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--)
    table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
  const out: DiffLine[] = []; let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) out.push({ kind: "same", text: a[i++], before: i, after: ++j });
    else if (j < b.length && (i === a.length || table[i][j + 1] >= table[i + 1][j])) out.push({ kind: "add", text: b[j++], after: j });
    else out.push({ kind: "del", text: a[i++], before: i });
  }
  return out;
}

export function renderDiff(container: HTMLElement, before: string, after: string): void {
  container.replaceChildren();
  const lines = lineDiff(before, after);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    const row = document.createElement("div"); row.className = `line ${line.kind}`;
    const number = document.createElement("span"); number.className = "num";
    number.textContent = line.kind === "add" ? `+${line.after}` : line.kind === "del" ? `-${line.before}` : String(line.after);
    const text = document.createElement("span");
    const prior = lines[index - 1], next = lines[index + 1];
    const pair = line.kind === "same" ? undefined : prior && prior.kind !== "same" && prior.kind !== line.kind ? prior : next && next.kind !== "same" && next.kind !== line.kind ? next : undefined;
    if (pair) for (const token of wordDiff(line.kind === "del" ? line.text : pair.text, line.kind === "add" ? line.text : pair.text, line.kind as "del" | "add")) {
      const span = document.createElement("span"); span.textContent = token.text; if (token.changed) span.className = `token ${line.kind}`; text.append(span);
    } else text.textContent = line.text || " ";
    row.append(number, text); container.append(row);
  }
}

export function wordDiff(before: string, after: string, side: "del" | "add"): DiffToken[] {
  const left = before.split(/(\s+)/), right = after.split(/(\s+)/);
  if (exceedsCellBudget(left.length + 1, right.length + 1, MAX_WORD_CELLS)) {
    return [{ changed: true, text: side === "del" ? before : after }];
  }
  const table = Array.from({ length: left.length + 1 }, () => Array<number>(right.length + 1).fill(0));
  for (let i = left.length - 1; i >= 0; i--) for (let j = right.length - 1; j >= 0; j--)
    table[i][j] = left[i] === right[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
  const selected: DiffToken[] = []; let i = 0, j = 0;
  while (i < left.length || j < right.length) {
    if (i < left.length && j < right.length && left[i] === right[j]) { selected.push({ changed: false, text: left[i] }); i++; j++; }
    else if (j < right.length && (i === left.length || table[i][j + 1] >= table[i + 1][j])) { if (side === "add") selected.push({ changed: true, text: right[j] }); j++; }
    else { if (side === "del") selected.push({ changed: true, text: left[i] }); i++; }
  }
  return selected;
}
