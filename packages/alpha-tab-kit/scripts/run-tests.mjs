#!/usr/bin/env node
// Runs every kit test file as its own `node --test` process, in file order, one per CPU at
// a time, each under a hard timeout.
//
// Why: `node --test packages/alpha-tab-kit/test/*.test.mjs` reports a file only when it
// finishes. In CI the step has stalled with no output until the job was cancelled, always
// right after the same test, so the culprit was unknown. Here a file that does not finish
// fails after the timeout, names itself, and leaves evidence before it is killed:
//   - the process tree under it (`ps -o pid,ppid,etime,args`), so a child still alive shows
//   - a Node diagnostic report from each live node process (`--report-on-signal`): the
//     JavaScript stack and the active libuv handles, which say what keeps a process alive
//     or what a blocked one is waiting on
// The evidence is gathered for at most DIAGNOSIS_MS, then the whole process group is killed.
//
//   node packages/alpha-tab-kit/scripts/run-tests.mjs [--timeout-ms 140000] [--concurrency N] [file...]
//
// Output: `START <file>` and `END <file> <status> <ms>` as each file starts and ends, and
// each file's own spec output after its END. Exit status 1 if any file failed or hung, or
// if no file matched; 2 for bad options; 130 or 143 if interrupted by SIGINT or SIGTERM.
// Interrupting the runner forwards the signal to every test process group first.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// A test gets 120 s; a file gets longer, so a test that never settles fails by name before
// the file as a whole is declared hung.
const TEST_TIMEOUT_MS = 120_000;
const DEFAULT_FILE_TIMEOUT_MS = 140_000;
const DIAGNOSIS_MS = 2_000;
const INTERRUPT_GRACE_MS = 3_000;

const kitDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const argv = process.argv.slice(2);

function usage(message) {
  console.error(`${message}\nusage: run-tests.mjs [--timeout-ms N] [--concurrency N] [file...]   (N a whole number, at least 1)`);
  process.exitCode = 2;
}
function takeOption(name, fallback) {
  const at = argv.indexOf(name);
  if (at < 0) return fallback;
  const raw = argv[at + 1];
  argv.splice(at, 2);
  const value = Number(raw);
  if (raw === undefined || raw === "" || !Number.isInteger(value) || value < 1) throw new Error(`${name} needs a whole number of at least 1, got ${JSON.stringify(raw)}`);
  return value;
}

let timeoutMs, concurrency, files;
try {
  timeoutMs = takeOption("--timeout-ms", DEFAULT_FILE_TIMEOUT_MS);
  concurrency = takeOption("--concurrency", Math.max(1, availableParallelism()));
  const unknown = argv.filter((arg) => arg.startsWith("--"));
  if (unknown.length) throw new Error(`unknown option ${unknown.join(", ")}`);
  files = argv.length
    ? argv.map((file) => resolve(file))
    : readdirSync(join(kitDir, "test")).filter((name) => name.endsWith(".test.mjs")).sort().map((name) => join(kitDir, "test", name));
  if (!files.length) {
    console.error("no kit test files matched: nothing was run");
    process.exitCode = 1;
  }
} catch (error) {
  usage(error.message);
}

if (process.exitCode === undefined) await main();

async function main() {
  const label = (file) => relative(process.cwd(), file);
  const reportDir = mkdtempSync(join(tmpdir(), "kit-test-reports-"));
  const testTimeoutMs = Math.min(TEST_TIMEOUT_MS, Math.max(1000, timeoutMs - 20_000));
  const active = new Set(); // child processes (each leads its own process group)
  let interrupted = null;
  let anyHung = false;

  const ps = (...args) => spawnSync("ps", args, { encoding: "utf8", timeout: 2000 }).stdout ?? "";
  const readProc = (path) => { try { return readFileSync(path, "utf8"); } catch { return "?"; } };
  const killGroup = (pid, signal) => { try { process.kill(-pid, signal); } catch { /* already gone */ } };
  const clip = (text, max) => (text.length > max ? `${text.slice(0, max)}…` : text);

  /** The pids under `root` (children, grandchildren, ...), found from one snapshot of the process table. */
  function descendants(root) {
    const parentOf = new Map();
    for (const line of ps("-eo", "pid=,ppid=").split("\n")) {
      const [pid, ppid] = line.trim().split(/\s+/).map(Number);
      if (pid) parentOf.set(pid, ppid);
    }
    const found = [];
    const queue = [root];
    while (queue.length) {
      const parent = queue.shift();
      for (const [pid, ppid] of parentOf) if (ppid === parent && !found.includes(pid)) { found.push(pid); queue.push(pid); }
    }
    return found;
  }

  /** What the reports of the node processes `pids` say: where JavaScript is stopped and which handles are alive. */
  function summariseReports(since, pids) {
    const lines = [];
    let names = [];
    try { names = readdirSync(reportDir).sort(); } catch { /* the directory is gone */ }
    for (const name of names) {
      let report;
      try { report = JSON.parse(readFileSync(join(reportDir, name), "utf8")); } catch { continue; }
      if (report.header?.event !== "SIGUSR2" || Date.parse(report.header.dumpEventTime) < since || !pids.includes(report.header.processId)) continue;
      const { header, javascriptStack, libuv } = report;
      lines.push(`  report ${name}: pid ${header.processId}, ${(header.commandLine ?? []).slice(0, 4).join(" ")}`);
      lines.push(`    javascript: ${clip((javascriptStack?.stack ?? [javascriptStack?.message ?? "(none)"]).slice(0, 8).join(" | "), 900)}`);
      const live = (libuv ?? []).filter((handle) => handle.is_active);
      const kinds = new Map();
      for (const handle of live) kinds.set(handle.type, (kinds.get(handle.type) ?? 0) + 1);
      lines.push(`    active libuv handles: ${live.length ? [...kinds].map(([type, count]) => `${type} x${count}`).join(", ") : "none"}`);
      for (const handle of live.filter((h) => h.type !== "timer").slice(0, 6)) lines.push(`      ${clip(JSON.stringify(handle), 220)}`);
    }
    return lines;
  }

  /** Evidence from a hung file's processes, in at most DIAGNOSIS_MS. Never throws. */
  async function diagnose(file, child) {
    const out = [`HUNG ${label(file)}: no exit after ${timeoutMs} ms (runner pid ${child.pid})`];
    try {
      const pids = [child.pid, ...descendants(child.pid)];
      out.push("  processes under it (ps -o pid,ppid,etime,args):");
      out.push(...ps("-o", "pid,ppid,etime,args", "-p", pids.join(",")).split("\n").filter(Boolean).map((line) => `    ${line}`));
      out.push(`  direct children of ${child.pid} (ps --ppid):`, ...ps("-o", "pid,ppid,etime,args", "--ppid", String(child.pid)).split("\n").filter(Boolean).map((line) => `    ${line}`));
      for (const pid of pids) {
        const state = (readProc(`/proc/${pid}/status`).match(/^State:\s*(.*)$/m) ?? [])[1] ?? "?";
        out.push(`  pid ${pid}: state ${state}, waiting in kernel: ${readProc(`/proc/${pid}/wchan`).trim() || "-"}`);
      }
      // Ask every live node process for a diagnostic report; a blocked event loop may not answer.
      const asked = Date.now() - 1000;
      for (const pid of pids) { try { process.kill(pid, "SIGUSR2"); } catch { /* gone */ } }
      const deadline = Date.now() + DIAGNOSIS_MS;
      let reports = summariseReports(asked, pids);
      while (Date.now() < deadline && !reports.some((line) => line.includes(`pid ${child.pid},`))) {
        await new Promise((done) => setTimeout(done, 200));
        reports = summariseReports(asked, pids);
      }
      out.push(...reports.length ? reports : ["  no diagnostic report came back (a process blocked in a synchronous call cannot write one); the process list above is the evidence"]);
    } catch (error) {
      out.push(`  (diagnosis stopped early: ${error.message})`);
    }
    return out.join("\n");
  }

  function runFile(file) {
    return new Promise((resolveFile) => {
      const started = Date.now();
      console.log(`START ${label(file)}`);
      const child = spawn(process.execPath, ["--test", "--test-reporter=spec", `--test-timeout=${testTimeoutMs}`, file], {
        cwd: process.cwd(),
        detached: true, // its own process group, so a hung tree can be killed (or signalled) as one
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --report-on-signal --report-signal=SIGUSR2 --report-directory=${reportDir} --report-compact`.trim() },
      });
      active.add(child);
      let output = "";
      child.stdout.on("data", (chunk) => { output += chunk; });
      child.stderr.on("data", (chunk) => { output += chunk; });
      let finished = false, hung = false;
      const finish = (status, extra = "") => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        active.delete(child);
        const ms = Date.now() - started;
        console.log(`END ${label(file)} ${status} ${ms}`);
        console.log(output.replace(/\n+$/, ""));
        if (extra) console.log(extra);
        resolveFile({ file, status, ms });
      };
      const timer = setTimeout(async () => {
        hung = true;
        anyHung = true;
        let report = `HUNG ${label(file)}`;
        try { report = await diagnose(file, child); } finally { killGroup(child.pid, "SIGKILL"); }
        finish("HUNG", report);
      }, timeoutMs);
      child.on("error", (error) => finish("ERROR", `could not start: ${error.message}`));
      child.on("close", (code, signal) => finish(hung ? "HUNG" : interrupted ? `INTERRUPTED(${interrupted})` : code === 0 ? "ok" : `FAILED(${signal ?? code})`));
    });
  }

  // Interrupting the runner must not orphan test processes: forward the signal to every
  // process group, stop starting files, and kill whatever is still there after a grace period.
  for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
    process.on(signal, () => {
      if (interrupted) return;
      interrupted = signal;
      process.exitCode = code;
      console.error(`${signal}: forwarding to ${active.size} running test process group(s)`);
      for (const child of active) killGroup(child.pid, signal);
      setTimeout(() => { for (const child of active) killGroup(child.pid, "SIGKILL"); }, INTERRUPT_GRACE_MS).unref();
    });
  }
  // Last resort: never leave a test process group behind when the runner ends.
  process.on("exit", () => { for (const child of active) killGroup(child.pid, "SIGKILL"); });

  const total = Date.now();
  const results = [];
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, files.length) }, async () => {
    while (next < files.length && !interrupted) results.push(await runFile(files[next++]));
  }));

  const bad = results.filter((result) => result.status !== "ok");
  const skipped = files.length - results.length;
  console.log(`\n${results.length} files in ${Date.now() - total} ms (${concurrency} at a time, ${timeoutMs} ms each): ${results.length - bad.length} ok${bad.length ? `, ${bad.length} not ok: ${bad.map((result) => `${basename(result.file)} ${result.status}`).join(", ")}` : ""}${skipped ? `, ${skipped} not run (interrupted)` : ""}`);
  // exitCode, not process.exit(): this runner exists because an explicit exit can hang on Node 24.
  if (process.exitCode === undefined) process.exitCode = bad.length ? 1 : 0;
  if (!anyHung) rmSync(reportDir, { recursive: true, force: true }); // keep the reports of a hang
}
