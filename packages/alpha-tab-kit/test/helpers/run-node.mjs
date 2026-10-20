// Runs `node <args>` for a test with every way a child can stall closed off, so a hung
// child fails that test with its own output instead of stalling the whole `node --test`
// step (which reports a file only when it finishes). Not a `*.test.mjs`, so the runner
// does not pick it up.
//
// - stdin is closed at once (an empty `input`): a child that reads it sees EOF, never waits
// - a hard `timeout` with `killSignal: "SIGKILL"`: a child that ignores SIGTERM cannot linger
// - an abnormal end (timed out, killed, could not start) throws, carrying stdout and stderr;
//   a normal non-zero exit is returned for the test to assert on, as before
import { execFile, spawnSync } from "node:child_process";

export const CHILD_TIMEOUT_MS = 60_000;
const MAX_BUFFER = 16 * 1024 * 1024;
const tail = (text) => { const value = String(text ?? ""); return value.length > 4000 ? `…${value.slice(-4000)}` : value; };

function describe(args, timeoutMs, error, signal, stdout, stderr) {
  const how = error?.code === "ETIMEDOUT" || error?.killed ? `did not finish within ${timeoutMs} ms and was killed`
    : signal ? `was ended by ${signal}` : `could not run (${error?.message ?? "unknown"})`;
  return new Error(`child \`node ${args.join(" ")}\` ${how}\n--- stdout ---\n${tail(stdout)}\n--- stderr ---\n${tail(stderr)}`);
}

/** Like `spawnSync(process.execPath, args)`: `{ status, stdout, stderr }`, throwing if the child did not end by itself. */
export function runNode(args, { cwd, timeoutMs = CHILD_TIMEOUT_MS } = {}) {
  const result = spawnSync(process.execPath, args, { cwd, encoding: "utf8", input: "", timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: MAX_BUFFER });
  if (result.error || result.signal) throw describe(args, timeoutMs, result.error, result.signal, result.stdout, result.stderr);
  return result;
}

/** Like `execFile(process.execPath, args)` resolved to `{ error, stdout, stderr }` (`error.code` is the exit status); rejects if the child did not end by itself. */
export function runNodeAsync(args, { cwd, timeoutMs = CHILD_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(process.execPath, args, { cwd, timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: MAX_BUFFER }, (error, stdout, stderr) => {
      if (error && (error.killed || error.signal || typeof error.code !== "number")) reject(describe(args, timeoutMs, error, error.signal, stdout, stderr));
      else resolve({ error, stdout, stderr });
    });
    child.stdin?.end();
  });
}
