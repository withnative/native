#!/usr/bin/env node
// alpha-tab-kit: check, digest, plan the install of, and locally host one
// alpha tab package. Run with no arguments for usage.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { loadPackage, validatePackage } from "../src/validate.mjs";
import { computeDigests } from "../src/digest.mjs";
import { planInstall } from "../src/install.mjs";
import { formatFinding } from "../src/findings.mjs";
import { LIMIT_SOURCES } from "../src/limits.mjs";
import { STRICT_DEFAULT } from "../src/html.mjs";
import { compareHosted } from "../src/hosted.mjs";
import { runInstall } from "../src/install.mjs";
import { requestCode, verifyCode, readBearer, createMcpClient, DEFAULT_ORIGIN, DEFAULT_BEARER_FILE } from "../src/remote.mjs";

import { SUPPORTED_ICON_NAMES, ICON_LIBRARY_VERSION } from "../src/icons.mjs";

const USAGE = `alpha-tab-kit <command> <descriptor.json> [options]

  validate <descriptor>   run every local install rule on the descriptor and its bundle
      --html <file>         bundle path (default: descriptor.bundle, relative to the descriptor)
      --no-strict / --strict  <main>/<h1>/heading order as warnings (current source) or
                            errors (hosted before ffd9c76cd); default: strict (see README)
      --json                machine-readable findings
  digest <descriptor>     print alpha-tab-digest.v1 digests; --write stores them in the descriptor
  install-plan <descriptor> --home <folder id> --reason <text>
      [--name <record name>] [--source <record id>=<why>]... [--chunked [--chunk-bytes 8000]]
      [--raw-body | --body-encoding utf8|base64|gzip+base64]
      [--bind <input port>=<collection id>]... [--allow-unbound]
      [--update <current install event id> | --replace <current install event id> | --after-removal <removal event id>] [--out <dir>]
                          print (or write, one file per call) the exact MCP calls of the
                          whole-body, digest-guarded install route (or explicit --chunked).
                          Every input port the manifest reads needs --bind (binds the new
                          source and grants it input.read); otherwise the plan is refused
                          unless --allow-unbound, because an unbound tab cannot render or Save
  serve <descriptor>      open the fake host at a local URL
      --fixtures <module>   ESM module whose default export is the fixtures object
      --mode live|sample    default live
      --port <n>            default ephemeral
  login --email <address> [--code <code>]
      [--origin ${DEFAULT_ORIGIN}] [--bearer-file ${DEFAULT_BEARER_FILE}]
                          sign in as yourself with an emailed code and store the session
                          bearer (0600, never printed). Without --code it emails the code
                          and, on a terminal, prompts for it
  install-run <plan dir|plan.json> [--origin ...] [--bearer-file ...] [--timeout-ms 120000]
                          execute an install-plan through hosted MCP with that bearer,
                          checking every digest; nothing after a mismatch is sent
  hosted <render.json>    compare a hosted render_artifact result (any native.html.v1
                          artifact) with main: validator, adapter and bridge versions
  icons                   print the finite supported Lucide PascalCase catalogue
                          (brand:<slug> selects the host's pinned Simple Icons catalogue)
  limits                  print limits.json with the source of every value
`;

const argv = process.argv.slice(2);
const command = argv[0];
const option = (name) => { const index = argv.indexOf(name); return index > 0 ? argv[index + 1] : undefined; };
const options = (name) => argv.flatMap((arg, index) => (arg === name ? [argv[index + 1]] : []));
const flag = (name) => argv.includes(name);
const descriptorPath = argv[1] && !argv[1].startsWith("--") ? resolve(argv[1]) : null;

function need(value, message) {
  if (!value) { console.error(message); console.error(USAGE); process.exit(2); }
  return value;
}

switch (command) {
  case "icons": {
    console.log(JSON.stringify({ library: "lucide", version: ICON_LIBRARY_VERSION, names: SUPPORTED_ICON_NAMES }, null, 2));
    break;
  }
  case "validate": {
    const { descriptor, html, bundlePath } = loadPackage(need(descriptorPath, "validate needs a descriptor"), option("--html"));
    const strict = flag("--no-strict") ? false : flag("--strict") ? true : STRICT_DEFAULT;
    const result = validatePackage({ descriptor, html, strict });
    if (flag("--json")) {
      console.log(JSON.stringify({ ok: result.ok, bundle: bundlePath, digests: result.digests, findings: result.findings, not_mirrored: result.notMirrored }, null, 2));
    } else {
      for (const item of result.findings) console.log(formatFinding(item));
      const errors = result.findings.filter((item) => item.severity === "error").length;
      const warnings = result.findings.length - errors;
      console.log(`${result.ok ? "ok" : "FAILED"}: ${descriptor.package} ${descriptor.version}, ${errors} error(s), ${warnings} warning(s)${result.digests ? `; ${result.digests.digest}` : ""}`);
      console.log(`not mirrored locally (the real query_sql / install is the authority): ${result.notMirrored.map((item) => item.rule).join(", ")}`);
    }
    process.exit(result.ok ? 0 : 1);
  }
  case "digest": {
    const path = need(descriptorPath, "digest needs a descriptor");
    const { descriptor, html } = loadPackage(path, option("--html"));
    const digests = computeDigests(need(html, "descriptor names no bundle; pass --html"), descriptor.declaration, descriptor.runtime);
    if (flag("--write")) {
      Object.assign(descriptor, digests);
      writeFileSync(path, `${JSON.stringify(descriptor, null, 2)}\n`);
    }
    console.log(JSON.stringify(digests, null, 2));
    break;
  }
  case "install-plan": {
    if (flag("--chunk-bytes") && !flag("--chunked")) {
      console.error("Warning: --chunk-bytes is ignored without --chunked; using the whole-body route.");
    }
    const { descriptor, html } = loadPackage(need(descriptorPath, "install-plan needs a descriptor"), option("--html"));
    const sources = options("--source").map((pair) => {
      const [record_id, ...why] = pair.split("=");
      return { record_id, reason: why.join("=") || "The work this install belongs to" };
    });
    const bindings = options("--bind").map((pair) => {
      const [port, ...rest] = String(pair ?? "").split("=");
      return { port, collection_id: rest.join("=") };
    });
    let plan;
    try {
      const transitions = ["--update", "--replace", "--after-removal"].filter(flag);
      if (transitions.length > 1) throw new Error(`${transitions.join(" and ")} are mutually exclusive`);
      plan = planInstall({
        descriptor,
        html,
        homeId: need(option("--home"), "install-plan needs --home"),
        reason: need(option("--reason"), "install-plan needs --reason"),
        name: option("--name"),
        sources,
        chunked: flag("--chunked"),
        bodyEncoding: flag("--raw-body") ? "utf8" : option("--body-encoding"),
        chunkBytes: option("--chunk-bytes") ? Number(option("--chunk-bytes")) : undefined,
        updateInstallEventId: flag("--update") ? need(option("--update"), "--update needs a current install event id") : undefined,
        replaceInstallEventId: flag("--replace") ? need(option("--replace"), "--replace needs a current install event id") : undefined,
        afterRemovalEventId: flag("--after-removal") ? need(option("--after-removal"), "--after-removal needs a removal event id") : undefined,
        bindings,
      });
      if (plan.unbound_inputs?.length && !flag("--allow-unbound")) {
        throw new Error(`input port(s) ${plan.unbound_inputs.join(", ")} would install unbound: the tab could not render, so every Save would be refused. `
          + `Pass --bind <port>=<collection id> for each (the Collection the previous install was bound to; read it with manage_artifact_inputs.read)${flag("--chunked") ? " on the whole-body route (drop --chunked)" : ""}, or --allow-unbound to bind later by hand.`);
      }
    } catch (error) {
      console.error(error.message);
      for (const item of error.findings ?? []) console.error(formatFinding(item));
      process.exit(1);
    }
    const out = option("--out");
    if (out) {
      mkdirSync(out, { recursive: true });
      plan.steps.forEach((step, index) => {
        writeFileSync(join(out, `${String(index + 1).padStart(2, "0")}-${step.step}.json`), `${JSON.stringify(step, null, 2)}\n`);
      });
      writeFileSync(join(out, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
      console.log(`${plan.steps.length} calls written to ${out}; digest ${plan.digests.digest}`);
    } else {
      console.log(JSON.stringify(plan, null, 2));
    }
    break;
  }
  case "serve": {
    const { startFakeHost } = await import("../src/fake-host/server.mjs");
    const { descriptor, html } = loadPackage(need(descriptorPath, "serve needs a descriptor"), option("--html"));
    const fixturesPath = option("--fixtures");
    const fixtures = fixturesPath ? (await import(pathToFileURL(resolve(fixturesPath)).href)).default : {};
    const host = await startFakeHost({
      descriptor,
      html,
      fixtures,
      mode: option("--mode") ?? "live",
      port: option("--port") ? Number(option("--port")) : undefined,
      onEvent: (event) => console.log(`${event.type}${event.need ? ` ${event.need} ${JSON.stringify(event.params ?? null)}` : ""}${event.code ? ` [${event.code}]` : ""}`),
    });
    console.log(`fake host for ${descriptor.package} ${descriptor.version}: ${host.url}  (Ctrl-C to stop)`);
    break;
  }
  case "hosted": {
    const path = need(argv[1] && !argv[1].startsWith("--") ? resolve(argv[1]) : null, "hosted needs a saved render_artifact JSON result");
    console.log(JSON.stringify(compareHosted(JSON.parse(readFileSync(path, "utf8"))), null, 2));
    break;
  }
  case "limits":
    console.log(JSON.stringify(LIMIT_SOURCES, null, 2));
    break;
  case "login": {
    const origin = option("--origin") ?? DEFAULT_ORIGIN;
    const email = need(option("--email"), "login needs --email");
    const bearerFile = resolve(option("--bearer-file") ?? DEFAULT_BEARER_FILE);
    let code = option("--code");
    if (!code) {
      await requestCode({ origin, email });
      console.log(`Code sent to ${email}.`);
      if (!process.stdin.isTTY) {
        const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
        const extra = [
          ...(option("--origin") ? ["--origin", quote(origin)] : []),
          ...(option("--bearer-file") ? ["--bearer-file", quote(bearerFile)] : []),
        ];
        console.log(`Finish with: alpha-tab-kit login --email ${quote(email)} ${extra.join(" ")}${extra.length ? " " : ""}--code <code>`);
        break;
      }
      const { createInterface } = await import("node:readline/promises");
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      code = (await rl.question("Code: ")).trim();
      rl.close();
    }
    await verifyCode({ origin, email, code, bearerFile });
    console.log(`Signed in to ${origin}; bearer stored at ${bearerFile} (0600).`);
    break;
  }
  case "install-run": {
    const timeoutMs = flag("--timeout-ms") ? Number(option("--timeout-ms")) : undefined;
    if (flag("--timeout-ms")) {
      need(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 2147483647,
        "--timeout-ms needs a positive integer no greater than 2147483647");
    }
    const target = resolve(need(descriptorPath, "install-run needs a plan directory or plan.json"));
    const plan = JSON.parse(readFileSync(target.endsWith(".json") ? target : join(target, "plan.json"), "utf8"));
    const origin = option("--origin") ?? DEFAULT_ORIGIN;
    const client = createMcpClient({
      origin, bearer: readBearer(resolve(option("--bearer-file") ?? DEFAULT_BEARER_FILE)),
      timeoutMs,
    });
    try {
      await client.open(`Install alpha tab ${plan.package} ${plan.version} with alpha-tab-kit install-run`);
      const result = await runInstall(plan, client, {
        onStep: (entry) => console.log(`${entry.ok ? "ok " : "BAD"} ${entry.step}${entry.record_id ? ` record ${entry.record_id}` : ""}${entry.mismatch ? ` ${JSON.stringify(entry.mismatch)}` : ""}`),
      });
      console.log(JSON.stringify({ run_key: client.runKey, record_id: result.record_id, source_revision: result.source_revision, ...(result.update_event_id ? { update_event_id: result.update_event_id, adoption_carried: result.adoption_carried, adoption_required: result.adoption_required, changed: result.changed, idempotent_retry: result.idempotent_retry } : {}) }, null, 2));
      if (result.update_event_id) {
        const message = result.changed === false
          ? "No change: this update was already applied"
          : result.adoption_carried
            ? "Updated; adoption carried over (no re-adoption needed)"
            : "Updated; Preview and Adopt it at /alpha/ before launching";
        console.log(message + (result.install_status === "disabled"
          ? " (tab is disabled; restore it to launch — restore requires fresh Preview → Adopt)" : ""));
      } else {
        console.log("Installed. Preview and Adopt it in a signed-in browser at /alpha/.");
      }
    } catch (error) {
      console.error(error.message);
      if (client.runKey) console.error(`run ${client.runKey}`);
      process.exit(1);
    }
    break;
  }
  default:
    console.log(USAGE);
    process.exit(command ? 2 : 0);
}
