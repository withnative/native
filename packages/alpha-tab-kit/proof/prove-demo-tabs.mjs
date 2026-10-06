#!/usr/bin/env node
// Evidence for the alpha-tab-kit PR, not part of the package API: run the
// kit's validator and fake host against real packages from the demo-tabs
// branches, read straight out of git. Each package's own synthetic fixture
// world is lifted from its check script, so only the host differs from what
// the package's author tested against.
//
//   node packages/alpha-tab-kit/proof/prove-demo-tabs.mjs [--ref origin/demo-tabs-all]
//
// Needs `git fetch origin demo-tabs-all` and Playwright (see README).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { validatePackage } from "../src/validate.mjs";
import { openFakeHost, loadChromium } from "../src/fake-host/playwright.mjs";

const refArg = process.argv.indexOf("--ref");
const REF = refArg > 0 ? process.argv[refArg + 1] : "origin/demo-tabs-all";
const DIR = "experiments/alpha-tab-proof-packages";
const show = (rev, path) => execFileSync("git", ["show", `${rev}:${path}`], { encoding: "utf8", maxBuffer: 16 << 20 });
// The last commit on REF that still carried Slack 0.1.0 (the one before
// "Slack workspace tab 0.1.1: serialise host reads").
const slack010 = execFileSync("git", ["log", "--format=%H", "--grep=Slack workspace tab 0.1.1", "-1", REF], { encoding: "utf8" }).trim() + "^";

function fixtureSection(check, start, end) {
  const from = check.indexOf(start);
  const to = check.indexOf(end, from);
  if (from < 0 || to < 0) throw new Error(`fixture markers not found: ${start} … ${end}`);
  return check.slice(from, to);
}

const PACKAGES = [
  {
    label: "prism 0.1.0",
    rev: REF,
    slug: "prism",
    world(check) {
      const section = fixtureSection(check, "// ---- fixture world", "const expect =");
      return new Function("createHash", `${section}; return { live, detail, T1, t1 };`)(createHash);
    },
    fixtures(world) {
      const sql = { "prism.records": world.live.sql["prism.records"].rows };
      for (const [need, byId] of Object.entries(world.detail)) sql[need] = ({ id }) => byId[id] ?? [];
      return { sql };
    },
    async drive(tab, world) {
      await tab.frame.locator("#rec-title").filter({ hasText: world.t1.name }).waitFor({ timeout: 5000 });
      await tab.page.waitForTimeout(1500);
      const skeletons = await tab.frame.locator(".skel").count();
      const docsHeading = await tab.frame.locator("#lens-docs .gd-body h4").first().textContent({ timeout: 3000 }).catch(() => null);
      return { opened: world.t1.name, skeletons_left: skeletons, docs_heading: docsHeading, loaded: skeletons === 0 && docsHeading === "Goal" };
    },
  },
  ...[["slack-workspace 0.1.1", REF], ["slack-workspace 0.1.0", slack010]].map(([label, rev]) => ({
    label,
    rev,
    slug: "slack-workspace",
    world(check) {
      const section = fixtureSection(check, "// ---- synthetic fixture", "// ---- walkthrough");
      return new Function("createHash", `${section}; return { R, live, bodies, threadRows, unfurlRows };`)(createHash);
    },
    fixtures(world) {
      const sql = {};
      for (const [key, section] of Object.entries(world.live.sql)) sql[key] = section.rows;
      sql["slack.body"] = ({ id }) => (world.bodies[id] === undefined ? [] : [{ id, body: world.bodies[id] }]);
      sql["slack.thread"] = ({ id }) => world.threadRows[id] ?? [];
      sql["slack.unfurl"] = ({ ref }) => world.unfurlRows[ref] ?? [];
      return { sql };
    },
    async drive(tab, world) {
      // The walkthrough step that 0.1.0 failed in the shell: open a thread,
      // which needs the record body and its comments.
      const root = tab.frame.locator("#msgs .msg", { has: tab.frame.locator(`.u-title[data-native-record-id="${world.R.T1.id}"]`) }).last();
      await root.hover();
      await root.locator(".thread-foot").click();
      await tab.page.waitForTimeout(1500);
      const pane = (await tab.frame.locator("#pane").textContent()) ?? "";
      const body = pane.includes("A changed task moves group");
      const comments = pane.includes("wire the keyed freshness read");
      return { thread: world.R.T1.name, body_loaded: body, comments_loaded: comments, says_could_not_be_read: pane.includes("could not be read"), loaded: body && comments };
    },
  })),
];

const chromium = await loadChromium();
if (!chromium) throw new Error("Playwright is not installed: see packages/alpha-tab-kit/README.md");
const browser = await chromium.launch();
const results = [];
try {
  for (const spec of PACKAGES) {
    const descriptor = JSON.parse(show(spec.rev, `${DIR}/${spec.slug}-descriptor.json`));
    const html = show(spec.rev, `${DIR}/${descriptor.bundle}`);
    const check = show(spec.rev, `${DIR}/${spec.slug}-check.mjs`);
    const validation = validatePackage({ descriptor, html });
    const world = spec.world(check);
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const tab = await openFakeHost(page, { descriptor, html, fixtures: spec.fixtures(world), latencyMs: 30 });
    let outcome;
    try {
      outcome = await spec.drive(tab, world);
    } finally {
      outcome = { ...outcome, audit: await tab.audit() };
      await tab.close();
      await page.close();
    }
    results.push({
      package: spec.label,
      rev: execFileSync("git", ["rev-parse", "--short", spec.rev], { encoding: "utf8" }).trim(),
      digest: validation.digests?.digest,
      validator: validation.ok ? "pass" : "fail",
      errors: validation.findings.filter((item) => item.severity === "error").map((item) => `${item.rule}: ${item.message}`),
      warnings: validation.findings.filter((item) => item.severity === "warning").map((item) => `${item.rule}: ${item.message}`),
      fake_host: outcome.loaded && outcome.audit.dropped.length === 0 ? "pass" : "fail",
      ...outcome,
    });
  }
} finally {
  await browser.close();
}
console.log(JSON.stringify(results, null, 2));
const expected = { "prism 0.1.0": "pass", "slack-workspace 0.1.1": "pass", "slack-workspace 0.1.0": "fail" };
const surprises = results.filter((result) => result.validator !== "pass" || result.fake_host !== expected[result.package]);
if (surprises.length) {
  console.error(`unexpected outcome for: ${surprises.map((result) => result.package).join(", ")}`);
  process.exit(1);
}
console.error("proof holds: prism and slack 0.1.1 pass; slack 0.1.0's busy bug is caught by the fake host");
