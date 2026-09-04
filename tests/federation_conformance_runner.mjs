import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const runner = join(repoRoot, "scripts/federation-conformance.mjs");
const generator = join(repoRoot, "scripts/generate-federation-fixtures.mjs");
const sourceProfile = join(repoRoot, "protocol/federation/experimental-jose-hpke-1");

function invoke(args, options = {}) {
  return spawnSync(process.execPath, [runner, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 10_000,
    ...options,
  });
}

function reportFor(args, expectedStatus = 2) {
  const result = invoke(args);
  assert.equal(result.status, expectedStatus, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function isolatedProfile() {
  const root = mkdtempSync(join(tmpdir(), "native-fed-profile-"));
  mkdirSync(root, { recursive: true });
  cpSync(join(sourceProfile, "fixtures"), join(root, "fixtures"), { recursive: true });
  cpSync(join(sourceProfile, "schemas"), join(root, "schemas"), { recursive: true });
  return root;
}

test("CLI rejects unknown, missing, duplicate, and invalid combinations", () => {
  const commands = [
    ["run", "--unknown", "value"],
    ["run", "--filter"],
    ["run", "--clock", "2026-08-02T09:10:00+00:00"],
    ["run", "--format", "yaml"],
    ["run", "--profile", "other-profile"],
    ["run", "--filter", "one", "--filter", "two"],
    ["run", "--adapter-arg", "orphan"],
    ["serve", "--host", "0.0.0.0"],
    ["serve", "--port", "65536"],
    ["probe"],
    ["probe", "--directory-url", "http://directory.example", "--relay-url", "https://relay.example", "--network-descriptor-url", "https://directory.example/v1/network"],
  ];
  for (const command of commands) {
    const report = reportFor(command);
    assert.equal(report.summary.status, "error");
    assert.equal(report.summary.total, 0);
    assert.equal(report.cases.length, 0);
    assert.ok(report.harness_error.code);
  }
});

test("zero selected cases is a harness failure", () => {
  const report = reportFor(["run", "--filter", "definitely-no-such-case"]);
  assert.equal(report.harness_error.code, "no_cases_selected");
  const customClock = "2026-08-02T09:11:00Z";
  const custom = reportFor(["run", "--clock", customClock, "--filter", "definitely-no-such-case"]);
  assert.equal(custom.clock, customClock);
  const invalid = reportFor(["run", "--clock", "not-a-clock", "--filter", "definitely-no-such-case"]);
  assert.equal(invalid.clock, "2026-08-02T09:10:00Z");
});

test("JSONL harness failures preserve one-record framing", () => {
  const customClock = "2026-08-02T09:11:00Z";
  const result = invoke(["run", "--clock", customClock, "--format", "jsonl", "--filter", "definitely-no-such-case"]);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  const lines = result.stdout.trim().split("\n");
  assert.equal(lines.length, 1);
  const summary = JSON.parse(lines[0]);
  assert.equal(summary.type, "summary");
  assert.equal(summary.summary.status, "error");
  assert.equal(summary.harness_error.code, "no_cases_selected");
  assert.equal(summary.clock, customClock);
});

test("adapter spawn, run time, shutdown grace, and output are bounded", () => {
  const missing = reportFor(["run", "--filter", "adapter-only", "--adapter", join(repoRoot, "does-not-exist")]);
  assert.equal(missing.harness_error.code, "adapter_spawn_failed");

  const hanging = reportFor([
    "run", "--filter", "adapter-only", "--adapter", process.execPath,
    "--adapter-arg", "-e", "--adapter-arg", "setInterval(() => {}, 1000)",
    "--adapter-timeout-ms", "100", "--adapter-shutdown-timeout-ms", "100",
  ]);
  assert.equal(hanging.harness_error.code, "adapter_timeout");

  const noisy = reportFor([
    "run", "--filter", "adapter-only", "--adapter", process.execPath,
    "--adapter-arg", "-e", "--adapter-arg", "process.stdout.write('x'.repeat(2048)); setInterval(() => {}, 1000)",
    "--adapter-output-bytes", "1024", "--adapter-timeout-ms", "1000", "--adapter-shutdown-timeout-ms", "100",
  ]);
  assert.equal(noisy.harness_error.code, "adapter_output_limit");
});

test("adapter cannot self-certify without a closed per-case corpus", () => {
  const result = invoke([
    "run", "--filter", "adapter-only", "--adapter", process.execPath,
    "--adapter-arg", "-e", "--adapter-arg", "process.stdout.write(JSON.stringify({status:'pass'}))",
  ]);
  assert.equal(result.status, 1, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.cases[0].status, "fail");
  assert.match(report.cases[0].observed.error, /manifest digest mismatch|corpus is not closed/);
});

test("schema validation and manifest closure fail closed", () => {
  const schemaRoot = isolatedProfile();
  try {
    const fixturePath = join(schemaRoot, "fixtures/positive/network-descriptor.json");
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
    fixture.schema_forbidden_extra = true;
    writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
    const invalid = invoke(["run", "--filter", "network-descriptor"], {
      env: { ...process.env, NATIVE_FEDERATION_PROFILE_ROOT: schemaRoot },
    });
    assert.equal(invalid.status, 1, invalid.stderr || invalid.stdout);
    const report = JSON.parse(invalid.stdout);
    assert.equal(report.summary.status, "fail");
    assert.equal(report.cases[0].observed.layer, "schema");
  } finally {
    rmSync(schemaRoot, { recursive: true, force: true });
  }

  const negativeRoot = isolatedProfile();
  try {
    const fixturePath = join(negativeRoot, "fixtures/negative/alias-local-part-case-mismatch.json");
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
    delete fixture.scenario_type;
    writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
    const invalid = invoke(["run", "--filter", "alias-local-part-case-mismatch"], {
      env: { ...process.env, NATIVE_FEDERATION_PROFILE_ROOT: negativeRoot },
    });
    assert.equal(invalid.status, 1, invalid.stderr || invalid.stdout);
    const report = JSON.parse(invalid.stdout);
    assert.equal(report.cases[0].status, "fail");
    assert.equal(report.cases[0].observed.layer, "schema");
    assert.equal(report.cases[0].observed.error, "invalid_request");
  } finally {
    rmSync(negativeRoot, { recursive: true, force: true });
  }

  const manifestRoot = isolatedProfile();
  try {
    const manifestPath = join(manifestRoot, "fixtures/manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.cases[1].id = manifest.cases[0].id;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const invalid = invoke(["run", "--filter", "network-descriptor"], {
      env: { ...process.env, NATIVE_FEDERATION_PROFILE_ROOT: manifestRoot },
    });
    assert.equal(invalid.status, 2, invalid.stderr || invalid.stdout);
    assert.equal(JSON.parse(invalid.stdout).harness_error.code, "fixture_manifest_invalid");
  } finally {
    rmSync(manifestRoot, { recursive: true, force: true });
  }
});

test("generator check rejects an orphan fixture", () => {
  const profileRoot = isolatedProfile();
  try {
    mkdirSync(join(profileRoot, "fixtures/positive/nested"));
    writeFileSync(join(profileRoot, "fixtures/positive/nested/orphan.json"), "{}\n");
    const result = spawnSync(process.execPath, [generator, "--check"], {
      cwd: repoRoot,
      env: { ...process.env, NATIVE_FEDERATION_PROFILE_ROOT: profileRoot },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /orphaned generated federation fixture/);
  } finally {
    rmSync(profileRoot, { recursive: true, force: true });
  }
});

test("live fakes enforce request proofs, scoped acknowledgements, and alias casing", () => {
  const report = reportFor([
    "run", "--filter", "fake-request-proof,fake-relay-fanout,fake-directory-alias",
  ], 0);
  assert.equal(report.summary.total, 3);
  assert.equal(report.summary.status, "pass");
});

test("request-proof authority is derived from signed principal records", () => {
  const profileRoot = isolatedProfile();
  try {
    const proofPath = join(profileRoot, "fixtures/request-proof-signing.json");
    const proof = JSON.parse(readFileSync(proofPath, "utf8"));
    proof.signers.alice_root.operations = ["relay.submit"];
    proof.directory_audience = "https://attacker.invalid";
    proof.relay_audience = "https://attacker.invalid";
    writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
    const result = invoke(["run", "--filter", "fake-request-proof"], {
      env: { ...process.env, NATIVE_FEDERATION_PROFILE_ROOT: profileRoot },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout).summary.status, "pass");
  } finally {
    rmSync(profileRoot, { recursive: true, force: true });
  }
});

test("freshness, expiry, and key validity use exact half-open boundaries", () => {
  const notBefore = reportFor(["run", "--filter", "profile-negotiation-response", "--clock", "2026-08-02T09:00:00Z"], 0);
  assert.equal(notBefore.summary.status, "pass");

  const keyBoundary = reportFor(["run", "--filter", "network-descriptor-authority-key-at-not-after"], 0);
  assert.equal(keyBoundary.summary.status, "pass");
  const installationBoundary = reportFor(["run", "--filter", "installation-authorization-at-signing-not-after"], 0);
  assert.equal(installationBoundary.summary.status, "pass");

  const stale = reportFor(["run", "--filter", "profile-negotiation-response", "--clock", "2026-08-02T09:15:00Z"], 1);
  assert.equal(stale.cases[0].observed.error, "stale_document");
  assert.equal(stale.cases[0].observed.layer, "freshness");

  const expired = reportFor(["run", "--filter", "profile-negotiation-response", "--clock", "2026-08-03T09:00:00Z"], 1);
  assert.equal(expired.cases[0].observed.error, "expired");
  assert.equal(expired.cases[0].observed.layer, "freshness");

  const profileRoot = isolatedProfile();
  try {
    const principalPath = join(profileRoot, "fixtures/positive/principal-document.json");
    const principal = JSON.parse(readFileSync(principalPath, "utf8"));
    principal.document.fresh_until = "2026-08-02T09:16:00Z";
    writeFileSync(principalPath, `${JSON.stringify(principal, null, 2)}\n`);
    const invalidWindow = invoke(["run", "--filter", "principal-document"], {
      env: { ...process.env, NATIVE_FEDERATION_PROFILE_ROOT: profileRoot },
    });
    assert.equal(invalidWindow.status, 1, invalidWindow.stderr || invalidWindow.stdout);
    const report = JSON.parse(invalidWindow.stdout);
    const baseline = report.cases.find((entry) => entry.id === "principal-document");
    assert.equal(baseline.observed.error, "invalid_request");
    assert.equal(baseline.observed.layer, "freshness");
  } finally {
    rmSync(profileRoot, { recursive: true, force: true });
  }
});
