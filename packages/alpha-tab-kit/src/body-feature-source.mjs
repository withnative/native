// Feature-only immutable source staging from qualified root 1bad1ca097caf0b78d5f46a974817e40a0e5f341.
// No ordinary plan/default/HTTP execution. Do not add legacy options here.
import { createHash } from "node:crypto";
import { computeDigests } from "./digest.mjs";
import { chunkUtf8 } from "./install.mjs";
const sha256 = text => createHash("sha256").update(text,"utf8").digest("hex");
const FEATURE_RUNTIME = "native.html.v1";

export function prepareSourceSteps(p) {
  const { descriptor, html } = p;
  const digests = computeDigests(html, descriptor.declaration, descriptor.runtime);
  const chunks = chunkUtf8(html, p.chunkBytes ?? 8000);
  const sources = p.sources ?? [];
  const steps = [];
  let prefix = "";
  chunks.forEach((chunk, index) => {
    const before = prefix;
    prefix += chunk;
    const args = index === 0
      ? { type: "Document", kind: "note", name: p.name ?? `${descriptor.package} ${descriptor.version} (alpha tab source)`, home_id: p.homeId, summary: p.summary ?? `Source bytes of alpha tab ${descriptor.package} ${descriptor.version}; staged as a note, then switched to native.html.v1.`, body: chunk, reason: p.reason, sources }
      : { id: "{{record_id}}", body_append: chunk, if_body_digest: sha256(before), reason: `${p.reason} (chunk ${index + 1} of ${chunks.length})`, sources };
    steps.push({
      step: index === 0 ? "create-note" : `append-${index + 1}`,
      executor: "records_write",
      operation: index === 0 ? "create_record" : "update_record",
      arguments: args,
      expect: { body_digest: sha256(prefix), body_bytes: Buffer.byteLength(prefix, "utf8") },
    });
  });
  steps.push({
    step: "source-revision",
    executor: "sql_read",
    operation: "query_sql",
    // Same event types as resolve_alpha_tab_source_in (alpha_tabs.rs:2008):
    // artifact writes also append `artifact.source_attested` events.
    // The engine additionally requires json_type(payload,'$.body') IS NOT
    // NULL, but content_events exposes no payload column to query_sql. This
    // query therefore relies on an invariant of this plan: every write before
    // this step (create_record with `body`, update_record with `body_append`)
    // carries a body, and nothing else writes the record meanwhile (each
    // append is guarded by if_body_digest). Do not insert a body-less write
    // before this step.
    arguments: { sql: "SELECT id, type FROM content_events WHERE record_id = ?1 AND type IN ('record.created', 'record.updated', 'receipt.committed.v1') ORDER BY local_seq DESC, id LIMIT 1", parameters: [{ type: "text", value: "{{record_id}}" }] },
    capture: { source_revision: "rows[0].id" },
    note: "Run before any other write to the record: the newest event is the last body-carrying write.",
  });
  steps.push({
    step: "rekind-artifact",
    executor: "records_write",
    operation: "update_record",
    arguments: { id: "{{record_id}}", kind: "artifact", facets: { runtime: FEATURE_RUNTIME }, if_body_digest: digests.bundle_sha256, reason: `${p.reason} (switch to native.html.v1; validates the complete document)`, sources },
    expect: { body_digest: digests.bundle_sha256 },
  });
  if (p.replaceInstallEventId) {
    steps.push({
      step: "remove-previous-install",
      executor: "artifacts_write",
      operation: "manage_alpha_tabs.remove",
      arguments: { package: descriptor.package, expected_install_event_id: p.replaceInstallEventId, reason: `${p.reason} (install refuses a package that is already installed)` },
    });
  }
  return { digests, chunks, steps };
}

