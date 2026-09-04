# Native Canvas — experimental-canvas-1

Status: Experimental. Public wire schemas for the Native Canvas v1 batch protocol, implemented by the `read_canvas` and `manage_canvas` tools on the reference SQLite engine. The narrative contract is [`docs/canvas-protocol-v1.md`](../../../docs/canvas-protocol-v1.md); the engine's own typed validation in `src/canvas.rs` is authoritative where the two disagree, and a disagreement is a bug to report.

- `schemas/batch.schema.json` — `native.canvas-batch.v1`, the envelope `manage_canvas.commit_batch` accepts.
- `schemas/batch-result.schema.json` — `native.canvas-batch-result.v1`, the structured outcome it returns.

Per-kind `props` contracts (note, shape, stroke, connector, frame, record_card) are documented in the protocol note and enforced by the engine; they are deliberately not frozen as schemas while the protocol is experimental. No conformance fixtures exist yet.
