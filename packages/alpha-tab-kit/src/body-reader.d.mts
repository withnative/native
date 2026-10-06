export type BodyReadRequest = {
  record_id: string;
  page_bytes: number;
} & ({ revision?: never; cursor?: never } | { revision: string; cursor: string });
export interface BodyReadLimits {
  max_page_bytes: number;
  max_response_bytes: number;
  max_body_bytes?: number;
  max_source_bytes?: number;
  max_provenance_payload_bytes?: number;
  max_provenance_events?: number;
  request_timeout_ms?: number;
}
/** Candidate canonical object; an adapter must remove its broker wrapper. */
export interface BodyPage {
  contract: "records.body.read.v1";
  record_id: string;
  revision: string;
  body_digest: string;
  body_present: boolean;
  encoding: "utf-8";
  start_byte: number;
  end_byte: number;
  total_bytes: number;
  text: string;
  complete: boolean;
  next_cursor: string | null;
  limits: BodyReadLimits;
}
/** Unknown or unpublished code/reason pairs are sanitized at runtime. */
export interface BodyRefusal {
  contract: "records.body.read.v1";
  error: { code: string; reason: string };
}
export interface CompleteBody {
  record_id: string;
  body: string | null;
  body_present: boolean;
  body_digest: string;
  revision: string;
  total_bytes: number;
}
export interface BodyReadProgress {
  readonly receivedBytes: number;
  readonly totalBytes: number;
  readonly pages: number;
}
export type BodyReadErrorCode = "invalid_params" | "unsupported_profile" | "unsupported_capability"
  | "undeclared_read" | "adoption_required" | "source_integrity" | "invalid_cursor" | "cursor_expired"
  | "record_unavailable" | "access_lost" | "scope_denied" | "revision_changed" | "timeout" | "engine"
  | "too_large" | "resource_exhausted" | "remote_refusal" | "protocol_error" | "incomplete"
  | "transport_error" | "client_error" | "client_limit" | "cancelled";
export type BodyReadErrorReason = "request" | "cursor" | "primary_sqlite_required" | "portability_policy"
  | "source" | "descriptor" | "target" | "scope" | "incarnation" | "integrity_or_execution"
  | "body_read_work_limit" | "process_busy"
  | "source_work_limit" | "provenance_work_limit" | "vm_work_limit" | "result_budget"
  | "unknown_refusal" | "invalid_error" | "invalid_page" | "invalid_limits" | "invalid_offsets"
  | "invalid_completion" | "invalid_presence" | "response_budget" | "published_body_limit"
  | "noncontiguous_page" | "assembly_changed" | "nonprogress" | "invalid_options" | "request_budget"
  | "progress_failed" | "body_memory_limit" | "missing_completion" | "read_page_failed" | "aborted";
export class BodyReadError extends Error {
  readonly code: BodyReadErrorCode;
  readonly reason: BodyReadErrorReason;
  constructor(code: BodyReadErrorCode, reason: BodyReadErrorReason);
}
export interface BodyReadOptions {
  recordId: string;
  /** Trusted callback returning parsed canonical objects, with no authority granted by this helper. */
  readPage: (request: BodyReadRequest, options: { signal?: AbortSignal }) => Promise<BodyPage | BodyRefusal>;
  /** Integer 4..32768, default32768. */
  pageBytes?: number;
  /** UTF-8 buffering cap 0..16777216, default16777216; not a heap/storage cap. */
  maxBodyBytes?: number;
  signal?: AbortSignal;
  /** Synchronous counts only, no partial text/revision/guard. */
  onProgress?: (progress: BodyReadProgress) => void;
}
export function readBody(options: BodyReadOptions): Promise<CompleteBody>;
