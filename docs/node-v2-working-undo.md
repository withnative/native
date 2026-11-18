# Private v2 working-copy undo qualification

`kernel::working_undo` is a private module with no production rebase caller.
The caller serializes W writes, owns the outer sqlx write transaction, and puts
each speculative proposal in a savepoint. Capture errors require rolling that
savepoint back. `retry_without_capture` marks W undo-unavailable in the same
transaction as the visible retry; a later rebase must rebuild W.

Undo borrows sqlx's locked native handle through rusqlite and runs synchronously
without an await while triggers are suppressed. Configuration guards restore
triggers and FK deferral. Dropping the outer sqlx transaction rolls back after
cancellation. Identical cached sqlx statements are tested before suppression,
during suppression and after re-enabling guards, all in one transaction.

## Foreign-key actions

Disabling application triggers and deferring foreign keys does **not** suppress
SQLite's FK actions. The collector resolves `foreign_key_list` once when it is
installed or reopened. Missing parents/columns, inconsistent composite metadata
or unsupported action names fail closed. Implicit references resolve to the
ordered parent primary key; composite references retain their column mapping.

Before an inverse DELETE with `ON DELETE CASCADE`, `SET NULL` or `SET DEFAULT`,
the collector checks for any surviving child referencing that parent. Before an
inverse UPDATE that changes a referenced parent column and has an ON UPDATE
action, it performs the same check. Surviving children cause the typed refusal
`UndoRefused::ForeignKeyAction { parent_table, child_table }`, before executing
the inverse. Ordinary captured children are undone first. An unusual nested
trigger ordering may refuse safely instead of completing an undo.

The existence query locates the current parent by its recorded key and joins
the child with the conservative comparison used by SQLite's action trigger.
In mixed-affinity cases that comparison can be broader than the FK constraint
lookup itself (for example TEXT parent '01' and INTEGER child 1); the guard
must refuse before such an action runs. NULL child keys do not match.
Available child indexes can serve the equality lookup.
After inverses, changed tables and all their referencing children still receive
`foreign_key_check` before deferral is cleared, including untouched children.

`sqlite3_total_changes64` (via `Connection::total_changes`) counts FK-action
changes even with application triggers disabled. Qualification covers DELETE
and UPDATE with CASCADE, SET NULL and SET DEFAULT: one direct parent statement
reports two total changes when it also changes one child. Undo compares total
changes with its ordinary inverse statement count and refuses any surplus or
deficit. A test corrupts the cached precheck registry and verifies this second
line of defence still refuses and rolls back the inverse savepoint.

FTS logical inverses run through the virtual table, preserving rowids and
repairing its index as they restore rows. Each legitimately changes physical
shadow rows too. Those measured deltas are accounted separately from ordinary
row inverses; FK prechecks still apply to the registered FTS content parent.
FTS5 can defer physical writes until an unrelated statement savepoint. Undo
uses the bundled FTS5 `flush` command after each logical FTS inverse, flushing
only pending terms inside its accounting window. Without that flush, the real
handler round trip showed 16 deferred FTS changes incorrectly charged to
ordinary inverses. No full index rebuild or optimize is used.
The qualification checks logical-row equality and FTS integrity rather than
requiring an unchanged physical index layout.

## Child-index cost

The gate prints an audit of every FK in the real v2 write fixture, checking for
a nonpartial index whose leading columns cover the child FK, or an INTEGER
PRIMARY KEY rowid lookup. It also measures 100 negative existence checks against
50,000 child rows, before and after adding the child-column index, and prints
both query plans. The timed loop reuses a prepared statement; it excludes SQL
preparation and the one-time metadata resolution. Timings are observations on
this VM, not latency guarantees.

Measured on this VM on 13 Nov 2026, with the bundled SQLite build:

| Child lookup | 100 checks | Mean per check | Query plan |
|---|---:|---:|---|
| No child index | 195,375 µs | 1,953.75 µs | `SCAN c` |
| `child_p(p)` covering index | 98 µs | 0.98 µs | `SEARCH c USING COVERING INDEX child_p (p=?)` |

The real v2 fixture has the following FKs without a qualifying child-prefix
index. All ten use NO ACTION for both DELETE and UPDATE. None of the current
mutating-action FKs used by the prechecks lacks a child lookup index. No schema
index changes are made by this module.

| Child columns | Referenced parent |
|---|---|
| `kernel_app_actions(event_seq)` | `content_events` |
| `kernel_app_state(event_seq)` | `content_events` |
| `kernel_attachment_blobs(sha256)` | `kernel_blobs` |
| `kernel_blob_handles(sha256)` | `kernel_blobs` |
| `kernel_identity_bindings(record_id)` | `kernel_records` |
| `kernel_instruction_bindings(account_principal)` | `kernel_principals` |
| `kernel_records(owner_id)` | `kernel_principals` |
| `kernel_root_bootstrap(principal_id)` | `kernel_principals` |
| `kernel_roots(owner_id)` | `kernel_principals` |
| `kernel_roots(parent_id)` | `kernel_roots` |

## Qualification result

`CARGO_BUILD_JOBS=8 RUST_MIN_STACK=536870912 cargo test -p native-ce --lib
--features v2-kernel-probe working_undo -- --nocapture`: **31 passed, 0 failed,
0 ignored**. This includes the prior 21 cases, the review-hardening regressions
below, all three mutating FK actions
for DELETE and key UPDATE, conservative affinity/collation matching, explicit
metadata refusal, the change-count fallback, and the indexed/unindexed cost
probe. The real-handler create/append/link/blob round trip retains full ordinary
row, event-log, logical FTS row, blob, receipt and sqlite_sequence equality,
plus FTS integrity.

Check, lib clippy with `-D warnings`, fmt, source-boundary admission and live
test-policy validation pass. The broad `scripts/gate` is deferred to integration
CI under the maintainer guide's hardware fallback; this module qualification
is not a claim that the full repository gate or release admission ran. A push
to this feature branch without a PR does not start the main/PR CI workflow.

## Review hardening

The manager must retain one **physical writer connection** for the collector's
lifetime. Every speculative write must call `proposal` inside its savepoint on
that writer before issuing SQL. No other pooled connection may write W. A
serial write pool with exactly one physical connection is suitable only while
that connection is retained; reconnect/replacement requires `Collector::open`
on the new pinned writer before writes resume. Collector entry points compare
the native SQLite handle with the registered writer and refuse a different
connection. Capture also refuses if recursive triggers, FK enforcement or
application triggers are off. This is a required manager contract, not a claim
that this module intercepts arbitrary SQL issued behind its back.

Borrowing sqlx's handle must not run rusqlite's non-owned `Connection` destructor:
rusqlite 0.32 clears shared hooks before checking ownership. The wrapper is held
in `ManuallyDrop`, and its statement cache is explicitly flushed on return or
unwind before the sqlx lock releases. This deliberately retains the wrapper's
small Rust bookkeeping allocations rather than invoking its unsafe-for-sharing
cleanup. Certification of ordinary copies with no private objects uses only
SQLx and never creates such a wrapper. Tests preserve progress and commit hooks
across successful callbacks, errors and unwind.

Private undo tables are no longer global projection-digest exclusions. A shared,
unconditionally compiled SQLx guard permits exclusion only for the exact three
table definitions, empty undo and boundary tables, and a singleton disabled
capture control. Populated ledgers or enabled capture refuse generic digests
and standby certification. Altered or partial DDL remains visible; exact trigger
names must also match generated DDL for schema-inventory exemption. A stray
`working_undo_x` is never exempted. The same guard precedes digest capture, so
cached projection proofs cannot silently skip retained private rows either.
The first live caller must supply the certification snapshot described below. A working copy with a
pending tail intentionally cannot claim a generic accepted-state digest.

REAL after-images compare their binary64 bits, including the sign of zero.
Installation/reopen validates the pinned FTS5 definition, logical column order
and internal content layout before installing any capture triggers. The real
write gate uses the existing private one-slot pool fixture, spans multiple proposal boundaries and renames an accepted record
twice through the ordinary field UPSERT path. Eligible handlers do not use
`INSERT OR REPLACE`; a separate collector gate qualifies its implicit delete
and tests that recursive-triggers-off is refused before it can run.


## Admission criteria for the first caller

- **Pinned writer.** The working-copy manager owns a **ONE-connection W pool**.
  Its pinned connection stays alive for the collector's entire lifetime, with
  no pool recycling. `recursive_triggers` and `foreign_keys` are set in the
  pool's connect options. `assert_writer` only detects a wrong connection; it
  does not prevent writes made elsewhere. The manager must enforce exclusive
  use of this writer for W writes.
- **Same snapshot.** `exclusions` must run inside the **same read transaction**
  as the schema inventory or digest it qualifies. `standby::schema` currently
  runs the inventory and exclusion checks on an autocommit connection. That is
  acceptable only while there is no live W; the first caller must establish
  the shared read transaction before admitting a live working copy.
