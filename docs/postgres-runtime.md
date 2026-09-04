# Postgres runtime adapter

`mcp-stdio` can select one Postgres logical database by setting
`NATIVE_CE_POSTGRES_CONFIG` to a JSON file. This stdio route is deliberately a
trusted-local boundary: possession of the process and its secret configuration
is the authority, matching local SQLite stdio. It uses the in-process local
caller and rejects `NATIVE_CE_ACCOUNT`, `--account`, or any simultaneous SQLite
target instead of treating an unbootstrapped account string as authenticated
membership. Hosted/member-authenticated Postgres ingress is not yet exposed.
The `postgres` feature is opt-in since 13 Aug 2026 (task e8074ff): build with
`--features postgres` (the shipped Docker image does); `postgres-tests` only
adds the external-server contract suite.

This is a production-selectable route, not a production support claim. The
compiled `postgres-server@5` profile remains `spike`. The registry exposes the
qualified operation set recorded in the generated backend-support manifest,
including record lifecycle and views, attachments, bounded logical queries,
identity resolution and binding, native-indexed `search`, schema discovery,
and the independently qualified `query_sql` boundary. Operations outside that
recorded set fail with the exact `not implemented for the postgres backend`
boundary until their domain substrate and qualification tasks land.

## Configuration

The file format is `native.postgres-runtime.v1` and rejects unknown fields.
It contains credentials, so deploy it through the platform's secret provider
with permissions limited to the Native process. Values are redacted from
`Debug`, `engine_info`, and configuration reports.

```json
{
  "format": "native.postgres-runtime.v1",
  "logical_database_id": "workspace:example",
  "endpoint_url": "postgresql://database.internal/native",
  "runtime_password": "secret-provider-value",
  "tls_mode": "verify-full",
  "application_name": "native-ce",
  "pool": {
    "min_connections": 1,
    "max_connections": 12,
    "acquisition_timeout_ms": 5000,
    "idle_lifetime_ms": 300000,
    "max_lifetime_ms": 1800000
  },
  "timeouts": {
    "statement_timeout_ms": 30000,
    "lock_timeout_ms": 5000
  },
  "admin_url": "postgresql://provisioner:secret-provider-value@database.internal/native",
  "ownership_token": "secret-provider-ownership-token"
}
```

`tls_mode` is required and accepts `disable`, `prefer`, `require`, `verify-ca`,
or `verify-full`. The Postgres feature explicitly compiles SQLx's rustls TLS
backend with native certificate roots. Pool acquisition, statement, lock,
idle, and maximum lifetime settings are explicit and bounded. `lock_timeout_ms` may not exceed
`statement_timeout_ms`. Runtime connection setup changes those two timeout
settings only; it never sets or mutates `search_path`.

`admin_url` and `ownership_token` are optional as a pair. When omitted, startup
connects to an already-provisioned target and requires the exact current schema
revision. When supplied, startup idempotently provisions before connecting.
Administrative credentials are never retained by the returned engine handle.

The schema and login role are deterministic hashes of `logical_database_id`;
operators cannot use this configuration to route the adapter into an arbitrary
existing schema. Every Native-owned statement schema-qualifies its relations.

## Provisioning and cleanup

Provisioning takes a database-global session advisory lock plus the logical
database's session lock and holds both through role and schema creation,
runtime-role migration, and the final readiness check. The global lock
serializes `GRANT CONNECT`, which rewrites one shared database ACL tuple even
for otherwise independent logical schemas; the logical lock fences concurrent
first provision of the same substrate. Both objects receive a comment containing hashes of the
logical database identity and ownership token. An existing name with a missing
or different marker fails closed. The runtime role is forced to `LOGIN`,
`NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOINHERIT`, `NOREPLICATION`, and
`NOBYPASSRLS`; it receives connect plus usage/create privileges on its own
schema. Native tables are created by that role inside one transaction.

`PostgresRuntimeConfig::drop_owned` verifies both ownership markers before it
drops anything. It drops only the deterministic schema and role and is
idempotent after success. It does not run `DROP OWNED`, change unrelated
schemas, or use a shared tenant table.

The dedicated provisioning connection is marked close-on-drop before it
acquires the session lock. Normal completion explicitly unlocks it; cancellation
or task abortion physically closes the connection so a session-held advisory
lock cannot be returned to the administrative pool.

### Schema v2/v3/v4 compatibility

The authoritative substrate uses physical schema v5. It is exactly the v4
delete and append-only, gapless identity-binding substrate plus the
`records_native_fts` GIN index. `provision_and_connect` accepts only an exact
owned v4 predecessor and installs that index and the v5 ledger entry in one
transaction. Plain `connect` refuses v4 so an unprivileged runtime never
silently changes physical shape.

The independently qualified v2 and v3 spike shapes did not contain the same
complete delete and binding-audit substrate as v4 and remain deliberately
non-migratable. Native does not claim that it can infer or backfill every
authoritative deletion, identity, policy, control, and audit invariant from
either layout. A v2 or v3 target therefore remains fail-closed and cannot
report read or write readiness under the v5 runtime.

Operators upgrading a v2 or v3 spike must use a controlled reprovision/import: export
the qualified canonical content slice with the prior binary, provision a clean
v5 logical database, import it through the canonical interchange path, verify
replay/readiness, and only then switch the runtime configuration. Keep the old
schema as a rollback artifact until that verification succeeds. Supplying
administrative credentials does not silently upgrade or overwrite either
marked predecessor schema; startup returns the explicit reprovisioning
requirement instead.

## Health contract

Process liveness is separate from target health. Readiness acquires a pooled
connection, verifies the authenticated runtime role and schema usage, checks
that the login has no database-level or foreign-schema create privilege, and
requires the complete owned relation set with effective SELECT/INSERT/UPDATE/
DELETE privileges. It separately checks the qualified migration ledger and
reports schema currency as `current`, `missing`, `behind`, or `ahead`. A maximum
migration version alone is therefore insufficient for readiness. Write
readiness additionally performs and rolls back a harmless update of the event
cursor, and is true only when that effective write probe and all other
readiness checks pass. `engine_info` returns this health report and the fully
redacted runtime configuration.

Postgres qualifies record-scoped `get_history` under one authorization and
selection snapshot. Metadata detail is the default and derives its visible
reason, changed fields, and UTF-8 JSON payload size only after member-facing
payload and attribution redaction; `detail: "full"` returns the complete
caller-visible payload. Whole-log history remains unqualified, so calls
without `record_id` fail closed.
