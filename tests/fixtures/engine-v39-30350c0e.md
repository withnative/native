# Frozen engine-39 database

`engine-v39-30350c0e.db.gz` is an immutable, checkpointed SQLite database
created by the released engine-39 tree at commit `30350c0e`, the exact parent
of the engine-40 schema change (`b8db9474`). It was not created by downgrading
or restamping current DDL.

The generator was a temporary binary compiled in a detached worktree at that
commit. It called that revision's `native_ce::create_database`, then its public
`store::create_record` with the pinned record id
`607a0000-0000-4000-8000-000000000001`, closed the database, and checkpointed
the WAL with the system SQLite before deterministic `gzip -n -9` compression.
The temporary generator is deliberately not product code; the immutable bytes,
source revision, and closed digests are the provenance authority.

- uncompressed database SHA-256:
  `189a64f4e4e429e6cc9739503f677eaccf3f3b956648cb9f10cd9d99e170dc76`
- deterministic gzip SHA-256:
  `96e0e67102ca98d61c107d339812fd78a3825dce25eef83792896e89b24ba971`
- measured structural-contract SHA-256:
  `3970006e1e92b8870f86506ba490f4ff8274a798a2df88e4700f12c135d6c1a7`

Tests verify both byte digests before use. Production read-only migration
preflight compares the complete on-disk table/column/index/trigger contract to
the independently pinned structural digest.
