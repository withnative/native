# Receiver producer evidence

`generate.py` captures engine-95 output from the actual PR #3467 production
constructors, registry, app dispatcher, export and delta paths. Its default
source revision is `79570567dc19b5fd1b91191d302a7a573265073f`.

Run it in an explicitly managed disposable checkout:

```sh
python3 tests/fixtures/receiver-shapes/generate.py --source-root /path/to/producer
```

The temporary test is restored on success or failure. It supplies a valid
database-origin input to the existing synthetic import fixture before import;
it never rewrites canonical event provenance. The app action is unkeyed while
its live room is open. The ordinary keyed no-op uses a separate record and the
verified base blob inventory accompanies the real delta capture.

SQLite and response files are gzip-compressed with a fixed gzip timestamp.
Canonical event bytes inside them remain the producer's bytes. `metadata.json`
records the source revision, actual shape and generated identities.
`contracts95.json` captures complete production operation descriptors, including
their actual public digests. Normalized descriptor fingerprints and journal
contract digests are different values; test history is never runtime discovery.

Regenerate and review against B's final code before its rollout. A production
constructor or schema change is not authorized by replacing a fixture.

The receiver registry's immutable v1 DDL lives in `src/standby/shapes/`.
Engine94 was captured from `03b1bbb3f4204591b69e0e80a2d14788bf0535ef`
(406 statements, `e8975ea5ec8a281d7ed4f70ca3bf68d56f70f7038571e3f20109423bda348fe5`),
and engine95 from `79570567dc19b5fd1b91191d302a7a573265073f`
(407 statements, `a122164c9e26ac98db3e04f3769a3edcc60ce25f78ecc2305c7aa5037afdc30f`).
Reproduce either with `freeze-v1-ddl.py --revision <exact-source> --sha256
<release-ddl-digest> --output <file>`. The script evaluates only the source DDL
constants; admission builds private in-memory reference databases from these
files and freshly compares the actual database's complete structural contract.
Frozen evidence never follows the current canonical writer's DDL implicitly.

Manual installed-v7 qualification uses `qualify-installed-v7.py`. It requires a
real pre-A03b1bbb3 `mcp-stdio` with `v2-kernel-probe`, a stamped A artifact at the
current tested commit, and either the exact79570567d disposable producer source
or its recorded frozen test-runtime artifact. `--producer-test-binary` verifies
the preserved source/artifact receipt; it never substitutes current A for the
reference producer. Both temporary harness edits are restored in `finally`.
Missing/wrong artifacts fail explicit qualification, and this manual cell is
not silently counted as passed by ordinary CI. Runtime files/logs are preserved
in its evidence directory on failure.3be9 remains the real copy-downgrade
artifact; it predates the installed flag and cannot generate v7, as recorded in
`pre-a-v7-artifact-mismatch.json`.

`qualify-a95-process.py` copies an explicitly generated private downgrade store
to a new directory under `/tmp`, selects its95 generation, invokes the stamped
receiver, and asserts ordinary reads, actual capture age, STANDBY_READ_ONLY on
writes, and unchanged94/95 snapshot and rollback-pin bytes. The source-stamped
79af result is historical pre-rebase evidence in `a79af-process-receipt.json`.
No script operates on an installed node service or production workspace copy.
