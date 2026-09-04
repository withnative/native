# Governed relationship pilot measurement appendix

This is the reproducibility record for the measurements summarized in
`docs/testing-strategy.md`. The before revision is the PR 490 merge base
`a1f711f4506bf939b9769dd7c947ab824b2bf667`; the after revision is the
relationship-kernel extraction in this pull request.

## Environment and commands

- Rust `1.90.0 (1159e78c4 2025-09-14)` and Cargo `1.90.0`.
- AMD EPYC 7232P, 8 cores / 16 hardware threads.
- Shared Linux host; measurements ran sequentially without another Cargo build.
- `CARGO_INCREMENTAL=0`, default features, one libtest thread.
- Wall seconds and peak resident KB came from GNU `/usr/bin/time` `%e` and `%M`.

Each cold sample used a different empty target directory. Commands ran from the
corresponding worktree:

```bash
env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<empty-before-target> \
  /usr/bin/time -f '%e %M' \
  cargo test --quiet --lib relationship::reducer::tests:: \
  -- --test-threads=1

env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<empty-after-target> \
  /usr/bin/time -f '%e %M' \
  cargo test --quiet -p native-relationship-kernel -- --test-threads=1
```

Warm samples used the same commands with populated target directories after two
warm-ups. Each recorded pair ran after first, then before. The after loop has
seven tests rather than the before loop's three because it adds registry,
lifecycle/endpoint precedence, causal failure, and serialization coverage.

## Raw samples

Cold focused loop:

| Sample | Before seconds | Before RSS KB | After seconds | After RSS KB |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 398.79 | 6,345,572 | 12.98 | 313,256 |
| 2 | 397.71 | 6,392,848 | 12.96 | 313,748 |
| 3 | 396.87 | 6,304,284 | 12.96 | 309,640 |

Warm focused loop:

| Sample | Before seconds | After seconds |
| ---: | ---: | ---: |
| 1 | 0.50 | 0.31 |
| 2 | 0.50 | 0.31 |
| 3 | 0.50 | 0.31 |
| 4 | 0.49 | 0.32 |
| 5 | 0.50 | 0.31 |
| 6 | 0.50 | 0.31 |
| 7 | 0.50 | 0.31 |
| 8 | 0.49 | 0.31 |
| 9 | 0.51 | 0.32 |
| 10 | 0.50 | 0.31 |
| 11 | 0.49 | 0.31 |
| 12 | 0.50 | 0.31 |
| 13 | 0.51 | 0.31 |
| 14 | 0.51 | 0.31 |
| 15 | 0.50 | 0.31 |

The complete root relationship and grouped relationship-tool suites passed
single-threaded after extraction. They were validation runs, not controlled
timing samples, so no full-binary or full-CI performance claim is made.
