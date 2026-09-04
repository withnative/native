# Record-policy pilot measurement appendix

This is the reproducibility record for the measurements summarized in
`docs/testing-strategy.md`. Measurements used pre-rebase commits
`d998c8d5d00f3798056315a35fb8620a4fd2800e` and
`5fc4be011f3c87ad0efe7b720b581875c7c7ca11`. Their pushed equivalents are
`48dd7059` and `9b7e999f`; the intervening `main` commits changed web,
devcontainer, documentation, and CI inventory files, not Cargo or Rust inputs.

## Environment and commands

- Rust `1.90.0 (1159e78c4 2025-09-14)` and Cargo `1.90.0`.
- AMD EPYC 7232P, 8 cores / 16 hardware threads.
- Shared Linux host; before and after ran sequentially with alternating order.
- `CARGO_INCREMENTAL=0`, default features, one libtest thread.
- Wall seconds and peak resident KB came from GNU `/usr/bin/time` `%e` and `%M`.

Each cold sample used a different empty target directory. Commands ran from the
corresponding detached worktree:

```bash
env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<empty-before-target> \
  /usr/bin/time -f '%e %M' \
  cargo test --quiet --lib mcp::tools::policy::transition::tests:: \
  -- --test-threads=1

env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<empty-after-target> \
  /usr/bin/time -f '%e %M' \
  cargo test --quiet -p native-policy-kernel -- --test-threads=1
```

Warm samples used the same commands with populated target directories, after
two warm-ups. The recorded set ran after first, then before, to check ordering
bias.

The policy-portfolio samples ran precompiled libtest executables directly, so
they measure test execution rather than Cargo metadata or compilation:

```bash
<before-native-ce-libtest> mcp::tools::policy::transition::tests:: \
  --test-threads=1 --quiet
<before-tools-libtest> record_policy_tool:: --test-threads=1 --quiet

<after-policy-kernel-libtest> --test-threads=1 --quiet
<after-tools-libtest> record_policy_tool:: --test-threads=1 --quiet
```

## Raw samples

Cold focused loop:

| Sample | Before seconds | Before RSS KB | After seconds | After RSS KB |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 410.19 | 6,352,816 | 12.85 | 308,948 |
| 2 | 403.81 | 6,387,636 | 12.63 | 310,504 |
| 3 | 489.94 | 6,365,680 | 12.37 | 312,292 |

Warm focused loop:

| Sample | Before seconds | After seconds |
| ---: | ---: | ---: |
| 1 | 0.87 | 0.94 |
| 2 | 1.19 | 0.67 |
| 3 | 0.52 | 0.33 |
| 4 | 0.52 | 0.31 |
| 5 | 0.51 | 0.33 |
| 6 | 0.51 | 0.32 |
| 7 | 0.64 | 0.32 |
| 8 | 0.64 | 0.39 |
| 9 | 0.71 | 0.53 |
| 10 | 0.62 | 0.38 |
| 11 | 0.52 | 0.33 |
| 12 | 0.52 | 0.32 |
| 13 | 0.65 | 0.32 |
| 14 | 0.57 | 0.45 |
| 15 | 0.60 | 0.36 |

Precompiled focused policy portfolio:

| Sample | Before seconds | After seconds |
| ---: | ---: | ---: |
| 1 | 5.68 | 3.96 |
| 2 | 5.11 | 4.09 |
| 3 | 5.18 | 4.08 |
| 4 | 5.19 | 4.11 |
| 5 | 5.22 | 4.20 |
| 6 | 5.18 | 3.93 |
| 7 | 5.13 | 3.92 |
| 8 | 5.15 | 4.26 |
| 9 | 4.98 | 4.04 |
| 10 | 5.06 | 4.03 |
| 11 | 5.25 | 4.15 |
| 12 | 5.14 | 3.93 |
| 13 | 5.24 | 3.95 |
| 14 | 5.30 | 4.02 |
| 15 | 5.07 | 5.45 |

The complete grouped `tools` binaries passed at both commits with
`--test-threads=1`. Their validation timing was not retained, so this appendix
makes no full-binary performance claim.
