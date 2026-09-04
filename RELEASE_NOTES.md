# Public source snapshots

This repository publishes Native's curated public source snapshots under the
GNU Affero General Public License v3.0 only (`AGPL-3.0-only`).

The snapshot contains the portable SQLite reference node, local MCP server,
selected protocol and storage work, bounded experimental MCP Apps, public
documentation, tests, and the machine-validated source boundary. Hosted
control-plane composition, the commercial Workbench, operated release
evidence, and private product history live upstream and are outside this
snapshot.

Native intends the public edition to progress from this inspection snapshot
to a qualified runnable node and then to meaningful self-hosting with a usable
public Workbench, team operation, recovery, and private coordination without
a mandatory Native-hosted dependency.

Native is developed in a private upstream. External contributions are not
accepted, and this repository's Issues, Discussions, and pull requests are not
supported feedback or support routes. For current product information and ways
to contact the Native team, visit [withnative.ai](https://www.withnative.ai/).

The maturity table in [`README.md`](README.md) and evidence routes in
[`docs/capability-map.md`](docs/capability-map.md) are the authorities for what
is included, partial, experimental, held, or intended in this snapshot.

## Verification and provenance

Each snapshot commit is the public verification artefact for its exact
source-only inspection tree. Its message records the exact private-upstream
source commit and tree, the SHA-256 of the public target-boundary manifest, the
SHA-256 of the complete selected-source manifest, the publication mode, and the named
public-candidate verification profile. These appear as the
`Source-Commit`, `Source-Tree`, `Boundary-SHA256`,
`Selected-Source-SHA256`, `Publication-Mode`, `Verification`, and
`Image-Provenance` trailers. The first snapshot commit has no parent. Later
snapshots are ordinary direct children of the preceding public snapshot, so
the public history remains linear and contains no private-upstream ancestry.
`main` is the only ref. Snapshot identity comes from the commit and its bound
provenance; snapshots have no public sequence number, version bump, tag, or
implied release ordinal.

The public-candidate profile proves the deny-by-default source boundary in both
upstream and materialised-target modes. The upstream authority retains the
source mapping and private exclusions; the generated public manifest contains
only target-native selected paths. The profile checks every selected file and
mode,
rejects held paths and credential-shaped content, validates public metadata,
toolchain and documentation links, and records the exact validator identities
in retained private evidence. A reader can re-run the checks available in the
snapshot:

```sh
python3 scripts/release/validate_source_boundary.py \
  --repo . --manifest native-boundary.json --mode target
python3 scripts/release/check_public_candidate.py --repo .
```

No binary, container image, tag, or GitHub Release is published with this
inspection snapshot, so source-to-image identity is not applicable. Runtime
and image provenance belong to the later Runnable Preview. The deterministic
root commit is intentionally unsigned in v1; this release does not claim a
separate signing or transparency-log attestation.

Public GitHub Actions are not release authority for this generated mirror.
The private upstream runs the governed source-boundary and candidate checks,
then the publication tooling re-runs the checks against the exact materialised
tree before producing the snapshot commit. Private CI logs and held release
evidence are not copied into the snapshot.

## Snapshot cadence

During active development, Native aims to publish one meaningful reviewed
snapshot about every two weeks. Thirty days without a new snapshot triggers an
explicit release review; it does not justify an empty or cosmetic update.
Snapshots are deliberate releases rather than a continuous mirror of private
upstream development, so the latest public commit may legitimately lag the
private product.
