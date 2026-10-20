# Read-only Markdown vault (on by default)

The node can publish a folder view of its authenticated account's local copy.
This is a generated view; hosted Native remains canonical. No changes flow back
from the vault, and no Git history or separate service is created.

The vault is on by default whenever `node.json` configures a `standby_config`:
the node publishes to a `vault/` directory beside the local copy's folder
(next to the standby `replica_root`). With no `standby_config` the vault is
simply off. Keep the node's directory out of synced folders (a cloud-synced
`~/Documents` or `~/Desktop`, for example), or set an explicit
`markdown_folder` path or `false`. The default follows the configured
`replica_root` path lexically: if that is a symlink to another disk, the
vault still lands beside the link; set an explicit path to put it elsewhere.

To use a different location, set an absolute `markdown_folder` path in
`node.json`:

```json
"markdown_folder": "/absolute/private/path/native-vault"
```

To turn the vault off:

```json
"markdown_folder": false
```

An explicit path requires `standby_config` and the existing explicit
`account_id`, exactly as before. The destination must be absent or empty on
its first use. The node
creates missing directories without traversing symlinks, binds the vault to the
source database and account, and holds one writer lock. It refuses a foreign
nonempty directory, an incompatible state contract, and a different source.
Do not point it at a live data/replica directory or share a vault between accounts.
The first time the node creates the vault directory it logs the path and the
off switch. Measured on Native HQ in October 2026: about 184 MB in ~11k files
for a workspace that size, on top of the ~2.5 GB local copy.

Before enabling the vault on v1, older local generations must have a repaired,
current logical link materialization. Use the supported node generation repair
and refresh path. The vault reads the authorized logical `links` relation; it
does not reconstruct relationship state or change replication transport.

For rollback to an older binary, first remove `markdown_folder` from `node.json`
(or leave it absent, which older binaries treat as off):
older `NodeConfig` versions deny unknown fields and reject `false`. Disabling the option leaves the
existing vault on disk, with its last status. No reader should infer continuing
freshness after the node has stopped publishing.

## Boundaries and authorization

A captured served generation retains the node's engine, authenticated caller
and generation lease. The v1 collector opens one read transaction on the
governed pool, clears connection-local principal/visible-id/actor state, installs
the production query authorization views and materializes a complete snapshot
at that transaction's act. The `v2-kernel-probe` build also supports an NKV2
generation: its collector resolves the account binding and stored roster, checks
root access, and installs the production v2 SQL visibility/placement views in
one read transaction. Its connection is discarded after collection, including
on failure or cancellation. Imported workspace names and summaries come from
the sealed root metadata; native-created v2 workspaces use `Native workspace`
when that metadata is absent. Unnamed v2 policy homes are placed under the
nearest represented visible folder, or the workspace root; this is a vault
layout choice and does not change canonical placement.

Records, facets, links and comment anchors are caller-visible. Related owners
and creator-person identities are emitted only when visible. This uses the same
authorization for a workspace owner and a member; there is no trusted-local
bypass or independent policy evaluator. The v2 collector does not enable v2
generation acquisition by itself: shipping node support and Mac installation
qualification still require N1 (#2516). See [continuity findings and the N3
plan](v2-continuity-n2-n3.md).

The collector avoids public SQL response row, cell and encoded-result limits;
large documents, artifacts and escaped text are returned whole. The transaction
is released before rendering or filesystem work. A debug diagnostic reports its
elapsed duration: rollback-journal writers may wait for this bounded snapshot
read, whose duration depends on workspace size. There is no hard elapsed-time
promise or partial-result publication.

Renderers receive only the caller-visible snapshot, source identity and renderer
version, and may assemble several records into one output. The publisher receives
bytes, contributor identities and allocated paths. Snapshot act provenance lives
in state and STATUS, avoiding changes to every note when an unrelated act moves.
The renderer version and origin are also flat scalar properties in note frontmatter.

Hidden records are not fetched as records or emitted through generated related
metadata. Authorized bodies and facet text remain verbatim: they may contain
arbitrary authored references. This is authorization filtering, not textual
scrubbing of visible prose. No hidden data is read to scrub that prose.

## Layout and content

The root contains `README.md`, `.native/`, the workspace folder and `Messages/`
when messages exist. Only live, unarchived, non-Configuration records are included.
Folders come from Collection/folder records. A nonempty folder has a folder note
at `Folder/Folder.md`; an empty folder still exists but has no note. A live child
under an archived visible home is flattened to the nearest included ancestor,
or the workspace root. A hidden home is not named.

Titles are NFC-normalized, preserving whole titles through 150 characters when
they fit the filesystem byte limit. Longer titles shorten at a word boundary
with an ellipsis and reference. UTF-8 byte caps leave room for collision suffixes
and extensions within 255 bytes. Unsafe path and wikilink delimiter characters
(including `%%`) are replaced, leading dots and trailing dots/spaces removed. Frontmatter keeps
the full title. Untitled records use type, kind and reference. Allocation compares
names without case, preserves existing names across later duplicates, and tests
all emitted filenames, companion extensions, directories and folder-note slots.
A renamed parent's folder-note slot takes precedence over a child's old name.
The allocation ledger is part of a fresh reconciliation's input, so historical
collision choices survive deleted duplicates and restarts.

Obsidian documents [problematic link characters](https://obsidian.md/help/links);
treating them as unsafe is the filename interpretation used here. Its
[properties UI does not support nested properties](https://obsidian.md/help/properties),
so facets use flat `facet.<key>` fields and provenance uses
`native_projection_origin` / `native_projection_renderer`. Structured source
values remain quoted strings.

Notes use quoted YAML properties, outgoing relationship properties containing
path-qualified wikilinks, and a generated Links section with notes. Incoming
links are left to Obsidian. Visible excluded targets show title, exclusion reason
and Native URL; hidden targets are omitted. HTML and MDX v2 artifacts have their
real extensions plus Markdown companions; boards have JSON companions. Recipes
and unknown runtimes remain Markdown. The original artifact bytes are preserved.

Comments appear under their target in a generated Comments section, ordered by
creation time with nested replies, caller-visible creator identity (not current
owner), timestamp and quoted `text_quote.exact` anchors. Missing identity is
shown as Unknown author. Nesting beyond 64 levels fails visibly. Messages are
grouped chronologically by visible home in `Messages/`; groups whose bodies total
more than 1 MiB split by calendar month. All generated paths are collision-checked.

## Publication, conflicts and recovery

The root and `.native/` are 0700; generated directories are 0555 and files 0444.
The root stays writable for `.obsidian/` and user notes. Publication temporarily
lifts owned directory permissions and seals them again, including after failure.
Files the node did not create are preserved; collisions and local edits to
managed files (including README and STATUS) are reported as conflicts.

Access loss takes precedence over preserving local edits. On the next successful
authorized cycle, the publisher purges affected generated notes, artifact
companions, message aggregates, inline comments, inbound generated links, old
owned directories and state metadata, even if edited. Aggregates are rebuilt
from the remaining authorized inputs. Revoked content is never quarantined.
Safe removal obstructed by a symlink, changed file type, or a user's file in a
revoked directory fails visibly. The node cannot promise removal while no usable
authorized local snapshot is available, or when the filesystem refuses removal.

All filesystem operations are descriptor-relative and refuse symlink components.
Generated files and state are replaced atomically; state publication fsyncs its
file and directory. A batch plan records both prior and pending digests and the
union of contributors before any content replacement. Recovery therefore tracks
old sensitive links even if a process stops between planning and replacement.
Initial ownership is durably saved under the writer lock before open returns.
Repeated interrupted plans retain all possible published digests.
Planned directories may be absent after a crash; recovery tolerates that and
cleans reserved stray temporary files at root and in owned directories. A
refused first write leaves no pathless record entry. State is a projection ledger,
not a second content history.

Ordinary generated files do not each require a content-file fsync. Before
retiring prior journal contributors and digests, the publisher fsyncs every
distinct changed parent directory, including newly established directories.
This prevents old names and sensitive links from reappearing after the ledger
forgets them. A failed sync retains the union and a durable dirty-directory set, including
through failure-status saves. An unchanged retry still syncs those directories
before retiring prior contributors. State and STATUS are fsynced too. Files are atomically visible, but the
whole vault is not an atomic snapshot and the latest content bytes may still
need reconciliation after sudden power loss.
A later reconciliation repairs missing generated bytes while preserving
recognized local edits. Full state is serialized a bounded number of times per
cycle, rather than once per output file.

Every five seconds the runner checks for a changed act/generation and updates
STATUS freshness from existing standby status machinery. Idle status carries no
record bodies. Every five minutes it takes a complete authorized snapshot and
reconciles again even at unchanged act. Only changed content files are replaced.
Rendering and publication run on blocking workers, separate from supervisor
handoff. A captured lease remains held through snapshot preparation/publication.
Shutdown waits for an in-progress cycle rather than abandoning a partially
applied journal. STATUS is written last and distinguishes the last successful
render time from its latest diagnostic tick; failures also produce node errors
and an unavailable status when that file can safely be written. Freshness and
refresh diagnostics expose actual age and over-RPO state, not a promise that a
scheduled refresh ran.

Fixture validation includes owner-binding and member privacy, pooled principal
changes and revocation, results larger than public SQL limits, directory and
artifact collisions, moves/renames, incremental/fresh rendering with the same
allocation ledger, aggregate revocation including edits, interrupted batch plans,
symlink/foreign-file obstructions, threaded anchors, monthly messages, UTF-8 byte
limits, cleanup after restart, permissions and idle/periodic tick decisions.
Opening the generated vault in Obsidian remains a manual integration check.
