# Saved-session schema proposal

The saver uses the ordinary `Document/agent-session` kind. Its lifecycle is
`open` while saving and `closed` when the daemon session ends. Native refuses
non-null lifecycle writes without an effective axis and governing vocabulary.
The kind's open-additive name alone does not establish that contract. A compatible inherited lifecycle declaration is also accepted: the saver reads the effective axis and its governing vocabulary, rather than requiring the proposal's axis name. A quarantined kind is refused.

[saved-session-lifecycle-proposal.json](../src/node/saved-session-lifecycle-proposal.json)
is a source proposal, exercised by ephemeral integration fixtures. It does not
admit metadata, enable a saver, or change an installed workspace. Session steps
and share cards do not acquire lifecycle axes through this proposal.

If no compatible effective lifecycle is already admitted, the database owner must review and admit the vocabulary and shape through the ordinary supported schema workflow before enabling saving. Read current schema
state and existing vocabulary first. Propose/promote the `agent-session` kind and its supplied meaning first; kind-specific shapes require an active canonical kind. Review the cited provenance in this workspace (for another workspace, import the reviewed proposal and replace its local record reference). Propose/promote `open` and `closed` with
the stated meanings, then merge the supplied kind-scoped shape fragment into
the existing user configuration under its current schema revision. Preserve
unrelated configuration; do not replace the whole user layer with the fragment.
An existing conflicting definition requires review, not automatic replacement.
Retain `required: false` so older saved records without lifecycle remain valid.
Preview the resulting `Document/agent-session` shape and confirm that both
lifecycle values resolve to this axis before admitting any saver configuration.

The saver performs ordinary record writes. It does not grant itself schema
administration or create/promote vocabulary. Without admission, initial record
creation refuses rather than saving an ungoverned lifecycle. Owner-facing Save
status reports the refusal; after admission, a fresh explicit Save can retry.

Source admission and ephemeral tests do not qualify provider live/rebuilt
continuity or authorize service/configuration/production activation.
