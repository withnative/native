# Agent messaging interventions (first slice)

This slice gives Codex, Claude Code, and other MCP harnesses one registry-owned
path for autonomous same-database messaging:

1. Call `bootstrap` once and retain its `run_key` and active instructions.
2. Call `manage_messages` with `action: "send"` for delivery. Include a concise,
   disclosure-safe `preview` of at most 500 characters whenever policy may block
   and request authority. The preview is sender-authored, immutable, and bound
   into the exact action and evaluation digests; it is the only Message summary
   disclosed to the intervention target before delivery. `create_record`
   may create only a private sender draft with `addressed_to: []`. Native
   resolves the sender, recipients, database and typed send operation, compiles
   active escalation policy, and commits the result in one transaction.
3. Inspect `delivery`. `delivered` means the addressed audience was sealed and
   granted view access. `blocked` means Native stored a sender-only draft and a
   Message-rooted intervention; intended recipients cannot read the draft.
4. The sole intended recipient is the intervention target. In that recipient's
   authenticated session, call `manage_interventions` with `action: "query"`
   and `execution: "blocked"`. The sender receives the canonical path in the
   send result but cannot read the recipient-relative intervention projection.
5. Resume only after the target person authors a `Resolution kind:decision`.
   Call
   `manage_interventions` with `action: "resume_delivery"`, the projection and
   evaluation guards, that Decision id, and a fresh idempotency key. Native
   rechecks ACLs, recipient bindings, action facts and current policy, then
   links that exact Decision to the draft with `authorizes`, expands the
   audience, and appends the resume fact atomically. The recipient can inspect
   the intervention request while blocked, but cannot read the Message body.

The harness should treat `delivery.status == "blocked"` as a durable pause, not
as a tool failure to retry. It may end the current process. A later Codex or
Claude Code session can query the same intervention and continue from its
projection.

## Principal policy source

Policy uses the existing portable standing-instruction authority. Create a
`Document kind:escalation-policy` whose whole body is the closed JSON contract,
then bind it with `manage_instructions` at member or workspace scope. Member
bindings can be authored only by that authenticated member; workspace bindings
remain database-owner-only. The compiler requires the document's
`issuer_principal_id` to match the document owner's canonical
`native-principal` binding, and retains both binding id and body digest in every
evaluation trace.

```json
{
  "format": "native.escalation-policy.v1",
  "issuer_principal_id": "native/alice",
  "statements": [
    {
      "statement_id": "same-workspace-default",
      "kind": "default",
      "scope": {
        "action.destination_kind": ["same_workspace"]
      },
      "effect": {
        "disposition": "notify_and_proceed"
      }
    },
    {
      "statement_id": "block-for-external-reviewer",
      "kind": "hard_rule",
      "scope": {
        "action.correspondent_principal_ids": ["native/external-reviewer"]
      },
      "when": {
        "all": [
          {
            "field": "action.operation",
            "op": "eq",
            "value": "send_message"
          }
        ]
      },
      "effect": {
        "disposition": "block_and_request_authority"
      }
    }
  ]
}
```

## Harness call shape

```json
{
  "action": "send",
  "body": "Status update for the team",
  "preview": "Team status update requesting a reply.",
  "addressed_to": ["portable-person-record-id"],
  "expectation": "reply",
  "idempotency_key": "stable-per-send-intent",
  "reason": "The recipient owns the requested review and needs the current state."
}
```

Caller-supplied agent and task labels are not policy facts and are rejected by
the send contract. A policy that depends on `agent.id` or `task.id` fails
closed until those selectors can be derived from authenticated registry state.
The registry deterministically derives the Message sender, database boundary,
resolved audience and `send_message` operation. Unrestricted prose is always
classified with sensitivity `unknown`; Native does **not** claim to understand
that a sentence is a promise, launch commitment, or other consequential act.
An active hard rule cannot be weakened by prose or by a caller-supplied model
classification. With no applicable statement, this slice uses the conservative
`notify_and_proceed` default.

## Current boundaries

- Same-database recipients only; cross-workspace transport and trust exchange
  remain out of scope. Every recipient must resolve to both a canonical portable
  principal and a canonical local account before policy evaluation or append.
- An intervention-producing send currently requires exactly one intended
  recipient. Multi-recipient sends are supported only when deterministic policy
  resolves to `silent_autonomy` or `log_only`; otherwise the call fails before
  writing. This avoids silently substituting a sender-relative target.
- Hard rules and defaults are enforced. Judgment clauses are traced but use the
  default because no registry-bound model evaluator is shipped yet.
- `query` examines at most the latest 200 intervention raises and returns at
  most 50 authorized views. A dedicated cross-Message index is deferred until
  production volume justifies a schema successor.
- Cancellation and exact-authority delivery/resumption are included. Delegation,
  deadlines/fallback execution, teaching proposals, MCP Apps, and a control
  tower are not.

Recipient-facing intervention views expose the immutable preview, evaluation
digest, disposition, and sanitized reason codes. They never expose policy
source, binding, or statement identifiers. A `reply` obligation is satisfied
only by a recipient-authored Message that was actually delivered to and
addressed to the original sender; a private reply draft is not evidence.
