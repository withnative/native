# Native for agents

Native is intended to improve the agent's working conditions as well as the
human team's. It provides shared, durable state that can survive a session,
carry corrections and history, and coordinate work across people and agents.

This is an evaluation route. Use it
to understand what the selected repository supports, where the benefit
comes from, and what remains dependent on maintenance or judgement. The
[capability and evidence map](capability-map.md) is the claim-to-proof
inventory; this page translates those same mechanisms into the agent's
experience.

## What changes for the agent

| Agent benefit | Value to the person or team | Mechanism | Important limit | Inspect |
|---|---|---|---|---|
| Recover project context instead of reconstructing it from one visible conversation. | Work can continue across sessions, agents and clients without asking one person to retell the project each time. | Records retain placement, relationships, history and attribution; exact reads, lexical search and structured queries retrieve them across the shared model. | Native knows only what was deliberately recorded or imported through available tools. Retrieval cannot recover an unrecorded rationale. | [Effective searching](../src/mcp/guides/effective-searching.md), [query DSL](../src/mcp/guides/query-dsl.md), and [temporal reads](temporal-reads.md) |
| See when earlier context has been corrected. | A later contributor is less likely to act on a plausible old statement whose replacement is hidden elsewhere. | Lifecycle, a recorded `supersedes` link, incoming-link traversal and historical reads keep the correction connected to the earlier record. | Native does not abolish staleness. Someone or something must still record the correction, and a live but wrong record can remain misleading. | [What's changed](whats-changed.md), [temporal reads](temporal-reads.md), and the first row of the [capability map](capability-map.md) |
| Work with clearer epistemic footing. | Reviewers can distinguish an assertion from its evidence and see who contributed what instead of treating every retrieved sentence as equally authoritative. | Event history, citations, attributions, governed record shapes and caller-relative access policy remain attached to the work. | Attribution identifies who asserted or assessed something; it does not prove truth, consensus or endorsement. | [Interpretive claims](interpretive-claims-conformance.md) and the [authorization contract](authorization-contract.md) |
| Coordinate through the same state that contains the work. | People and other agents can inspect current purpose, active work and review points without reconstructing them from separate private chats. | Run intent, work claims, comments, suggestions, interventions and lineage operate over durable records. | A claim is an advisory coordination signal, not a lock, permission grant or automatic project manager, and claims do not expire automatically. This snapshot does not prove a general notification inbox. | [Coordination guide](../src/mcp/guides/coordination.md) and [agent interventions](agent-interventions.md) |
| Leave work intelligible after the current session ends. | The next contributor can recover the artifact, consequential context, current boundary and next step rather than inheriting only a transcript or opaque summary. | Durable records, links, history, attribution and review state persist independently of the current model session. | The substrate cannot preserve reasoning or decisions that were never recorded, or guarantee that a contributor leaves good state behind. | [Record types](../src/mcp/guides/record-types.md), [placement](../src/mcp/guides/placement.md), and [working in a shared world](../src/mcp/guides/working-in-a-shared-world.md) |
| Traverse a connected working world rather than a folder of isolated context files. | People, conversations, messages, work, decisions, documents and artifacts can remain connected instead of becoming separate application silos. | Ten spine types share placement, facets, links, governed relationships, history, query and policy. | Native does not automatically aggregate every inbox, address book or external application. The connected world has an explicit acquisition boundary. | [Record types](../src/mcp/guides/record-types.md), [message-first conversations](message-first-conversations.md), and the [capability map](capability-map.md) |
| Depend less on one session, model or provider retaining the memory. | A later authorized agent using a compatible client can recover the caller-visible recorded state exposed by the same node. | Native exposes a shared MCP surface over durable records; the selected node can export its complete SQLite database, and explicit interchange contracts define bounded movement. | This is continuity of recorded shared state, not hidden reasoning or unrecorded model memory. Cross-backend movement remains incomplete, and a portable database does not prove portable hosted composition. | [Tool surface](tool-surface.md), [storage portability](../protocol/storage-portability/v1/README.md), and the final row of the [capability map](capability-map.md) |

## When this is likely to help

Native is a stronger fit when work spans several sessions or contributors,
decisions and assumptions change over time, agents need to coordinate or hand
off work, or the team needs inspectable history and evidence around what the
agents did. The benefit grows when useful context must remain available across
different clients or models.

It may add more structure than value for a one-off task with stable context and
one contributor. It needs someone to maintain the shared state, and it offers
lexical search rather than automatic semantic search or passive aggregation.
The hosted control-plane composition and commercial Workbench live upstream,
outside this snapshot.

## How to evaluate the repository

Start with the [capability and evidence map](capability-map.md). It labels each
claim as current, partial, experimental or directional, names selected
implementation and executable evidence, and keeps the material boundary beside
the claim. The root README's source-exploration path names selected
SQLite and MCP entry points.

An evaluation should be able to answer all of these from the selected
tree:

1. Which recurring coordination or context problem would Native address here?
2. What becomes easier for the agent, and what value does that create for the
   person or team?
3. Which mechanism produces each claimed benefit?
4. What still depends on deliberate recording, maintenance or judgement?
5. Which capabilities are current, partial, experimental, directional or
   held?
6. What cannot be determined from this repository?

If an answer cannot be supported by a selected path or a command runnable from
this root, treat it as unproven for this snapshot.
