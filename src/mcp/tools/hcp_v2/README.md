# Native and Human Context Protocol

This is an independent, experimental implementation of the [Human Context Protocol](https://digitaleconomy.stanford.edu/project/loyal-agents/hcp-human-context-protocol/) (HCP) from [Stanford's Digital Economy Lab](https://digitaleconomy.stanford.edu/), backed by Native's durable context and event history.

> ℹ️ **Specification status:** this implementation targets a preview, draft version of HCP. The draft may change, and this code may differ from the interfaces described in public HCP materials.

*(We do not claim formal HCP conformance or endorsement by the HCP team. The draft itself is not included or reproduced here.)*

## What is HCP?

HCP aims to make personal context portable across AI assistants and applications. A common interface lets clients request and update context without requiring every client and context provider to use the same storage system.


## Why Native x HCP?

We see Native and HCP as two complementary approaches to context ownership.
- **HCP: common interface**, to let you connect from compatible context stores with any AI assistant or application
- **Native: sovereign context**, so that your context can sit on your machine, 100% owned and inspectable by you

Since your data is all yours in Native, it supports arbitrary interfaces:
- You can read it as raw Markdown in a file editor
- You can have a frontend client that queries the database
- You can have AI read and write via CLI, MCP -- and HCP!

## HCP implementation

The module implements five MCP context operations:

| Tool | Purpose |
| --- | --- |
| `hcp_searchPreferences` | Find personal context within requested categories. |
| `hcp_getPreference` | Retrieve an entry previously disclosed to the calling client. |
| `hcp_addPreference` | Add a personal context entry with assertion provenance. |
| `hcp_updatePreference` | Revise an existing entry. |
| `hcp_deletePreference` | Soft-delete an entry. |

Here's how we've implemented it:

- The implementation keeps trusted state in admitted events.
- Editable Native records are views of that state, rather than authority for provenance or confirmation.
- Reads record the client's stated purpose before returning content.
- Conflict transitions and human confirmations are recorded alongside the versions they concern; confirmation of one version does not endorse a later revision.

Useful starting points:

- [Registration and module overview](mod.rs), [tool schemas](schemas.rs), and
  [operations](ops.rs).
- [Entry model](model.rs), [event folding](fold.rs), and [storage](store.rs).
- [Conflict handling](conflicts.rs), [confirmations](confirm.rs), and
  [audit and disclosure](audit.rs).
- [Workspace opt-in](setup.rs) and [record views](view.rs).
- [Operation tests](tests.rs), [conflict and audit tests](c2_tests.rs), and
  [confirmation tests](c3_tests.rs).
