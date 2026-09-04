# MCP transport choice

Status: decided for the selected portable node. Scope: transport code under
`src/mcp/`; operation semantics remain owned by the transport-neutral registry.

## Constraint

Handlers return structured domain values and transports render them. Tool
registration therefore cannot be coupled to a transport library's MCP content
block or response-framing types.

## Selected stdio implementation

The portable node uses a small hand-rolled JSON-RPC layer:

- [`src/mcp/protocol.rs`](../src/mcp/protocol.rs) owns lifecycle negotiation,
  discovery, dispatch, and protocol error mapping;
- [`src/mcp/stdio.rs`](../src/mcp/stdio.rs) owns newline-delimited stdin/stdout
  framing;
- [`src/mcp/registry.rs`](../src/mcp/registry.rs) remains the one typed
  operation registry.

This keeps framing out of handlers and adds no protocol dependency for the
selected stdio server. The cost is explicit: maintainers must track supported
MCP revisions, update constants only with compatibility tests, and verify the
selected lifecycle and response shapes.

The repository may contain dependencies used by optional selected features,
but their presence does not change this stdio registration boundary. Hosted
HTTP composition and its framework choice are held outside this snapshot and
are not part of the portable-node contract.

See [`tool-surface.md`](tool-surface.md) for the cross-cutting operation rules
and [`tool-surface.generated.md`](tool-surface.generated.md) for the exact
inventory.
