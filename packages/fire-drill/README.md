# @emilia-protocol/fire-drill

**Static receipt-declaration scanner for MCP manifests, OpenAPI documents, and tool lists.**

```bash
npx @emilia-protocol/fire-drill ./mcp-manifest.json
cat openapi.json | npx @emilia-protocol/fire-drill -- --json
```

The scanner classifies high-risk operation names and checks whether each one
structurally declares a **required** receipt/evidence input. Optional properties,
descriptions that merely mention receipts, and arbitrary nested strings do not
count.

```text
Target: mcp   Operations: 3   Dangerous: 2   Receipt declared: 0
Static receipt declaration score: 0/100

MISSING DECLARATION: `delete_customer_data` does not declare a required
receipt input. Runtime enforcement is not assessed.
```

## What it checks

- Money movement
- Data destruction, including HTTP `DELETE`
- Production deployment
- Permission and administrative changes
- Bulk data export
- Regulated-decision overrides

For MCP, a receipt-shaped property must appear in `inputSchema.properties` and
also in `inputSchema.required`, or an explicit boolean EMILIA marker must be set.
For OpenAPI, a receipt-shaped parameter must have `required: true`, or a required
request body must require the receipt property.

Input is capped at 8 MiB, duplicate JSON member names are refused, and scans are
limited to 10,000 operations.

## Output semantics

- `score`: static declaration coverage only.
- `static_result`: `complete` or `incomplete`.
- `eg1`: always `not_assessed`.
- Exit `0`: all detected dangerous actions declare evidence.
- Exit `1`: one or more declarations are missing.
- Exit `2`: malformed, duplicate-key, oversized, or unsupported input.

The badge renderer is deliberately amber even at 100/100. Static metadata cannot
show that the handler validates trusted keys, binds every material action field,
fails closed, or consumes evidence exactly once.

## Runtime boundary

A complete static scan is only a review prerequisite. To establish enforcement,
run the separate EG-1 runtime conformance suite against the deployed gate and
exercise missing, forged, wrong-action, revoked, replayed, concurrent, and
storage-unavailable evidence. This package does not issue an enforcement
certification.

Apache-2.0.
