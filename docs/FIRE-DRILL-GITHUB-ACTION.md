# EMILIA Fire Drill GitHub Action

Fail CI when a detected high-risk MCP/OpenAPI action omits a structurally
required receipt declaration. This is a static schema gate, not EG-1 runtime
certification.

```yaml
name: Receipt declaration review
on: [push, pull_request]
jobs:
  fire-drill:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - uses: emiliaprotocol/emilia-protocol/.github/actions/fire-drill@main
        with:
          manifest: ./mcp-manifest.json
          fail-on: fail
```

Outputs:

- `score`: static required-receipt declaration coverage, 0-100.
- `static-result`: `complete` or `incomplete`.
- `eg1`: always `not_assessed`, retained for compatibility.

The action pins `@emilia-protocol/fire-drill@0.5.0`, rejects malformed or
oversized input, and fails on missing declarations by default. A complete result
does not establish that handlers validate pinned issuers, bind exact actions,
check revocation, fail closed, or consume receipts exactly once.

To make a runtime claim, separately run the EG-1 runtime conformance checks against the
deployed gate, including missing, forged, wrong-action, replayed, concurrent,
and storage-unavailable cases. No static EG-1 badge is issued.
