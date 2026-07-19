# Gate control-plane demonstration

This vendor-neutral demonstration composes the three planes:

- executor-side Gate coverage (deployment attestation + independent 428 probe);
- a pinned network witness that observes but does not enforce; and
- control-plane settlement eligibility plus usage metering.

Run:

```bash
node examples/gate-control-plane/demo.mjs
```

The second scenario removes the Gate while keeping the witness. The result must be
`witness_only / refuse_coverage`; any implementation that calls that surface `gated` fails the
demonstration.

The reference process uses an explicitly enabled in-memory witness sequence store so the demo is
self-contained. Production deployments must use the durable Postgres witness adapter; the Gate
fails witness-dependent coverage and settlement closed when that store is absent or unavailable.
