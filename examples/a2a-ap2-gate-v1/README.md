# A2A/AP2 Gate reference composition

This example is the runnable composition documented in
[`docs/integrations/A2A-AP2-GATE-EXPERIMENTAL.md`](../../docs/integrations/A2A-AP2-GATE-EXPERIMENTAL.md).
The executable harness is intentionally kept in
[`packages/gate/a2a-ap2-gate.test.ts`](../../packages/gate/a2a-ap2-gate.test.ts)
so the six hostile cases run in the package's normal qualification gate instead
of drifting into non-executable sample code.

The integration preserves the native AP2 mandate and reports
`emilia_originated: false`. It uses A2A for the authorization interruption,
AE-CHALLENGE for the exact evidence request, CAID/AEB for exact-action evidence
composition, and the consequence actuator for reserve-before-effect custody.

Run:

```sh
npm --prefix packages/verify run test:qualification
npm --prefix packages/gate run test:qualification
npx vitest run tests/a2a-ap2-gate-hostile-corpus.test.ts
```

Status: experimental, same-team reference only. Independent reproduction is
required before proposing an A2A/AP2 extension or making interoperability claims.
