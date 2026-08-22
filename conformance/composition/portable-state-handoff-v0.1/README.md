# EP Portable State Handoff v0.1 conformance lab

This lab runs the independent Continuum producer, the EMILIA recipient, the
SOMA/COGOBJ adapter, the normative CAID bindings, the process-local atomic
recipient boundary, and the hostile controls described in the public profile.

Run:

```bash
npx tsx --test packages/verify/portable-state-handoff.test.ts \
  examples/portable-state-handoff/roundtrip.test.mts \
  conformance/composition/portable-state-handoff-v0.1/schemas.test.mts
npx tsx conformance/composition/portable-state-handoff-v0.1/run.mts --check
```

The reference digest is a deterministic regression contract. Updating it is a
deliberate semantic act, not a way to make a failing test green.

The lab does not establish external implementation independence, production
durability, source truth, source-population completeness, physical erasure, or
IETF status.
