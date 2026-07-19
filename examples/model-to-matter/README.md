# Model-to-Matter

This example demonstrates a verifiable clearance boundary between a frontier
model's proposed experiment and a physical executor such as a cloud laboratory.
The executor clears one exact action only when its own pinned profile receives:

1. model attestation;
2. safety-case attestation;
3. institutional authority;
4. biosafety review;
5. domain screening; and
6. Class-A human authorization.

Every leg is signed, action-bound, time-bounded, issuer-pinned, revocation-aware,
and consumed through durable challenge and action-level clearance stores. The
action contains only digests and opaque commitments, never raw sequences,
protocols, prompts, or reasoning traces.

The example uses `createModelToMatterExecutor()`: the profile, issuer pins,
revocation provider, clock, and both stores are captured at construction.
Presenter input never carries trust configuration.

Run the self-checking demonstration:

```bash
node examples/model-to-matter/demo.mjs
```

Run the adversarial contract:

```bash
npx vitest run tests/model-to-matter.test.js
npm run m2m:conformance
npm run test:mutation:model-to-matter
```

The Experimental Internet-Draft source is staged at
`standards/posted/draft-schrock-model-to-matter-00.xml`. It is a July 19
Experimental filing candidate, scheduled after the four-document protocol
line. An executor partner remains necessary for any deployment or adoption
claim, not for publication of the open profile.

## Honest boundary

This is a control-plane reference implementation. It does not screen a
biological sequence, certify that an experiment is safe, operate equipment, or
independently establish what happened in the physical world. It verifies signed
statements from issuers and executors that the relying party chose to trust.
The demonstration uses synthetic identities and opaque benign fixtures; it
claims no integration or partnership with a model provider, screening service,
institution, or cloud laboratory.
