# EMILIA Gate for A2A/AP2 (experimental)

This integration composes three existing protocol surfaces at one receiving
executor:

1. A2A `TASK_STATE_AUTH_REQUIRED` carries an `AE-CHALLENGE-v1` object in
   `Task.status.message.metadata` under the EMILIA extension URI. The challenge
   names the server-derived exact action, required evidence, status or freshness
   constraints, audience, and the `ap2-native` presentation method.
2. A relying-party-pinned AP2 implementation verifies the AP2 mandate as native
   evidence. EMILIA does not reissue the mandate, change its protocol identity,
   or claim to have originated its authorization.
3. AEB maps the verified native result to an executor-computed CAID, composes it
   with any other required evidence, and Gate reserves the challenge, A2A task,
   AEB evaluation, and native replay identities before provider entry.

The caller supplies only the A2A task, signed AEB evaluation, and native
artifacts. The executor owns the expected action and CAID, clock, live status
resolution, local authorization, execution envelope, challenge registry, and
admission stores. A caller therefore cannot turn a request field into authority.

## Decision contract

- `ADMIT`: the challenge was registered and unused; AP2 evidence was natively
  verified and current; every AEB requirement and local policy passed; the
  admission state was reserved; and the provider returned a committed result.
- `REFUSE`: a hard negative exists, including action substitution, revocation,
  wrong evidence role, replay, or local-policy denial. The provider is not
  entered.
- `INDETERMINATE`: a required fact or provider outcome is unknown. A provider
  timeout after entry permanently blocks blind retry until reconciliation.

## Security boundaries

This profile does not modify A2A or AP2, transfer admission ownership, prove a
provider effect, or provide cross-domain exactly-once execution. Its one-time
guarantee holds within the configured authoritative atomic admission domain.
The implementation and vectors are same-team reference evidence. No independent
A2A or AP2 interoperability result is claimed yet.

## Executable evidence

- `packages/verify/a2a-evidence-challenge.test.ts` rejects
  `TASK_STATE_INPUT_REQUIRED` substitution, action swap, and challenge expiry.
- `packages/verify/ap2-native-adapter.test.ts` verifies native AP2 preservation,
  exact action mapping, revocation, unavailable status, and pinned-verifier
  substitution.
- `packages/gate/a2a-ap2-gate.test.ts` runs the composed hostile cases: approve
  A/execute B, concurrent admission, replay under another task, revoked
  evidence, malicious authorization-server evidence, and provider timeout.
- `conformance/vectors/a2a-ap2-gate-hostile.v1.json` is the closed public case
  catalog. `external_reproductions` remains empty until an independent
  implementation reproduces the cases.

Run the focused checks:

```sh
npm --prefix packages/verify run test:qualification
npm --prefix packages/gate run test:qualification
npx vitest run tests/a2a-ap2-gate-hostile-corpus.test.ts
```

An extension proposal or market claim is gated on one independent A2A or AP2
implementation reproducing the hostile cases.
