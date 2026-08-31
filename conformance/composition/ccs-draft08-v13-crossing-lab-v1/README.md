<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS draft-08 v1.3 Crossing Lab profile

This package turns one source-locked CCS v1.3 receipt into a runnable AEB
Crossing Lab workspace. It asks a deliberately narrow question: can a CCS
receipt be verified under CCS's own pinned Ed25519, issuer, audience,
freshness, and replay rules, then mapped without material loss to the exact
tool action the relying party is considering?

Run it after building Verify 3.21.0:

```sh
npm --prefix packages/verify run build
node conformance/composition/ccs-draft08-v13-crossing-lab-v1/run.mjs --check
node --test conformance/composition/ccs-draft08-v13-crossing-lab-v1/run.test.mjs
node packages/verify/cli.js crossing-lab run \
  examples/aeb-crossing-lab/ccs-wang-draft08-v13
```

To regenerate the committed artifact, workspace pins, hostile vectors, and
reference report after a reviewed adapter change:

```sh
node conformance/composition/ccs-draft08-v13-crossing-lab-v1/run.mjs --write
```

## What is pinned

- `draft-correctover-ccs-08.txt`: 153,156 bytes, SHA-256
  `fbac2a025f11baec104687ee04ba5c9fb0dad1b5bbb5ad38494965565a977cd3`.
- The exact 22-field v1.3 receipt shape and detached Ed25519 signature over
  RFC 8785 canonical fields 1-21.
- One relying-party issuer key and audience. The artifact cannot supply either
  trust choice.
- One mapping profile from signed `tool`, the 16-hex `params_hash`, and the
  full 64-hex digest embedded in `action` to
  `agent.tool-invocation.1`.
- One exact action, CAID, authenticated status snapshot, and native replay unit
  based on `(issuer, nonce)`.

The workspace directory intentionally contains only `artifact.json`,
`adapter.mjs`, and `workspace.json`. The adapter is a reviewed one-file bundle
with no network or package dependency.

## Hostile coverage

The deterministic suite covers signature mutation, unsigned extra fields,
issuer-key substitution, audience substitution, expiry, action-parameter and
mapping-profile substitution, a changed full digest that preserves the signed
16-hex prefix, consumed replay state, unavailable status, valid deny and
escalate receipts, and wrapper-independent replay identity. Crossing Lab also
repeats adapter calls and tests malformed output, duplicate JSON members, and
workspace pin drift.

## Claim boundary

CCS contributes a signed `machine-policy-decision`. A valid `allow` can satisfy
that named evidence role, but it does not authorize execution. Gate still
decides admission under its complete local requirement. The signed
`response_hash` commits to response bytes; it is not proof that an external
effect occurred or had the intended result.

The report is self-attested public test evidence. It is not Correctover
certification, independent interoperability evidence, deployment evidence, an
authorization, or effect proof. Public deterministic keys are fixtures only.

External adoption requires three additional facts: a native author confirms
the mapping preserves CCS semantics, a second runner reproduces the report,
and the profile is installed beside one real CCS verifier and Gate deployment.
