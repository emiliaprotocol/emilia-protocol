<!-- SPDX-License-Identifier: Apache-2.0 -->
# AADP and EP authorization-artifact composition v0.1

This package implements and tests a profile-neutral authorization-artifact
digest hook for the Agentic Action Decision Protocol (AADP). It then exercises
one concrete profile in which the external artifact is an
`EP-AUTHORIZATION-BUNDLE-v1`.

The result is a digest join, not a dependency claim. AADP still owns its local
policy decision, approval state, `permit_id`, obligations, provider adapter,
and report lifecycle. EP verifies bounded approval evidence for an exact mapped
action. Neither protocol inherits the other's transport or trust model.

## The neutral hook

```json
{
  "profile": "AADP-AUTHORIZATION-ARTIFACT-v1",
  "artifact_profile": "EP-AADP-AUTHORIZATION-ARTIFACT-v1",
  "artifact_digest": "sha256:6d8a602f...",
  "action_mapping_profile": "https://emiliaprotocol.ai/profiles/aadp-ep-payment-release-v1",
  "action_digest": "sha256:a84820a5..."
}
```

An AADP implementation records this object only after the selected native
verifier succeeds. The profile identifier selects the native verification
rules. `artifact_digest` binds the exact verified artifact.
`action_mapping_profile` identifies the relying-party-pinned mapping from the
AADP action to the artifact's action model. `action_digest` binds the mapped
material action.

The hook MUST NOT be treated as an approval, credential, permit, obligation,
provider idempotency key, or authorization decision. A presenter-supplied hook
MUST be compared with the projection independently derived by the PDP.

## Executed cases

The runner executes fourteen cases:

1. Valid exact-action composition.
2. Material action substitution.
3. Artifact tampering.
4. Unpinned approver keys.
5. Wrong relying-party audience.
6. Unavailable action mapping.
7. Unavailable current EP policy.
8. Mapping-profile substitution.
9. Missing required hook.
10. AADP kill switch after valid EP verification.
11. Single-use AADP approval replay.
12. Separation of artifact digest, permit ID, and provider key.
13. Timeout reporting without reopening approval.
14. Informational AADP source metadata.

All fourteen pass in `report.reference.json`. The report digest is
`sha256:49af4e8fe20ea2ba96ca2ccd7697d368f9c5161cb3777a788b5aef166ac6e7b2`.

## Source boundary

`source-lock.json` pins the official text of `draft-saha-aadp-01`, the EP
Authorization Bundle vector and verifier bytes, and the inspected onedoor
revision. The AADP lifecycle in `run.mts` is a bounded model derived from the
draft. It is not onedoor and is not described as an independent AADP
implementation. The onedoor source was inspected for alignment but was not
executed by this runner.

## Run

```bash
npm run conformance:composition:aadp-ep
```

Direct commands:

```bash
npm --prefix packages/verify run build
node --test packages/verify/aadp-authorization-artifact.test.js
node --test conformance/composition/aadp-ep-authorization-v0.1/run.node-test.mjs
node conformance/composition/aadp-ep-authorization-v0.1/run.mjs --check
```

Regenerate the deterministic report only after a deliberate behavior change:

```bash
node conformance/composition/aadp-ep-authorization-v0.1/run.mjs --emit
```

## Publication state

This is an EMILIA-authored working profile, not an IETF working-group result,
AADP update, or joint publication. Joint authorship and publication require
Shamik Saha's explicit agreement. A candidate joint document can normatively
reference both AADP and EP while each core protocol remains independent.
