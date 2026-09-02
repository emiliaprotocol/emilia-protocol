<!-- SPDX-License-Identifier: Apache-2.0 -->
# OASNT-CAID and AEB composition

Status: experimental implementation note and executable local vectors. This is
not a new wire format, an external interoperability result, or a claim of
adoption by either draft.

## Source locks and compatibility boundary

The native token verifier is locked to the current public core draft:

- `draft-thallapelly-oasnt-02`
- official archived-text SHA-256
  `sha256:3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603`

The lifecycle and namespace-separation cases come from the separate companion:

- `draft-thallapelly-oasnt-caid-01`, Sections 4.1 and 6.4
- official archived-text SHA-256
  `sha256:75dfecb65e56accc5b55aa66a570e6fae52d3fe417631482eb8172d50e771963`

The companion remains revision -01 and normatively references core OASNT-01.
This repository applies only its Section 4.1 single-use boundary and Section
6.4 namespace-separation rule to tokens verified under the OASNT-02 adapter.
The adapter tests separately establish that the canonical action bytes and
published Appendix A.6 V5 token used here are unchanged and verify under the
-02 source lock. This does not claim that an OASNT-CAID revision for OASNT-02
has been published.

## Single-use boundary

The OASNT token is verified and matched to the executor's expected material
action before AEB reserves its native replay unit. A native-verification or
action-matching refusal therefore creates no reservation and consumes nothing.
After every pre-consumption check and the relying party's local authorization
succeed, AEB atomically reserves the operation and native replay unit before
provider entry:

- `NOT_COMMITTED` releases the reservation and permits a legitimate retry;
- `COMMITTED` permanently consumes it and a subsequent presentation is
  refused; and
- `INDETERMINATE` keeps the reservation closed for authenticated
  reconciliation and never creates retry authority.

These are AEB execution-state properties. OASNT remains one native
human-authorization evidence leg and is not itself an evidence-sufficiency,
local-authorization, provider-entry, or execution-outcome verdict.

The checked-in positive controls are:

- `near_miss_refusal_preserves_authority`;
- `not_committed_release_is_terminal`; and
- `committed_admission_consumes_and_replay_refuses`.

## Executor-owned dual-profile join

The executor derives both profile-specific identifiers from its own material
action:

1. `oasnt:caid:1:<base64url-digest>` is derived under OASNT-CAID-01 from the
   OASNT native action type and parameters.
2. `caid:1:<type>:<suite>:<digest>` is derived under the exact
   relying-party-pinned EMILIA mapping profile from the complete expected
   action.

The identifiers have distinct namespaces, preimages, and semantics. They do
not compare equal and MUST NOT be used as direct cross-profile join keys. The
local composition check succeeds only after independently deriving both
expected identifiers from one executor-owned action representation and
comparing each presented identifier to its own derivation. Namespace
substitution, mutation of either identifier, or a changed material action
returns no join.

`computeOasntCaid` exposes the source-locked OASNT-local derivation. The
dual-profile join itself remains executor policy demonstrated in the local test
harness; the OASNT adapter's production output continues to map the verified
native leg into the relying party's pinned EMILIA CAID profile. Neither draft's
artifact is extended.

## Reproduce and limits

The source-locked manifest is
`conformance/vectors/oasnt-caid-aeb.v1.json`. The handlers are in:

- `packages/verify/aeb-oasnt-adapter.test.ts`; and
- `packages/verify/aeb-acceptance-profile.test.ts`.

Run:

```sh
npm --prefix packages/verify run build
npm run build:standalone-runtimes
node --test packages/verify/aeb-oasnt-adapter.test.js \
  packages/verify/aeb-acceptance-profile.test.js
```

The result is same-repository source and local-harness evidence. It does not
establish an independent implementation, external reproduction, deployment,
certification, standards adoption, or IETF endorsement. It also does not prove
civil identity, organizational standing, current non-revocation without the
required status input, complete mediation, or provider effect.
