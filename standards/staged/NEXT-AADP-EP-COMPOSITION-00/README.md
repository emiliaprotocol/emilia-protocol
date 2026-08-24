<!-- SPDX-License-Identifier: Apache-2.0 -->
# Candidate AADP and EP joint composition document

Status: blocked on explicit coauthor agreement. Do not submit or attribute
joint authorship yet.

The implementation-backed profile is:

- `docs/protocol/AADP-EP-AUTHORIZATION-ARTIFACT-PROFILE.md`
- `packages/verify/src/aadp-authorization-artifact.ts`
- `conformance/composition/aadp-ep-authorization-v0.1`

The candidate Internet-Draft should be created only after Shamik Saha agrees
to the joint document and author order. It can normatively reference both
`draft-saha-aadp` and `draft-schrock-ep-authorization-receipts` while leaving
both core protocols independent.

The requested AADP -02 mention is informative and bounded to the working
profile and implementation. It must not call EP an AADP dependency, claim
working-group adoption, or imply onedoor executed this runner.

Suggested AADP implementation-status sentence:

> A profile-neutral authorization-artifact digest composition with EP
> Authorization Bundles is implemented and exercised against fourteen
> source-pinned cases. The profile records the verified artifact digest,
> action-mapping profile, and exact mapped-action digest without treating the
> artifact as an AADP permit or changing AADP's local trust model.
