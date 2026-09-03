# Joint Note — AIC × EMILIA Exact-Action Binding Crossing

Date: 2026-09-03
Participants: Jijie Wei (author of draft-wei-aic-identity-cert and
draft-wei-aic-jwt, Varwof); Iman Schrock (EMILIA Protocol)

## 1. Purpose

This note records the agreed semantics of the AIC-to-AEB exact-action
binding crossing merged in emiliaprotocol/emilia-protocol PR #685, and
the boundary it establishes between the two projects. It serves as the
joint consistency statement referenced during review. It does not
create, extend, or reimplement any AIC or EMILIA mechanism.

## 2. Anchors

- PR: emiliaprotocol/emilia-protocol#685 "feat(composition): add
  bounded AIC-to-AEB exact-action mappings", merged 2026-09-02 by Iman
  Schrock into main at merge commit
  `3eeca91ca5942d5a4b4b94e7a0a4afd9e53b4498`; reviewed head
  `4dffbf6c5e85243d12c010d02609b7200620b7df`.
- AIC drafts: draft-wei-aic-identity-cert-01, draft-wei-aic-jwt-00;
  IPR 7553/7565 (Royalty-Free, Reasonable and Non-Discriminatory
  License to All Implementers).
- The crossing consumes native AIC verification results only; it does
  not reimplement AIC-JWT signature, delegation, capability,
  constraint, or status validation, nor X.509 path validation.

## 3. Semantic boundaries (as reviewed, both heads)

1. Native verification is authoritative: FAILED/INDETERMINATE are
   refused before any mapping.
2. Relying-party policy is structurally separate from the presented
   result: mapping profile, action-projection profile, native verifier
   descriptor, and issuer trust anchors are pinned by RP policy; the
   presented result cannot self-pin any of them.
3. Raw-carrier provenance is required on both paths: the JKT path
   requires the original compact token (typ=aic+jwt; iss/sub/jti/aud
   checked; signed validity envelope equals mapped validity; RFC 7638
   thumbprint matched); the X.509 path requires exact agent and
   principal certificate DER, distinct leaves, and principal SPKI
   SHA-256 computed from the principal certificate public key.
4. RFC 7638 JKT and X.509 SPKI remain separate native mappings; type
   confusion is refused by exact kind/hash_alg checks.
5. BOUND-v2 request binding commits requested_capability_digest, caid,
   action_digest, and the admission-domain digest; the no-transplant
   property across relying parties holds via the bound-authority
   constraints digest.
6. Status handling is fail-closed: status must be CURRENT and include
   checked_at and source_head_digest. The v0.2 relying-party profile
   fixes max_status_age_seconds at 60. The adapter accepts that
   context field structurally only within 0 to 86,400 seconds, then
   requires it to equal 60 for this profile and enforces the 60-second
   age limit.
7. The SVID projection is workload-identity-only: single audience,
   SPIFFE subject, fresh typ=JWT signature, with
   authority_semantics_preserved=false and
   authorization_decision=false.

## 4. Documentation corrections completed in this revision

Main already contained the source-lock pin for
draft-wei-aic-identity-cert-01 (adapter semantics unaffected by the
-00 to -01 update; the sole normative delta in the bounded area is
the RSA-PSS signature-algorithm sentence: SHA-256/384/512 MAY instead
of SHA-256 only) and the corrected jwt bounded_sections labels
(Claims / Credential Bundle (Optional) / Validation Pipeline).

This revision completes the identity-cert bounded_sections with
Section 10 (Security Considerations) and refreshes the generated
report (source_lock_digest updated). The retained jwt Section 16 pin
(Compatibility with the Varwof Unified JWT Profile) is unchanged;
the labels listed above are not exhaustive of every pinned section.

Adapter semantics are unchanged by these corrections; the pinned
evidence bytes are refreshed and rerun as part of this revision.
Neither project's code or semantics change as a result.

## 5. Stewardship and IPR

IPR disclosures 7553 and 7565 state that Necessary Patent Claims
for implementing the relevant IETF specification are available under
a "Royalty-Free, Reasonable and Non-Discriminatory License to All
Implementers" declaration.

EMILIA's contribution in this repository remains Apache-2.0 licensed.
This note does not change either side's patent position beyond the
licenses and declarations that already apply.

This note does not commit either side to any future joint document,
scope, or work item beyond the crossing itself.

Proposed by:

Jijie Wei (pki@varwof.com) — AIC drafts author

Confirmation record:

emiliaprotocol/emilia-protocol#730
