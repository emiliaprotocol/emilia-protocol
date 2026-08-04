# Authorization Server Confirmation Profile v1

This profile adds an enterprise Authorization Server (AS) confirmation as an
independently verified evidence leg in EMILIA. It does not add a second
signature to the base receipt, and it does not let the AS signature promote a
receipt from `VERIFIED` to `AUTHORIZED`.

The security objective is narrower and stronger: the relying party can require
proof that its own identity and authorization system vouched for the named
human, the exact human evidence, the exact action, the applicable policy and
directory snapshot it actually observed, and the intended Resource Server
before Gate admission. It does not convert token freshness into a claim that
the underlying HR or entitlement source was current.

## Three separate decisions

1. The human verifier decides whether the human signoff is cryptographically
   valid under the relying party's pinned approver keys and ceremony policy.
2. The AS adapter decides whether the AS grant is valid under the relying
   party's pinned AS key, issuer, audience, Resource Server binding and
   freshness limits, while preserving the AS-signed policy and directory
   commitments as evidence.
3. AEB/AEC decides whether both independently verified legs satisfy the local
   evidence requirement for the same exact action. Gate alone decides whether
   the action may be admitted and consumed.

An agent orchestrator signature is not an AS confirmation. Initiator
attestation remains provenance about which software asked; it cannot satisfy
the `authorization-server-confirmation` role.

## Signed AS claims

The reference profile consumes a compact EdDSA JWS with a closed protected
header and a closed claim set. The signed claims bind:

- AS issuer, key identifier, human subject and Resource Server audience;
- issued-at, not-before, expiry and native grant identifier;
- the closed `{ action_type, parameters }` exact-action projection and digest;
- the digest of the exact human-evidence artifact carried with the grant;
- the AS policy digest, customer identity-directory digest, fixed observation
  basis, and the time the AS observed that snapshot; and
- the intended Resource Server key or KMS identity and its public-key digest.

The artifact cannot nominate its own key, issuer, algorithm, audience, action
type, mapper, status source, or evidence requirement. Those values are pinned
by the relying party. The relying party also pins a maximum directory-snapshot
age. A signed token issued now over an older snapshot remains cryptographically
`VERIFIED` but is `INDETERMINATE`, never `ACCEPTED`. Current revocation and
consumption status remains a separate authenticated input; token expiry alone
is not current status.

`directory_observed_at` means only when the Authorization Server observed the
state represented by `directory_digest`. It does not assert when an HR decision
occurred, when an upstream system synchronized, or that the named human still
holds a role at some finer resolution. A signature cannot manufacture source
precision the underlying record does not possess.

## Evidence binding

`AEB-REQUIREMENT-v1` adds the fail-closed `evidence-binding` term:

```json
{
  "type": "evidence-binding",
  "source_role": "authorization-server-confirmation",
  "target_role": "human-authorization",
  "require_same_subject": true
}
```

The AS adapter emits the human-evidence digest only after verifying that the AS
signed it and that it matches the artifact bytes supplied to the adapter. The
term succeeds only when that digest equals the `evidence_digest` of a separately
`SATISFIED` human-authorization leg and both legs identify the same human.
Sharing a CAID is necessary but not sufficient.

## Exact-action mapping

The AS-signed action is mapped through
`EP-AUTHORIZATION-SERVER-CONFIRMATION-CAID-MAPPING-v1`. A valid AS signature
over a different action remains valid native evidence but produces `MISMATCH`
against the action Gate is considering. This preserves the distinction between
signature validity and authorization applicability.

## Standards relationship

The implementation consumes a design already emerging in
`draft-liu-agent-operation-authorization`, which carries a user confirmation
record and an AS signature, and follows the boundary in
`draft-klrc-aiagent-auth`: local confirmation alone is not authorization, and
the final authorization decision remains with the AS. This document is an
EMILIA implementation profile, not a claim that either external draft has
adopted this exact schema or verifier.

No new Internet-Draft is required now. The base authorization-receipt wire
format remains unchanged. Carrier standardization, if needed, should follow
implementation and author review rather than precede it.

## Deliberate limits

- It does not prove the human understood the display.
- It does not prove instantaneous employment, entitlement or role standing.
- It does not prove how fresh an upstream HR record was when the AS observed it.
- It does not prove the AS policy was legally or substantively correct.
- It does not make the AS a relying-party administrator or trust federation.
- It does not prove execution or observed effect.
- It does not replace one-time Gate admission, revocation, reconciliation or
  remedy.

Reference code is exported from
`@emilia-protocol/verify/authorization-server-confirmation`.
