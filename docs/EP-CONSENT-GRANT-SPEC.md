<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-CONSENT-GRANT-v1: the standing, scoped, revocable consent grant

> A named object that is exactly a `{asset, control_verb, expiry}` consent grant,
> independently revocable, DISTINCT from the per-action receipt at the binding
> moment. It fills binding 3 (Consent Grant) of Blake Morrison's Command
> Authority Envelope ([`draft-morrison-ot-command-authority`]) as its own
> first-class artifact.

- Verifier + reference issuer: [`packages/verify/consent-grant.js`](../packages/verify/consent-grant.js)
- Tests: [`packages/verify/consent-grant.test.js`](../packages/verify/consent-grant.test.js)
- Schema: [`public/schemas/ep-consent-grant.schema.json`](../public/schemas/ep-consent-grant.schema.json)
- CAE mapping (binding-3 row): [`docs/standards-engagement/EP-CAE-COMMAND-AUTHORITY-MAPPING.md`](standards-engagement/EP-CAE-COMMAND-AUTHORITY-MAPPING.md)

## Motivation

The Command Authority Envelope separates two things EP had previously expressed
through one path. Binding 3 is the **consent grant**: standing authority, scoped
to an asset and a control verb, bounded by an expiry, revocable at any time.
Binding 4 is the **binding moment**: a named human's device-bound signature over
the exact action at the moment of consequence. An EP receipt is the binding
moment, and always has been. What EP did not ship until now was one artifact that
is exactly the standing grant, independently revocable, distinct from the receipt.

The pieces existed (policy scoping, the Approver Directory's scope, admissibility
profiles, delegation, and revocation statements), they were just not assembled
into one named grant. This spec assembles them. The grant is the standing
authority a relying party pins once; the receipt is the per-action authorization
that references it. Keeping them separate is the point: a valid grant does not
authorize an action without a receipt bound to it, and a receipt bound to a grant
does not authorize an action the grant does not cover.

## The object

```
{
  "profile": "EP-CONSENT-GRANT-v1",
  "grant_id": "grant_ot_pump_7",
  "principal": "ep:approver:diane_staheli",
  "asset": "ot:site-3/pump-array/valve-7",
  "control_verb": "setpoint.write",
  "constraints": { "amount_ceiling": "500000" },
  "issued_at": "2026-07-01T00:00:00.000Z",
  "expires_at": "2026-08-01T00:00:00.000Z",
  "grant_hash": "sha256:<hex over JCS(grant minus grant_hash and minus signature)>",
  "signature": "<principal's Ed25519 signature over the canonical grant bytes, base64url>"
}
```

- **principal** is the granting party reference: who conferred this authority. It
  MAY name a single accountable approver or reference a quorum policy that
  authorized the grant. The field NAMES the principal; the relying party pins the
  key that signs the grant. The binding of key to natural person is only as strong
  as the enrollment ceremony's proofing, exactly as for the receipt approver.
- **asset** is the resource the grant covers. **control_verb** is the exact
  operation authorized. **constraints** is optional (for example an amount
  ceiling); like every EP signed field, non-integer quantities are STRING-encoded
  so the canonical bytes are byte-identical across JS, Python, and Go.
- **issued_at** and **expires_at** are RFC 3339 with an explicit UTC offset. The
  no-timezone and date-only forms are rejected as ambiguous (fail closed). Keep
  the window short: a short window plus a pushed, signed revocation snapshot is
  how EP bounds staleness for an air-gapped executor.

### grant_hash

`grant_hash` is `"sha256:"` followed by the hex SHA-256 over the JCS/RFC-8785
canonical bytes of the grant with **both** `grant_hash` and `signature` excluded.
It reuses the same `canonicalize()` plus SHA-256 that EP uses everywhere. The
`signature` is the principal's device-bound Ed25519 signature over those same
canonical bytes, verified with `crypto.verify(null, bodyBytes, key)` against the
pinned principal key (base64url SPKI DER), exactly as EP verifies Ed25519
elsewhere. Hash and signature cover an identical, self-consistent body: neither
field can contain its own value.

## Verifier contract and closed refusals

`verifyConsentGrant(grant, pinnedPrincipalKey, { now, revocation, revokerKeys, revocationMaxAgeSeconds })`
returns `{ valid, checks: { hash, signature, within_window }, reason? }` and is
fail-closed on every axis:

| condition | refusal reason |
|---|---|
| grant_hash does not bind the canonical body (tampered or malformed) | `grant_hash does not bind the canonical grant body ...` |
| no pinned principal key | `no pinned principal key (grant principal identified but not trusted)` |
| signature does not verify under the pinned key | `grant signature does not verify under the pinned principal key` |
| `now` before `issued_at` | `grant is not yet valid (now is before issued_at)` |
| `now` after `expires_at` | `grant is expired (now is after expires_at)` |
| a valid revocation statement binds this grant_hash | `grant_revoked` |

An unpinned revoker cannot revoke: a presented revocation statement is only
honored when it verifies under a key **pinned** for its `revoker_id`, and only
when it binds the exact `grant_hash` (revoking grant A must never revoke grant B).
Both are enforced by reusing [`verifyRevocation`](../packages/verify/revocation.js)
against a `commit`-typed target keyed on `grant_hash`, no new revocation
machinery.

### Composition: a receipt acting under a grant

`verifyReceiptUnderGrant(receipt, grant, { now, pinnedPrincipalKey, revocation, revokerKeys, grantHash, assetCovers, verbCovers })`
returns `{ ok, checks: { grant, asset_covered, verb_covered, grant_binding }, reason? }`.
It is the join between the binding moment and the standing grant. It verifies:

1. the grant itself (via `verifyConsentGrant`);
2. the receipt's action asset is covered by the grant's asset (strict equality by
   default; a relying party MAY supply a fail-closed scope predicate);
3. the receipt's action control verb is covered by the grant's control_verb;
4. the receipt is bound to `grant_hash`: it references the grant's `grant_hash`
   and that reference equals the grant's own `grant_hash`.

Any mismatch refuses with a distinct reason:

`grant_signature_invalid` | `grant_expired` | `grant_revoked` | `asset_mismatch`
| `verb_mismatch` | `grant_binding_mismatch` (plus structural refusals
`missing_receipt`, `missing_action`, `missing_grant_reference`).

`verifyReceiptUnderGrant` checks the grant and the scope/binding join; it does
NOT re-run the receipt's own end-to-end cryptography. Call
[`verifyReceipt` / `verifyTrustReceipt`](../packages/verify/index.js) for that.
Because it reads the receipt's asset, verb, and `grant_hash` from the signed
Action Object, those fields are covered by the receipt's own signature.

## How the per-action receipt references grant_hash

The per-action receipt SHOULD carry `grant_hash` INSIDE its signed Action Object,
so the binding-moment authorization is cryptographically tied to the standing
grant it exercised and the reference is covered by the human signature over the
action. The reference implementation now does exactly this: when a caller mints an
action under a standing grant, the mint path
([`lib/guard-adapter.js`](../lib/guard-adapter.js)) puts `grant_hash` into the
canonical Action Object before hashing, so it is folded into the action hash and
therefore into the receipt's signature. The field is OPTIONAL and
backwards-compatible: an action minted without a standing grant canonicalizes and
hashes exactly as before, and a malformed `grant_hash` is refused at mint time
rather than folded into signed bytes.

The verifier reads the reference, in precedence order, from
`receipt.action.grant_hash`, then `receipt.action.consent_grant_hash`, then
`receipt.grant_hash`, and falls back to a caller-supplied override
(`opts.grantHash`) for the transitional case where a receipt does not carry a
native one.

The precedence prefers the SIGNED reference over the override on purpose, because
the two bindings are NOT equally trustworthy:

- A `grant_hash` read from the signed Action Object is the STRONG binding.
  Tampering it breaks the action hash and thus the receipt's own signature, so a
  verifier that re-runs the receipt's cryptography would reject the tamper.
- A caller-supplied override is ADVISORY. Nothing in the receipt's cryptography
  covers it, so a receipt without a native `grant_hash` can still be bound to a
  grant, but that binding is then only as trustworthy as the caller who supplied
  the hash.

`verifyReceiptUnderGrant` surfaces which one applied as `binding_strength`
(`signed_action` | `top_level` | `caller_override` | `none`) so a relying party
can price the difference. `receiptGrantBindingStrength(receipt, override)` reports
the same value without running the full composition. A future receipt revision
SHOULD also promote `grant_hash` to a named top-level field for receipt profiles
that fold top-level fields under their signature.

## Revocation and the offline currency bound

The grant is standing authority; the binding-moment receipt is the per-action
authorization. Neither establishes business correctness, that the authorized
operation is the right thing to do. And offline verification of either is
authenticity-as-of-commit, not proof of current validity: a grant authentic today
may have been revoked one second later, and absence of a revocation statement is
NOT proof of not-revoked. This verifier checks a PRESENTED revocation statement
and refuses when one validly binds the grant; it cannot manufacture the absence
of one. Revocation currency therefore needs a fresh revocation snapshot pushed to
the verifier, exactly like any other EP status (see
[`EP-REVOCATION-SPEC`](EP-REVOCATION-SPEC.md) and EP-CURRENCY-v1). For an
air-gapped OT executor the reconciliation is the same one EP states throughout: a
short validity window plus a pushed, signed, witnessed revocation snapshot, with
the staleness of that snapshot as the priced residual.

## Status

EP-CONSENT-GRANT-v1 is a SHIPPED artifact in `@emilia-protocol/verify` (issuer,
verifier, composition, schema, tests). It is a CANDIDATE profile to fold into the
authority / receipts drafts
([`draft-schrock-human-authorization-binding`] and
[`draft-schrock-ep-authorization-receipts`]) in a future revision, so binding 3
becomes a named object in the standards text as well as in the code. It is NOT
filed as a draft today.

[`draft-morrison-ot-command-authority`]: standards-engagement/EP-CAE-COMMAND-AUTHORITY-MAPPING.md
[`draft-schrock-human-authorization-binding`]: standards-engagement/EP-CAE-COMMAND-AUTHORITY-MAPPING.md
[`draft-schrock-ep-authorization-receipts`]: ../packages/verify/index.js
