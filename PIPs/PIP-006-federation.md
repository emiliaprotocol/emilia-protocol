# PIP-006: Federation

**Status:** Draft
**Type:** Extension
**Created:** 2026-04-27
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze), PIP-002 (Handshake), PIP-004 (Commit)

## Abstract

The Federation extension defines how multiple independent EP operators
issue, verify, and cross-redeem trust evidence without a central authority.
Federation is what makes EP an open standard rather than a single-vendor
service: an EP-RECEIPT-v1 issued by Operator A must be verifiable by
Operator B using only the documented public discovery surfaces.

Federation does NOT define a multi-party consensus protocol, a shared
ledger, or a settlement layer. Each operator remains sovereign over its
own entity registry, policy catalogue, and audit log. What Federation
defines is the minimal cross-operator verification contract.

## Status note

This PIP is a Draft. The core mechanisms below are implemented in EP today
(`packages/verify/`, the `/.well-known/ep-trust.json` discovery surface,
the conformance test suite that exercises cross-operator verification).
Acceptance is gated on:

1. A second independent operator running EP and passing the conformance
   suite end-to-end against the primary operator's published artifacts.
2. A public Federation Registry document describing the operator-discovery
   convention.
3. A formal model (TLA+ or Alloy) of the cross-operator verification path
   that proves the same safety properties already verified for the
   single-operator case (see `formal/PROOF_STATUS.md`).

## Federation contract

Every conformant EP operator MUST publish:

1. `GET /.well-known/ep-trust.json` — operator capabilities, public keys,
   accepted protocol versions, supported extensions. Schema is defined in
   `public/.well-known/ep-trust.json` and exercised by the conformance
   suite.
2. `GET /.well-known/ep-keys.json` — Ed25519 verification keys for receipts
   issued by this operator. Served via the existing
   `/api/discovery/keys` route under a stable URL contract.
3. `GET /api/verify/{receipt_id}` — verifier-of-record endpoint that any
   relying party can hit to confirm an EP-RECEIPT-v1 document is well-formed,
   signed by a key the operator currently advertises, and not in the
   operator's revocation set.

Every conformant EP-RECEIPT-v1 document MUST include:

- `@version: "EP-RECEIPT-v1"`
- A `signature.signer` field identifying the issuing operator's entity_id
- A `signature.key_discovery` URL pointing to the issuing operator's
  `/.well-known/ep-keys.json`
- A `signature.value` Ed25519 signature over the canonical receipt payload
- A receipt_id matching the EP-RECEIPT-v1 receipt_id pattern

These three surfaces are what `packages/verify/` consumes to verify a
receipt offline without contacting the issuing operator. They are what
makes a receipt portable.

## Cross-operator semantics

Operator B, presented with a receipt from Operator A, MUST:

1. Fetch Operator A's `/.well-known/ep-keys.json` (or use a cached copy
   that has not exceeded its declared TTL).
2. Verify the Ed25519 signature on the canonical receipt payload using
   Operator A's currently-advertised key.
3. Verify the receipt has not been revoked by Operator A by consulting
   Operator A's `/api/verify/{receipt_id}` endpoint (or a published
   revocation feed if one is in use).
4. Apply Operator B's local trust policy to the verified receipt. The
   receipt is evidence; what Operator B does with it is policy.

Operator B is NOT required to:

- Trust Operator A's policy decisions about its own entities.
- Accept Operator A's trust scores at face value.
- Carry Operator A's audit log forward.

Federation enables receipt portability. It does not enable trust laundering.

## Out of scope

- Settlement, payments, or any economic exchange between operators.
- Multi-party consensus on entity identity.
- Cross-operator dispute adjudication (each operator runs its own
  adjudication; reciprocal procedures may be defined in a future PIP).
- A federation registry as a centralized service. The Federation
  Registry, when defined, will be a published convention (similar to
  RFC 7517 JWKS) that any operator can implement, not an endpoint owned
  by EMILIA.

## Security considerations

- **Key rotation:** Operators MUST publish current and historical keys
  in `/.well-known/ep-keys.json` so receipts signed before a rotation
  remain verifiable.
- **Revocation:** Operators MUST honor their own revocation lists.
  Receipts are short-lived by design; a revocation that arrives after
  the action has executed is a dispute, not a verification failure.
- **Time skew:** Receipt expiry checks across operators tolerate small
  clock skew (NTP-bounded); operators that drift more than 30 seconds
  from UTC SHOULD not issue receipts.

## Open questions (to resolve before Acceptance)

1. Should there be a canonical Federation Registry document published
   under the `ep-protocol` GitHub org, or should operator discovery
   remain ad-hoc?
2. Should EP-RECEIPT-v1 carry a `federation_version` field separate
   from `@version` so federation semantics can evolve independently
   of the receipt schema?
3. What is the minimum set of formal properties (TLA+ or Alloy) that
   federation must verify before this PIP transitions from Draft to
   Accepted?

## References

- `packages/verify/` — offline receipt verification library
- `public/.well-known/ep-trust.json` — operator self-claim schema
- `app/api/discovery/keys/route.js` — `/.well-known/ep-keys.json`
  serving route
- `conformance/conformance.test.js` — receipt-verification conformance suite
- `formal/PROOF_STATUS.md` — current formal verification scope
