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
(`packages/verify/`, the `/.well-known/ep-trust.json` and `/.well-known/ep-keys.json`
discovery surfaces, the conformance test suite that exercises cross-operator
verification). The three acceptance gates stand as follows:

1. **A second independent operator passing the conformance suite end-to-end.**
   *Verified against a second, separately-deployed LIVE operator.* The
   relying-party (Operator B) verification path is published as
   `@emilia-protocol/verify` → `verifyFederatedReceipt` /
   `verifyFederatedReceiptOffline` (version 1.3.0+ on npm; earlier releases
   lack the federation exports), with a two-operator cross-redemption harness
   (`conformance/federation.mjs`, `packages/verify/federation.test.js`, 14
   cases) proving valid redemption plus tamper, wrong-operator, rotation, and
   revocation rejection.
   - **Live proof:** a second operator — *EP Federation Operator 2* — runs on
     separate infrastructure (a Supabase Edge Function, different project /
     region) with its own Ed25519 key, publishing the PIP-006 surfaces
     (`conformance/operator2/`). A relying party fetches Operator 2's published
     keys *and* its revocation surface from Operator 2's own origin and verifies
     a receipt Operator 2 signed — live, end to end, with tampered receipts
     rejected. Run it: `node conformance/operator2/verify-live.mjs`.
   - **Remaining for full acceptance:** Operator 2 is operated by the same party
     as the primary, so it demonstrates the *mechanism* across separate
     deployments but is not yet an *independent third party*. The final step is
     an externally-operated instance passing
     `node conformance/operator2/verify-live.mjs https://<their-origin>` — the
     contract and a working reference operator (`conformance/operator2/`) are
     both published for them.

2. **A public Federation Registry document.** *Done* —
   `docs/FEDERATION-REGISTRY.md` defines the operator-discovery convention
   (JWKS-style, no central registrar), the `ep-keys.json` shape, the
   self-locating receipt fields, and the join procedure.

3. **A formal model of the cross-operator verification path.** *Done and
   verified* — `formal/ep_federation.als` models the path and proves seven
   safety assertions (soundness, tamper rejection, unadvertised-key rejection,
   rotation safety, revocation, no-trust-laundering, observer-independence) with
   **no counterexample** under the Alloy model checker. Run in CI on every
   change to `formal/*.als` (see `formal/PROOF_STATUS.md`).

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
  Registry is a published convention (similar to RFC 7517 JWKS) that any
  operator can implement, not an endpoint owned by EMILIA — see
  `docs/FEDERATION-REGISTRY.md`.

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

## Resolved questions

1. **Registry: canonical document or ad-hoc discovery?** Resolved — a
   canonical convention is published as `docs/FEDERATION-REGISTRY.md`
   (JWKS-style: a documented shape any operator implements; pinning a
   known origin is a convenience, the receipt's `key_discovery` URL is
   always authoritative).
3. **Minimum formal properties before Acceptance?** Resolved — the seven
   safety assertions in `formal/ep_federation.als` (soundness, tamper
   rejection, unadvertised-key rejection, rotation safety, revocation,
   no-trust-laundering, observer-independence), verified with no
   counterexample and run in CI on every change to `formal/*.als`.

## Open questions (to resolve before Acceptance)

2. Should EP-RECEIPT-v1 carry a `federation_version` field separate
   from `@version` so federation semantics can evolve independently
   of the receipt schema?

## References

- `packages/verify/` — offline receipt verification library
- `public/.well-known/ep-trust.json` — operator self-claim schema
- `app/api/discovery/keys/route.js` — `/.well-known/ep-keys.json`
  serving route
- `conformance/conformance.test.js` — receipt-verification conformance suite
- `formal/PROOF_STATUS.md` — current formal verification scope
