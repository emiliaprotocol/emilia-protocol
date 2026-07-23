# Federation Proof — Two-Operator Live Cross-Verification

**Date:** 2026-06-12
**Scope:** PIP-006 acceptance gate #1 (second operator passing the conformance suite end-to-end).
**Artifacts:** `conformance/operator2/` — `gen-operator2.mjs`, `index.ts`, `verify-live.mjs`, `operator2-receipt.json`.

---

## What this proves

Federation is what makes EP an open standard rather than a single-vendor service: a receipt issued by one operator must be verifiable by another using only the documented public discovery surfaces (PIP-006). This document records the live proof of that mechanism between two separately-deployed operators.

## What was deployed

**EP Federation Operator 2** is a second EP operator standing on its own infrastructure: a Supabase Edge Function (`conformance/operator2/index.ts`) on a different project and region, with its own Ed25519 key. It publishes exactly the three PIP-006 surfaces a relying party needs:

- `GET …/.well-known/ep-keys.json` — Operator 2's published verification keys plus a `verify_url_template` (the discovery doc; `version: "1.1"`, `protocol_version: "EP-CORE-v1.0"`).
- `GET …/receipt` — a real `EP-RECEIPT-v1` document Operator 2 signed (`conformance/operator2/operator2-receipt.json`): a `fin/payment-release` of $42,000, signed with Operator 2's key, carrying a `signature.key_discovery` hint that points back at Operator 2's own `ep-keys.json`.
- `GET …/api/verify/{receipt_id}` — Operator 2's verifier-of-record / revocation surface.

The identity and the signed receipt are generated together by `gen-operator2.mjs` (the served public key and the served receipt's signature are produced in the same run, so they always match), and the canonicalization is byte-identical to `packages/verify/index.js`. There is no private key at runtime — the receipt is pre-signed and the edge function only static-serves.

## The recorded live proof (6 checks)

The following records the June 2026 run. The current verifier is stricter:
HTTP success and a JSON `revoked: false` value no longer establish current
non-revocation. A live acceptance run now also requires a relying-party-pinned
status verifier that authenticates the status document, binds it to the exact
receipt, and verifies freshness. The historical deployment therefore proves
cross-origin discovery and signature verification, but it must be upgraded to
`EP-STATUS-v1` (or an equivalent pinned status verifier) before rerunning the
current live-acceptance check.

`node conformance/operator2/verify-live.mjs` runs the relying-party path against Operator 2's live origin and asserts six things:

1. It **fetched a receipt Operator 2 issued** from Operator 2's own `/receipt` endpoint.
2. The **receipt verifies against Operator 2's published keys** — resolved live from Operator 2's pinned discovery origin (`verifyFederatedReceipt`, `packages/verify/federation.js`).
3. The **signer is Operator 2** (`signature.signer` matches the verified signer).
4. **Operator 2's revocation surface was consulted** — the discovery doc's `verify_url_template` is followed to Operator 2's `/api/verify/{receipt_id}`.
5. The legacy verifier's verdict was **`accepted`** — verified and reported not
   revoked under the status rule in force at the time. The current verifier
   intentionally refuses that same unverified status response.
6. A **tampered receipt is rejected** (the amount is mutated to 999,999,999): even with live keys, a forgery does not verify. This is the no-trust-laundering control.

This upgrades PIP-006 acceptance gate #1 from a self-hosted synthetic harness to two separately-deployed live operators cross-verifying, end to end.

## What this demonstrates about PIP-006 mechanics

- **Key discovery works against a foreign origin.** The relying party pins Operator 2's discovery origin, fetches `ep-keys.json`, and treats the receipt's `key_discovery` field as a non-authoritative hint.
- **`verify_url_template` works as transport discovery.** The response is still
  untrusted input until a relying-party-configured status verifier authenticates
  it, binds the exact target, and proves freshness.
- **Offline and online both hold, under different trust boundaries.**
  `verifyFederatedReceiptOffline` verifies with a supplied `ep-keys.json` and
  revocation set (air-gapped). `verifyFederatedReceipt` requires a relying-party
  resolver plus pinned transport that proves the connected address belongs to
  the all-public approved DNS set; plain/global fetch, redirects, private or
  mixed DNS answers, and an unapproved connected address are refused. Historical
  keys accept only receipts whose signed strict-RFC-3339 `issued_at` is no later
  than the key's valid `retired_at`. The executable suite covers tamper,
  wrong-operator, rotation, retirement, revocation, DNS rebinding, and status
  authentication. The path is also modeled and machine-checked in
  `formal/ep_federation.als` (seven safety assertions, no counterexample).

## Honest limitation

**Both operators are operated by EMILIA, and the recorded status/network
surface is not yet upgraded to the current verifier contract.** Operator 2 runs on separate
infrastructure, with its own key, on a different project and region — but it is
the same owner. So this proof demonstrates the discovery and signature
mechanism across separate deployments; it is **not** independent-operation
proof or a current live-acceptance proof. Both remain open milestones.

The final step is an externally-operated instance — a different organization standing up the same surfaces and passing:

```bash
node conformance/operator2/verify-live.mjs https://<their-origin>
```

The contract and a working reference operator are both already published. If you want to run an EP node, `conformance/operator2/` is the smallest complete example, the full conformance suite is in `conformance/`, and `app/adopt` Level 5 ("Operator — run your own node") is the on-ramp. Stand one up and the open milestone closes.

---

*Reference: `PIPs/PIP-006-federation.md` (acceptance gates and status), `docs/FEDERATION-REGISTRY.md` (operator-discovery convention).*
