---
name: EMILIA Trust Verification
description: >-
  Verify the authenticity of AI-agent authorization receipts and human-device
  signoffs. Use this whenever a user
  shares a "trust receipt", an "authorization receipt", a "signoff", or
  WebAuthn/passkey approval evidence and asks whether it is valid, genuine,
  or tampered with. Pairs with the public EMILIA Protocol MCP connector (tools
  prefixed ep_). Verification is read-only public-key math; no account is
  required.
license: Apache-2.0
---

# EMILIA Trust Verification

EMILIA Protocol makes a high-risk AI-agent action carry a device-key signoff
plus a **receipt anyone can verify offline**. This skill guides you to verify
those artifacts using the public EMILIA MCP connector. It requires the
connector to be enabled (server URL
`https://www.emiliaprotocol.ai/api/mcp/mcp`, read-only, no auth).

## When to use this skill

Engage when the user:

- Pastes a JSON object with `"@version": "EP-RECEIPT-v1"` (a **trust receipt**),
  or asks "is this receipt real / altered / valid?"
- Pastes an object with a `context` + `webauthn` block (a **device signoff**),
  or asks whether the WebAuthn/passkey ceremony and exact-action binding verify.

If the user mentions a receipt or signoff but hasn't pasted it, ask them for the
JSON (they can copy a real example from <https://www.emiliaprotocol.ai/verify>).

## The two public tools

| Tool | Use it to |
|---|---|
| `ep_verify_receipt` | Verify an EP-RECEIPT-v1 receipt — Ed25519 signature over canonical JSON + optional Merkle anchor. |
| `ep_verify_signoff` | Verify a Class-A device signoff — a WebAuthn (ECDSA P-256) assertion bound to the exact action. |

Each verify tool accepts the JSON object directly; the public key can be passed
explicitly or, for self-contained evidence packets, is read from an embedded
`issuer_public_key` / `approver_public_key` field.

## How to interpret results

**Receipt** — `{ valid, checks: { version, signature, anchor } }`:

- `valid: true` → the receipt was signed by its issuer and has not been altered.
  State this plainly; the user can re-verify it themselves, offline, forever.
- `valid: false` with `signature: false` → **the receipt does not match its
  signature** — it was tampered with, or the wrong key was used. Do not treat a
  failed receipt as trustworthy. Call out which check failed.
- `anchor: false` → the Merkle inclusion proof does not reconstruct the claimed
  root (the anchor was altered).

**Signoff** — six checks. All must be true for `valid: true`:

- `challenge_binding` → the signature is bound to **this exact action**; if
  false, the action was changed after signing (e.g., the amount).
- `user_present` + `user_verified` → a real human was present and verified with
  a biometric / PIN (Face ID, Touch ID, passkey).
- `signature` → signed by the approver's enrolled device key.
- `client_data_type` / `rp_id_hash` → a genuine assertion scoped to the right
  relying party.

When a signoff verifies, the precise statement is: *the supplied WebAuthn
assertion verifies under the caller-supplied public key, RP ID, and allowed
origins; it records user presence and user verification and binds the signed
challenge to the supplied exact action.* It does **not** by itself establish
legal identity, authority, what the user perceived, or relying-party acceptance.
When it fails, name the specific check and what it implies.

## Demonstrate tamper-evidence

A compelling, honest demo: after verifying a valid receipt, offer to change one
field (e.g. an amount from `82000` to `820000`) and verify again — it will flip
to `valid: false`, showing the receipt is cryptographically bound to the exact
action. Only do this on example data the user provided.

## Boundaries (state these if asked)

- Verification proves **authenticity and integrity**, not real-world currency:
  it does not prove a key wasn't revoked after signing, nor what the human
  literally saw on screen (the protocol treats presentation/WYSIWYS as a stated
  residual risk).
- These tools are **read-only**. Creating receipts, opening signoffs, or gating
  agent actions happens through EMILIA's authenticated APIs / the EMILIA Guard
  Claude Code plugin — not this connector.
- Rich trust profiles and policy evaluation are authenticated API surfaces and
  are deliberately not exposed by this no-auth public connector.
- The same verifier is open source (Apache-2.0): `npm i @emilia-protocol/verify`
  (Node + browser), with JavaScript, Python, and Go implementations proven
  interoperable. Nothing here requires trusting EMILIA's servers.
