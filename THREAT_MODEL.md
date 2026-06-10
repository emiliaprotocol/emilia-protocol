# EMILIA Protocol — Threat Model & Trust Assumptions

EMILIA's guarantee is precise: **a key bound to a named principal authorized this exact
action, exactly once, with the approver distinct from the initiator — and the receipt
proves it offline, tamper-evident.** This document states plainly what that rests on,
where the current implementation is strong, and where it is not yet. We publish it
because a trust system that hides its own attack surface should not be trusted.

**Status key:** ✅ enforced today · 🔶 scaffolded / partial · ⬜ roadmap

---

## 1. Approver authentication — the weakest link  ✅ Class A shipped · 🔶 not yet default
**Risk.** The receipt proves "principal X's key signed," *not* that X wasn't phished,
coerced, or compromised. If X is authenticated weakly, a stolen credential is a valid
approval.

**Current state.** Class A signoff is **shipped and accepted on real hardware**: an
approver enrolls a device-bound passkey (`/approvers/enroll`) and signs the
WebAuthn challenge = `SHA-256(JCS(AuthorizationContext))` with biometric user
verification; the assertion is recorded in the receipt and verifies fully offline
(`@emilia-protocol/verify` `verifyWebAuthnSignoff`, ES256/P-256). EP orchestrates but
holds no approver key and cannot forge a signoff. First real-device acceptance:
2026-06-09, a $82,000 release approved by Touch ID, receipt verified offline, forged
copy rejected. The legacy bearer path remains as Class C (operator-custodied, labeled
as such on every receipt).

**Remaining.** Class A is *available* but not yet the *enforced default*: high-value
policies should **require** `key_class: A` and reject Class C, and the real
`authStrength` from the assertion should flow into the policy decision (the engine
already accepts `password | mfa | phishing_resistant_mfa`; the mint path still passes a
hardcoded `'mfa'`). Making Class A mandatory above a policy threshold is the next step.

**Status.** ✅ approver-held hardware keys shipped + real-device accepted ·
🔶 making Class A the required default for high-value policies is the remaining work.

## 2. Key custody  🔶
**Risk.** If EP signs receipts server-side, compromising EP (or a user session) forges
approvals.

**Current state.** Signing is server-side (`lib/signatures.js`, `lib/create-receipt.js`).

**Fix.** Client-held / hardware-held approver keys remove EP from the signing trust path —
EP becomes a witness and anchor, not the signer-of-record. Same roadmap as #1.

**Status.** 🔶 server-side today; client/hardware keys roadmap.

## 3. WYSIWYS — "what you see is what you sign"  ⬜
**Risk.** The signoff binds the action **hash**. If the approval UI renders benign text
while the hashed payload is malicious, the human signs blind.

**Fix.** Render the approval surface deterministically **from the same canonical action
object that is hashed** — never from separately re-described text. UI and signed payload
must derive from one source. EMILIA will ship a canonical approval renderer and document
this requirement for every integrator.

**Status.** ⬜ canonical renderer + integrator guidance (next security build).

## 4. Enrollment, limits & revocation (authority registry)  🔶
**Risk.** Who is a *valid* approver, up to what limit, and how is a compromised one
revoked? If anyone can enroll as "Maria Chen," the root is broken.

**Current state.** The rules engine already implements authority checks — missing
authority, `max_amount_usd`, scope, and `revoked` (`lib/rules-engine.js`) — but it runs
in shadow mode and is fed a *stub* authority in the live mint path
(`app/api/v1/trust-receipts/route.js`). The checking logic exists; the registry **data**
and its live enforcement do not yet.

**Fix.** A first-class authority registry — principals, scopes, per-action limits,
status — consulted on the live path, with revocation and rotation.

**Status.** 🔶 checks exist; registry data + live enforcement is the **#2 build**.

## 5. A real-but-deceived human (BEC / coercion)  ✅ partial
**Risk.** A legitimate approver is socially engineered ("the CFO says approve now").

**Reality.** No gate stops a deceived *real* human from approving. EMILIA's contribution
is accountability + friction: the approval is **named, signed, and evidenced**, and the
policy surfaces risk signals (new destination, after-hours, velocity — `riskFlags` in
`lib/guard-policies.js` and the rules engine) to slow the decision.

**Status.** ✅ accountability + risk signals — it raises the cost and creates the paper
trail; it does not read minds, and we say so.

## 6. Separation of duties  ✅
**Risk.** One person both initiating an action and approving it.

**Current state.** Enforced: the approver **must not** be the initiator, checked at
approve time (`lib/guard-signoff.js` — "Approver cannot be the initiator"), and a signoff
is decided exactly once (race-safe).

**Residual.** Only as strong as account separation — distinct strong-auth principals
(see #1) close the "one person, two keys" gap.

**Status.** ✅ enforced in protocol; strengthened by #1.

## 7. The deployment gap  ⬜
**Risk.** A perfect signoff is moot if the executing system never checks the receipt. An
in-process gate is skippable by the operator who controls the process.

**Fix.** End-to-end enforcement requires the **system of record** (the bank API, the
benefits system, the deploy pipeline) to verify the receipt before it executes. Until
that integration exists, EMILIA is a strong default and an offline-verifiable evidence
layer — not a physical barrier. Also stated on
[/security](https://www.emiliaprotocol.ai/security).

**Status.** ⬜ system-of-record verification integrations.

---

## Build order
1. **Hardware-backed approver auth** (WebAuthn/passkey) — closes #1, #2, and strengthens #6.
   Build ticket: [docs/WEBAUTHN-SIGNOFF.md](docs/WEBAUTHN-SIGNOFF.md) · protocol spec: [standards/](standards/) §5.
2. **Authority registry** (data + live enforcement) — closes #4.
3. **Canonical approval renderer** (WYSIWYS) — closes #3.
4. **System-of-record verification** integrations — closes #7.

## Reporting
Found a flaw in this model or the implementation? Use the responsible-disclosure process
at <https://www.emiliaprotocol.ai/security>. We acknowledge within 48 hours and publish an
advisory + credit on resolution.
