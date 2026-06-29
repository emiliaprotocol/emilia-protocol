<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA for insurers & insureds — verifiable proof a human authorized the transfer

**The control insurers already require, finally provable.** A brief for cyber /
crime-fidelity carriers, brokers, and the finance teams they cover.

## The problem you already underwrite — and can't verify
Cyber and crime policies increasingly make **dual authorization** and **out-of-band
callback verification** of wires and payment-instruction changes **conditions precedent**
to funds-transfer-fraud (FTF) and social-engineering (SEF) coverage. MFA is a hard
underwriting gate. And carriers **enforce** it:
- Claims are **denied** when the attested control wasn't actually followed (Coalition's
  2024 report: 82% of denied claims involved missing/improper MFA; 25% of firms were
  denied coverage because they **couldn't prove** controls they had).
- Policies are **rescinded** for misrepresenting controls on the application (*Travelers v.
  ICS*).
- Voluntary-parting / "the employee approved it" losses fall outside computer-fraud cover
  (*Pestmaster*, *Apache*), so the *quality of the human authorization* is the whole ballgame.

**The proof, today, is ad hoc** — recorded calls, callback logs, emails, signed attestation
forms — reconstructed forensically after a loss. There is **no machine-checkable artifact**
that a specific human authorized a specific transfer. (Even baseline ACH authorizations
"don't have a standard format.")

## Two things just broke the old control
1. **Deepfakes defeat the callback.** The out-of-band call-back — the gold-standard
   proof-of-authorization — now fails: the "known number" can reach a **voice-cloned**
   executive (the Arup $25.6M deepfake case). The control insurers mandate no longer proves
   an authentic human authorized anything.
2. **AI agents break attribution.** Autonomous agents move money at machine speed; "the AI
   did it" is being **statutorily foreclosed** (California AB 316, Jan 2026 — liability on
   the deployer) exactly when the deployer can least *prove* who authorized the action.
   Underwriters "cannot audit a model's behavior the way they audit a firewall," so carriers
   are adding **AI exclusions** and separately pricing agentic risk.

## What EMILIA provides
An **authorization receipt**: before a high-risk transfer or instruction change executes, a
**named human approves the exact action** (amount, payee, account) on their own device
(WebAuthn / passkey / Face ID), producing a signed artifact **anyone can verify offline —
no account, no trust in the insured's systems**. Alter one byte and it fails.

- **Dual authorization, made cryptographic — and deepfake-resistant.** EP-QUORUM binds *two
  distinct, device-bound humans* to the exact action. Unlike a callback, it cannot be
  defeated by a cloned voice — the approval is a hardware-held signature over the action,
  not a phone conversation.
- **Portable, durable evidence.** The receipt is the machine-checkable artifact the carrier
  reconstructs by hand today — verifiable years later (EP-EVIDENCE-RECORD handles multi-year
  retention), without the insured's cooperation.
- **Open protocol.** Apache-2.0, IETF Internet-Drafts, three independent verifiers — no
  vendor lock-in for carrier or insured.

## The pilot (and why it's the fast path)
- **For an insured:** run EP in observe mode on one workflow (vendor bank-account changes ≥
  $X). Every flagged action emits a receipt the **insurer's underwriter or the insured's
  auditor can verify offline** — turning an attestation into provable, claims-ready evidence.
- **For a carrier:** accept EP receipts as proof the dual-auth/verification control was
  followed — a **premium-credit or coverage condition** that is, for the first time,
  *machine-auditable* rather than forensic. This also **survives the deepfake failure mode**
  your actuaries are now pricing in.

That first acceptance — *"[carrier/auditor] verified an EMILIA receipt as proof of
authorization"* — is the reliance event that proves the control works.

## Honest bounds
EP proves a named human (or quorum) authorized *this exact action* before it executed; it
does not prove the decision was *correct*, nor establish real-world identity beyond the
enrollment layer (the identity-binding profile addresses that). No production deployment yet.

**Contact:** Iman Schrock · EMILIA Protocol · team@emiliaprotocol.ai · `npx @emilia-protocol/crash-test`

*Sources: Coalition 2024/2025 Cyber Claims Reports; Travelers v. ICS; Pestmaster v.
Travelers; Apache v. Great American; California AB 316; Arup deepfake (2024).*
