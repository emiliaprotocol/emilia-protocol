# EMILIA GovGuard — 60-Day Observe-Mode Pilot

**For:** County finance, treasury, and audit offices
**From:** Iman Schrock, EMILIA Protocol

---

## The problem, in your words

When software drafts or triggers a disbursement — or when a vendor's bank-account
record changes — who approved it, and can you prove it?

The login was valid. The role had permission. But the specific action — a payment
released, a vendor's bank account redirected — was never tied to a named human who
owns it, and never produced evidence an auditor could check later. As more of this
work gets drafted or triggered by AI and automated workflows, the question only gets
harder: *who approved this disbursement, and where is the proof?*

A disbursement that leaves the account is irreversible. The proof of who approved it
should exist before the money moves — not be reconstructed afterward from logs you
have to trust.

---

## The offer

A **GovGuard Fire Drill**, followed by a **60-day observe-mode pilot. $25,000 fixed.**

GovGuard watches one workflow you choose — for example:

- vendor payment-destination changes
- disbursement releases
- grant disbursements
- benefit bank-account changes
- benefit address/contact routing changes
- provider enrollment changes
- eligibility or caseworker overrides

It does **not block anything** at first. It evaluates each protected action
against policy and records what **would** have required a named human's signoff
before executing.

You change nothing about how work gets done. We show you what a control would have
caught.

---

## What you get — an audit evidence packet

At the end of the pilot, your auditors receive a packet covering every flagged
action:

- **Each flagged action** — what it was, what would have required a named signoff.
- **What policy fired** — the exact rule, policy hash, action hash, and execution
  binding hash, so every decision is traceable to the rule and fields that
  produced it.
- **GG-1 conformance status** — missing receipt, wrong org, wrong approver,
  self-approval, Class-C approval, replay, tampering, execution mismatch, and
  observe-mode export checks.
- **Sample authorization receipts** — for a representative set of actions, a
  cryptographic receipt your auditors can **verify offline** with one command
  (`npx @emilia-protocol/verify receipt.json`). The receipt proves a named approver
  produced a user-verified signature over that exact action, before it would have
  executed. No network, no account, no trust in EMILIA required to check it.

**Your audit evidence survives vendor turnover, acquisition, and SaaS sunset.** A
receipt is a portable, signed artifact — it verifies with open-source code and the
approver's public key, independent of whether EMILIA is still around to ask.

---

## Deployment options

- **Hosted, on-prem, or fully air-gapped.** The air-gapped bundle installs on an
  isolated host with no route off the machine; receipts still verify with pure
  cryptography, no network.
- **SSO (SAML 2.0 / OIDC) and SCIM 2.0** connect to your directory. Offboarding a
  person in your directory removes their signing authority in the same sync.
- **No integration required to start.** Observe mode reads a scoped feed of the
  action metadata for your chosen workflow. That is enough to produce the report.

---

## How your data is handled

- **Scoped, read-only feed.** GovGuard sees only the action metadata for the one
  workflow in scope — what changed, by whom, against what policy.
- **No payment credentials.** We do not receive or store bank account numbers,
  routing details, or payment rails. The metadata that an action *occurred* is
  enough; the secret values are not in scope.
- **Evidence verifiable without trusting us.** Every receipt is checkable offline
  against open-source code and the approver's public key. The receipt proves what
  happened; you do not take our word for it.

---

## Success criteria, and what happens after

**Success for the pilot is simple:** at day 60, your auditors can point to the
flagged actions and the sample receipts and answer — for that workflow — *"here is
who would have approved this disbursement, and here is the proof."* Concretely:

- A count of actions that would have required a named signoff over the 60 days.
- The policy that fired for each, pinned to an immutable version.
- Sample receipts your team verified offline, themselves.

**After the pilot**, the natural next step is to move that one workflow from
observe mode to **enforce mode**: before the irreversible action executes, a
named human approves the exact action on their own device (Face ID / Touch ID /
passkey), and a verifiable receipt is issued. Same workflow, now with the proof
captured before the money moves.

---

## See it now

- **Live signoff demo:** https://www.emiliaprotocol.ai/try — approve an action with
  Face ID on your own device; the receipt is issued and verified in front of you.
- **GovGuard Fire Drill:** https://www.emiliaprotocol.ai/pilot/sandbox?v=gov —
  run sample high-risk actions through the gate yourself, nothing blocked, and
  pull the procurement evidence packet.

---

## Contact

**Iman Schrock**, EMILIA Protocol
team@emiliaprotocol.ai · https://www.emiliaprotocol.ai/govguard

EMILIA Protocol is an open standard (Apache 2.0) for authorization receipts, with a
published IETF Internet-Draft (`draft-schrock-ep-authorization-receipts`). The
verifier is open source; the evidence outlives the vendor.
