# Technical Exhibit A — A Worked Example of an Independently-Verifiable Human-Authorization Record

*Accompanying the pre-rulemaking comment of EMILIA Protocol on the Automated Decision-Making Technology Act (SB 26-189).*

**Purpose.** This exhibit illustrates, concretely and vendor-neutrally, the kind of record recommended in our comment: one that makes *"a named human was responsible for this consequential decision"* an **auditable fact** rather than an unverifiable claim. It relies only on royalty-free cryptography (a digital signature over a canonical record) and requires no particular product.

## 1. The decision

A paradigm consequential decision — an adverse credit determination produced with the help of an automated decision-making system:

> Application `CO-2026-44817` was **denied**; principal reasons: debt-to-income above threshold, insufficient credit history. System: `LoanScore-v7`, policy `co-fair-lending-2026.2`.

## 2. The record

A reviewer signs the **exact** decision on their own device (a WebAuthn platform authenticator with user-verification). The record carries no personal data beyond a pseudonymous reference:

```json
{
  "@record": "human-authorization-record/v1",
  "payload": {
    "typ": "human-authorization-record",
    "reviewer_id": "loan.officer:j.martinez (WebAuthn, user-verified)",
    "decision": {
      "decision_type": "credit.application.adverse_action",
      "subject_ref": "applicant:CO-2026-44817",
      "outcome": "denied",
      "principal_reasons": ["debt_to_income_above_threshold", "insufficient_credit_history"],
      "admt_system": "LoanScore-v7",
      "policy_version": "co-fair-lending-2026.2",
      "jurisdiction": "US-CO"
    },
    "decision_digest": "sha256:844650f11806dca57ef8ea781985aba6325b5ce080f7af9e324a9e218872125d",
    "reviewed_at": "2026-06-24T18:30:00Z"
  },
  "signature": { "alg": "Ed25519", "value": "imellDXzeCoS2IeNN5oIsXh96w2h5UwGAAif2eXK86JkWeruiExu8RDByHe2joTPCaThKENL_-xj4xoQCUUeBA" }
}
```

## 3. How any third party verifies it — offline, without trusting the deployer

1. Recompute the canonical bytes of `payload` (RFC 8785 / JCS — a published standard that yields the same bytes on every platform).
2. Verify `signature` against the reviewer's **published** public key, pinned out of band — *never* a key carried inside the record.
3. Confirm `decision_digest` equals `sha256(canonical(decision))` and that `decision` is the decision in question.

If all three hold, a specific, named, user-verified human authorized **this exact decision**, and the record has not been altered — established with no trust in the deployer's systems, its logs, this Office's resources, or any vendor.

## 4. What it catches (each is an accountability gap the Act addresses)

- **Tampering** — any change to the outcome or reasons after the fact breaks verification.
- **Substitution ("confused deputy")** — a record for decision A cannot be presented as authorization for decision B.
- **Replay** — each record authorizes a single decision; reuse is detectable.
- **Forgery** — a record signed by anyone other than the pinned reviewer fails.

## 5. Why this fits the ADMT Act

Where the rules address documentation of human review or oversight, a consumer's right to human review or to appeal, or the records a deployer must retain, this record form lets a deployer **demonstrate** compliance, gives a consumer a **verifiable** basis for appeal, and gives this Office an **artifact it can audit** rather than a log it must take on faith. It is technology-neutral (any standard digital-signature scheme plus canonicalization) and royalty-free.

## 6. Reference

One open implementation of this record form is EMILIA Protocol (Apache-2.0; IETF Internet-Drafts `draft-schrock-ep-authorization-receipts` and `-quorum`), including multi-approver (quorum) review and revocation. Provided as a reference, not a required product.

*EMILIA Protocol · team@emiliaprotocol.ai · github.com/emiliaprotocol*
