<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provable approval for high-risk public payments
### The accountability control several of the committee's recommendations imply

*Leave-behind for the Minnesota House fraud-committee's technology evaluators · EMILIA Protocol, Inc. · team@emiliaprotocol.ai*

---

## The pattern in your report
Across 25 meetings and hundreds of whistleblower accounts, the same root failure recurs in program after program: **money moved because no specific person had to put their name on the specific transaction — provably — before it executed, and afterward no one could establish who authorized it.** Approval lived in a workflow the same office controlled; the record could be edited; accountability evaporated under scrutiny.

## What EMILIA does
EMILIA holds a defined high-risk action — a payment release, a vendor bank-account change, an eligibility override — until a **named, enrolled official approves that exact action on their own device** (Face ID / security key). It then emits a **cryptographic authorization receipt**: tamper-evident, and **verifiable offline by anyone** — auditors, the Office of the Legislative Auditor, whistleblowers' attorneys, the public — with **no access to the agency's systems**. Alter the record and verification fails by construction.

## What it makes *enforceable* (not just policy on paper)
| The recommendation theme | What EMILIA turns it into |
|---|---|
| A named human must approve high-risk transactions | A **precondition** — the action cannot execute without that approval, not a checkbox after the fact |
| Maintain auditable records of who authorized what | **Cryptographic evidence**, not a database row the controlling office can rewrite |
| Independent oversight and verification | Verification needs **zero trust** in the agency that ran the payment — the OIG checks the math |
| Protect taxpayers *and* the wrongly accused | The same receipt that proves misuse also **clears an official who did follow the process** |

## Why this, vs. internal controls and approval logs
- **Evidence, not testimony.** An approval log is a record the controlling office can change. An EMILIA receipt is offline-verifiable by a third party and **fails verification if tampered** — testimony becomes proof.
- **Open standard, no vendor lock-in.** Apache-2.0, a published IETF Internet-Draft, with machine-checked formal proofs (TLA+ + Alloy) gated in CI. **The state owns the control; no vendor owns the evidence.**
- **Per-action, named, on-device.** Not a role, a permission, or a batch sign-off — a specific human approves a specific transaction with phishing-resistant device authentication.

## Try it before any procurement
- **20-second self-check, no account:** `emiliaprotocol.ai/try` — approve an action, then watch a tampered copy fail verification.
- **Observe-mode sandbox:** `emiliaprotocol.ai/govguard` — run the state's *own* high-risk scenarios through it; it reports **"N of M would have been held for a named human"** before anything changes. No integration, no commitment.

*Honest status: EMILIA is an open-source reference implementation, formally verified and publicly testable. It is not yet deployed by a relying party — which is exactly why a no-risk **observe-mode pilot** is the right first step: it measures what the control would catch against real workflows without touching a live payment.*

## What it is **not**
Not fraud detection, eligibility determination, or case management. It is the **accountability layer those systems lack**: provable, named, per-action human authorization with evidence anyone can verify.

---

**Next step:** a 20-minute technical brief for your evaluators, mapped to the specific cases in the committee's report.
**Iman Schrock**, Founder — **team@emiliaprotocol.ai** · emiliaprotocol.ai
Open source (Apache-2.0): github.com/emiliaprotocol/emilia-protocol
