<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA for Public Benefits Integrity

Pre-execution accountability for the sensitive actions in benefits administration: payment-destination changes, eligibility overrides, and operator actions on a beneficiary's case — the failure pattern behind large pandemic-era benefit fraud losses.

> EMILIA proves a named official authorized a specific irreversible action under a stated policy before execution, producing evidence an inspector general, auditor, or appeals body can verify offline. It does not adjudicate eligibility or correctness; one-time-use and revocation are relying-party server state.

---

## Control area 1 — Benefit payment-destination redirects

| | |
|---|---|
| **Risk** | A beneficiary's payment destination (bank account, card) is changed and benefits are redirected to a fraudster. |
| **Current control failure** | The change is recorded as "processed" by the same system; after the fact, the agency often cannot establish which named official authorized that specific change before it executed. |
| **EMILIA control** | The destination change is held pre-execution; policy requires a named official's signoff bound to the exact change; high-risk changes can require a second approver; a one-time receipt is consumed. |
| **Evidence generated** | Receipt binding the exact destination change · official identity · authority chain · policy version · timestamp · nonce · consume event — verifiable offline, independent of the benefits system. |
| **Auditor / IG question answered** | "Who authorized redirecting this beneficiary's payments, under what authority and policy, and could it be replayed?" |
| **Integration pattern** | EMILIA Gate on the disbursement-detail write path; Observe mode produces an "N of M changes that would have required a named approval" report with zero production change. |

## Control area 2 — Eligibility overrides / operator actions

| | |
|---|---|
| **Risk** | An operator override grants, suspends, or alters benefits outside normal determination. |
| **Current control failure** | Overrides are logged but not bound to a named accountable approver at the moment of action, complicating due-process review and IG reconstruction. |
| **EMILIA control** | Override gated pre-execution; named approval bound to the exact override and case; receipt issued. |
| **Evidence generated** | Receipt naming the responsible official and the exact override, supporting both audit and a beneficiary's due-process review. |
| **Auditor / IG question answered** | "Who overrode this determination, on what authority, and can the action be reconstructed for appeal?" |
| **Integration pattern** | Gate on the override action; policy encodes which overrides require single vs. dual approval. |

## Control area 3 — Appeal-ready reconstruction

| | |
|---|---|
| **Risk** | A contested action cannot be reconstructed cleanly, exposing the agency on due process and the beneficiary to error. |
| **Current control failure** | Logs are unstructured and operator-controlled; reconstruction is slow and contestable. |
| **EMILIA control** | Every gated action leaves a portable, tamper-evident receipt that reconstructs the who/what/policy/when independently. |
| **Auditor / IG question answered** | "Reconstruct this action and its authorization from evidence we don't have to take the agency's word for." |
| **Integration pattern** | Evidence packets exported for IG / appeals workflows. |

---

*Maps EMILIA to common public-benefits integrity objectives. Not legal advice; control design and due-process sufficiency are determined by the agency and its counsel.*
