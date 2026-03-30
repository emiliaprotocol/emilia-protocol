# Agent Satisfaction Signal -- Governance Policy

Status: Active
Applies to: `agent_satisfaction` field on EP receipts

---

## Problem Statement

The `agent_satisfaction` signal is a self-reported 0-100 numeric value submitted by the purchasing agent on each receipt. In v1 scoring (`lib/scoring.js`), it carries 10% weight (`EMILIA_WEIGHTS.agent_satisfaction: 0.10`). There is no verification mechanism -- any agent can submit any value, creating a directly gameable signal.

A colluding agent can inflate a merchant's score by submitting `agent_satisfaction: 100` on every receipt, or depress a competitor's score by submitting `agent_satisfaction: 0`. Unlike behavioral signals (which are self-enforcing because agents route based on scores), raw satisfaction numbers have no feedback loop that punishes dishonesty.

---

## Current Behavior in Code

### v1 Scoring (`lib/scoring.js`)

`agent_satisfaction` is one of six weighted signals in `EMILIA_WEIGHTS`:

```
agent_satisfaction: 0.10  // 10% weight
```

It is included in `computeReceiptComposite()` (single-receipt composite score) and `computeEmiliaScore()` (entity-level score). Both functions iterate over all keys in `EMILIA_WEIGHTS` and include `agent_satisfaction` if present on the receipt.

**Note:** `computeEmiliaScore()` is marked `@deprecated` and is described as a test-only remnant. No production `app/` or `lib/` code imports it. The v1 entity-level scoring path is effectively dead in production.

### v2 Scoring (`lib/scoring-v2.js`)

`agent_satisfaction` does **not appear** in `EP_WEIGHTS_V2`. The v2 scoring algorithm (`computeTrustProfile()`) uses four signal dimensions:

- `delivery_accuracy` (mapped to `delivery`, 12% weight)
- `product_accuracy` (mapped to `product`, 10% weight)
- `price_integrity` (mapped to `price`, 8% weight)
- `return_processing` (mapped to `returns`, 5% weight)

The `signalMap` on line 176 of `scoring-v2.js` explicitly maps only these four fields. `agent_satisfaction` is excluded from v2 trust profiles entirely.

### Receipt Creation (`lib/create-receipt.js`)

`agent_satisfaction` is still accepted as an input signal and stored on receipts. However, when `agent_behavior` is provided, the behavior-derived satisfaction value overwrites any manually submitted value:

```javascript
let agentSatisfaction = signals.agent_satisfaction ?? null;
if (agentBehavior) {
  agentSatisfaction = behaviorToSatisfaction(agentBehavior);
}
```

This means that for v2-style receipts (which include `agent_behavior`), the stored `agent_satisfaction` value is always the behavior-derived value from `behaviorToSatisfaction()` in `lib/scoring.js`, not the raw self-reported value.

### Receipt Hash (`lib/scoring.js`)

`agent_satisfaction` is included in the hash payload of `computeReceiptHash()`. This means it is part of the cryptographic integrity chain regardless of whether it is used in scoring.

### Behavioral Replacement (`lib/scoring.js`)

`behaviorToSatisfaction()` converts observed behavior into a satisfaction proxy:

| Behavior | Derived Satisfaction |
|---|---|
| `completed` | 95 |
| `retried_same` | 75 |
| `retried_different` | 40 |
| `abandoned` | 15 |
| `disputed` | 5 |

This is the v2 approach: replace the opinion with the action. The behavioral signal is self-enforcing because an agent that falsely reports `completed` will route back to the same merchant and suffer the consequences.

---

## Governance Policy

### Rule 1: Unverified Agent Satisfaction Carries 0% Weight

`agent_satisfaction` signals from agents that cannot be verified carry zero weight in scoring. In v2 scoring, this is already the case -- the signal is not referenced in `EP_WEIGHTS_V2` or `computeTrustProfile()`.

For any future scoring path that reintroduces `agent_satisfaction`, the following rules apply.

### Rule 2: Verification Requirements

`agent_satisfaction` signals carry standard weight only when the submitting agent meets one of the following verification criteria:

**a) EP-Registered Agent with Verified Principal Binding**

The submitting agent must be:
1. Registered in the EP entity registry with a valid `owner_id`
2. Established (5+ effective evidence from 3+ unique submitters)
3. Bound to a verified human principal via EP's identity layer

**b) Cryptographic Attestation**

The satisfaction signal must be cryptographically signed using the purchasing agent's registered EP key. The signature covers the `agent_satisfaction` value along with the `entity_id`, `transaction_ref`, and timestamp, preventing replay attacks.

**c) Human Principal Confirmation**

If cryptographic attestation is not available, the human principal behind the purchasing agent must confirm the satisfaction signal within 24 hours. This aligns with EP's Accountable Signoff primitive -- a human must sign off on consequential signals.

### Rule 3: Unconfirmed Signal Handling

Signals that do not meet any of the verification criteria in Rule 2 are:
- Stored on the receipt with a `satisfaction_status: 'unverified'` marker
- Excluded from all scoring calculations
- Available for audit and dispute resolution purposes
- Not deleted (the ledger is append-only)

### Rule 4: Behavioral Override

When `agent_behavior` is present on a receipt, the behavior-derived satisfaction value from `behaviorToSatisfaction()` takes precedence over any raw `agent_satisfaction` value. This is already enforced in `lib/create-receipt.js`.

The behavioral signal does not require the verification mechanisms in Rule 2 because it is self-enforcing: agents that lie about behavior will route back to bad merchants and suffer the consequences.

### Rule 5: Alignment with Accountable Signoff

This governance policy aligns with EP's Accountable Signoff primitive. The core principle is: consequential signals that affect trust scores require either cryptographic proof of origin or human confirmation within a bounded time window. Self-reported numeric opinions without either verification mechanism are treated as unverified data, not trust signals.

---

## Implementation Status

| Requirement | Status | Code Path |
|---|---|---|
| Excluded from v2 scoring | Done | `lib/scoring-v2.js` -- absent from `EP_WEIGHTS_V2` and `signalMap` |
| Behavioral override in receipt creation | Done | `lib/create-receipt.js` lines 349-351 |
| Included in receipt hash | Done | `lib/scoring.js` -- `computeReceiptHash()` |
| `satisfaction_status` marker on receipts | Not implemented | Requires schema migration |
| Cryptographic attestation verification | Not implemented | Requires EP key infrastructure |
| Human principal confirmation flow | Not implemented | Requires Accountable Signoff integration |
| Unverified exclusion from v1 scoring | Not implemented | v1 `computeEmiliaScore()` still includes it (test-only path) |

---

## Migration Path

1. **Current state (Phase 1):** `agent_satisfaction` is accepted on receipts but ignored by v2 scoring. The behavioral override in `create-receipt.js` means most new receipts have behavior-derived values rather than raw self-reports.

2. **Near-term:** Add `satisfaction_status` column to receipts schema. Default existing receipts to `'unverified'` where `agent_behavior` is null and `agent_satisfaction` is not null.

3. **Phase 2:** When EP key infrastructure is available, implement cryptographic attestation verification. Verified satisfaction signals may be reintroduced to scoring at reduced weight (proposed: 5%, pending scoring rationale review).

4. **Phase 3:** With oracle verification, satisfaction signals backed by independent evidence may carry full weight under the `oracle_verified` provenance tier.
