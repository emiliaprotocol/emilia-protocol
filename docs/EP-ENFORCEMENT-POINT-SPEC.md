<!-- SPDX-License-Identifier: Apache-2.0 -->

# EP Enforcement-Point Profile — Implementer Specification

**Status:** Experimental. Companion to the Guard / PEP Internet-Draft (individual submission, work in progress). This document is implementer-facing and tracks the EP authorization-receipt draft (`standards/draft-schrock-ep-authorization-receipts-01.md`). Where this spec and that draft diverge, the draft is normative.

This document specifies the **EP Enforcement Point (EP-EP)**: the component that sits in front of a high-risk action, asks for a decision, and refuses to let the action proceed unless the decision permits it. An EP-EP is a **Policy Enforcement Point (PEP)** in the AuthZEN sense — it *consumes* a decision; it does not author policy. The decision is produced by a Policy Decision Point (PDP): in this codebase, the pure function `evaluateGuardPolicy()` in `lib/guard-policies.js`, reached in-process or over HTTP. The authorization receipt (wire-format tag `EP-RECEIPT-v1`) is the verifiable artifact that binds a decision to one exact action.

EP-EP composes over, rather than reinvents, existing standards:

| Layer | EP-EP reuses | EP-EP adds |
|---|---|---|
| Decision interface (PEP ↔ PDP) | AuthZEN Authorization API 1.0 request/response shape | the four-state decision vocabulary below and the receipt binding |
| Policy engine (PDP) | OPA/Cedar-class engines; here, the formally-modeled `evaluateGuardPolicy()` | nothing — the engine is consumed, not redefined |
| Event/transport envelope | SET (RFC 8417), SSF + CAEP 1.0 for signal delivery | verifiable scope-bound advisory semantics; the "never the sole gate" invariant |
| Transparency anchor | SCITT Signed Statement + Merkle-log inclusion Receipt | nothing — Commit seals register as Signed Statements |
| Attestation evidence | RATS (RFC 9334) / EAT (RFC 9711) as optional input | nothing — attestation is consumed as context |

EP-EP is **not** the trust core. The core is the set of shared properties that any verifier checks against — action binding, one-time consumption, separation of duties, offline verifiability. No single party owns it. An EP-EP is one profile that verifies against those properties.

---

## 1. Decision Vocabulary

A PDP returns exactly one `decision` value. An EP-EP MUST treat the value as a closed enumeration and MUST fail closed on any value it does not recognize. The enumeration is defined in `lib/guard-policies.js` (`GUARD_DECISIONS`).

| `decision` value | Enforcement outcome at the EP-EP | Meaning | Source of truth |
|---|---|---|---|
| `allow` | Execute the action immediately. No human approval required. | Permitted without further gating. | `lib/guard-policies.js` — `GUARD_DECISIONS.ALLOW` |
| `allow_with_signoff` | **Block** until a named human approves the exact action, then execute only on a verified approval. | Permitted, but a named accountable human MUST sign off before consume. | `lib/guard-policies.js` — `GUARD_DECISIONS.ALLOW_WITH_SIGNOFF` |
| `deny` | **Refuse outright.** No signoff path. The action MUST NOT proceed. | Hard refusal (e.g. sanctions hit, impossible travel, known-compromised device). Not overridable by human approval. | `lib/guard-policies.js` — `GUARD_DECISIONS.DENY` |
| `observe` | Log only. **Never block.** Record what *would* have been enforced. | Used in `observe` enforcement mode for staged rollout / audit without enforcement. | `lib/guard-policies.js` — `GUARD_DECISIONS.OBSERVE` |

Four decision states map to three enforcement outcomes: `allow` → proceed; `deny` → refuse; `allow_with_signoff` → block-then-verify-then-proceed. `observe` is `allow`-at-the-EP-EP plus a recorded shadow decision.

### 1.1 Enforcement modes (orthogonal to the decision)

The caller selects an enforcement mode; the PDP applies it to the base decision before returning. Modes are defined in `lib/guard-policies.js` (`ENFORCEMENT_MODES`).

| `enforcement_mode` | PDP behavior | EP-EP obligation |
|---|---|---|
| `enforce` (default) | Returns the base decision verbatim. | The EP-EP MUST honor the decision. |
| `warn` | Returns the base decision verbatim, advisory. | The EP-EP MAY proceed against the decision; it MUST surface the decision to the caller. |
| `observe` | Downgrades any blocking decision (`deny` or `allow_with_signoff`) to `observe`; `signoff_required` stays `true`; the would-be decision is reported as `observed_decision`. | The EP-EP MUST NOT block; it MUST record `observed_decision`. |

An EP-EP MUST NOT silently treat `warn` or `observe` as enforcement. A deployment claiming enforcement MUST run `enforce`.

### 1.2 Signoff tier (carried with `allow_with_signoff`)

When `decision` is `allow_with_signoff`, the PDP MAY set `signoff_tier`:

| `signoff_tier` | Requirement |
|---|---|
| `single` | One accountable senior human MUST approve. |
| `dual` | A second, independent senior human (distinct from the first and from the initiator) MUST also approve. |

The tier is computed by the formally-modeled engine. Enforcement that the second approver is a *different* person is performed at approval time in `lib/guard-signoff.js`, not in the PDP. See conformance items C-08 and C-09.

---

## 2. Decision-Request Schema

The EP-EP sends a decision request to the PDP. Two surfaces exist and an EP-EP MUST use the one matching its need:

- `POST /api/v1/trust-receipts` — full guard engine; returns a verifiable receipt. Use this for any action that must be auditable or offline-verifiable. (`app/api/v1/...`, engine in `lib/guard-policies.js`, adapter in `lib/guard-adapter.js`.)
- `POST /api/trust/gate` — lightweight entity-trust/delegation decision; returns `{decision, reason}` only, **no receipt**. Use only where no verifiable artifact is needed. (`app/api/trust/gate/route.js`.)

The canonical request body for the receipt-producing surface:

```json
{
  "organization_id": "org_acme",
  "actor_role": "treasury_agent",
  "action_type": "large_payment_release",
  "target_changed_fields": ["beneficiary_account"],
  "amount": 82000.00,
  "currency": "USD",
  "risk_flags": ["new_beneficiary"],
  "enforcement_mode": "enforce",
  "before_state": { "beneficiary_account": "acct_old" },
  "after_state": { "beneficiary_account": "acct_new" },
  "counterparty_name": "Globex Ltd",
  "counterparty_country": "US",
  "recent_amounts": [9500, 9800, 9700]
}
```

Field rules:

- `organization_id` (string) is **REQUIRED**.
- `action_type` (string) is **REQUIRED** and MUST be a value from `GUARD_ACTION_TYPES` in `lib/guard-policies.js` (e.g. `large_payment_release`, `vendor_bank_account_change`, `ai_agent_payment_action`, `caseworker_override`, `benefit_bank_account_change`).
- `before_state` and `after_state` (objects) are **REQUIRED** — they are the pre- and post-action state hashed into the receipt.
- `actor_role`, `target_changed_fields` (string[]), `amount` (number), `currency` (string), `risk_flags` (string[]) are OPTIONAL.
- `enforcement_mode` is OPTIONAL; default `enforce`. One of `observe` / `warn` / `enforce`.
- AML context is OPTIONAL: `counterparty_name` (aliases `beneficiary_name`, `payee_name`), `counterparty_country` (alias `beneficiary_country`), `recent_amounts` (number[]). When supplied, the PDP delegates to `screenAml()` in `lib/aml/screening.js`.

The in-process form `evaluateGuardPolicy(input)` takes the same data in camelCase (`organizationId`, `actorId`, `actionType`, `riskFlags`, `authStrength` ∈ `password|mfa|phishing_resistant_mfa|service_account`, optional `actorRole`, `targetChangedFields`, `amount`, `currency`, `initiatorId`, `approverId`, `aml`). It performs no I/O.

This request is structurally an AuthZEN evaluation 4-tuple: subject = `(organization_id, actor_role)`, action = `action_type`, resource = the target identified in `before_state`/`after_state`, context = `risk_flags` + AML + `enforcement_mode`. An EP-EP MAY front it with the AuthZEN `POST /access/v1/evaluation` shape; the mapping is mechanical.

---

## 3. Decision-Response Schema

### 3.1 Base decision (returned by `evaluateGuardPolicy()` and any precheck)

```json
{
  "decision": "allow_with_signoff",
  "reasons": ["money destination changed; accountable signoff required"],
  "signoffRequired": true,
  "signoffTier": "single",
  "aml_signals": [],
  "observed_decision": null
}
```

- `decision` (string) — one of `{allow, allow_with_signoff, deny, observe}`.
- `reasons` (string[]) — human-readable explanation. Non-empty for any non-`allow` decision.
- `signoffRequired` (boolean) — `true` when a human approval is required before consume. Stays `true` even when `observe` mode downgrades `decision`.
- `signoffTier` (string, OPTIONAL) — `single` | `dual`.
- `aml_signals` (string[], OPTIONAL) — AML screening signals, if any.
- `observed_decision` (string, OPTIONAL) — set only in `observe` mode; the decision that would have been enforced.

### 3.2 HTTP 201 receipt response (`POST /api/v1/trust-receipts`)

```json
{
  "receipt_id": "tr_01J...",
  "decision": "allow_with_signoff",
  "observed_decision": null,
  "action_hash": "sha256:9f2c...",
  "nonce": "b64u:R9w1...",
  "expires_at": "2026-06-13T17:36:05Z",
  "signoff_required": true,
  "signoff_tier": "single",
  "aml_signals": null,
  "initiator_attestation": {
    "escalation_trigger": "magnitude",
    "policy_basis": "ep:policy:wires-over-100k@v12/rule:dual-auth",
    "statement": "Exceeds my single-action limit; new beneficiary."
  },
  "receipt_status": "pending_signoff",
  "reasons": ["amount >= single-auth tier; signoff required"],
  "next_step": "Route to a named approver; do not execute until approved."
}
```

- `receipt_id` (string) — unique identifier, `tr_*`.
- `decision` (string) — one of `{allow, allow_with_signoff, deny, observe}`.
- `observed_decision` (string | null) — present only in `observe` mode.
- `action_hash` (string) — SHA-256 of the canonical action. This is the WYSIWYS binding key (Section 4).
- `nonce` (string) — single-consumption key for this decision.
- `expires_at` (ISO 8601) — validity window end.
- `signoff_required` (boolean), `signoff_tier` (string | null — `single` | `dual`).
- `aml_signals` (string[] | null).
- `initiator_attestation` (object | null) — PIP-007 §1 escalation attestation; present only when the decision escalates to signoff. Members and rules are identical to the authorization-receipt draft, Section 4.1: `escalation_trigger` ∈ `{irreversibility, magnitude, uncertainty, novelty, authority_gap, policy_rule}` (REQUIRED), `policy_basis` (string), `statement` (string, ≤ 280 chars). The attestation is a claim by the initiator — a party EP identifies but never trusts.
- `receipt_status` (string) — `issued` | `pending_signoff` | `denied`.
- `reasons` (string[]), `next_step` (string).

### 3.3 Adapter-normalized form

The framework adapters (`examples/claude_guard.py`, `examples/grok_guard.py`, `examples/crewai_guard.py`, `examples/autogen_guard.py`, `examples/openai_agents_guard.py`, `examples/vercel-ai-guard.mjs`, `packages/openai-guard/index.js`) present the same decision under a uniform contract. Each maps the four-state vocabulary to: `allowed` (boolean) + `decision` (string) + `signoffRequired` (boolean), plus `reason` and the raw response. An EP-EP built on an adapter MUST preserve the underlying `decision` value and MUST NOT collapse `deny` and an unrecognized value into the same path.

---

## 4. Receipt-Binding Rule

The decision binds to the action through the authorization receipt (`EP-RECEIPT-v1`), produced by `signEvidenceReceipt()` in `lib/guard-evidence-receipt.js`.

**The rule (WYSIWYS — What You See Is What You Signed):**

1. At receipt creation, the EP-EP MUST preserve the **canonical action object** exactly as evaluated, and MUST compute `action_hash = sha256(canonicalize(canonical_action))`.
2. The signed payload MUST include, at minimum: `receipt_id`, `claim.action_type`, `claim.outcome` (the decision), `claim.canonical_action` (the exact object hashed at creation), `claim.action_hash`, `claim.enforcement_mode`, `claim.policy_id`, and `claim.policy_hash`.
3. The signature is **Ed25519 over the recursive-canonical-JSON of the payload**. A verifier re-derives `canonicalize(payload)` and re-derives the exact bytes the signature covers — without trusting the server.
4. The signer is the EP operator's commit signing key (`ep-signing-key-1`, key class `C`, published at `/.well-known/ep-keys.json`). An offline verifier MUST pin the signer to a server-independent trust root and MUST NOT trust an inline key alone.

**Honesty gate.** `signEvidenceReceipt()` MUST return `null` (and the route MUST serve the unsigned `ep-guard-evidence-v1` packet) unless the receipt is in a positive terminal state (`approved_pending_consume` or `consumed`) **and** carries the `canonical_action`. It MUST NOT sign `pending`, `denied`, `rejected`, `expired`, or canonical-action-less receipts. A signature asserts a fact that was actually true.

Signed-document structure (abbreviated):

```json
{
  "@version": "EP-RECEIPT-v1",
  "payload": {
    "receipt_id": "tr_01J...",
    "issuer": "ep_operator_emilia_primary",
    "protocol_version": "EP-CORE-v1.0",
    "claim": {
      "action_type": "large_payment_release",
      "outcome": "allow_with_signoff",
      "enforcement_mode": "enforce",
      "canonical_action": { "...": "EXACT action object from creation" },
      "action_hash": "sha256:...",
      "before_state_hash": "sha256:...",
      "after_state_hash": "sha256:...",
      "policy_id": "ep:policy:...",
      "policy_hash": "sha256:..."
    },
    "authorization": {
      "status": "approved_pending_consume",
      "signoff_required": true,
      "approver_id": "ep:approver:jchen-controller",
      "approved_at": "2026-06-13T17:24:40Z",
      "approver_key_class": "A",
      "consumed_at": null,
      "consumed_by_system": null,
      "execution_reference_id": null
    },
    "created_at": "2026-06-13T17:21:05Z",
    "expires_at": "2026-06-13T17:36:05Z"
  },
  "signature": {
    "algorithm": "Ed25519",
    "signer": "ep_operator_emilia_primary",
    "key_class": "C",
    "key_id": "ep-signing-key-1",
    "key_source": "operator-commit-signing-key",
    "value": "b64u:..."
  },
  "metadata": { "operator": "...", "issued_at": "2026-06-13T17:25:02Z" }
}
```

**Binding consequence.** Because the signature covers the exact `canonical_action`, a tampered action cannot produce a valid signature. Replay of a receipt issued for `$1` cannot authorize `$82,000` — the `action_hash` will not match. Offline verifiers (`@emilia-protocol/verify`, the `emilia-verify` Python package; see `examples/grok_guard.py`) re-canonicalize and verify the Ed25519 signature with no server round-trip.

**Composition with SCITT.** A Commit seal MAY be registered as a SCITT Signed Statement; the returned Merkle-inclusion Receipt becomes the Commit's transparency anchor. This is optional and does not change the binding rule above.

---

## 5. Architectural Invariant — Never the Sole Gate

An EP-EP advisory input (from EMILIA Eye) **warns**; the receipt layer **verifies**; signoff **owns** the decision. An advisory MUST NOT be the only thing standing between an entity and a high-risk action. If an Eye advisory is ever the sole gate, the integration is non-conformant (see `docs/architecture/EMILIA_EYE.md`). Advisories are policy *inputs*, consumed at the PDP; they are not enforcement artifacts. The enforcement artifact is the verifiable receipt.

---

## 6. Conformance Checklist

An enforcement point self-certifies by asserting each item below. Each row is one **MUST**. An EP-EP that cannot assert an item MUST NOT claim that item's behavior. Numbering is stable.

| # | Conformance requirement (MUST) |
|---|---|
| C-01 | The EP-EP MUST treat `decision` as a closed enumeration `{allow, allow_with_signoff, deny, observe}` and MUST fail closed on any unrecognized value. |
| C-02 | On `allow`, the EP-EP MUST execute the action and MUST NOT require additional gating. |
| C-03 | On `allow_with_signoff`, the EP-EP MUST block execution until a named human approves the **exact** action, and MUST execute only after a verified approval. |
| C-04 | On `deny`, the EP-EP MUST refuse the action outright and MUST NOT offer a signoff override. |
| C-05 | On `observe`, the EP-EP MUST NOT block and MUST record `observed_decision` (the decision that would have been enforced). |
| C-06 | A deployment claiming enforcement MUST run `enforcement_mode: "enforce"`; it MUST NOT present `warn` or `observe` results as enforced decisions. |
| C-07 | When `signoff_required` is `true`, the EP-EP MUST obtain approval from a named approver before consuming the receipt. |
| C-08 | The EP-EP MUST NOT allow the initiator to approve its own action (no self-approval). |
| C-09 | For `signoff_tier: "dual"`, the EP-EP MUST require a second approver who is distinct from the first approver and from the initiator. |
| C-10 | The EP-EP MUST send `organization_id`, a valid `action_type` from `GUARD_ACTION_TYPES`, `before_state`, and `after_state` in every receipt-producing decision request. |
| C-11 | The EP-EP MUST compute `action_hash = sha256(canonicalize(canonical_action))` and MUST bind the decision to that exact canonical action object (WYSIWYS). |
| C-12 | The EP-EP MUST recompute the action hash from the presented canonical action and MUST reject any request whose recomputed hash does not match the bound `action_hash`. |
| C-13 | The EP-EP MUST enforce one-time consumption: a receipt's `nonce`/`receipt_id` MUST transition to a terminal state at most once, and any replay MUST be rejected. |
| C-14 | The EP-EP MUST NOT execute an action whose receipt `receipt_status` is `consumed`, `denied`, `rejected`, `pending_signoff`, or expired (`expires_at` in the past). |
| C-15 | For a signed receipt, the EP-EP (or its verifier) MUST verify the Ed25519 signature over `canonicalize(payload)` and MUST pin the signer key to a server-independent trust root, never trusting an inline key alone. |
| C-16 | The EP-EP MUST treat a receipt that fails signature verification, signer pinning, or claim binding as non-authorizing and MUST refuse the action. |
| C-17 | The EP-EP MUST treat transport failures (DNS/TLS/connection) as errors, never as a policy decision; HTTP 4xx/5xx policy outcomes are returned as data, not exceptions. |
| C-18 | The EP-EP MUST render the human-readable action to the approver from the exact bytes that were hashed, never from a separately supplied description (anti presentation-attack). |
| C-19 | When an `initiator_attestation` is present, the EP-EP MUST render its `statement` as untrusted content (plain text, no markup/links, ≤ 280 chars) and MUST NOT use attestation content to relax thresholds, skip approvers, or raise any trust score. |
| C-20 | The EP-EP MUST NOT let an Eye advisory be the sole gate for a high-risk action; an advisory is an input to the decision, not the decision. |
| C-21 | The EP-EP MUST declare its enforcement class (STRONG / STANDARD / BASIC) and MUST NOT claim a stronger class than deployed. |
| C-22 | For receipt-producing flows, the EP-EP MUST use `POST /api/v1/trust-receipts` (or the in-process `evaluateGuardPolicy()` plus `signEvidenceReceipt()`); it MUST NOT rely on `POST /api/trust/gate` where a verifiable artifact is required. |
| C-23 | The EP-EP MUST persist trust records only through the guarded client (`getGuardedClient()` in `lib/write-guard.js`); it MUST NOT write `TRUST_TABLES` directly. |
| C-24 | The EP-EP MUST record which engine decided each action — the formally-modeled `guard-policies` engine or a clearly-labeled non-formal `agent-gate` rule (`scripts/emilia-gate.mjs`) — and MUST NOT represent a non-formal rule as covered by the formal proofs. |

### 6.1 Enforcement classes (declared in C-21)

| Class | Definition |
|---|---|
| STRONG — EP-Verified Execution | The system of record verifies the receipt/authorization bundle before executing and refuses otherwise. The gate cannot be bypassed by any party that does not control the system of record. |
| STANDARD — EP-Gated Middleware | An interception layer between the agent and the executing credential enforces the gate. Strong against agent error and prompt injection; an operator with code control can bypass. Receipts remain valid evidence of what was approved. |
| BASIC — EP-Evidence Only | Actions execute independently; receipts are produced for audit only. No enforcement claim is made. |

---

## 7. Formal-Verification Scope (honest boundary)

The PDP's pure decision function `evaluateGuardPolicy()` is the only part covered by formal proofs: **26 TLA+ safety properties (413,137 states, 0 errors)** and **35 Alloy facts + 22 assertions** (see `formal/PROOF_STATUS.md`). The proofs cover the policy-engine logic that maps `(organizationId, actorId, actionType, amount, riskFlags, aml)` → `(decision, signoffRequired, reasons)` — including no-self-approval at decision time, no-replay binding to the issued `action_hash`, money-destination escalation, large-payment tiering, AML fail-closed, and non-overridable hard-deny flags.

The proofs do **not** cover: cryptographic verification, signer pinning, replay detection via store, web endpoint routing, audit logging, database I/O, the signoff approval process itself, or the `agent-gate` non-formal rules (`rm -rf`, `git push --force`, `DROP TABLE`, destructive Supabase ops in `scripts/emilia-gate.mjs`). An EP-EP MUST NOT represent the proofs as covering deployment topologies or steps they do not model (C-24).

---

## 8. Referenced Files (guard recon)

Policy engine and binding:
- `lib/guard-policies.js` — `GUARD_DECISIONS`, `GUARD_ACTION_TYPES`, `ENFORCEMENT_MODES`, `evaluateGuardPolicy()`
- `lib/guard-adapter.js` — precheck/HTTP adapter
- `lib/guard-evidence-receipt.js` — `signEvidenceReceipt()`, `EP-RECEIPT-v1`, honesty gate
- `lib/guard-signoff.js` — approval-time self-approval and dual-tier enforcement
- `lib/write-guard.js` — `getGuardedClient()`, `TRUST_TABLES`
- `lib/aml/screening.js` — `screenAml()`
- `scripts/emilia-gate.mjs` — agent-gate non-formal rules
- `app/api/trust/gate/route.js` — lightweight gate surface
- `docs/AGENT-GATE.md` — agent-gate behavior

Adapters (uniform contract):
- `examples/claude_guard.py`, `examples/grok_guard.py`, `examples/crewai_guard.py`, `examples/autogen_guard.py`, `examples/openai_agents_guard.py`, `examples/emilia_guard.py`, `examples/vercel-ai-guard.mjs`
- `packages/openai-guard/index.js`, `packages/openai-guard/README.md`

Advisory invariant:
- `docs/architecture/EMILIA_EYE.md` — "Eye warns. EP verifies. Signoff owns."

Companion draft:
- `standards/draft-schrock-ep-authorization-receipts-01.md` / `.xml` — normative where this spec and the draft diverge.

---

## 9. References

- [draft-schrock-ep-authorization-receipts] Schrock, I., "Authorization Receipts for High-Risk Agent Actions", individual Internet-Draft (work in progress).
- [RFC8417] Hunt, P., et al., "Security Event Token (SET)".
- [RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)".
- [RFC9334] Birkholz, H., et al., "Remote ATtestation procedureS (RATS) Architecture".
- [RFC9711] Lundblade, L., et al., "The Entity Attestation Token (EAT)".
- [AuthZEN] OpenID Foundation, "Authorization API 1.0".
- [CAEP] OpenID Foundation, "Continuous Access Evaluation Profile 1.0".
- [SSF] OpenID Foundation, "Shared Signals Framework 1.0".
- [SCITT] IETF SCITT WG, "An Architecture for Trustworthy and Transparent Digital Supply Chains" (draft-ietf-scitt-architecture, work in progress).
