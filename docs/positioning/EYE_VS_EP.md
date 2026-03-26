# EMILIA Protocol -- Eye vs. EP vs. Signoff

## The Principle

**Eye warns. EP verifies. Signoff owns.**

These are three distinct responsibilities with three distinct owners. No layer performs the work of another. No layer is optional when its responsibility is triggered. The boundaries between them are architectural, not configurable.

---

## What Each Layer Does

### Eye

Eye observes contextual signals and produces advisories. It answers the question: *given what we know right now, should this scope receive additional scrutiny?*

Eye does not answer the question of whether a specific action should proceed. It does not evaluate identity, authority, or policy. It surfaces contextual information that the policy layer may use to adjust enforcement.

### EP (Handshake)

EP verifies trust requirements at the point of action. It answers the question: *does this actor have the identity, authority, and policy basis to perform this specific action right now?*

EP does not observe context between handshakes. It does not maintain state about an entity's behavior pattern or environment. It evaluates the trust requirements defined by policy and produces a binary verified/rejected outcome for each handshake.

### Signoff

Signoff records human accountability. It answers the question: *has a named human with matching authority seen this specific action, understood its consequences, and accepted responsibility for its execution?*

Signoff does not verify identity or authority on its own. It does not assess context. It consumes a verified handshake and produces an attestation that a human owns the outcome.

---

## Boundary Table

| Responsibility | Eye | EP (Handshake) | Signoff |
|---|---|---|---|
| Observes contextual signals | Yes | No | No |
| Produces advisory status | Yes | No | No |
| Evaluates identity binding | No | Yes | No |
| Evaluates authority | No | Yes | Verifies authority class match |
| Evaluates policy requirements | No | Yes | Inherits from policy |
| Makes the trust decision | **No** | Yes | No (defers to human) |
| Records human accountability | No | No | Yes |
| Blocks actions | **No** | Yes (rejects handshake) | Yes (withholds attestation) |
| Produces a consumed artifact | No | Yes (binding consumption) | Yes (attestation consumption) |
| Has TTL-bounded outputs | Yes | Yes (binding TTL) | Yes (attestation TTL) |
| Maintains persistent entity state | **No** | No | No |
| Exposes data to target entities | **No** | No | Challenge displayed to signoff actor |

---

## What Each Layer Does NOT Do

### Eye Does Not

- Make trust decisions. Eye never approves or rejects an action. It produces a status level and reason codes. Policy decides what to do with them.
- Block actions. There is no enforcement gate in Eye. An `elevated` or `review_required` advisory does not prevent an action. It informs policy, which may or may not change the enforcement path.
- Replace EP verification. A `clear` Eye status does not mean the handshake can be skipped. Eye and EP are complementary, not alternative.
- Score entities. Eye does not maintain reputation scores, trust indices, or cumulative risk assessments. Observations expire. Advisories are recomputed.
- Notify target entities. Eye does not tell an entity that it has been flagged. Advisory data flows to the operator's policy layer, not to the entity.

### EP Does Not

- Observe context between handshakes. EP evaluates trust at the moment of verification. It does not track what happened since the last handshake.
- Produce warnings. EP produces a binary outcome: verified or rejected. There is no "verified with warnings" state in EP. That is Eye's role.
- Record human accountability. EP verifies machine-checkable requirements. If human ownership is required, EP triggers signoff. It does not perform signoff.
- Recommend enforcement changes. EP enforces the policy as written. It does not suggest that policy should be different for this instance. That is Eye's role (via advisory → policy input).

### Signoff Does Not

- Assess context. Signoff presents a fully formed action description to a human. It does not evaluate whether the action is risky. That assessment was already made by Eye (context) and EP (trust requirements).
- Verify identity independently. Signoff authenticates the signoff actor, but the underlying trust verification (identity, authority, policy) was performed by EP's handshake.
- Operate without a verified handshake. Signoff cannot be triggered without a verified handshake. It is downstream of EP, not parallel to it.
- Persist beyond consumption. A signoff attestation is consumed exactly once. It is not a standing approval.

---

## What Each Layer Owns

| Ownership | Eye | EP (Handshake) | Signoff |
|---|---|---|---|
| Observation lifecycle | Yes | No | No |
| Advisory lifecycle | Yes | No | No |
| Suppression lifecycle | Yes | No | No |
| Handshake lifecycle | No | Yes | No |
| Binding lifecycle | No | Yes | No |
| Policy resolution | No | Yes (with Eye input) | No |
| Challenge lifecycle | No | No | Yes |
| Attestation lifecycle | No | No | Yes |
| Consumption gate | No | Partial (binding) | Partial (attestation) |
| Audit trail | Observations + advisories | Handshake events | Signoff events |

---

## How They Compose

The three layers compose sequentially in the trust evaluation path:

```
1. Eye: "There are active signals for this scope. Status: elevated.
         Reason: device_fingerprint_changed. Recommended: step_up_auth."
         |
2. EP:   Policy reads Eye advisory.
         Policy rule: if eye_status >= elevated, required_assurance = high.
         Handshake initiated with elevated requirements.
         Presentations added. Handshake verified.
         Policy rule: if eye_status == review_required, signoff_required = true.
         (In this case, elevated does not trigger signoff. Handshake proceeds.)
         |
3. Result: Action authorized with stepped-up assurance.
           Eye advisory recorded in handshake audit trail.
```

For a `review_required` status:

```
1. Eye: "Critical signals for this scope. Status: review_required.
         Reason: credential_issuer_compromised. Recommended: require_signoff."
         |
2. EP:   Policy reads Eye advisory.
         Policy rule: if eye_status == review_required, signoff_required = true.
         Handshake verified. Signoff gate activates.
         |
3. Signoff: Challenge issued to accountable actor.
            Challenge includes Eye advisory detail in consequences_summary.
            Human sees: "This action requires signoff because the credential issuer
            has been reported compromised (Eye advisory adv_...)."
            Human approves, denies, or escalates.
            |
4. Result: If approved, action authorized with signoff attestation.
           Eye advisory + signoff attestation recorded in audit trail.
```

Eye never bypasses EP. EP never bypasses Signoff (when policy requires it). Signoff never bypasses EP. The chain is sequential and non-negotiable.
