# EP Federation Semantics (supplements FEDERATION-SPEC.md)

**Status:** v1 (Apr 2026).
**Supplements:** `FEDERATION-SPEC.md` — which covers receipt portability, discovery, and anchor layer.
**Scope:** Cross-domain trust semantics that were not resolved in the v1 federation spec. The receipt-portability model is clear; this doc defines what happens when two domains need to *co-authorize* an action, not merely exchange history.

---

## 1. The gap this doc closes

The existing federation spec solves *portability* — Operator B can verify a receipt that Operator A issued, because both anchor to the same L2 and receipts are self-contained. That is necessary but not sufficient for most real federation workflows, which require:

- **Co-authorization**: an action at Domain A requires a sign-off from an actor whose trust root lives in Domain B.
- **Cross-domain dispute resolution**: a disagreement between A and B about whether an action was legitimately authorized.
- **Coordinated key rotation**: A and B both rotate roots; how do in-flight handshakes remain valid?

Without semantics for these, "federation" is just shared log readership, not shared protocol operation. This doc defines the semantics.

---

## 2. Cross-certification, not merged trust roots

Two domains never merge authority tables. Federation is always **cross-certification**:

- Domain A issues a `cross_cert` attestation: "Domain B's authority key X is accepted for role Y, up to assurance level Z, until time T."
- The attestation is signed by A's maintainer set using the same 2-of-N protocol as any internal authority change (see `docs/AUTHORITY-GOVERNANCE.md`).
- Every cross_cert is scoped:
    - **role**: what kind of actor (initiator? verifier? signoff?) B's authority is accepted as.
    - **assurance_ceiling**: the maximum assurance level A will credit B's presentations with, regardless of what B claims.
    - **action_classes**: which action classes (low/medium/high/critical) the cross-cert applies to. Default is low+medium only; high/critical require explicit scoping.
    - **expiry**: cross-certifications are never indefinite. Max 400 days, matching maintainer rotation cadence.

This matches what PKI does well (cross-certification) and avoids what PKI does poorly (transitive trust). **Cross-certs are never transitive.** If A cross-certs B, and B cross-certs C, A does not cross-cert C. A must explicitly cross-cert C or the trust edge does not exist.

---

## 3. Co-authorization flow

A handshake that requires parties from two domains has a canonical shape:

```
initiator (domain A)           verifier (domain A)
    │                                    │
    │   binding_material includes:       │
    │   - domain_a.party_set_hash        │
    │   - domain_b.party_set_hash        │
    │   - cross_cert_hash                │
    │                                    │
    v                                    │
responder (domain B, cross-certed) ─────┘
    │
    signoff (domain B, cross-certed)
```

Every cross-domain binding MUST include:

1. **Both domains' `party_set_hash`**, concatenated in lexicographic order of the domain identifier, then hashed.
2. **The `cross_cert_hash`**: SHA-256 of the canonical serialization of the cross-certification in effect at binding time. If the cross-cert was revoked between binding and consumption, the verifier will fail the binding (see §5).
3. **Both domains' `policy_hash`**: the cross-domain policy is the combination of local policies. Either domain tightening its policy tightens the combined policy; either loosening is ignored by the other.

This is a straightforward extension to the existing canonical binding envelope. It requires `binding_material_version` bump to 2 if not already done for other reasons, and the cross-domain fields are gated on that version.

---

## 3A. Dual-anchor requirement for high-stakes bindings

Any binding whose action class is `high` or `critical` MUST be anchored to **two independent chains**. The second anchor does not need to be a blockchain — an append-only log at a trusted third-party certificate transparency service, or a second L2, or even an L1 checkpoint, is acceptable — but it must be operationally independent of the first.

**Why this matters**: §4's dispute resolution falls back to comparing each domain's event log against the anchored Merkle root. If a single anchor chain is compromised at issue time (51% attack on a small L2, oracle compromise, coordinated reorg window), an adversary could produce self-consistent logs that match the compromised anchor — and §4's dispute process would incorrectly validate them. Dual anchoring requires the adversary to compromise both independent chains simultaneously, which is materially harder.

For `low` and `medium` action classes, single anchoring is acceptable; the cost of a coordinated dual-chain attack exceeds the value of compromising any single binding at those classes.

## 4. Dispute resolution

When Domain A and Domain B disagree about whether a specific handshake was legitimately authorized (e.g., A says "your actor signed off," B says "that actor was revoked before the signoff"):

1. **Both parties publish their event log hashes** at the disputed time window. If the hashes differ, at least one domain has corrupt logs.
2. **The anchored Merkle roots on L2 are the tie-breaker.** The log whose hash matches the anchor at the time of the event wins. A domain whose log does not match its own anchor is excluded from federation pending remediation.
3. **If both logs match their anchors** but contain inconsistent claims, the dispute goes to the federation arbitration ledger — an on-chain record of the dispute, both sides' evidence, and the outcome. No further handshakes across the disputing domains until arbitration concludes.

This avoids the failure mode where two domains arbitrarily accuse each other with no external reference. The anchor is the external reference.

**Arbitration ledger format** lives in a separate spec (future work). For v1, disputes MUST be handled off-protocol; this doc defines only the structural hooks (`federation_disputes` table, `dispute_raised` event type, L2 anchor verification).

---

## 5. Key rotation coordination

The hardest part of federation is handling the case where Domain B rotates its root keys while Domain A has outstanding cross-domain bindings.

**Rule: in-flight bindings are protected by the `cross_cert_hash` at bind time.**

When A issues a binding that includes B's cross-certified key, the `cross_cert_hash` in the binding pins the exact cross-certification instance. If B rotates and A updates its cross-cert to point at the new key, the old cross-cert does NOT disappear — it transitions to `rotated` state with a cutover date (usually 24 hours). Bindings created before the cutover can still be verified against the old cross-cert until binding expiry. New bindings MUST use the new cross-cert.

**Operational consequence**: A cross-cert rotation requires ≤24h of dual-state operation on both sides. During this window, verifiers must accept either cross-cert. After the window, the old cross-cert is `retired` and no new bindings may use it.

**Emergency rotation** (compromise) bypasses the 24h window. The compromised cross-cert transitions directly to `compromise_revoked`, all in-flight bindings that reference it fail verification with `CROSS_CERT_REVOKED`, and affected actions must be re-initiated. Yes, this causes legitimate user pain. The alternative — accepting a compromised key — is worse.

---

## 6. Policy composition across domains

A cross-domain action is gated by the **union of strict requirements** across both domains' policies. Specifically:

- **Required parties**: union. If A requires initiator+verifier and B requires responder, the handshake needs all three.
- **Minimum assurance per role**: max of the two domains' floors for that role. If A requires substantial for the responder role and B requires high, the binding requires high for the responder.
- **Binding strength**: union. If either domain requires payload_hash, it's required. If either requires nonce, it's required. expiry_minutes is the min of both.
- **Signoff**: if either domain requires signoff for the action class, signoff is required.

### 6.1. Interaction with cross-cert ceilings (MUST fail closed)

The `assurance_ceiling` on a cross-cert (see §2) imposes a **cap** on how much assurance Domain A will credit to Domain B's presentations. This interacts with the "max of the two domains' floors" rule above in a specific way that MUST be enforced:

> **If the composed minimum for a role exceeds the cross-cert's `assurance_ceiling` for that role, the binding MUST fail closed.** The verifier rejects with `COMPOSED_ASSURANCE_UNREACHABLE`. The action is unreachable via this cross-cert by design; either the cross-cert must be renegotiated with a higher ceiling, or the cross-domain path cannot be used for this action.

Without this rule, composition becomes unsound in a specific way: suppose Domain A's local policy requires `high` assurance for the responder role. A grants Domain B a cross-cert with `assurance_ceiling: substantial` for the responder role. When B presents a claim with `assurance_level: high`, the verifier is obligated to clip it to `effective_assurance: substantial` (by the ceiling). The composed policy still demands `high`. If the verifier accepts the binding by treating B's clipped `substantial` as "good enough because it's the max available from B," the composed policy has been loosened below A's own standalone requirement — the opposite of the "union always tightens" claim.

The correct behavior: fail the binding. The composition arithmetic and the cross-cert enforcement MUST agree; where they don't, closed. A conformance test MUST exercise this path.

### 6.2. What "tightening" means in composed policies

"Tightening" is a post-condition on verification outcomes, not on policy arithmetic. The composition rules above produce a combined policy whose accept set is a subset of each domain's standalone accept set. Some actions will be unreachable under the composed policy that would have been reachable in one domain or the other alone; that is the intended behavior. Operators who want more cross-domain actions to succeed must raise ceilings in cross-certs, not loosen composition.

This is conservative by design. It is operationally annoying. The operational resolution is to pre-negotiate a compatible shared policy at cross-cert time, not to relax at composition time.

---

## 7. What a cross-domain presentation looks like on the wire

```json
{
  "presentation_type": "federated",
  "party_role": "responder",
  "issuer_ref": "domain-b-authority-key",
  "cross_cert_ref": "cross_cert:abc123",      // pinned at binding time
  "cross_cert_hash": "sha256:...",             // must match binding
  "assurance_claimed": "high",
  "assurance_ceiling": "substantial",          // enforced by cross-cert
  "effective_assurance": "substantial",        // min(claimed, ceiling)
  "raw_claims": { ... },
  "signature": "..."                           // signed by B's authority
}
```

The `effective_assurance` is what flows into `checkAssuranceLevel`. The ceiling enforcement at the protocol level prevents B from being able to elevate its own presentations in A's domain beyond what A authorized.

---

## 8. Implementation staging

1. **v1.0** (this doc): wire protocol shape, cross_cert_hash in binding, assurance ceiling, policy composition rules. No arbitration ledger yet — disputes are handled manually referencing anchor state.
2. **v1.1**: `cross_certifications` table, `apply_cross_cert_change` RPC (uses same 2-of-N maintainer signing as internal authority changes).
3. **v1.2**: verifier integration (every conformant verifier re-checks cross_cert_hash under `FOR UPDATE`, matching the `present_handshake_writes` pattern).
4. **v2.0**: arbitration ledger spec and on-chain anchoring of disputes.

---

## 9. Open questions

- **Revocation propagation across domains.** Even with the protocol semantics above, the network time between A revoking a cross-cert and B learning of it is unbounded unless B polls. Should cross-cert revocations be pushed via webhook? What happens if the webhook fails? Likely answer: B MUST refresh cross-cert status at least every 5 minutes, and A MUST retain revoked cross-cert records for at least 30 days post-revocation for late lookup.
- **Multi-party cross-certification (A+B+C in one binding).** The protocol above handles pairs cleanly. Chains of three are nominally the same (two pairwise cross-certs), but party_set_hash construction and policy composition scale quadratically. Test before claiming support.
- **Cross-domain signoff.** A named human in Domain B signing off on an action initiated in Domain A raises thorny accountability questions. Legal coverage is addressed in `LEGAL-FRAMEWORK.md`; protocol coverage should probably require explicit opt-in per cross-cert rather than being default-on.
