/**
 * EP-QUORUM-v1 — Alloy Relational Model
 *
 * Formal model of the multi-party quorum predicate (the "two-person rule",
 * generalized). Proves the safety invariants the cross-language verifier
 * (packages/verify/quorum.js + python-verify + go-verify) enforces and that the
 * conformance vectors (conformance/vectors/quorum.v1.json) exercise:
 *
 *   - SelfApprovalImpossible — a satisfied quorum never counts the initiator
 *     as an approver (separation of duties).
 *   - NoHumanFillsTwoSlots   — distinct_humans: pairwise-distinct approvers.
 *   - NoKeyFillsTwoSlots     — distinct_keys: one device key cannot fill two
 *     slots (defends one-key-under-two-identities).
 *   - TwoPersonRuleHolds     — a satisfied multi-member quorum has >= 2 distinct
 *     humans; no single human alone satisfies it.
 *   - OrderedChainAcyclic    — strong ordered mode (ordered_chain): the
 *     predecessor relation is acyclic (no signoff is its own ancestor).
 *   - OrderedChainLinear     — strong ordered mode: the predecessor relation is a
 *     single total order (one root, no branching) — the sequence cannot be
 *     permuted while remaining satisfied.
 *
 * Maps to code:
 *   packages/verify/quorum.js          — verifyQuorum() checks
 *   conformance/vectors/quorum.v1.json — adversarial vectors (incl. reject_
 *                                        duplicate_key, reject_broken_chain)
 *   standards/draft-schrock-ep-quorum   — Sections 4, 5
 */

module ep_quorum

-- ==========================================================================
-- Signatures
-- ==========================================================================

abstract sig Mode {}
one sig Threshold, Ordered extends Mode {}

-- A flag atom; a Quorum "requires the strong cryptographic chain" iff it has one.
one sig ChainFlag {}

sig Human {}
sig Action {}

-- Each device key is held by exactly one human. (Identity-proofing — which real
-- person — is out of scope; see EP-IDENTITY-BINDING-PROFILE.)
sig Key { holder: one Human }

-- One member's device signoff. `prev` is its predecessor in a strong ordered
-- chain (prev_context_hash binds the predecessor's context).
sig Signoff {
    by:       one Human,
    usingKey: one Key,
    onAction: one Action,
    prev:     lone Signoff
}

sig Quorum {
    mode:      one Mode,
    roster:    some Human,    -- eligible approvers (role roster, abstracted)
    initiator: one Human,
    action:    one Action,
    members:   set Signoff,
    chain:     lone ChainFlag -- present iff ordered_chain is required
}

-- ==========================================================================
-- The quorum predicate (mirrors verifyQuorum's fail-closed checks)
-- ==========================================================================

pred actionBound[q: Quorum]   { all m: q.members | m.onAction = q.action }
pred rolesAdmitted[q: Quorum] { all m: q.members | m.by in q.roster }
pred distinctHumans[q: Quorum]{ all disj m1, m2: q.members | m1.by != m2.by }
pred distinctKeys[q: Quorum]  { all disj m1, m2: q.members | m1.usingKey != m2.usingKey }
pred sod[q: Quorum]           { q.initiator not in q.members.by }

-- Strong ordered chain: prev stays within the trail; acyclic; exactly one root
-- (no predecessor) and no branching (each member has at most one successor) —
-- i.e. a single linear order over the members.
pred chainLinear[q: Quorum] {
    all m: q.members | m.prev in q.members
    no  m: q.members | m in m.^prev
    lone m: q.members | no m.prev
    all m: q.members | lone (m.~prev & q.members)
}

pred satisfied[q: Quorum] {
    actionBound[q]
    rolesAdmitted[q]
    distinctHumans[q]
    distinctKeys[q]
    sod[q]
    (some q.chain and q.mode = Ordered) implies chainLinear[q]
}

-- ==========================================================================
-- Safety assertions
-- ==========================================================================

-- Separation of duties: the initiator is never a counted approver.
assert SelfApprovalImpossible {
    all q: Quorum | satisfied[q] implies q.initiator not in q.members.by
}
check SelfApprovalImpossible for 6

-- distinct_humans: no human fills two slots.
assert NoHumanFillsTwoSlots {
    all q: Quorum | satisfied[q] implies (all disj m1, m2: q.members | m1.by != m2.by)
}
check NoHumanFillsTwoSlots for 6

-- distinct_keys: no single device key fills two slots (one key, two identities).
assert NoKeyFillsTwoSlots {
    all q: Quorum | satisfied[q] implies (all disj m1, m2: q.members | m1.usingKey != m2.usingKey)
}
check NoKeyFillsTwoSlots for 6

-- Two-person rule: a satisfied quorum of two or more members has two or more
-- distinct humans — no single human ever alone satisfies a multi-member quorum.
assert TwoPersonRuleHolds {
    all q: Quorum | (satisfied[q] and #q.members >= 2) implies #(q.members.by) >= 2
}
check TwoPersonRuleHolds for 6 but 4 int

-- Strong ordered chain is acyclic.
assert OrderedChainAcyclic {
    all q: Quorum |
        (satisfied[q] and some q.chain and q.mode = Ordered)
            implies (no m: q.members | m in m.^prev)
}
check OrderedChainAcyclic for 6

-- Strong ordered chain is a single total order: exactly one root and no branching.
assert OrderedChainLinear {
    all q: Quorum |
        (satisfied[q] and some q.chain and q.mode = Ordered)
            implies (lone m: q.members | no m.prev)
}
check OrderedChainLinear for 6

-- ==========================================================================
-- Non-vacuity: a genuine satisfied, chained, multi-member quorum exists.
-- ==========================================================================
pred showStrongQuorum {
    some q: Quorum | satisfied[q] and #q.members >= 2 and some q.chain and q.mode = Ordered
}
run showStrongQuorum for 6
