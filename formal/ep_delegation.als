/**
 * EP-CAPABILITY-DELEGATION-v1 — Alloy Relational Model
 *
 * Formal model of the capability delegation chain and the ingest-time
 * structural invariants the runtime validator enforces
 * (packages/gate/capability-receipt.js -> assertDelegationChain). The TLA+
 * capability model (formal/ep_capability.tla) surfaced that
 * DelegationAuthorityNonIncreasing held only emergently via the runtime parent
 * reserve guard, with no standalone chain-validation assertion — and that a
 * hand-crafted envelope could carry a CYCLIC or authority-inflating chain and
 * still pass shape/length validation. This model states the properties the
 * hardened validator now checks directly, at ingest, on the chain alone:
 *
 *   - DelegationAcyclic          — no parent_capability_id recurs and no entry
 *                                  is its own ancestor: the chain is a simple
 *                                  path, never a cycle.
 *   - DelegationIdsUnique        — no delegation_id recurs (each hop is a
 *                                  distinct parent spend).
 *   - LeafIsNotItsOwnAncestor    — the leaf capability never appears as a
 *                                  parent in its own delegation chain.
 *   - AuthorityNonIncreasing     — each hop grants at most what the hop that
 *                                  delegated to it granted; authority is
 *                                  monotonically non-increasing from root to
 *                                  leaf. Holds standalone, independent of the
 *                                  runtime reserve guard.
 *
 * Maps to code:
 *   packages/gate/capability-receipt.js  — assertDelegationChain() ingest checks
 *   packages/gate/capability-receipt.test.js
 *                                        — cyclic / repeated-id / increasing-
 *                                          amount / leaf-as-parent rejections
 *   formal/ep_capability.tla             — DelegationAuthorityNonIncreasing
 *
 * STATUS: authored to the repo's Alloy convention (formal/ep_quorum.als,
 * formal/ep_relations.als). NOT executed in this environment — the Alloy 6 jar
 * (~80 MB) was not fetched here. Run per formal/RUN_ALLOY.md:
 *   java -jar alloy.jar formal/ep_delegation.als   (Execute -> Check All Assertions)
 */

module ep_delegation

-- ==========================================================================
-- Signatures
-- ==========================================================================

-- A capability atom (identity). A delegation hop names the capability it
-- delegates FROM as its parent.
sig Cap {}

-- A delegation identifier atom (the per-hop parent spend id).
sig DelegId {}

-- One delegation hop. `prev` points root-ward: the hop that delegated to this
-- one (lone; the root hop has none). `amount` is the granted budget of this
-- hop. This mirrors one entry of capability.delegation_chain.
sig Entry {
    parent: one Cap,       -- parent_capability_id
    delegId: one DelegId,  -- delegation_id
    amount: one Int,       -- granted amount (non-negative)
    prev: lone Entry       -- the root-ward neighbouring hop
}

-- A capability's delegation chain: the leaf capability plus its ordered hops.
sig Chain {
    leaf:    one Cap,
    entries: set Entry
}

-- ==========================================================================
-- The ingest validator (mirrors assertDelegationChain's fail-closed checks)
-- ==========================================================================

-- The chain is a single linear order over its entries: prev stays inside the
-- chain, is acyclic, has exactly one root (no prev) and no branching.
pred linear[c: Chain] {
    all e: c.entries | e.prev in c.entries
    no  e: c.entries | e in e.^prev
    lone e: c.entries | no e.prev
    all e: c.entries | lone (e.~prev & c.entries)
}

-- No delegation_id recurs.
pred distinctDelegIds[c: Chain] { all disj e1, e2: c.entries | e1.delegId != e2.delegId }

-- No parent_capability_id recurs (a capability delegates at most once as a
-- parent). Either repeat would be a cycle in the delegation graph.
pred distinctParents[c: Chain] { all disj e1, e2: c.entries | e1.parent != e2.parent }

-- The leaf capability never appears as a parent in its own chain.
pred leafNotParent[c: Chain] { all e: c.entries | e.parent != c.leaf }

-- Non-negative budgets, and each hop grants at most what its root-ward
-- predecessor granted.
pred monotonic[c: Chain] {
    all e: c.entries | e.amount >= 0
    all e: c.entries | some e.prev implies e.amount <= e.prev.amount
}

pred valid[c: Chain] {
    linear[c]
    distinctDelegIds[c]
    distinctParents[c]
    leafNotParent[c]
    monotonic[c]
}

-- ==========================================================================
-- Safety assertions
-- ==========================================================================

-- A valid chain is acyclic: no hop is its own ancestor and no parent recurs.
assert DelegationAcyclic {
    all c: Chain | valid[c] implies
        ((no e: c.entries | e in e.^prev)
         and (all disj e1, e2: c.entries | e1.parent != e2.parent))
}
check DelegationAcyclic for 6

-- Delegation identifiers are unique within a valid chain.
assert DelegationIdsUnique {
    all c: Chain | valid[c] implies (all disj e1, e2: c.entries | e1.delegId != e2.delegId)
}
check DelegationIdsUnique for 6

-- The leaf capability is never one of its own ancestors' parents.
assert LeafIsNotItsOwnAncestor {
    all c: Chain | valid[c] implies (all e: c.entries | e.parent != c.leaf)
}
check LeafIsNotItsOwnAncestor for 6

-- Authority never grows along the chain: transitively, every hop grants no more
-- than any of its root-ward ancestors — so the leaf-most hop can never exceed
-- the root-most grant.
assert AuthorityNonIncreasing {
    all c: Chain | valid[c] implies
        (all e: c.entries, a: e.^prev | e.amount <= a.amount)
}
check AuthorityNonIncreasing for 6 but 5 int

-- ==========================================================================
-- Non-vacuity: a genuine valid multi-hop chain exists.
-- ==========================================================================
pred showChain {
    some c: Chain | valid[c] and #c.entries >= 2
}
run showChain for 6 but 5 int
