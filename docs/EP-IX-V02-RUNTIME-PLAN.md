# EP-IX v0.2 — Improved CTO Contributions, Next Steps, and Additions

## Executive Summary

The CTO’s six additions are the right ones. They close the production-grade holes that would have made EP-IX elegant on paper but fragile in reality.

The strongest shift is this:

**EP-IX is no longer just an identity continuity concept. It is becoming a continuity governance system.**

That matters because identity continuity is dangerous if it is:
- automatic
- permanent
- non-challengeable
- able to preserve good trust while shedding bad history

The additions below make EP-IX much harder to abuse and much more credible as part of a future trust standard.

---

## The Six CTO Contributions — Improved

## 1) Bootstrap Mode

### What problem it solves
EP-IX cannot assume a trust graph already exists. The first principals exist in a trust vacuum:
- there is no prior graph to anchor them
- there are no established counterparties yet
- continuity cannot be graph-derived

Without a bootstrap mode, the spec quietly assumes the hardest part away.

### Improved version
Use **bootstrap governance**, not just “first N principals.”

Recommended structure:

- `bootstrap_mode = true | false`
- `bootstrap_exit_policy`
- `bootstrap_operator_quorum`
- `bootstrap_principal_classifications`

### Better rule
A deployment remains in bootstrap mode until a configurable exit policy is satisfied, for example:
- minimum number of established principals
- minimum graph density
- minimum number of bilateral receipts across distinct principals
- optional operator approval

### Why this is better
It avoids hard-coding a magic number and makes bootstrap an explicit governance phase rather than a temporary hack.

### Recommended constitutional statement
**Bootstrap authority exists only to seed a graph that can later govern itself.**

---

## 2) Continuity Challenge Window

### What problem it solves
A legitimate continuity claim is not the only continuity claim.

A hostile actor who temporarily controls:
- a domain
- a publisher account
- a marketplace account
- a key

could claim succession to a high-trust entity and inherit trust before anyone notices.

### Improved version
Add an explicit **challengeable continuity state machine**:

- `pending`
- `under_challenge`
- `approved_full`
- `approved_partial`
- `rejected`
- `expired`

### Recommended timing
- default challenge window: **7 days**
- shorter windows only for low-risk continuity types
- immediate approval only for tightly-scoped automated rotations with dual-signature proof and no active disputes

### Who can challenge
Make rights explicit:
- old entity controller
- existing principal owner
- currently bound hosts
- active dispute counterparties
- operator/reviewer
- affected enterprise admin where relevant

### Recommended constitutional statement
**Continuity may be claimed quickly, but it must be challengeable before it becomes trust-bearing.**

---

## 3) Fission Rules

### What problem it solves
Real organizations split.

Without explicit fission rules, trust becomes duplicable:
- A → B + C
- both successors claim continuity
- both inherit the same trust
- total trust exceeds the original

That is trust multiplication.

### Improved version
Fission must be policy-governed and conservation-bound.

Recommended rule:
- one **primary successor** may inherit the main trust lineage
- one or more **secondary successors** may receive partial continuity
- the sum of transferable trust weight across successors must never exceed the parent’s eligible transferable trust

### Practical implementation model
For each continuity decision:
- `continuity_mode = linear | fission | merger`
- `transfer_budget`
- `primary_successor`
- `secondary_successors[]`
- `allocation_rule`

### Recommended constitutional statement
**Fission does not multiply trust.**

### Additional note
Bad history must also be conserved:
- unresolved disputes
- sanctions
- warnings
- reversals
must remain visible in the lineage outcome

---

## 4) Freeze Continuity During Active Disputes

### What problem it solves
If continuity is allowed while active disputes remain unresolved, continuity becomes an accountability escape hatch.

A principal could:
- request succession
- move trust to a new entity
- leave disputes on the abandoned entity
- wait for attention to decay

### Improved version
Continuity should enter a **frozen** state when:
- active disputes exceed policy threshold
- active appeals exist
- severe unresolved sanctions exist

### Recommended exception
Allow a narrow exception for:
- `recovery_after_compromise`
only when:
- operator approval exists
- old entity is cryptographically compromised or provably unavailable
- the dispute burden is preserved on the successor

### State addition
- `frozen_pending_dispute`

### Recommended constitutional statement
**Continuity during active disputes is frozen.**

### Stronger companion line
**Identity continuity may preserve trust, but it may not erase accountability.**

---

## 5) Provenance Tier Alignment

### What problem it solves
Parallel provenance systems fracture implementability.

If EP core uses one vocabulary and EP-IX uses another, implementers will:
- map incorrectly
- weight incorrectly
- misunderstand transfer significance

### Improved version
Do not run two provenance universes.

EP-IX should explicitly map to EP’s shared provenance model with identity-specific examples.

### Recommended mapping pattern
Use one shared tier vocabulary:

- `self_attested`
- `identified_signed`
- `bilateral_confirmed`
- `host_verified`
- `adjudicated_verified`

If numeric tiers remain useful internally, they should be aliases only, not the public vocabulary.

### Why this is better
Implementers should learn one provenance language, not two parallel systems.

### Recommended rule
**Identity continuity uses the same provenance vocabulary as trust receipts. Only the evidence classes differ.**

---

## 6) Continuity Expiration

### What problem it solves
Unresolved continuity claims create state leaks:
- open forever
- ambiguous trust lineage
- lingering governance burden
- unclear evaluator behavior

### Improved version
Treat continuity claims like other bounded protocol obligations.

Recommended default:
- expiration after **30 days**
- warning at 21 days
- auto-expire at 30 unless challenged or resolved
- if challenged, expiry pauses and shifts to dispute/continuity review SLA

### Why this is important
It keeps continuity from becoming permanent ambiguity.

### Recommended constitutional statement
**Pending continuity cannot live forever. Trust lineage must resolve or expire.**

---

# Recommended New Constitutional Statements

These are the best additions to keep and publish:

1. **Trust must never be more powerful than appeal.**
2. **Continuity during active disputes is frozen.**
3. **Fission does not multiply trust.**
4. **Identity continuity may preserve trust, but it may not erase accountability.**
5. **Bootstrap authority exists only to seed a graph that can later govern itself.**
6. **Pending continuity cannot live forever. Trust lineage must resolve or expire.**

---

# Suggested EP-IX v0.2 Runtime Plan

## Phase 1 — Core Data Model
Add these tables / models:

- `principals`
- `identity_bindings`
- `continuity_claims`
- `continuity_decisions`
- `continuity_challenges`
- `continuity_events`

### Key fields
For `principals`:
- `principal_id`
- `principal_type`
- `status`
- `bootstrap_verified`
- `created_at`

For `identity_bindings`:
- `binding_type`
- `binding_target`
- `proof_type`
- `provenance`
- `status`
- `verified_at`

For `continuity_claims`:
- `old_entity_id`
- `new_entity_id`
- `reason`
- `continuity_mode`
- `status`
- `challenge_deadline`
- `expires_at`

For `continuity_decisions`:
- `decision`
- `transfer_policy`
- `allocation_rule`
- `reasoning`
- `decided_by`
- `decided_at`

---

## Phase 2 — API Surface

### Identity binding
- `POST /api/identity/bind`
- `POST /api/identity/verify`
- `GET /api/identity/principal/:principalId`
- `GET /api/identity/lineage/:entityId`

### Continuity
- `POST /api/identity/continuity`
- `POST /api/identity/continuity/challenge`
- `POST /api/identity/continuity/respond`
- `POST /api/identity/continuity/resolve`

### Evaluator integration
- `POST /api/trust/evaluate`
- `POST /api/trust/install-preflight`

Both should optionally return:
- continuity status
- inherited dispute burden
- lineage summary
- whitewashing flag

---

## Phase 3 — Cron / Deadline Enforcement

Add continuity handling to the existing scheduler model:

### Hourly or daily job
- expire stale continuity claims
- warn on approaching challenge deadline
- freeze or unblock continuity based on dispute status
- escalate unresolved challenged continuity claims

### New cron rules
- challenge window default: 7 days
- continuity expiry default: 30 days
- challenged continuity review SLA: configurable

---

## Phase 4 — Evaluator Changes

The canonical evaluator should become continuity-aware.

### It should compute
- entity-local trust
- principal lineage
- continuity status
- transfer policy
- inherited dispute burden
- inherited sanctions
- continuity confidence
- whitewashing risk flag

### It should expose
```json
{
  "continuity": {
    "status": "approved_partial",
    "mode": "fission",
    "lineage_depth": 2,
    "inherits_historical_establishment": true,
    "inherits_unresolved_disputes": true,
    "whitewashing_risk": false
  }
}
```

---

# What to Add Next

These are the best additions after the six CTO fixes.

## 1) Merger support
You now cover:
- linear succession
- fission

Add:
- `merger`

Example:
- A + B → C

This needs rules for:
- trust aggregation
- dispute aggregation
- conflict resolution
- sanction carry-forward

## 2) Continuity visibility levels
Define explicit visibility for continuity records:

- public summary
- redacted proof metadata
- restricted raw evidence

This should be separate and explicit, not implied.

## 3) Principal sanctions / principal warnings
Once a principal controls multiple entities, sanctions should be able to exist at:
- entity level
- principal level

Otherwise bad behavior can hop across sibling entities too easily.

## 4) Compromise workflow
`recovery_after_compromise` should be formalized:
- what evidence proves compromise
- who can approve emergency continuity
- what trust gets dampened temporarily
- how long emergency status persists

## 5) Whitewashing flags in public trust outputs
Users should be able to see:
- possible continuity gap
- denied transfer
- disputed succession
- continuity under review

This is one of the biggest practical trust features EP-IX can provide.

## 6) Conformance vectors for continuity
At minimum:
- bootstrap principal
- legitimate key rotation
- hostile succession challenge
- frozen continuity due to dispute
- fission allocation
- expiration
- partial transfer with inherited disputes

---

# Suggested FAQ Additions

## Q: Can a bad actor just re-register under a new identity?
EP-IX is designed to make continuity visible and trust laundering difficult. A new entity may start fresh, but it cannot automatically inherit only favorable trust while leaving bad history behind.

## Q: What if someone falsely claims succession to a trusted entity?
Continuity claims are challengeable. They do not become trust-bearing immediately when risk is non-trivial.

## Q: What happens if a company splits?
Fission is policy-governed. Trust does not multiply across successors.

## Q: What happens if an entity is under active dispute?
Continuity is frozen during active disputes unless a narrow recovery-after-compromise exception applies.

---

# Best Next Step

If you want the cleanest next move, do this next:

## Build EP-IX v0.2 as a runtime skeleton
Not full production logic yet — just the skeleton:

1. tables
2. API routes
3. cron deadlines
4. evaluator return shape
5. conformance fixtures

That gets EP-IX from:
- very strong design
to:
- real executable architecture

---

# Final Assessment

These CTO comments were the right intervention at the right time.

They improved EP-IX by making it:

- less idealized
- more adversarially sound
- more operational
- more governance-aware
- more production-ready

The best result is this:

**EP-IX now has a credible answer to continuity, laundering, succession abuse, and trust conservation.**

That is a major leap.

