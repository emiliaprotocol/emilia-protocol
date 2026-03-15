# EP-IX — Identity Continuity Extension  
**Version:** 0.1 Draft  
**Status:** Working Draft  
**Base Protocol:** EMILIA Protocol / EP Core  
**Purpose:** Bind principals to entities, preserve continuity across rotation and migration, and prevent trust laundering through re-registration.

## 1. Why EP-IX exists

EP already evaluates trust **given an identity**.

EP-IX adds the missing layer between identity and trust:

- who controls this entity
- whether this new entity is the successor of an old one
- whether trust should transfer, partially transfer, or not transfer at all
- whether a bad actor is trying to whitewash a reputation by starting over

EP-IX does **not** try to become a universal identity provider.  
It defines how identity evidence, control proofs, and continuity proofs are represented inside EP so trust can follow real principals without being easily laundered.

## 2. Core principles

### 2.1 Identity and trust are separate
Identity answers:
- who is this principal

Trust answers:
- should this principal or entity be trusted for this context and policy

EP-IX connects them, but does not collapse them.

### 2.2 Continuity must be provable
A principal should be able to rotate keys, migrate infrastructure, or change hosts without losing all trust, but only with explicit proof.

### 2.3 Continuity must not become laundering
A principal must not be able to transfer only the good parts of trust history and discard the bad parts.

### 2.4 Trust transfer is policy-governed
Continuity does not automatically mean full trust inheritance.

### 2.5 Append-only history
Identity bindings, continuity claims, challenges, reversals, and decisions must be preserved in append-only form.

## 3. Core objects

## 3.1 Principal
A principal is the enduring actor behind one or more entities.

Examples:
- human operator
- organization
- merchant
- seller
- software publisher
- AI operator
- service provider

```json
{
  "principal_id": "ep_principal_123",
  "principal_type": "organization",
  "display_name": "Acme Labs",
  "created_at": "2026-03-15T00:00:00Z",
  "status": "active"
}
```

## 3.2 Entity
An entity is a trust surface controlled by a principal.

Examples:
- one merchant API
- one MCP server
- one GitHub App
- one npm package
- one marketplace seller profile

```json
{
  "entity_id": "mcp-server-acme-v2",
  "entity_type": "mcp_server",
  "principal_id": "ep_principal_123",
  "status": "active"
}
```

A principal may control many entities.  
An entity belongs to exactly one principal at a time.

## 3.3 Identity Binding
An identity binding proves that a principal controls a real-world surface.

Binding types:
- domain control
- GitHub org control
- npm publisher control
- marketplace account control
- current key control
- enterprise identity control

```json
{
  "binding_id": "ep_bind_001",
  "principal_id": "ep_principal_123",
  "binding_type": "domain_control",
  "binding_target": "emiliaprotocol.ai",
  "proof_type": "dns_txt",
  "provenance_tier": 3,
  "status": "verified",
  "verified_at": "2026-03-15T00:00:00Z"
}
```

## 3.4 Continuity Claim
A continuity claim asserts that one entity is the successor of another under the same principal.

```json
{
  "continuity_id": "ep_ix_001",
  "principal_id": "ep_principal_123",
  "old_entity_id": "mcp-server-acme-v1",
  "new_entity_id": "mcp-server-acme-v2",
  "reason": "key_rotation",
  "proofs": [
    {"type": "old_key_signature"},
    {"type": "new_key_signature"},
    {"type": "domain_control"}
  ],
  "status": "pending",
  "created_at": "2026-03-15T00:00:00Z"
}
```

## 3.5 Continuity Decision
A continuity decision records whether continuity is accepted, rejected, or partially accepted.

```json
{
  "continuity_id": "ep_ix_001",
  "decision": "approved_partial",
  "transfer_policy": "partial",
  "reasoning": [
    "same principal proven",
    "domain control verified",
    "old unresolved disputes preserved"
  ],
  "decided_at": "2026-03-16T00:00:00Z"
}
```

## 4. Binding methods

EP-IX should support multiple proof channels.

## 4.1 Domain control
Methods:
- DNS TXT challenge
- HTTPS well-known file
- signed challenge returned from verified domain

Best for:
- merchants
- MCP servers
- software publishers
- organizations

## 4.2 Host account control
Methods:
- GitHub org/app challenge
- npm trusted publisher proof
- Chrome Web Store listing owner proof
- Shopify app/store ownership proof
- marketplace seller/admin proof

Best for:
- software and marketplace identities

## 4.3 Key control
Methods:
- signed challenge with current protocol key
- dual-signature rotation proof
- old-key-to-new-key succession proof

Best for:
- key rotation
- server migration
- principal continuity

## 4.4 Enterprise identity
Methods:
- OIDC
- SAML-backed admin assertion
- SCIM-backed org assertion

Best for:
- enterprise deployments

## 4.5 Human identity
Methods:
- verified email
- passkey
- optional stronger KYC when required by a host ecosystem

EP-IX should not require government identity by default.

## 5. Provenance tiers for identity

Identity evidence should carry provenance, just like trust receipts.

- **Tier 0** — self-asserted only
- **Tier 1** — signed by the claimant
- **Tier 2** — bilateral host/claimant confirmed
- **Tier 3** — host-originated verified fact
- **Tier 4** — adjudicated continuity or independently verified institutional proof

Examples:
- DNS TXT verified by EP server: Tier 2 or 3 depending on verifier design
- GitHub org ownership confirmed via GitHub-side artifact: Tier 3
- dual old/new key signature plus verified domain: Tier 3
- operator-upheld continuity after dispute: Tier 4

## 6. Continuity reasons

Allowed continuity reasons should be explicit.

- `key_rotation`
- `infrastructure_migration`
- `host_migration`
- `entity_rename`
- `domain_change`
- `publisher_transition`
- `merger_or_acquisition`
- `recovery_after_compromise`

This matters because trust transfer should depend partly on the reason.

## 7. Trust transfer policies

Continuity does not imply equal trust transfer.

EP-IX should support at least four transfer outcomes.

## 7.1 Full transfer
Use when:
- same principal is strongly proven
- old and new key control is demonstrated
- same host/domain relationship exists
- no unresolved severe disputes block transfer

Effect:
- trust profile lineage preserved
- historical establishment preserved
- current trust state largely preserved
- unresolved disputes remain attached

## 7.2 Partial transfer
Use when:
- same principal is likely or proven
- host or environment changed materially
- trust should carry, but with caution

Effect:
- historical establishment preserved
- current confidence dampened
- some host-specific signals reset
- unresolved adverse history preserved

## 7.3 No transfer
Use when:
- continuity proof is insufficient
- identity evidence is weak
- high-risk context or sanctions block transfer

Effect:
- new entity starts fresh
- old trust remains attached to old entity only
- continuity attempt recorded publicly or semi-publicly depending on visibility rules

## 7.4 Rejected / laundering suspected
Use when:
- continuity proof is inconsistent
- principal appears to be evading adverse history
- selective migration is attempted

Effect:
- continuity denied
- laundering flag attached
- policy engines may downgrade or reject

## 8. Whitewashing resistance

This is the main reason EP-IX exists.

The protocol should be able to say:

- this entity is new
- this principal appears linked to a previously low-trust or disputed entity
- trust transfer is denied or partial
- unresolved disputes remain visible in lineage

### Rule
**Continuity may carry good trust, but it must also carry bad history.**

That should be constitutional.

## 9. Evaluator changes

The trust evaluator should become continuity-aware.

When evaluating an entity, it should compute:

- entity-local trust profile
- principal-level lineage
- continuity status
- transfer mode
- inherited dispute burden
- inherited sanctions or warnings
- continuity confidence

### Output additions
```json
{
  "continuity": {
    "principal_id": "ep_principal_123",
    "continuity_status": "approved_partial",
    "transfer_policy": "partial",
    "lineage_depth": 2,
    "inherits_historical_establishment": true,
    "inherits_unresolved_disputes": true
  }
}
```

## 10. Public trust and identity views

Add two public or semi-public surfaces.

## 10.1 Principal view
`GET /api/identity/principal/:principalId`

Returns:
- principal metadata
- active bindings
- controlled entities
- lineage summary
- public continuity decisions

## 10.2 Lineage view
`GET /api/identity/lineage/:entityId`

Returns:
- predecessor entities
- successor entities
- continuity reasons
- transfer decisions
- inherited dispute burden

This makes whitewashing visible.

## 11. API surface

Recommended EP-IX endpoints:

### Bindings
- `POST /api/identity/bind`
- `POST /api/identity/verify`
- `GET /api/identity/bindings/:principalId`

### Continuity
- `POST /api/identity/continuity`
- `POST /api/identity/continuity/respond`
- `POST /api/identity/continuity/resolve`
- `GET /api/identity/lineage/:entityId`

### Principal
- `GET /api/identity/principal/:principalId`

### Install/use-time trust
- `POST /api/trust/evaluate` should optionally return continuity data
- `POST /api/trust/install-preflight` should optionally fail on suspicious continuity gaps

## 12. Human and operator roles

Identity continuity is too sensitive to fully automate.

Roles should include:

- **claimant** — requests a binding or continuity link
- **counterparty / affected party** — may challenge
- **host verifier** — external host-originated proof source
- **operator / reviewer** — resolves disputed continuity claims
- **appeal reviewer** — handles escalations

### Rule
**Continuity claims may be automated when cryptographic proof is strong, but disputed continuity requires review.**

## 13. Visibility and privacy

Not all identity evidence should be public.

### Public
- continuity existence
- principal linkage summary
- approved/rejected/partial outcome
- reason category

### Redacted public
- sanitized proof metadata
- proof types without sensitive contents

### Restricted
- raw signed challenges
- internal account evidence
- enterprise proofs
- reviewer notes

This is especially important for:
- private repositories
- marketplace accounts
- corporate migrations
- compromised-entity recovery

## 14. Threat model

EP-IX should explicitly defend against:

- bad actor abandons a low-trust entity and re-registers
- good actor rotates keys and loses trust unfairly
- attacker hijacks identity binding without real control
- principal selectively transfers only favorable history
- disputed entity attempts silent continuity migration
- compromised account attempts to claim succession
- **hostile succession claim** — attacker claims continuity with a high-trust entity they don't control
- **continuity-as-evasion** — entity files for succession while active disputes are open, letting disputes expire on the abandoned entity
- **principal fission gaming** — entity splits into two successors to dilute inherited dispute burden across both

## 14.1 Architectural constraints (co-CTO additions)

These six constraints address production-scale gaps in the base design.

### Constraint 1: Bootstrap governance

The first principals in any EP-IX deployment cannot be verified by the trust graph because the graph doesn't exist yet. EP-IX must define an explicit bootstrap governance phase — not just "first N principals."

Configuration:
- `bootstrap_mode`: `true | false`
- `bootstrap_exit_policy`: configurable conditions for transition
- `bootstrap_operator_quorum`: required approvals during bootstrap

A deployment remains in bootstrap mode until an exit policy is satisfied:
- minimum number of established principals
- minimum graph density (bilateral receipts across distinct principals)
- optional operator approval

Bootstrap authority exists only to seed a graph that can later govern itself. Once the exit policy is met, the system transitions to graph-native verification and bootstrap mode cannot be re-entered.

### Constraint 2: Continuity challenge window

Continuity claims must have a **challenge window** (default: 7 days) with an explicit state machine:

- `pending` → claim filed, challenge window open
- `under_challenge` → challenge received, requires review
- `approved_full` → continuity accepted, full trust transfer
- `approved_partial` → continuity accepted, dampened transfer
- `rejected` → continuity denied
- `frozen_pending_dispute` → blocked by active disputes
- `expired` → 30-day deadline passed without resolution

**Who can challenge** (rights must be explicit):
- old entity controller
- existing principal owner
- currently bound hosts
- active dispute counterparties
- operator/reviewer
- affected enterprise admin

Immediate approval is permitted only for tightly-scoped automated rotations with dual-signature proof and no active disputes. All other claims require the full challenge window.

```json
{
  "continuity_id": "ep_ix_001",
  "status": "pending",
  "challenge_deadline": "2026-03-22T00:00:00Z",
  "challenges": []
}
```

### Constraint 3: Dispute freeze on continuity

If an entity has **active disputes** (status: `open` or `under_review`), continuity claims from that entity enter `frozen_pending_dispute` state until all disputes resolve.

Continuity should freeze when:
- active disputes exceed policy threshold
- active appeals exist
- severe unresolved sanctions exist

Rationale: continuity during active disputes creates a race condition — the principal can abandon the disputed entity and let disputes expire on the orphan. Freezing forces the principal to face its challenges before migrating trust.

**Exception:** `recovery_after_compromise` reason may bypass the freeze with operator approval when:
- old entity is cryptographically compromised or provably unavailable
- the dispute burden is explicitly preserved on the successor
- operator approval is recorded in the continuity decision

**Identity continuity may preserve trust, but it may not erase accountability.**

### Constraint 4: Fission and merger rules

**Fission (A → B + C):** When a principal splits, both successors cannot inherit full trust. EP-IX supports fission continuity with conservation rules:

- **Primary successor:** inherits trust profile + full dispute burden
- **Secondary successor(s):** start with `partial` transfer — historical establishment preserved, current confidence dampened, all inherited disputes attached
- **Conservation rule:** the sum of transferred trust weight across successors must never exceed the original

Implementation model:
```json
{
  "continuity_mode": "fission",
  "transfer_budget": 1.0,
  "primary_successor": "entity-new-commerce",
  "primary_allocation": 0.7,
  "secondary_successors": [
    {"entity_id": "entity-new-software", "allocation": 0.3}
  ],
  "original_entity": "entity-original"
}
```

Bad history must also be conserved: unresolved disputes, sanctions, warnings, and reversals remain visible in the lineage of all successors.

**Merger (A + B → C):** When entities merge, the new entity inherits the combined trust lineage. This requires rules for:
- trust aggregation (weighted by receipt count and evidence strength)
- dispute aggregation (all active disputes from all predecessors carry forward)
- conflict resolution (when predecessors have contradictory trust signals)
- sanction carry-forward (worst-case sanctions from any predecessor apply)

Merger is Phase 2 — the data model is specified here, the implementation follows after linear and fission cases are proven.

```json
{
  "continuity_mode": "merger",
  "predecessor_entities": ["entity-a", "entity-b"],
  "successor_entity": "entity-c",
  "aggregation_rule": "weighted_evidence"
}
```

### Constraint 5: Provenance alignment — single vocabulary

EP-IX identity provenance must use the same vocabulary as EP receipt provenance. Parallel tier systems fracture implementability.

**One shared vocabulary:**

| Provenance | EP receipts | EP-IX identity | Meaning |
|---|---|---|---|
| `self_attested` | Submitter claim only | Identity claim only | No verification |
| `identified_signed` | Signed receipt | Signed challenge | Cryptographic proof from claimant |
| `bilateral_confirmed` | Counterparty confirmed | Host + claimant both confirm | Two-party verification |
| `host_verified` | Oracle verified | External host confirms independently | Third-party verification |
| `adjudicated_verified` | (new) | Operator-upheld after challenge | Reviewed and approved |

If numeric tiers (0-4) remain useful internally, they are aliases only — not the public vocabulary. Implementers learn one provenance language, not two.

**Identity continuity uses the same provenance vocabulary as trust receipts. Only the evidence classes differ.**

### Constraint 6: Continuity claim expiration

Pending continuity claims must resolve or expire. Trust lineage cannot live in permanent ambiguity.

Deadlines:
- **Warning** at 21 days
- **Auto-expire** at 30 days unless challenged or resolved
- If challenged, expiry pauses and shifts to dispute/continuity review SLA
- Expired claims are recorded as `expired` — not deleted. The principal may file a new claim.

This mirrors EP's existing deadline enforcement:
- Bilateral confirmations: 48 hours
- Dispute responses: 7 days
- Continuity claims: 30 days

The `/api/cron/expire` endpoint should enforce continuity expiration alongside bilateral and dispute deadlines.

## 15. Conformance requirements

EP-IX needs test vectors too.

At minimum:
- domain-control proof vector
- key-rotation proof vector
- partial-transfer scenario
- rejected continuity / laundering attempt
- evaluator output including inherited disputes
- public lineage view fixture
- hostile succession claim — challenged and rejected
- continuity-during-active-disputes — frozen correctly
- fission scenario — primary and secondary successor trust sums correctly
- expired continuity claim — 30-day deadline enforced

This is what turns EP-IX from “good idea” into protocol.

## 16. Rollout phases

## Phase 1
- principal model
- domain control
- key rotation continuity
- public lineage view
- no automatic transfer except narrow cases

## Phase 2
- host adapters for GitHub, npm, Shopify, MCP server identities
- partial transfer rules
- reviewer workflow

## Phase 3
- enterprise/OIDC bindings
- richer sanction/lineage rules
- cross-host continuity
- policy-native whitewashing controls

## 17. Constitutional statements

These are non-negotiable governance anchors:

1. **Trust must never be more powerful than appeal.**
2. **EP evaluates trust given an identity. EP-IX governs how identity continuity is proven.**
3. **Continuity must not become trust laundering.**
4. **A principal may change keys or infrastructure without losing itself. It may not shed its history selectively.**
5. **Identity continuity must never be more powerful than review.**
6. **Continuity during active disputes is frozen.**
7. **Identity continuity may preserve trust, but it may not erase accountability.**
8. **Fission does not multiply trust.**
9. **Bootstrap authority exists only to seed a graph that can later govern itself.**
10. **Pending continuity cannot live forever. Trust lineage must resolve or expire.**
11. **Continuity may be claimed quickly, but it must be challengeable before it becomes trust-bearing.**

## 18. The strategic significance

EP becomes much more important once it can model:

- a merchant changing domains
- an MCP server rotating keys
- a GitHub App moving publishers
- a seller reappearing under a new listing
- a plugin maintainer trying to escape incident history
- a legitimate organization recovering from compromise without losing all trust

That is the bridge from:

- trust evaluation for entities

to:

- trust evaluation for enduring principals across software, commerce, and machine systems

And that is how EP begins to become the future of trust.
