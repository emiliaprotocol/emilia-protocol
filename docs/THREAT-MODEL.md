# EP Threat Model

This document describes the adversary classes that EP is designed to resist, the specific defenses currently implemented, residual risks that remain, and the mitigation roadmap for each. It is intended to be honest about what EP does and does not defend against today.

## Adversary Classes

### 1. Trust Farming Rings

- **Attack**: Colluding entities generate fake positive receipts for each other to inflate trust scores. A ring of 3-5 entities can rapidly accumulate receipts with `completed` behavior and high signal values, mimicking legitimate commerce.

- **EP Defenses**:
  - **Closed-loop detection** (`lib/sybil.js` `detectClosedLoop()`): Detects bidirectional scoring (A scores B AND B scores A) and applies a 0.4x `graph_weight` penalty to receipts between reciprocal pairs.
  - **Cluster detection** (`lib/sybil.js` `analyzeReceiptGraph()`): When 2-3 submitters account for 80%+ of intra-group receipts, the `cluster_detected` flag fires and the receipt is blocked (`graph_weight` capped at 0.1x).
  - **Thin graph penalty** (`lib/sybil.js`): Entities with many receipts but fewer than 3 unique submitters receive a 0.5x weight; single-source entities receive 0.3x.
  - **Retroactive weight adjustment** (`lib/sybil.js` `retroactivelyApplyGraphWeight()`): When fraud is detected between a pair, all historical receipts between them are retroactively downgraded. Weights are only ever reduced, never increased retroactively.
  - **Quality-gated evidence** (`lib/scoring-v2.js` lines 259-268): Unestablished submitters contribute at most 2.0 effective evidence regardless of volume. 200 fake identities cannot cross the establishment threshold because `qualityGatedEvidence = establishedEvidence + min(unestablished, 2.0)`.
  - **Establishment threshold** (`lib/scoring-v2.js` line 272): An entity requires `qualityGatedEvidence >= 5.0` AND `uniqueSubmitters >= 3` to reach `established` status.
  - **Provenance tier weighting** (`lib/scoring-v2.js` lines 182-188): `self_attested` receipts receive only 0.3x weight in scoring; `bilateral` gets 0.8x; `oracle_verified` gets 1.0x.

- **Residual Risk**: Small rings (3-5 entities) with diverse behavioral patterns, varied timing, and receipts spread across multiple transaction types may evade graph analysis in Phase 1, particularly if they avoid triggering the 80% intra-group threshold.

- **Mitigation Roadmap**: Phase 2 oracle-verified claims reduce the value of self-attested receipts. Phase 3 cross-platform receipt correlation can detect rings operating across EP instances.

### 2. Fraudulent Receipts

- **Attack**: Submitting fabricated or inflated receipts -- claiming `delivery_accuracy: 100` for transactions that never occurred, or inflating signal values for real but mediocre transactions.

- **EP Defenses**:
  - **Idempotency / deduplication** (`lib/create-receipt.js` lines 38-111, 248-282): Two-layer TOCTOU guard using Redis `SET NX EX` (production) or in-memory mutex (dev), plus a Postgres unique constraint on `(entity_id, submitted_by, transaction_ref)` as defense-in-depth. The same `transaction_ref` from the same submitter for the same entity always returns the existing receipt.
  - **Provenance tier system** (`lib/scoring-v2.js` `PROVENANCE_WEIGHTS`): Self-attested receipts carry 0.3x scoring weight. Bilateral receipts (confirmed by counterparty) carry 0.8x. Platform-originated receipts carry 0.9x. Oracle-verified carry 1.0x. The tier is resolved and validated at submission time (`lib/signatures.js` `resolveProvenanceTier()`).
  - **Consistency scoring** (`lib/scoring-v2.js` lines 233-244): High variance across an entity's receipt history reduces the consistency component of their trust profile. A pattern of 100-scored receipts interspersed with legitimate low scores will depress consistency.
  - **Signal clamping** (`app/api/receipts/submit/route.js` lines 49-58 and `lib/scoring-v2.js` lines 219-224): All numeric signals are validated and clamped to `[0, 100]`. Non-finite values are rejected outright.
  - **Velocity spike detection** (`lib/sybil.js` `detectVelocitySpike()`): More than 100 receipts per hour from a single submitter triggers a block.
  - **Per-entity daily quota** (`lib/create-receipt.js` `checkEntityDailyQuota()`): 500 receipts per entity per UTC day, enforced via Redis or DB count fallback.
  - **Self-scoring prohibition** (`lib/create-receipt.js` line 235): An entity cannot submit receipts for itself.

- **Residual Risk**: Self-reported receipts (`provenance_tier: self_attested`) have minimal verification in Phase 1 beyond graph analysis. A submitter can fabricate plausible signal values for real transaction references.

- **Mitigation Roadmap**: Bilateral confirmation requirement for higher weight (already implemented as `requestBilateral` flow via `app/api/receipts/confirm/route.js`). Phase 2 host verification will allow platform operators to attest receipt accuracy.

### 3. Malicious Operators

- **Attack**: Operators with elevated privileges (`reviewer`, `appeal_reviewer`, `operator` roles as defined in `lib/procedural-justice.js`) abuse their access to resolve disputes in bad faith, manipulate continuity claims, or selectively suspend entities.

- **EP Defenses**:
  - **Append-only audit trail** (`lib/ep-ix.js` `emitAudit()`): Every trust-changing action is recorded to the `audit_events` table with `event_type`, `actor_id`, `before_state`, and `after_state`. Audit records are insert-only.
  - **Role-based permissions** (`lib/procedural-justice.js` `OPERATOR_ROLES` and `hasPermission()`): Seven distinct roles with explicit permission sets. A `reviewer` cannot perform `entity.suspend`; only `operator` role has that permission. A `disputant` cannot `dispute.resolve`.
  - **Operator action logging** (`lib/procedural-justice.js` `recordOperatorAction()`): Records operator identity, role, reasoning, and full before/after state diffs through the audit system.
  - **State machine enforcement** (`lib/procedural-justice.js` `validateTransition()`): Dispute and continuity state machines enforce valid transitions. Terminal states (`appeal_upheld`, `appeal_reversed`, `withdrawn`, etc.) have empty `valid_transitions` arrays and cannot be modified.
  - **Evidence visibility tiers** (`lib/procedural-justice.js` `VISIBILITY_TIERS`): Four tiers from `public_summary` to `operator_only`, with explicit `includes`/`excludes` lists preventing information leakage.

- **Residual Risk**: Single-operator deployments lack dual-control. An operator who is the sole reviewer can resolve disputes without independent oversight. The audit trail records the action but no one may be reviewing it.

- **Mitigation Roadmap**: Dual-control for trust-sensitive actions (dispute resolution, entity suspension). Operator audit dashboards for independent review. Separation of `reviewer` and `appeal_reviewer` roles is already enforced but requires organizational discipline.

### 4. Replay Attacks

- **Attack**: Reusing valid commit tokens or receipts to authorize duplicate actions or inflate transaction counts.

- **EP Defenses**:
  - **Nonce uniqueness on commits** (`supabase/migrations/029_commits.sql` line 34): `nonce TEXT NOT NULL UNIQUE` constraint at the database level. Any attempt to reuse a nonce fails with a constraint violation.
  - **In-memory nonce set** (`lib/commit.js` line 43 `_usedNonces`): Supplements the DB constraint with a fast in-process check via `Set`. Nonces are added immediately after commit creation (line 344).
  - **Nonce replay verification** (`lib/commit.js` `verifyCommit()` lines 405-424): During verification, the system queries for any other commit sharing the same nonce. If found, the commit is rejected with `nonce_reuse`.
  - **Expiry windows** (`lib/commit.js` lines 39-40, 219-220): Default 10-minute expiry, clamped to 5-15 minute range. Auto-expiry on read (lines 380-391). Expired commits cannot be fulfilled or used.
  - **Commit state machine** (`lib/commit.js` lines 37, 506-512, 568-574): Terminal states (`fulfilled`, `revoked`, `expired`) are immutable. The state machine is enforced with optimistic concurrency (`WHERE status = 'active'` on all transitions).
  - **Receipt deduplication** (`lib/create-receipt.js`): Two-layer TOCTOU guard (Redis lock + DB unique constraint) prevents duplicate receipt insertion from the same `(entity_id, submitted_by, transaction_ref)` tuple.

- **Residual Risk**: The in-memory nonce set (`_usedNonces`) does not survive process restarts or span across serverless instances. The DB `UNIQUE` constraint is the durable defense. Between process cold-start and the first DB write, there is a theoretical window where only the DB constraint provides protection (which is sufficient).

### 5. Compromised Signing Keys

- **Attack**: An attacker obtains the `EP_COMMIT_SIGNING_KEY` environment variable (base64-encoded 32-byte Ed25519 seed) and can forge commit signatures that appear valid.

- **EP Defenses**:
  - **Key rotation support** (`lib/commit.js` lines 277, 435): Every commit includes a `kid` (key identifier) field. Signature verification references the `kid` to determine which key to use.
  - **Key discovery endpoint** (`app/api/commit/keys/route.js`): Public `/api/commit/keys` endpoint returns the active key set with `kid`, algorithm, status, and rotation policy metadata. Consumers can cache and re-fetch to detect rotations.
  - **Rotation policy declaration** (`app/api/commit/keys/route.js` lines 35-39): Declared 90-day rotation interval with 14-day overlap period. Old signatures remain verifiable via archived keys during the overlap window.
  - **Canonical payload signing** (`lib/commit.js` `buildCanonicalPayload()`): Fields are sorted alphabetically for deterministic serialization before Ed25519 signing, preventing payload manipulation.

- **Residual Risk**: No automatic key rotation is implemented yet; the rotation policy is declared but manual rotation requires redeployment and environment variable changes. The `TODO(trust-root)` comment at `lib/commit.js` line 427 notes that verification currently checks the public key embedded in the commit record itself (self-consistency) rather than fetching from a trusted key discovery endpoint.

- **Mitigation Roadmap**: Automated key rotation with overlap windows. HSM integration for production deployments to prevent key extraction. Trust-root verification against the discovery endpoint rather than the embedded public key.

### 6. Dispute Spam / Brigading

- **Attack**: Filing mass disputes to tank a competitor's trust profile while disputes are pending, or coordinating multiple accounts to file disputes against a single target.

- **EP Defenses**:
  - **Dispute dampening** (`lib/scoring-v2.js` lines 41-60): Receipts under active dispute count at `DISPUTE_DAMPENING_FACTOR = 0.3` (30% weight), not 0%. This limits the scoring impact of frivolous disputes. Resolved disputes restore full weight (`dismissed: 1.0`) or exclude the receipt entirely (`upheld: 0.0`).
  - **Abuse detection** (`lib/procedural-justice.js` `checkAbuse()`): Six abuse patterns with thresholds:
    - `repeated_identical_reports`: 5+ same-type reports against same entity in 24h triggers rate limit.
    - `brigading`: 10+ total reports against same entity in 24h triggers flag for review.
    - `ip_report_flooding`: 10+ reports from same IP hash in 24h triggers rate limit.
    - `retaliatory_filing`: Detects tit-for-tat dispute patterns within 24h.
    - `dispute_flooding`: 10+ disputes filed by same entity in 24h triggers rate limit.
    - `continuity_challenge_spam`: 2+ challenges against same continuity claim from same source in 7d.
  - **Rate limiting** (`lib/rate-limit.js`): `dispute_write` category allows 5 dispute actions per hour per API key. `report_write` allows 3 human reports per hour per IP. Sensitive categories fail-closed on Redis errors.
  - **Dispute reason validation** (`app/api/disputes/file/route.js` lines 22-28): Only 7 canonical dispute reasons are accepted; arbitrary strings are rejected.

- **Residual Risk**: Sophisticated distributed brigading using many distinct API keys and IP addresses may bypass IP-based and key-based throttling. The `brigading` threshold of 10 reports per 24h may be too high for targeted attacks or too low for legitimate mass complaints.

- **Mitigation Roadmap**: Behavioral pattern analysis across dispute filers. Dispute filing reputation (entities that file many dismissed disputes receive lower dispute weight). Cross-entity dispute velocity tracking.

### 7. Identity Churn (Whitewashing)

- **Attack**: Abandoning a low-trust entity and registering a new one to start fresh with a clean score. The attacker discards the accumulated negative history and begins building trust from scratch.

- **EP Defenses**:
  - **Establishment threshold** (`lib/scoring-v2.js` lines 267-272): New entities start at score 50 with `confidence: 'pending'`. They require `qualityGatedEvidence >= 5.0` AND `uniqueSubmitters >= 3` to reach `established` status. Consuming agents using `standard` or `strict` trust policies will not route to unestablished entities.
  - **Cold-start penalty** (`lib/scoring-v2.js` lines 111-119): Zero-receipt entities return `score: 50, confidence: 'pending', established: false`. The score is dampened toward 50 until sufficient quality-gated evidence accumulates (line 268).
  - **Registration rate limiting** (`lib/sybil.js` `checkRegistrationLimits()`): Maximum 5 entities per owner per day, 50 entities per owner total. Prevents rapid entity generation from a single API key.
  - **Trust policies as gatekeepers** (`lib/scoring-v2.js` `TRUST_POLICIES`): The `standard` policy requires `min_confidence: 'emerging'` and `min_receipts: 5`. The `strict` policy requires `min_confidence: 'confident'` and `min_receipts: 20`. New entities cannot satisfy these policies.
  - **EP-IX continuity system** (`lib/ep-ix.js`): The identity continuity framework tracks entity lineage. Continuity claims are frozen during active disputes (`frozen_pending_dispute` state). Fission does not multiply trust.

- **Residual Risk**: No cross-entity identity linking exists in Phase 1. An attacker who uses different API keys and avoids linking to the same principal can create genuinely independent entities that EP cannot correlate.

- **Mitigation Roadmap**: Host verification binding (tying entities to verified platform identities). Identity attestation chains through EP-IX. Cross-instance entity correlation in Phase 3.

### 8. Privacy Attacks on Commitment Proofs

- **Attack**: Attempting to reverse-engineer receipt contents, counterparty identities, or transaction amounts from the publicly shared commitment proofs.

- **EP Defenses**:
  - **HMAC-SHA256 commitments excluding sensitive fields** (`lib/zk-proofs.js` `generateReceiptCommitment()` lines 65-73): Commitment input is strictly `receipt_id|entity_id|created_at`. Counterparty IDs, transaction amounts, signal values, submitter identity, and provenance tier are deliberately excluded from the commitment input.
  - **Random salt per proof** (`lib/zk-proofs.js` line 261): Each proof generation uses a fresh 32-byte random salt (`randomBytes(32)`). The salt is public (included in the proof) but the privacy comes from what is NOT in the commitment input.
  - **Merkle tree binding** (`lib/zk-proofs.js` `buildCommitmentTree()`): The commitment root binds the proof to a specific set of receipts without revealing them. The root is anchored on Base L2 for tamper-evidence.
  - **Proof expiry** (`lib/zk-proofs.js` lines 293): Proofs expire after 30 days. Live re-evaluation during verification ensures proofs cannot outlive reality.
  - **Explicit privacy documentation** (`lib/zk-proofs.js` lines 11-15): Code documents precisely what is revealed vs. hidden: claim type, threshold, domain, receipt count, and commitment root are public; receipt contents, counterparty identities, and transaction amounts are hidden.

- **Residual Risk**: The commitment scheme is HMAC-based, not a ZK circuit. It provides computational hiding (an adversary cannot reverse the HMAC without the receipt data) but is not formally proven in the ZK sense. An adversary who independently knows the `receipt_id`, `entity_id`, and `created_at` of a receipt can verify its inclusion in a proof (this is by design for auditability but could be an information leak in adversarial contexts).

## Security Invariants

The following invariants must hold at all times. Violations of any invariant indicate a security regression:

1. **No trust decision path mixes normalized (0-1) and unnormalized (0-100) score scales.** The `scoring-v2.js` composite operates on 0-100 throughout; `zk-proofs.js` behavioral score operates on 0-1 throughout. The commit system defaults to `decision: 'review'` rather than falling back to raw score comparison across scales (`lib/commit.js` lines 265-268).

2. **Every route claiming restricted access has a tested permission check.** The `hasPermission(role, permission)` function in `lib/procedural-justice.js` is the canonical gate. Routes authenticate via `authenticateRequest()` from `lib/supabase.js` before any trust-modifying operation.

3. **Every public enum matches the DB constraint exactly.** Valid transaction types in `app/api/receipts/submit/route.js`, valid dispute reasons in `app/api/disputes/file/route.js`, valid commit actions in `lib/commit.js` (`VALID_ACTIONS`), and valid decisions (`VALID_DECISIONS`) are enforced at both the application and database layers.

4. **Terminal commit states (fulfilled/revoked/expired) are immutable.** Enforced by the `TERMINAL_STATUSES` set in `lib/commit.js` and optimistic concurrency (`WHERE status = 'active'`) on all state transitions. Attempting to revoke a fulfilled commit returns HTTP 409 with `INVALID_STATE_TRANSITION`.

5. **Audit trail is append-only -- no deletes, no updates to historical events.** The `emitAudit()` function in `lib/ep-ix.js` only calls `.insert()` on the `audit_events` table. No update or delete operations exist for audit records in the codebase.

6. **Commitment proofs never include counterparty IDs or transaction amounts.** The `generateReceiptCommitment()` function in `lib/zk-proofs.js` uses only `receipt_id|entity_id|created_at` as input. This is enforced by the function signature and documented in the code comments.

## Out of Scope

The following threat categories are explicitly out of scope for EP's application-layer defenses:

- **Network-level attacks** (DDoS, TLS stripping, BGP hijacking): Handled by infrastructure and CDN (Vercel Edge Network). EP assumes TLS termination is correct.
- **Side-channel attacks on the runtime** (timing attacks on HMAC comparison, memory inspection): Mitigated by Node.js crypto library internals and runtime isolation. Not addressed at the application layer.
- **Social engineering of human operators**: EP provides audit trails and role separation but cannot prevent an operator from being socially engineered into taking a legitimate-seeming action. Organizational controls (training, dual-control policies) are the defense.
- **Compromise of the Supabase/Postgres infrastructure**: EP trusts the database layer for constraint enforcement, RLS policies, and data durability. A compromised database is a total compromise.
- **Supply chain attacks on EP's own dependencies**: Handled by dependency auditing and lockfile integrity (`package-lock.json`), not by EP protocol mechanisms.
