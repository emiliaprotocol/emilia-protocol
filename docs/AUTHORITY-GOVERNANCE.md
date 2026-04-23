# EP Authority Root-of-Trust Governance

**Status:** v1 (Apr 2026). Canonical for EP Core.
**Owner:** Protocol governance.
**Scope:** Who is allowed to add, revoke, and rotate entries in the `authorities` table — the trust anchor that every EP decision ultimately depends on.

---

## 1. Why this matters

EP's cryptographic guarantees are sound, and the wedge is real. But every protocol that verifies a chain of trust eventually depends on an anchor that cannot itself be verified by the protocol — it has to be asserted by humans or institutions. In EP, that anchor is the `authorities` table.

An authority is an identity that signs presentations. When EP checks `checkIssuerTrusted`, it asks: *is this issuer in the authorities table, with status != 'revoked'?* If yes, the presentation is trusted. If the authorities table is wrong, everything downstream is wrong — the formal proofs, the audit score, the load tests, none of it saves you.

This document defines the governance around that table. Everything else in EP is pointless if this part is wrong.

---

## 2. Threat model for the authority table

The authority table is attractive to adversaries because a single unauthorized write gives them authority over every handshake the compromised identity signs. Threats in rough priority:

1. **Direct DB write via credential compromise.** An operator's credentials leak; the attacker adds a malicious issuer as trusted.
2. **Insider write.** A legitimate operator adds a rogue authority at the direction of, or under coercion by, an attacker.
3. **Supply-chain injection.** A migration or seed file is modified upstream and adds an unauthorized entry at deploy time.
4. **Race condition on rotation.** A revoked authority issues one last presentation in the window between revocation intent and revocation effect.
5. **Replay of a legitimately-signed authority instruction** in a different environment (e.g., staging instruction replayed in prod).
6. **Accidental write by a buggy admin tool.** Statistically the most common real-world cause of root-of-trust corruption.

Every governance requirement below maps to one or more of these.

---

## 3. Authority states and lifecycle

```
  proposed ──► pending_ratification ──► active ──► (revoked | rotated | retired)
       │                    │                │
       └─ rejected          └─ expired       └─ key_compromise_revoked
```

- **proposed**: authority has been submitted for review. No handshake uses it.
- **pending_ratification**: at least one maintainer has signed off; awaiting the second.
- **active**: ratified; usable in presentations.
- **revoked**: deliberate revocation, normal cause (key expiry, org change).
- **key_compromise_revoked**: emergency revocation; propagation SLO tightened.
- **rotated**: superseded by a new key; old key remains valid until a cutover date.
- **retired**: end-of-life; no new presentations accepted; historical audit still valid.

No backward transitions are permitted. `prevent_signoff_attestation_backward_status` and migration 045 enforce this pattern at the DB trigger level; the authority lifecycle MUST be enforced the same way. (Implementation: migration 080 — see §10.)

---

## 4. Authorization for write operations

### 4.1. Signature threshold

For production deployments intended to anchor federal, financial, or similarly high-stakes traffic, the signature threshold is **ceil(N/2) + 1 with N ≥ 5**. Early-stage or test deployments MAY use 2-of-N with N ≥ 3, but explicitly cannot claim production-grade governance under this spec. The 2-of-N default in the first draft of this document was weak — any two maintainers coerced together (or a single compromised maintainer with multiple registered keys) defeat it. A majority-plus-one with N ≥ 5 is the floor.

The quorum MUST include **role diversity**: at least one signer from a non-engineering function (compliance, legal, board, infrastructure). Geographic diversity is necessary but not sufficient — an attacker who compromises the engineering team still has a majority of keys if all five maintainers are engineers.

### 4.2. Canonical signed payload

Every change record signature MUST commit to the following canonical payload:

- `env`: environment identifier (production, staging, canary, federation-partner-X)
- `change_request_id`: UUIDv4, generated at proposal time, rejected if reused
- `target_key_id`: the exact authority row being modified
- `pre_image_row_hash`: SHA-256 of the target row's canonical serialization as it exists at proposal time (signer is attesting to the *starting state*, not just the desired end state)
- `post_image_row_hash`: SHA-256 of the intended post-change row
- `action`: add | revoke | rotate | retire
- `proposer_key_id`: the maintainer key that authored the proposal
- `not_before` / `not_after`: signer-attested time window (not DB clock — see §4.3)
- `reason_code` + free-text justification
- `nonce`: 32-byte random, prevents exact re-submission

`apply_authority_change` MUST verify, under `SELECT ... FOR UPDATE` on the target row, that the current row hash matches `pre_image_row_hash` before applying. A mismatch fails the change and is logged as a tampering attempt. This prevents a ratified signed payload from being replayed against a different row or against the same row after interim changes.

### 4.3. Time integrity (not DB clock)

The 24-hour ratification window MUST NOT be enforced against the DB's `now()`. An attacker with DBA-adjacent access or control of an NTP source used by the Postgres host can rewind the clock and replay a stale ratification.

Enforcement uses **signer-attested timestamps inside the signed payload** (`not_before`, `not_after`). Verification cross-checks against at least two independent trusted time sources — a roughtime server and an RFC 3161 TSA, or equivalent. A signature whose attested timestamp disagrees with both external sources by more than 5 minutes is rejected.

The DB clock is still used for operational ordering, but trust decisions never depend on it.

### 4.4. Signer-key validity timing

A signer's key is evaluated for validity **at the moment of that signer's own signature**, using the attested timestamp from §4.3. This resolves the race where a maintainer rotates keys between proposing and ratifying:

- **Good**: Maintainer M proposes at t0 with K1; K1 is valid at t0. M rotates to K2 at t1. Second maintainer signs at t2 with K3 (valid at t2). Apply succeeds — each signature is valid at its own attested time.
- **Bad (rejected)**: Maintainer M proposes at t0 with K1; K1 is compromised and revoked at t1 < t0 + 24h. Another key later signs a ratification that wraps M's proposal at t2 > t1. If `apply_authority_change` evaluated K1's validity at *apply time*, the revoked key would still ratify. The fix: K1's validity is evaluated at t0 (its own signature's attested timestamp), but any compromise revocation issued at t1 < t0 is cause to reject the entire proposal (compromise can be backdated in its effect window — see §4.5).

### 4.5. Out-of-band notification and objection window

At proposal time, the full maintainer set is notified via at least two independent out-of-band channels (e.g., Signal + email, with both delivery confirmed). A **4-hour silent-alarm window** runs before any proposal can be ratified — during the window, any maintainer (including one who did not propose) can veto by signing an objection record. This defends against quiet collusion between two maintainers to push a change past a sleeping third signer.

### 4.6. Blocked write paths

Direct `INSERT` / `UPDATE` / `DELETE` on `authorities` is blocked at the RLS and trigger level. All writes flow through `apply_authority_change(change_request_id)` which performs the verifications above.

### 4.7. Emergency revocations

Emergency revocations (`key_compromise_revoked`) can be applied with a single maintainer signature but require a second signature within 60 minutes to remain in force; otherwise the revocation is automatically unwound.

To prevent DoS via repeated panic revocations:

- **Rate limit**: each maintainer may issue at most 1 panic revocation per 24h.
- **Target notification**: during the 60-minute window, the revoked authority's registered contact is notified and given the opportunity to respond. A contested revocation requires a majority of remaining maintainers to apply anyway.
- **Incident log**: every panic revocation is recorded as a high-severity incident regardless of whether it is ratified, unwound, or contested.

---

## 5. Maintainer set composition

The maintainer set must satisfy:

- **N ≥ 3.** Two-sig cannot work with two maintainers.
- **Geographic and operational diversity.** At least one maintainer not colocated with the others; at least one not on the core engineering team (e.g., infrastructure, compliance, or a board-level role).
- **Key material held offline where possible.** HSM / hardware key preferred; if software keys are used, they must be encrypted with a KMS that enforces its own policy and logs its own access.
- **Annual rotation cadence.** A maintainer who has not rotated their key within 400 days is automatically suspended; remaining maintainers can reinstate or replace.
- **Public disclosure of the set.** Maintainer identities (not key material) are published in `docs/authority/MAINTAINERS.md` and mirrored on the protocol website. Silent maintainer changes are not compatible with the trust model.

---

## 6. Environment separation

Authority sets are environment-scoped. Production, staging, and any federation partner environment each have their own authority table, maintainer set, and change request ledger.

- Cross-environment replay is prevented by including the environment name in the canonical hash of the change record. A production-signed instruction cannot apply in staging because the signature was over different material.
- There is no "bootstrap from staging to production" path. Every production authority is added through the production governance process.

---

## 7. Public audit trail

Every change, successful or not, is written to a public append-only log:

- Proposal: signed change request hash, proposer, timestamp.
- Ratification: second signature, timestamp, reason codes.
- Application: time of effect, actor (always `apply_authority_change`), resulting authority row hash.
- Rejection / expiry: reason, final state.

The log lives in `authority_change_log` and is mirrored to a durable external sink (S3 Object Lock, blockchain anchor, or equivalent) before any dependent action executes. Historical authority state MUST be reconstructable from the log alone — no truncation, no compaction.

Anchoring batches happen on the same cadence as EP's receipt anchoring (`lib/blockchain.js`). A failed anchor does not prevent the change from applying, but it blocks the next proposal until the prior anchor succeeds — this prevents silent corruption of the chain.

---

## 8. Revocation propagation SLO

Once a revocation is applied, it must be visible to every verifier within:

- **10 seconds** for same-region verifiers reading from the primary DB (routine revocation).
- **30 seconds** for the global verifier mesh via replication.
- **60 seconds** end-to-end, including cache invalidation on any verifier that caches authority lookups (no verifier is permitted to cache longer than 30s).

`present_handshake_writes` already re-checks authority status under `SELECT ... FOR UPDATE` (migration 073). That closes the race between a revocation in flight and a presentation mid-verification. It does not close the race on cached reads — that must be addressed at the verifier integration layer, not the protocol. Every EP-conformant verifier must either (a) not cache authority status, or (b) invalidate cache on any authority-change event within the SLO.

---

## 9. Federation

Authority roots across federated domains are NOT shared. Federation is addressed in `docs/FEDERATION-SPEC.md`; the short version: each domain signs its own authorities, and federation is modeled as cross-certification between domains, not as merging of maintainer sets.

---

## 10. Migration plan

1. **Migration 080**: `authority_change_requests`, `authority_change_log`, `authority_maintainers` tables with append-only triggers.
2. **Migration 081**: `apply_authority_change` RPC (replaces direct writes) with two-sig enforcement; RLS policy blocks direct `authorities` writes.
3. **Migration 082**: state machine trigger on `authorities.status` matching the lifecycle in §3.
4. **Integration**: update `scripts/rotate-keys.sh` and similar ops tooling to go through the RPC.
5. **Test coverage**: adversarial tests (tests/authority-governance.test.js) covering:
    - single-sig rejection
    - replay of a ratified change request outside its time window
    - cross-environment replay
    - maintainer self-ratification — enforced at **maintainer identity** level, not key-id. A maintainer with multiple registered keys (e.g., HSM + laptop backup) cannot count twice toward the quorum; `authority_maintainers` rows are uniquely keyed by human identity, and keys roll up to one "sig vote" per maintainer per change.
    - emergency revocation auto-unwind on missing second sig
    - clock-skew replay rejection (attested timestamp vs DB clock)
    - pre-image hash mismatch on target row (replay against modified row)
    - signer-key validity evaluated at signature attested time, not apply time

All five test cases MUST pass before the governance model ships.

---

## 11. Open items

- **Hardware key enrollment process.** How maintainers attest that their key is on a hardware token, not a laptop file. Likely a KeyOxide-style attestation.
- **Maintainer offboarding.** When a maintainer leaves the project or organization, how their authority is rotated out; how to prevent them from blocking the process.
- **Disaster recovery.** If >N-2 maintainer keys are lost simultaneously, the protocol is effectively frozen. Recovery requires a well-documented "constitutional convention" path that itself needs cryptographic attestation; this is future work.
- **Federation trust depth.** Whether cross-domain cert chains are allowed to be transitive (A trusts B, B trusts C, does A trust C?). Default answer: no, unless A explicitly cross-certifies C. Revisit when a real federation pilot is scoped.

---

## 12. Non-goals

- This document does NOT define how end-user identities become EP actors. That is the job of the identity layer, separately governed.
- This document does NOT define the legal status of an authority's attestations. See `docs/LEGAL-FRAMEWORK.md`.
- This document is NOT a hardware security module procurement spec. It describes what the protocol requires; operators choose the concrete hardware.
