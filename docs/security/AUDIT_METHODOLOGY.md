# Internal Security Audit — Methodology and Scope

**Score**: 100/100 across all 10 categories
**Date**: April 2, 2026
**Conducted by**: Internal L99 adversarial audit (see methodology below)
**Artifact**: This document + `formal/PROOF_STATUS.md` + `tests/` test suite

---

## What "100/100" Means

The audit uses a 10-category rubric where each category is scored 0–10. A score of 100/100 means all 10 categories reached the maximum score. This is a **code-level security audit** — it evaluates protocol design correctness, implementation security, and operational readiness. It is not a statement that the software is bug-free in perpetuity.

---

## Audit Categories and Scoring

| # | Category | Weight | Score | Evidence |
|---|---|---|---|---|
| 1 | **Protocol design correctness** | 10 | 10/10 | 20 TLA+ safety properties verified by TLC 2.19 (7,857 states, 0 errors); 15 Alloy assertions verified (Alloy 6.1.0, 0 counterexamples) |
| 2 | **Replay and double-consumption prevention** | 10 | 10/10 | `SELECT ... FOR UPDATE` in `verify_handshake_writes` RPC; DB-level unique constraint on `handshake_bindings`; binding consumption tested in 100-way concurrent race |
| 3 | **Nonce and binding integrity** | 10 | 10/10 | `checkBinding()` enforces symmetric nonce_required guard (mirrors payload_hash_required pattern); empty/null/undefined nonce all rejected; 9 test cases in `handshake-bind.test.js` and `protocol-hardening-v2.test.js` |
| 4 | **Policy integrity and version pinning** | 10 | 10/10 | `policy_version_number` written atomically in `create_handshake_atomic` RPC (migration 070); `policy_version_pin_mismatch` error code added; verified in `verify.js` before binding consumption |
| 5 | **Issuer authority TOCTOU** | 10 | 10/10 | `present_handshake_writes` re-checks authority under `SELECT ... FOR UPDATE` (migration 073); overrides `verified=false` and sets `issuer_status = 'authority_revoked_at_write'` if race detected |
| 6 | **Tenant isolation** | 10 | 10/10 | All 8 cloud routes scope queries by `auth.tenantId`; `tenant_id` column added to all cloud-facing tables (migration 072); tested in cloud route test suite |
| 7 | **EP-IX state machine safety** | 10 | 10/10 | Rate limit (max 5 open challenges), self-contest guard (principal + ownership graph check via entities table), freeze/unfreeze/withdraw lifecycle, expiry excludes frozen; 6 TLA+ safety invariants (T21–T26); 20+ EP-IX test cases |
| 8 | **Write-bypass prevention** | 10 | 10/10 | `getGuardedClient()` Proxy in `lib/write-guard.js` throws `WRITE_DISCIPLINE_VIOLATION` on direct trust-table mutation; verified by TLA+ `WriteBypassSafety` property; 0 violations in 3,277 tests |
| 9 | **Adjudication determinism** | 10 | 10/10 | `CONFIDENCE_WEIGHT_INT` integer weights used for sort and vote computation; no float comparison; tested in `dispute-adjudication.test.js` |
| 10 | **Scoring invariants and dampening** | 10 | 10/10 | Named constants (`DAMPENING_THRESHOLD`, `ESTABLISHMENT_EVIDENCE_GATE`, `ESTABLISHMENT_MIN_SUBMITTERS`, `MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION`, `MAX_SINGLE_SUBMITTER_CONTRIBUTION`); invariant relationship tests verify no single submitter can escape dampening alone |

---

## Audit Scope

**In scope:**
- `lib/` — all protocol library code (handshake, verify, consume, bind, EP-IX, scoring, adjudication, delegation, signoff)
- `app/api/` — all Next.js API route handlers
- `supabase/migrations/` — all Postgres RPC functions and schema migrations (001–073)
- `lib/handshake/bind.js` — binding validation pipeline
- `lib/ep-ix.js` — EP-IX continuity state machine
- `lib/scoring-v2.js` — evidence scoring and dampening
- `lib/dispute-adjudication.js` — dispute resolution logic
- `lib/write-guard.js` — write discipline enforcement

**Out of scope:**
- Network-layer security (TLS configuration, DDoS protection) — delegated to infrastructure layer
- Third-party dependencies (Supabase, Vercel, Upstash Redis) — not audited beyond interface usage
- Authentication provider security (OAuth, OIDC providers) — out of protocol scope

---

## Methodology

### Phase 1: Protocol Design Audit (TLA+ and Alloy)

All protocol safety properties were expressed as formal invariants in `formal/ep_handshake.tla` (TLA+) and `formal/ep_relations.als` (Alloy). The model checkers were run to exhaustive state-space exploration within the declared scope.

**TLC 2.19 configuration:**
- `Handshakes = {h1}` (single handshake covers all per-handshake properties)
- `Actors = {a1, a2}` (two actors covers delegation cycles and multi-actor races)
- `Policies = {p1}`, `MaxPolicyVer = 2`
- `Claims = {c1}` (single claim covers all EP-IX per-claim properties)
- `BoundedExploration: Len(events) <= 10`
- **Result**: 7,857 states generated, 1,374 distinct states, 0 errors

**Alloy 6.1.0 configuration:**
- Scope: `for 6` (default); `for 8` for multi-actor checks
- **Result**: All 15 assertions verified, 0 counterexamples

### Phase 2: Adversarial Code Review (116 Red Team Cases)

All 116 red team cases in `docs/conformance/RED_TEAM_CASES.md` were reviewed against the implementation. Each case specifies:
- Attack vector and threat model
- Expected system behavior (must reject / must accept / must rate-limit)
- Code location that enforces the defense
- Test case that validates the defense

31 findings were identified during review and remediated before the audit concluded.

### Phase 3: Concurrent and Race Condition Testing

- **100-way concurrent consumption race**: 100 VUs simultaneously call `verify_handshake` on the same binding. Expected: exactly 1 succeeds, 99 get `already_consumed`. Tested in `tests/adversarial/concurrency.test.js` and `load-tests/binding-lock-contention.js`.
- **TOCTOU windows**: Authority revocation race (migration 073), binding expiry race (migration 071), binding consumption race (migration 069) — all tested with synthetic delay injection.

### Phase 4: Property-Based and Mutation Testing

- **fast-check**: 27 property-based tests covering binding validation invariants, scoring monotonicity, and delegation scope bounds
- **Stryker.js mutation testing**: ≥80% mutation kill threshold across all invariant-bearing modules
- **27 CI quality gates** across 12 automated workflows enforce test coverage, build integrity, schema conformance, and security scanning

### Phase 5: Static Analysis

- **CodeQL**: Active on every push; queries for injection, unsafe deserialization, credential exposure
- **SBOM/provenance**: Generated on every release via GitHub Actions `attest-build-provenance`

---

## Findings Summary

| Severity | Count | Status |
|---|---|---|
| Critical (L99) | 8 | All remediated |
| High (L90) | 12 | All remediated |
| Medium (L75) | 11 | All remediated |
| Low (L50–L60) | 0 | N/A |
| **Total** | **31** | **All remediated before audit close** |

All findings and their remediations are documented in `docs/security/PENTEST_REMEDIATION.md`.

---

## Limitations and Caveats

1. **Model scope**: TLC verified single-handshake and single-claim safety. Multi-handshake cross-contamination properties were verified by Alloy (A10: `MultiActorNoDoubleConsume`). Two-handshake TLC verification is feasible but was not run in this audit cycle.

2. **Clock assumptions**: The protocol now uses DB-authoritative clock (`now()`) for binding expiry inside the RPC. Client-side clocks are untrusted. Clock drift between Postgres instances in a multi-region deployment is not modeled.

3. **Third-party trust**: The audit does not attest to the security of Supabase's hosted Postgres, Vercel's edge runtime, or Upstash Redis. These are trusted infrastructure components.

4. **Score interpretation**: 100/100 reflects the audit rubric at the time of evaluation. New attack surface added after this date (new API endpoints, new protocol features) requires incremental audit coverage.

---

## Reproducing the Audit

```bash
# 1. Run the full test suite
npm test
# Expected: 3,277 passing, 0 failing

# 2. Run TLC formal verification
cd formal
java -jar tla2tools.jar -config ep_handshake.cfg ep_handshake.tla
# Expected: no error found, see formal/PROOF_STATUS.md for full output

# 3. Run Alloy verification
# Open Alloy 6.1.0, load ep_relations.als, run all check commands
# Expected: no counterexamples (see formal/PROOF_STATUS.md)

# 4. Run mutation testing
npm run test:mutation
# Expected: ≥80% kill threshold

# 5. Review red team case registry
cat docs/conformance/RED_TEAM_CASES.md
# 116 cases with implementation references and test mappings
```

---

## Related Documents

- `formal/PROOF_STATUS.md` — TLA+ and Alloy verification results with exact state counts
- `docs/conformance/RED_TEAM_CASES.md` — Complete red team case registry
- `docs/security/PENTEST_REMEDIATION.md` — All findings and remediations
- `docs/security/THREAT_MODEL.md` — Threat model defining the attack surface
- `docs/operations/OBSERVABILITY.md` — Runtime monitoring for security events post-deployment
- `docs/operations/MIGRATION_RUNBOOK_065_073.md` — Ordered deployment of all security migrations

*Last updated: 2026-04-04. Score reflects audit conducted 2026-04-02 through 2026-04-04.*
