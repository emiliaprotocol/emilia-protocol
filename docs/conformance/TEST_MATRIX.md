# EP Conformance Test Matrix

Maps every protocol invariant to the test file(s) and test name(s) that prove it holds.

## Core Conformance Suite

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 1 | All 17 command types have validators | conformance.test.js | Write-path completeness > every trust-changing command type has a validator | Pass |
| 2 | All 17 command types have handlers | conformance.test.js | Write-path completeness > every trust-changing command type has a handler | Pass |
| 3 | All 17 command types have aggregate mappings | conformance.test.js | Write-path completeness > every trust-changing command type has an aggregate mapping | Pass |
| 4 | VALID_COMMAND_TYPES = COMMAND_TYPES values | conformance.test.js | Write-path completeness > VALID_COMMAND_TYPES matches COMMAND_TYPES values | Pass |
| 5 | No orphan validators or handlers | conformance.test.js | Write-path completeness > no orphan validators / no orphan handlers | Pass |
| 6 | All trust-bearing tables are write-guarded | conformance.test.js | Write-guard table coverage > all trust-bearing tables are guarded | Pass |
| 7 | TRUST_TABLES is frozen at runtime | conformance.test.js | Write-guard table coverage > TRUST_TABLES is frozen | Pass |
| 8 | Canonical binding fields are frozen | conformance.test.js | Binding material canonical fields > canonical binding fields list is frozen | Pass |
| 9 | BINDING_MATERIAL_VERSION is a positive integer | conformance.test.js | Binding material canonical fields > binding material version is a positive integer | Pass |
| 10 | All required binding fields present | conformance.test.js | Binding material canonical fields > all required binding fields are present | Pass |
| 11 | Assurance levels ordered low-to-high | conformance.test.js | Assurance level ordering > assurance levels are ordered low to high | Pass |
| 12 | ASSURANCE_RANK monotonically increasing | conformance.test.js | Assurance level ordering > ASSURANCE_RANK values are monotonically increasing | Pass |
| 13 | Handshake lifecycle states complete | conformance.test.js | Handshake lifecycle states > handshake has all required status values | Pass |
| 14 | CI enforcement covers all canonical functions | conformance.test.js | CI enforcement script covers all canonical functions | Pass |
| 15 | Protocol event builder returns all required fields | conformance.test.js | Protocol event builder > buildProtocolEvent returns all required fields | Pass |
| 16 | Idempotency key is deterministic | conformance.test.js | Idempotency key determinism > same command produces same idempotency key | Pass |
| 17 | assertInvariants rejects bad commands | conformance.test.js | Protocol-level assertInvariants > rejects command with no type | Pass |
| 18 | Authority resolution handles all actor formats | conformance.test.js | Authority resolution > resolves string/object/missing actors | Pass |

## Write-Path Enforcement Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 19 | All writes through protocolWrite() | protocol-write.test.js | Command validation, idempotency, handler routing | Pass |
| 20 | Write guard blocks mutations on trust tables | ci-guardrails.test.js | Trust-table write violation detection | Pass |
| 21 | Route files use getGuardedClient not getServiceClient | ci-guardrails.test.js | getServiceClient violation detection | Pass |
| 22 | Receipt path unity (manual = auto path) | receipt-path-unity.test.js | Manual and auto receipt share same write path | Pass |

## Handshake Invariant Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 23 | Must not finalize after expiry | handshake-invariants.test.js | checkNotExpired | Pass |
| 24 | All required parties must present | handshake-invariants.test.js | checkAllPartiesPresent | Pass |
| 25 | Binding payload hash verification | handshake-invariants.test.js | checkBindingValid | Pass |
| 26 | Issuer must be in trusted authorities | handshake-invariants.test.js | checkIssuerTrusted | Pass |
| 27 | Authority must not be revoked | handshake-invariants.test.js | checkAuthorityNotRevoked | Pass |
| 28 | Assurance level meets minimum | handshake-invariants.test.js | checkAssuranceLevel | Pass |
| 29 | No duplicate accepted results | handshake-invariants.test.js | checkNoDuplicateResult | Pass |
| 30 | Must have interaction reference | handshake-invariants.test.js | checkInteractionBound | Pass |
| 31 | No role spoofing (actor = party) | handshake-invariants.test.js | checkNoRoleSpoofing | Pass |
| 32 | Finalized result is immutable | handshake-invariants.test.js | checkResultImmutability | Pass |
| 33 | runAllInvariants aggregates all checks | handshake-invariants.test.js | runAllInvariants | Pass |
| 34 | Handshake attack resistance | handshake-attack.test.js | Attack vector coverage | Pass |

## Cryptographic Integrity Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 35 | Ed25519 signature verification | signatures.test.js | Identified_signed provenance tier | Pass |
| 36 | Merkle tree integrity | blockchain.test.js | Cryptographic integrity layer | Pass |
| 37 | Canonical claim normalization | handshake-normalize.test.js | normalizeClaims, claimsToCanonicalHash | Pass |

## Trust Scoring and Dispute Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 38 | Scoring determinism | scoring.test.js | Protocol surface behavior | Pass |
| 39 | Scoring v2 improvements | scoring-v2.test.js | Updated scoring model | Pass |
| 40 | Dispute adjudication lifecycle | dispute-adjudication.test.js | Dispute state transitions | Pass |
| 41 | Abuse detection enforcement | abuse-detection.test.js | Rate limiting and pattern detection | Pass |

## Authorization and Authentication Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 42 | Actor identity from auth middleware | middleware-policy.test.js | Middleware route policy enforcement | Pass |
| 43 | authenticateRequest correctness | authenticate-request.test.js | Auth request validation | Pass |
| 44 | Audit route requires permission | audit.test.js | audit.view permission check | Pass |
| 45 | Dual control for sensitive actions | dual-control.test.js | DUAL_CONTROL_ACTIONS coverage | Pass |

## Operational Robustness Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 46 | Fail-closed on infrastructure errors | fail-closed.test.js | Fail-closed behavior | Pass |
| 47 | Operational failure resilience | operational-failure.test.js | Partial outage handling | Pass |
| 48 | Receipt idempotency | receipt-idempotency.test.js | System-level idempotency | Pass |
| 49 | Replay attack resistance | replay.test.js | Replay detection | Pass |

## Integration and E2E Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 50 | Protocol event sourcing | protocol-events.test.js | Append-only event store, authority registry | Pass |
| 51 | Commit lifecycle (issue/verify/revoke) | commit.test.js | issueCommit, verifyCommit, revokeCommit | Pass |
| 52 | Commit route contracts | commit-routes.test.js | Route handler integration | Pass |
| 53 | Route contracts (API surface) | route-contracts.test.js | Route contract validation | Pass |
| 54 | Route coverage completeness | route-coverage.test.js | All routes tested | Pass |
| 55 | Handshake route integration | handshake-route-integration.test.js | Route-to-service arg passing | Pass |
| 56 | Handshake trust decision bridge | handshake-trust-decision.test.js | TrustDecision bridge, event sourcing | Pass |
| 57 | E2E protocol flows | e2e-flows.test.js | End-to-end scenarios | Pass |
| 58 | Integration protocol surface | integration.test.js | Protocol surface behavior | Pass |

## Adversarial Resistance Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 59 | Sybil ring detection | adversarial-benchmarks.test.js | Sybil rings, reciprocal farming | Pass |
| 60 | Adversarial input handling | adversarial.test.js | Adversarial input vectors | Pass |
| 61 | Breakage resistance | adversarial-breakage.test.js | Adversarial breakage scenarios | Pass |

## Supplementary Tests

| # | Invariant | Test File | Test Name | Status |
|---|-----------|-----------|-----------|--------|
| 62 | Public claims match implementation | public-claims.test.js | Static analysis of public claims | Pass |
| 63 | Language guard consistency | language-guard.test.js | Language constraint enforcement | Pass |
| 64 | Auto-receipt configuration | auto-receipt.test.js | Auto-receipt config, MCP integration | Pass |
| 65 | Auto-submit route correctness | auto-submit.test.js | POST /api/receipts/auto-submit | Pass |
| 66 | Attribution scoring | attribution.test.js | Attribution score calculation | Pass |
| 67 | Delegation judgment | delegation-judgment.test.js | Delegation judgment scoring | Pass |
| 68 | Report type handling | report-types.test.js | Report type validation | Pass |
| 69 | ZK proof verification | zk-proofs.test.js | Zero-knowledge proof layer | Pass |
| 70 | State reconstitution from events | reconstitution.test.js | Event reconstitution | Pass |
| 71 | Cross-layer invariants | invariants.test.js | Cross-layer contract checks | Pass |

---

**Total test files**: 44
**Total invariants covered**: 71
**Conformance suite (structural invariants)**: 47 tests in `conformance.test.js`
