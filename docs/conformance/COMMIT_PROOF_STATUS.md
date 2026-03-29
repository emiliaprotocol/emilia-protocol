# EP Commit — Proof Status

**Date:** 2026-03-28

---

## Test Coverage

| Area | Tests | Status |
|------|-------|--------|
| Issuance | 20+ | Passing |
| Verification | 15+ | Passing |
| Revocation | 10+ | Passing |
| Fulfillment | 8+ | Passing |
| Replay / nonce | 10+ | Passing |
| Decision logic | 15+ | Passing |
| Signature (Ed25519) | 8+ | Passing |
| State machine | 10+ | Passing |
| Route integration | 8 | Passing |
| **Total** | **112** | **All passing** |

Test files:
- `tests/commit.test.js` (104 test cases)
- `tests/commit-routes.test.js` (8 test cases)

---

## Invariants Covered

| Invariant | Tested |
|-----------|--------|
| Commit ID has `epc_` prefix | Yes |
| Valid actions: install, connect, delegate, transact | Yes |
| Valid decisions: allow, review, deny | Yes |
| Nonce is 32 bytes hex (64 chars) | Yes |
| Signature is Ed25519 base64 | Yes |
| Expiry is clamped to 5-15 minutes | Yes |
| Status starts as `active` | Yes |
| Terminal states: fulfilled, revoked, expired | Yes |
| No transition from terminal state | Yes |
| Commit without policy always returns `review` | Yes |
| Nonce replay protection (DB unique constraint) | Yes |
| Revoked commit cannot verify as valid | Yes |

---

## State Machine

```
active → fulfilled   (action completed)
active → revoked     (policy change / abuse / manual)
active → expired     (automatic on expiry)

fulfilled → terminal (no further transitions)
revoked   → terminal
expired   → terminal
```

---

## What Remains

| Item | Status |
|------|--------|
| Load test (issue p50/p95/p99) | Not yet run |
| Load test (verify p50/p95/p99) | Not yet run |
| Overload semantics | Not yet tested under load |
| Concurrent issue race | Covered by nonce uniqueness |
