# Performance Benchmark Baseline

This document records the official performance baseline for the EMILIA Protocol.
All SLOs below are enforced as k6 thresholds in `.github/workflows/k6.yml` and in
`tests/k6/baseline.js`. A regression that breaks any threshold must be investigated
before merging.

## Environment

| Attribute | Value |
|-----------|-------|
| Date | 2026-03-28 |
| Platform | Vercel Pro (pdx1) |
| Database | Supabase (us-west-2, pooler mode) |
| Cache | Upstash Redis (us-west-1, 256 MB) |
| Protocol version | EP/1.1-v2 |
| Test tool | k6 v0.54 |

## SLO Targets

These targets apply to every production deployment. The k6 CI workflow fails
if any threshold is violated under the smoke load (5 VUs, 30s).

| Route | p50 | p95 | p99 | Error rate |
|-------|-----|-----|-----|------------|
| `POST /api/handshake` (create) | < 60ms | < 150ms | < 300ms | < 1% |
| `POST /api/trust/evaluate` | < 40ms | < 100ms | < 200ms | < 1% |
| `POST /api/receipts/submit` | < 80ms | < 200ms | < 500ms | < 1% |
| `POST /api/signoff/challenge` | < 80ms | < 200ms | < 500ms | < 1% |

## Verified Results (2026-03-28)

Full staircase load test: 10 → 500 VUs, 60s per step.
See `docs/operations/PERFORMANCE_PROOF.md` for the full optimization history.

### POST /api/handshake (4th optimization round, production)

| Metric | Result |
|--------|--------|
| p50    | 41ms   |
| p95    | 87ms   |
| p99    | 142ms  |
| Error rate | 0.0% |
| Req/s  | 214    |

All SLO targets met at 500 VUs sustained.

## Regression Policy

If a PR causes any of the following, it must not be merged:

- p95 increases by > 20% versus the baseline above
- Error rate exceeds 0.5% under smoke load
- k6 CI workflow exits with non-zero status

To investigate a regression:
1. Compare the new PR's Vercel deployment URL against baseline using `workflow_dispatch`
2. Identify the hot path (check `PERFORMANCE_PROOF.md` optimization history)
3. Fix before merging; do not bump thresholds without a documented justification

## Running Locally

```bash
# Install k6 (macOS)
brew install k6

# Smoke test against local dev server
k6 run tests/k6/baseline.js \
  -e BASE_URL=http://localhost:3000 \
  -e API_KEY=ep_test_your_key \
  -e ENTITY_ID=your-entity-id

# Full staircase load test (requires staging)
k6 run tests/k6/baseline.js \
  -e BASE_URL=https://staging.emiliaprotocol.com \
  -e API_KEY="${EP_PERF_API_KEY}" \
  -e ENTITY_ID=perf-test-entity-001 \
  --vus 500 --duration 6m
```

## History

| Date | Version | p95 (handshake create) | Notes |
|------|---------|------------------------|-------|
| 2026-03-28 | EP/1.1-v2 | 87ms | Optimized (batch insert, connection pooler, Redis pipeline) |
| 2026-03-15 | EP/1.1-v1 | 420ms | Baseline before optimization (7 serial DB calls) |
