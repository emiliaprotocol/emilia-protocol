/**
 * EMILIA Protocol — k6 Staircase Load Test
 *
 * Purpose: Validate SLOs hold under sustained ramp-up to 500 VUs.
 * Documents that the "87ms p95 at 500 VUs" claim in README/BENCHMARK_BASELINE.md
 * is reproducible from CI or manual runs.
 *
 * Run on a schedule (nightly via .github/workflows/k6.yml) rather than on
 * every commit to avoid excess load on staging.
 *
 * Usage:
 *   k6 run tests/k6/staircase.js \
 *     -e BASE_URL=https://staging.emiliaprotocol.ai \
 *     -e API_KEY=ep_staging_...  \
 *     -e ENTITY_ID=bench-entity-001
 *
 * Required env:
 *   BASE_URL   - Target environment base URL (no trailing slash)
 *   API_KEY    - Valid EP API key for authenticated endpoints
 *   ENTITY_ID  - Entity ID pre-registered in the target environment
 *
 * Staircase profile:
 *   Step 1:  10 VUs  × 60s  — warmup / connection pool fill
 *   Step 2:  50 VUs  × 60s
 *   Step 3: 100 VUs  × 60s
 *   Step 4: 200 VUs  × 90s
 *   Step 5: 500 VUs  × 120s  ← peak; this is the "500 VU" claim checkpoint
 *   Step 6: 100 VUs  × 30s   — cooldown (verify no tail latency spike)
 *   Total wall time: ~7 minutes
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// SLO thresholds — must hold across the entire test including the 500-VU peak
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    staircase: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 10  },  // ramp to step 1
        { duration: '60s', target: 10  },  // hold step 1
        { duration: '10s', target: 50  },  // ramp to step 2
        { duration: '60s', target: 50  },  // hold step 2
        { duration: '10s', target: 100 },  // ramp to step 3
        { duration: '60s', target: 100 },  // hold step 3
        { duration: '10s', target: 200 },  // ramp to step 4
        { duration: '90s', target: 200 },  // hold step 4
        { duration: '15s', target: 500 },  // ramp to peak
        { duration: '120s', target: 500 }, // hold peak — 500 VU checkpoint
        { duration: '10s', target: 100 },  // step down
        { duration: '30s', target: 100 },  // cooldown
        { duration: '5s',  target: 0   },  // ramp down
      ],
    },
  },
  thresholds: {
    // Handshake creation (protocol write) — hot path SLO
    'http_req_duration{route:handshake_create}': [
      'p(95)<150',   // 95th percentile < 150ms (SLO)
      'p(99)<400',   // 99th percentile < 400ms (budget)
    ],
    // Trust evaluation (read) — must stay fast under all load
    'http_req_duration{route:trust_evaluate}': [
      'p(95)<100',   // 95th percentile < 100ms
      'p(99)<250',
    ],
    // Trust profile read (database lookup)
    'http_req_duration{route:trust_profile}': [
      'p(95)<200',
    ],
    // Global error rate
    'http_req_failed': ['rate<0.01'],  // <1% errors across all requests
    // Handshake-specific error counter
    'handshake_errors': ['count<50'],  // Fewer than 50 absolute failures at peak
  },
};

// ---------------------------------------------------------------------------
// Custom metrics for step-level observability
// ---------------------------------------------------------------------------

const handshakeErrors  = new Counter('handshake_errors');
const trustEvalErrors  = new Counter('trust_eval_errors');
const p95Handshake     = new Trend('p95_handshake_latency');
const p95TrustEval     = new Trend('p95_trust_eval_latency');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL  = __ENV.BASE_URL   || 'http://localhost:3000';
const API_KEY   = __ENV.API_KEY    || 'ep_test_key';
const ENTITY_ID = __ENV.ENTITY_ID  || 'bench-entity-001';

const AUTH_HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type':  'application/json',
};

const READ_HEADERS = {
  'Content-Type': 'application/json',
};

function randomNonce() {
  return `k6-staircase-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

function randomResponder() {
  const ids = ['responder-a', 'responder-b', 'responder-c', 'responder-d'];
  return ids[Math.floor(Math.random() * ids.length)];
}

// ---------------------------------------------------------------------------
// Default scenario function
// ---------------------------------------------------------------------------

export default function () {
  // ── 1. Trust evaluation — read path, should scale well ─────────────────
  const evalRes = http.post(
    `${BASE_URL}/api/trust/evaluate`,
    JSON.stringify({ entity_id: ENTITY_ID, policy: 'standard' }),
    { headers: READ_HEADERS, tags: { route: 'trust_evaluate' } },
  );

  const evalOk = check(evalRes, {
    'trust evaluate 200': (r) => r.status === 200,
    'trust evaluate has decision': (r) => {
      try { return JSON.parse(r.body).decision !== undefined; } catch { return false; }
    },
  });

  if (!evalOk) trustEvalErrors.add(1);
  p95TrustEval.add(evalRes.timings.duration);

  sleep(0.05);

  // ── 2. Trust profile read — DB lookup ──────────────────────────────────
  http.get(
    `${BASE_URL}/api/trust/profile/${ENTITY_ID}`,
    { headers: READ_HEADERS, tags: { route: 'trust_profile' } },
  );

  sleep(0.05);

  // ── 3. Handshake initiation — protocol write, the hot path claim ────────
  const hsRes = http.post(
    `${BASE_URL}/api/handshake`,
    JSON.stringify({
      initiator_id:  ENTITY_ID,
      responder_id:  randomResponder(),
      nonce:         randomNonce(),
      policy_id:     'policy-staircase-bench',
    }),
    { headers: AUTH_HEADERS, tags: { route: 'handshake_create' } },
  );

  const hsOk = check(hsRes, {
    'handshake initiate 200 or 201': (r) => r.status === 200 || r.status === 201,
    'handshake has handshake_id': (r) => {
      try { return JSON.parse(r.body).handshake_id !== undefined; } catch { return false; }
    },
  });

  if (!hsOk) handshakeErrors.add(1);
  p95Handshake.add(hsRes.timings.duration);

  // Variable think-time: simulate realistic client pacing, avoids thundering herd
  sleep(0.1 + Math.random() * 0.2);
}

// ---------------------------------------------------------------------------
// Per-stage summary (printed at end of test)
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const hs  = data.metrics['http_req_duration{route:handshake_create}'];
  const tev = data.metrics['http_req_duration{route:trust_evaluate}'];

  const summary = {
    test: 'staircase-500vu',
    timestamp: new Date().toISOString(),
    slos: {
      handshake_create_p95_ms:   hs?.values?.['p(95)']  ?? 'N/A',
      handshake_create_p99_ms:   hs?.values?.['p(99)']  ?? 'N/A',
      trust_evaluate_p95_ms:     tev?.values?.['p(95)'] ?? 'N/A',
      error_rate_pct:            ((data.metrics.http_req_failed?.values?.rate ?? 0) * 100).toFixed(2) + '%',
    },
    thresholds_passed: Object.entries(data.thresholds ?? {})
      .filter(([, v]) => v.ok)
      .map(([k]) => k),
    thresholds_failed: Object.entries(data.thresholds ?? {})
      .filter(([, v]) => !v.ok)
      .map(([k]) => k),
  };

  return {
    stdout: JSON.stringify(summary, null, 2) + '\n',
    'tests/k6/staircase-results.json': JSON.stringify(summary, null, 2),
  };
}
