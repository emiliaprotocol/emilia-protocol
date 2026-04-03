import { NextResponse } from 'next/server';
import { checkRateLimit, getClientIP, RATE_LIMITS } from '@/lib/rate-limit';

/**
 * EMILIA Protocol — API Rate Limiting Middleware
 *
 * Write routes: throttled by API key prefix + IP (identity-aware)
 * Read routes:  throttled by IP only
 * Register:     throttled by IP only (no API key yet)
 */

// =============================================================================
// Route Policy Table — single source of truth for route classification.
// Every mutating endpoint MUST be listed here.
// Unlisted routes default to 'read'.
//
// `rateCategory` maps to a key in RATE_LIMITS (lib/rate-limit.js).
// `useAuth` means the rate-limit key includes the API key prefix + IP.
// =============================================================================

const ROUTE_POLICIES = {
  // Trust evaluation (reads)
  'GET /api/trust/profile/*':          { rateCategory: 'read', useAuth: false },
  'POST /api/trust/evaluate':         { rateCategory: 'read', useAuth: false },   // evaluation is a read
  'POST /api/trust/install-preflight': { rateCategory: 'read', useAuth: false },
  'POST /api/trust/gate':             { rateCategory: 'read', useAuth: true },
  'GET /api/trust/domain-score/*':     { rateCategory: 'read', useAuth: false },
  'POST /api/trust/zk-proof':         { rateCategory: 'dispute_write', useAuth: true },  // generates proof
  'GET /api/trust/zk-proof':          { rateCategory: 'read', useAuth: false },           // verify proof

  // Receipts (writes)
  'POST /api/receipts/submit':        { rateCategory: 'submit', useAuth: true },
  'POST /api/receipts/confirm':       { rateCategory: 'dispute_write', useAuth: true },   // bilateral confirm: sensitive write
  'POST /api/receipts/auto-submit':   { rateCategory: 'submit', useAuth: true },           // HIGH VOLUME

  // Entities
  'POST /api/entities/register':      { rateCategory: 'register', useAuth: false },        // no API key yet
  'GET /api/entities/search':         { rateCategory: 'read', useAuth: false },
  'POST /api/entities/*/auto-receipt': { rateCategory: 'dispute_write', useAuth: true },

  // Disputes (writes)
  'POST /api/disputes/file':          { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/disputes/respond':       { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/disputes/resolve':       { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/disputes/report':        { rateCategory: 'report_write', useAuth: true },
  'POST /api/disputes/appeal':        { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/disputes/appeal/resolve': { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/disputes/withdraw':      { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/disputes/*/adjudicate':  { rateCategory: 'dispute_write', useAuth: true },

  // Delegations (writes)
  'POST /api/delegations/create':     { rateCategory: 'dispute_write', useAuth: true },
  'GET /api/delegations/*/verify':    { rateCategory: 'read', useAuth: false },

  // Keys (writes)
  'POST /api/keys/rotate':            { rateCategory: 'dispute_write', useAuth: true },

  // Identity (writes)
  'POST /api/identity/bind':          { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/identity/continuity':    { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/identity/continuity/challenge': { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/identity/continuity/resolve':   { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/identity/verify':        { rateCategory: 'dispute_write', useAuth: true },

  // Needs (writes)
  'POST /api/needs/broadcast':        { rateCategory: 'submit', useAuth: true },
  'POST /api/needs/*/claim':          { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/needs/*/complete':       { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/needs/*/rate':           { rateCategory: 'submit', useAuth: true },

  // Commits (pre-action authorization)
  'POST /api/commit/issue':           { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/commit/verify':          { rateCategory: 'read', useAuth: false },
  'GET /api/commit/*':                { rateCategory: 'read', useAuth: true },
  'POST /api/commit/*/revoke':        { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/commit/*/receipt':       { rateCategory: 'dispute_write', useAuth: true },
  'POST /api/commit/*/dispute':       { rateCategory: 'dispute_write', useAuth: true },

  // Signoff (EP Signoff — accountable human sign-off ceremony)
  // Write routes use protocol_write (60/min per key), same as handshake.
  // GET challenge uses read; all mutations require auth-scoped rate limiting.
  'POST /api/signoff/challenge':              { rateCategory: 'protocol_write', useAuth: true },
  'GET /api/signoff/*':                       { rateCategory: 'read', useAuth: true },
  'POST /api/signoff/*/attest':               { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/signoff/*/consume':              { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/signoff/*/deny':                 { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/signoff/*/revoke':               { rateCategory: 'protocol_write', useAuth: true },

  // Handshake (EP Handshake — structured identity exchange)
  // Write routes use protocol_write (60/min per key) — previously null which created a DoS vector.
  // DB-level idempotency on present/verify is not a substitute for rate limiting on creation.
  'POST /api/handshake':              { rateCategory: 'protocol_write', useAuth: true },
  'GET /api/handshake':               { rateCategory: 'read', useAuth: true },
  'GET /api/handshake/*':             { rateCategory: 'read', useAuth: true },
  'POST /api/handshake/*/present':    { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/handshake/*/verify':     { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/handshake/*/revoke':     { rateCategory: 'protocol_write', useAuth: true },

  // Operations / Cron
  // Cron routes skip rate limiting (CRON_SECRET auth is sufficient)
  'POST /api/blockchain/anchor':      { rateCategory: null, useAuth: false },
  'GET /api/blockchain/anchor':       { rateCategory: null, useAuth: false },
  'POST /api/cron/expire':            { rateCategory: null, useAuth: false },
  'GET /api/cron/expire':             { rateCategory: null, useAuth: false },

  // Public forms (no auth — open submission endpoints)
  'POST /api/operators/apply':        { rateCategory: 'submit', useAuth: false },
  'POST /api/inquiries':              { rateCategory: 'submit', useAuth: false },
  'POST /api/waitlist':               { rateCategory: 'waitlist', useAuth: false },

  // Cloud — scoring calibration
  'GET /api/cloud/scoring/recommendations': { rateCategory: 'cloud_read', useAuth: true },

  // Cloud — reads (dashboards, audit, events)
  'GET /api/cloud/signoff/pending':   { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/signoff/queue':     { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/signoff/dashboard': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/signoff/analytics': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/audit/export':      { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/audit/integrity':   { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/audit/report':      { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/events/search':     { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/events/timeline/*': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/policies/*/versions': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/policies/*/diff':   { rateCategory: 'cloud_read', useAuth: true },

  // Cloud — writes (notifications, escalations, simulations)
  'POST /api/cloud/signoff/notify':   { rateCategory: 'cloud_write', useAuth: true },
  'POST /api/cloud/signoff/escalate': { rateCategory: 'cloud_write', useAuth: true },
  'POST /api/cloud/policies/*/simulate': { rateCategory: 'cloud_write', useAuth: true },

  // Cloud — admin (policy rollouts)
  'POST /api/cloud/policies/*/rollout': { rateCategory: 'cloud_admin', useAuth: true },

  // Cloud — webhooks
  'GET /api/cloud/webhooks':            { rateCategory: 'cloud_read', useAuth: true },
  'POST /api/cloud/webhooks':           { rateCategory: 'cloud_write', useAuth: true },
  'GET /api/cloud/webhooks/*':          { rateCategory: 'cloud_read', useAuth: true },
  'PUT /api/cloud/webhooks/*':          { rateCategory: 'cloud_write', useAuth: true },
  'DELETE /api/cloud/webhooks/*':       { rateCategory: 'cloud_admin', useAuth: true },
  'POST /api/cloud/webhooks/*/test':    { rateCategory: 'cloud_write', useAuth: true },
};

// =============================================================================
// Route classifier — matches METHOD + pathname against the policy table.
// Supports '*' wildcards for dynamic path segments.
// =============================================================================

// Pre-compile patterns into regexes for fast matching
const _compiledPolicies = Object.entries(ROUTE_POLICIES).map(([pattern, policy]) => {
  const spaceIdx = pattern.indexOf(' ');
  const method = pattern.slice(0, spaceIdx);
  const pathPattern = pattern.slice(spaceIdx + 1);

  // Convert '/api/entities/*/auto-receipt' -> /^\/api\/entities\/[^/]+\/auto-receipt$/
  const regexStr = '^' + pathPattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]+') + '$';
  return { method, regex: new RegExp(regexStr), policy };
});

/**
 * Classify a route by method + pathname against the policy table.
 *
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @param {string} pathname - URL pathname (e.g. /api/receipts/submit)
 * @returns {{ rateCategory: string, useAuth: boolean }}
 */
function classifyRoute(method, pathname) {
  const upperMethod = method.toUpperCase();
  for (const { method: m, regex, policy } of _compiledPolicies) {
    if (m === upperMethod && regex.test(pathname)) {
      return policy;
    }
  }

  // Default: unmatched routes get 'read'
  // Warn on unmatched mutating methods — potential missing classification
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod)) {
    console.warn(
      `[rate-limit] Unclassified write route: ${upperMethod} ${pathname} — defaulting to 'read'. ` +
      `Add this route to ROUTE_POLICIES in middleware.js.`
    );
  }

  return { rateCategory: 'read', useAuth: false };
}

// =============================================================================
// Auth helper
// =============================================================================

function getApiKeyPrefix(request) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  // API keys are like ep_live_abc123... — use first 16 chars as identity
  return token ? token.slice(0, 16) : null;
}

// =============================================================================
// CSP nonce generator
// =============================================================================

/**
 * Build a per-request Content-Security-Policy header with a nonce.
 * The nonce replaces 'unsafe-inline' for script-src, satisfying the
 * HIGH-09 pentest finding while still supporting Next.js inline scripts.
 */
function buildCSP(nonce) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: blob:",
    "font-src 'self' https://fonts.gstatic.com",
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://mainnet.base.org https://sepolia.base.org",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

// =============================================================================
// Middleware
// =============================================================================

export async function middleware(request) {
  const { pathname } = request.nextUrl;

  // Non-API page requests: inject per-request nonce and CSP header.
  // The nonce is forwarded via x-nonce request header so server components
  // can read it (e.g. in app/layout.js) and pass it to <Script> tags.
  if (!pathname.startsWith('/api/')) {
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-nonce', nonce);
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set('Content-Security-Policy', buildCSP(nonce));
    return response;
  }

  const { rateCategory, useAuth } = classifyRoute(request.method, pathname);

  // Protocol routes (rateCategory: null) skip middleware rate limiting entirely.
  // They rely on auth + DB-level idempotency instead, saving an Upstash roundtrip (~80ms).
  if (rateCategory === null) {
    return NextResponse.next();
  }

  const ip = getClientIP(request);

  // For authenticated write routes, use API key prefix + IP as rate limit key.
  let rateLimitKey = ip;
  if (useAuth) {
    const keyPrefix = getApiKeyPrefix(request);
    if (keyPrefix) {
      rateLimitKey = `${keyPrefix}:${ip}`;
    }
  }

  const result = await checkRateLimit(rateLimitKey, rateCategory);

  if (!result.allowed) {
    // Distinguish between rate-limited and rate-limiter-unavailable (fail-closed)
    if (result.error === 'rate_limit_unavailable') {
      return NextResponse.json(
        { error: 'Service temporarily unavailable — rate limiting backend offline', retry_after: 60 },
        { status: 503 }
      );
    }

    const config = RATE_LIMITS[rateCategory];
    const res = NextResponse.json(
      {
        error: 'Rate limit exceeded',
        limit: config.max,
        window_seconds: config.window,
        retry_after: result.reset,
      },
      { status: 429 }
    );
    res.headers.set('X-RateLimit-Limit', String(config.max));
    res.headers.set('X-RateLimit-Remaining', '0');
    res.headers.set('X-RateLimit-Reset', String(result.reset));
    res.headers.set('Retry-After', String(result.reset));
    return res;
  }

  const response = NextResponse.next();
  response.headers.set('X-RateLimit-Limit', String(RATE_LIMITS[rateCategory].max));
  response.headers.set('X-RateLimit-Remaining', String(result.remaining));
  response.headers.set('X-RateLimit-Reset', String(result.reset));
  return response;
}

export const config = {
  matcher: [
    // Apply to all routes: page routes get nonce-based CSP; API routes get rate limiting.
    // Exclude Next.js internals and static files.
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
