import { NextResponse } from 'next/server';
import { checkRateLimit, getClientIP, RATE_LIMITS } from '@/lib/rate-limit';
import { siemEvent } from '@/lib/siem';

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

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const DEFAULT_API_BODY_LIMIT_BYTES = 1024 * 1024;
const MULTIPART_API_BODY_LIMIT_BYTES = 26 * 1024 * 1024; // 25 MB file + form overhead
const RELEASE_LOCK_BROWSER_MUTATIONS = Object.freeze([
  /^\/api\/v1\/release-locks\/invitations\/exchange$/,
  /^\/api\/v1\/release-locks\/pairings\/exchange$/,
  /^\/api\/v1\/release-locks\/[^/]+\/registration\/(?:options|verify)$/,
  /^\/api\/v1\/release-locks\/[^/]+\/rounds\/[^/]+\/(?:approvals|pairings)$/,
  /^\/api\/v1\/release-locks\/[^/]+\/rounds\/[^/]+\/action-check\/options$/,
]);

const ROUTE_POLICIES = {
  // Pilot-request intake (public lead form; honeypot + validation in route)
  'POST /api/pilot/request':          { rateCategory: 'submit', useAuth: false },
  'POST /api/pilot/sandbox/provision': { rateCategory: 'submit', useAuth: false },
  'GET /api/pilot/sandbox/report':     { rateCategory: 'read', useAuth: true },

  // SCIM 2.0 provisioning (RFC 7644). The IdP authenticates with an ep_scim_
  // bearer token; rate-limit per token + IP. Initial directory sync is bursty,
  // so creates use the write category. The token-mint route is gated by the
  // customer's EP API key.
  'POST /api/scim/v2/Users':                 { rateCategory: 'submit', useAuth: true },
  'PUT /api/scim/v2/Users/*':                { rateCategory: 'submit', useAuth: true },
  'PATCH /api/scim/v2/Users/*':              { rateCategory: 'submit', useAuth: true },
  'DELETE /api/scim/v2/Users/*':             { rateCategory: 'submit', useAuth: true },
  'POST /api/scim/v2/Groups':                { rateCategory: 'submit', useAuth: true },
  'PUT /api/scim/v2/Groups/*':               { rateCategory: 'submit', useAuth: true },
  'PATCH /api/scim/v2/Groups/*':             { rateCategory: 'submit', useAuth: true },
  'DELETE /api/scim/v2/Groups/*':            { rateCategory: 'submit', useAuth: true },
  'POST /api/scim/v2/provisioning-token':    { rateCategory: 'submit', useAuth: true },

  // Enterprise SSO (SAML 2.0 SP + OIDC RP). The ACS receives the IdP's signed
  // assertion (no EP key — the signature IS the authentication, verified
  // in-route); connection config is gated by the customer's EP API key.
  'POST /api/sso/saml/acs':                  { rateCategory: 'submit', useAuth: false },
  'POST /api/sso/connections':               { rateCategory: 'submit', useAuth: true },
  'DELETE /api/sso/session':                 { rateCategory: 'read', useAuth: false }, // logout — revoke this session's jti + clear cookie
  'POST /api/sso/session':                   { rateCategory: 'submit', useAuth: false }, // logout-all-devices — subject-wide cutoff
  // Emergency commit signing-key revocation (T6) — operator-authed in-route.
  'POST /api/commit-keys/revoke':            { rateCategory: 'submit', useAuth: false },

  // Trust evaluation. Rich evaluator/profile surfaces are auth-scoped to avoid
  // anonymous system mapping; only narrow public verification/capability surfaces
  // stay unauthenticated.
  'GET /api/trust/profile/*':          { rateCategory: 'read', useAuth: true },
  'POST /api/trust/evaluate':         { rateCategory: 'read', useAuth: true },
  'POST /api/trust/install-preflight': { rateCategory: 'read', useAuth: true },
  'POST /api/trust/gate':             { rateCategory: 'read', useAuth: true },
  'GET /api/trust/domain-score/*':     { rateCategory: 'read', useAuth: true },
  'POST /api/trust/zk-proof':         { rateCategory: 'dispute_write', useAuth: true },  // generates proof
  'GET /api/trust/zk-proof':          { rateCategory: 'read', useAuth: false },           // verify proof

  // Receipts (writes)
  'POST /api/receipts/submit':        { rateCategory: 'submit', useAuth: true },
  'POST /api/receipts/confirm':       { rateCategory: 'dispute_write', useAuth: true },   // bilateral confirm: sensitive write
  'POST /api/receipts/auto-submit':   { rateCategory: 'submit', useAuth: true },           // HIGH VOLUME

  // Entities
  'POST /api/entities/register':      { rateCategory: 'register', useAuth: false },        // no API key yet
  'GET /api/entities/search':         { rateCategory: 'read', useAuth: true },
  'POST /api/entities/*/auto-receipt': { rateCategory: 'dispute_write', useAuth: true },

  // Protocol-standard surfaces (singular, EP-RECEIPT-v1 / EP-IX vocabulary)
  'POST /api/entity':                 { rateCategory: 'register', useAuth: false },        // entity registration
  'POST /api/receipt':                { rateCategory: 'submit',   useAuth: true },         // receipt submission
  'GET /api/trust':                   { rateCategory: 'read',     useAuth: true },         // auth-scoped trust profile lookup
  'GET /api/discovery/keys':          { rateCategory: 'read',     useAuth: false },        // public well-known keys discovery
  'GET /api/stats':                   { rateCategory: 'read',     useAuth: true },
  'GET /api/leaderboard':             { rateCategory: 'read',     useAuth: true },
  'GET /api/feed':                    { rateCategory: 'read',     useAuth: true },

  // GovGuard + FinGuard product API (v1) — pre-execution trust receipts.
  // All v1 endpoints require auth (per MD §12.2.1: actor identity must come
  // from authenticated context, never request body alone).
  'POST /api/v1/trust-receipts':                   { rateCategory: 'submit', useAuth: true }, // create receipt (precheck + policy eval)
  'GET /api/v1/trust-receipts/*':                  { rateCategory: 'read',   useAuth: true }, // single-receipt lookup
  'POST /api/v1/trust-receipts/*/consume':         { rateCategory: 'submit', useAuth: true }, // one-time consume
  'POST /api/v1/trust-receipts/*/execution':       { rateCategory: 'submit', useAuth: true }, // post-mutation execution attestation
  'GET /api/v1/trust-receipts/*/evidence':         { rateCategory: 'read',   useAuth: true }, // evidence packet
  'POST /api/v1/rx-reliance/evaluate':             { rateCategory: 'submit', useAuth: true }, // Rx reliance verdict over a submitted packet (stateless, no PHI)
  'POST /api/v1/rx-reliance/profiles':             { rateCategory: 'submit', useAuth: true }, // content-hash pin of a relying-party reliance profile
  'POST /api/v1/signoffs/request':                 { rateCategory: 'submit', useAuth: true }, // request human signoff
  'POST /api/v1/signoffs/*/approve':               { rateCategory: 'submit', useAuth: true }, // approver acts
  'POST /api/v1/signoffs/*/reject':                { rateCategory: 'submit', useAuth: true }, // approver acts
  // Class A signoff (WebAuthn, docs/WEBAUTHN-SIGNOFF.md). The signing pair is
  // capability-URL + device assertion (no bearer key — the assertion IS the
  // authentication, verified in-route), so rate-limit by IP. Enrollment
  // requires an authenticated org-admin key (second-party attestation).
  'POST /api/v1/signoffs/*/webauthn-options':      { rateCategory: 'submit', useAuth: false }, // issue signing challenge
  'POST /api/v1/signoffs/*/approve-webauthn':      { rateCategory: 'submit', useAuth: false }, // device-key decision
  'POST /api/v1/approvers/webauthn/register-options': { rateCategory: 'submit', useAuth: true }, // begin passkey enrollment
  'POST /api/v1/approvers/webauthn/register-verify':  { rateCategory: 'submit', useAuth: true }, // complete enrollment

  // Native approval reference apps. Pairing creation and demo injection use
  // organization API keys. Pairing exchange is capability-code authenticated;
  // runtime routes authenticate an ep_mobile_ bearer token in-route and apply a
  // second, session-scoped limit after token verification. The edge limit is
  // deliberately IP-only so attacker-supplied bearer text cannot create free
  // rate-limit identities before authentication.
  'POST /api/v1/mobile/pairings':               { rateCategory: 'mobile_pairing', useAuth: true },
  'POST /api/v1/mobile/pairings/exchange':      { rateCategory: 'mobile_pairing', useAuth: false },
  'GET /api/v1/mobile/inbox':                   { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/mobile/challenges':             { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/mobile/ceremonies':             { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/mobile/enrollments/challenges': { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/mobile/enrollments':            { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'DELETE /api/v1/mobile/session':              { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/mobile/demo/actions':           { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/v1/mobile/executors':              { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/v1/mobile/actions/*/alignments':   { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/v1/mobile/actions/*/consume':      { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/v1/mobile/actions/*/outcomes':     { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/v1/mobile/actions/*/supersede':    { rateCategory: 'protocol_write', useAuth: true },
  'POST /api/v1/mobile/actions/*/withdraw':     { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/grace/curtailment/actions':      { rateCategory: 'protocol_write', useAuth: true },

  // Release Lock. Organization mutations authenticate an EP API key in-route.
  // Invitation/pairing exchanges are single-use capability authenticated.
  // Participant ceremonies use a host-only, SameSite=Strict session cookie,
  // then enforce lock + role + contact + optional round scope transactionally.
  'POST /api/v1/release-locks':                                   { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/release-locks/*/amendments':                      { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/release-locks/*/draw-release':                    { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/release-locks/invitations/exchange':              { rateCategory: 'mobile_pairing', useAuth: false },
  'POST /api/v1/release-locks/pairings/exchange':                 { rateCategory: 'mobile_pairing', useAuth: false },
  'POST /api/v1/release-locks/*/registration/options':            { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/release-locks/*/registration/verify':             { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/release-locks/*/rounds/*/action-check/options':   { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/release-locks/*/rounds/*/approvals':              { rateCategory: 'mobile_runtime_ip', useAuth: false },
  'POST /api/v1/release-locks/*/rounds/*/pairings':               { rateCategory: 'mobile_pairing', useAuth: false },
  'POST /api/internal/release-lock/reconcile':                    { rateCategory: null, useAuth: false },
  // GovGuard + FinGuard demo adapters (MD §8) — thin façades over
  // /api/v1/trust-receipts pre-filled for specific workflows. Same auth +
  // rate posture as the underlying create endpoint. All implemented via
  // lib/guard-adapter.runGuardPrecheck().
  'POST /api/v1/adapters/gov/benefit-bank-change/precheck':  { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/benefit-address-change/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/caseworker-override/precheck':  { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/vendor-payment-destination-change/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/disbursement-release/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/grant-disbursement/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/provider-enrollment-change/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/gov/eligibility-override/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/health/hospice-claim/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/health/hospice-claim/reconcile': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/fin/vendor-bank-change/precheck':   { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/fin/beneficiary-creation/precheck': { rateCategory: 'submit', useAuth: true },
  'POST /api/v1/adapters/fin/payment-release/precheck':      { rateCategory: 'submit', useAuth: true },

  // Public demo evidence endpoint — unauthenticated by design. Serves
  // ONLY the synthetic /r/example demo receipt (handler enforces this
  // via isDemoReceiptId). Production receipts still require auth via
  // /api/v1/trust-receipts/{id}/evidence above. The auth-required
  // production endpoint blocked the "verify yourself" code block on
  // /r/example for cold buyers — this gives them a working URL without
  // opening up real tenant evidence.
  'GET /api/demo/trust-receipts/*/evidence':       { rateCategory: 'read', useAuth: false },
  'POST /api/demo/require-receipt':                { rateCategory: 'read', useAuth: false },
  'POST /api/demo/x402':                           { rateCategory: 'read', useAuth: false },

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

  // Remote MCP server (streamable HTTP) — public read-only connector for
  // claude.ai / MCP Directory. JSON-RPC rides on POST, but every exposed tool
  // is a read or an in-process offline verification, so read-tier limits fit.
  'POST /api/mcp/*':                  { rateCategory: 'read', useAuth: false },
  'GET /api/mcp/*':                   { rateCategory: 'read', useAuth: false },
  'DELETE /api/mcp/*':                { rateCategory: 'read', useAuth: false },

  // Operations / Cron
  // Cron routes skip rate limiting (CRON_SECRET auth is sufficient)
  'POST /api/blockchain/anchor':      { rateCategory: null, useAuth: false },
  'GET /api/blockchain/anchor':       { rateCategory: null, useAuth: false },
  'POST /api/cron/expire':            { rateCategory: null, useAuth: false },
  'GET /api/cron/expire':             { rateCategory: null, useAuth: false },
  'POST /api/cron/collusion-scan':    { rateCategory: null, useAuth: false },   // operator-token gated in-route
  'GET /api/cron/collusion-scan':     { rateCategory: null, useAuth: false },

  // Public forms (no auth — open submission endpoints)
  'POST /api/operators/apply':        { rateCategory: 'submit', useAuth: false },
  'POST /api/inquiries':              { rateCategory: 'submit', useAuth: false },
  'POST /api/waitlist':               { rateCategory: 'waitlist', useAuth: false },
  'POST /api/checkout':               { rateCategory: 'submit', useAuth: false },
  'POST /api/v1/guarded':             { rateCategory: 'submit', useAuth: false },
  // EP-APPROVAL-v1 acquisition: creation uses the tenant-bound Cloud key;
  // polling uses a separate high-entropy capability and is IP-throttled again
  // in-route without placing that private capability in rate-limit telemetry.
  'POST /api/v1/approvals':           { rateCategory: 'cloud_write', useAuth: true },
  'GET /api/v1/approvals/*':          { rateCategory: 'mobile_runtime_ip', useAuth: false },

  // Cloud — scoring calibration
  'GET /api/cloud/scoring/recommendations': { rateCategory: 'cloud_read', useAuth: true },

  // Cloud — reads (dashboards, audit, events)
  'GET /api/cloud/signoff/pending':   { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/signoff/queue':     { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/signoff/dashboard': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/signoff/analytics': { rateCategory: 'cloud_read', useAuth: true },
  // Connected high-risk payment approval reference endpoint. Route-level
  // authorization additionally requires the named approval_request capability
  // (or admin) and binds every operation to the authenticated tenant/key.
  'GET /api/cloud/approvals':          { rateCategory: 'cloud_read',  useAuth: true },
  'POST /api/cloud/approvals':         { rateCategory: 'cloud_write', useAuth: true },
  'POST /api/cloud/approvals/*/consume': { rateCategory: 'cloud_write', useAuth: true },
  'GET /api/cloud/approvals/*/evidence': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/audit/export':      { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/audit/integrity':   { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/audit/report':      { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/evidence-readiness/runs': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/events/search':     { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/events/timeline/*': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/policies/*/versions': { rateCategory: 'cloud_read', useAuth: true },
  'GET /api/cloud/policies/*/diff':   { rateCategory: 'cloud_read', useAuth: true },

  // Cloud — writes (notifications, escalations, simulations)
  'POST /api/cloud/signoff/notify':   { rateCategory: 'cloud_write', useAuth: true },
  'POST /api/cloud/signoff/escalate': { rateCategory: 'cloud_write', useAuth: true },
  'POST /api/cloud/policies/*/simulate': { rateCategory: 'cloud_write', useAuth: true },

  // Cloud — admin (tenant credentials and policy rollouts)
  'POST /api/cloud/tenants/*/api-keys': { rateCategory: 'cloud_admin', useAuth: true },
  'GET /api/cloud/authorities/policy-rollout': { rateCategory: 'cloud_admin', useAuth: true },
  'POST /api/cloud/authorities/policy-rollout': { rateCategory: 'cloud_admin', useAuth: true },
  'POST /api/cloud/authorities/policy-rollout/*/revoke': { rateCategory: 'cloud_admin', useAuth: true },
  'POST /api/cloud/policies/*/rollout': { rateCategory: 'cloud_admin', useAuth: true },

  // Cloud — webhooks
  'GET /api/cloud/webhooks':            { rateCategory: 'cloud_read', useAuth: true },
  'POST /api/cloud/webhooks':           { rateCategory: 'cloud_write', useAuth: true },
  'GET /api/cloud/webhooks/*':          { rateCategory: 'cloud_read', useAuth: true },
  'PUT /api/cloud/webhooks/*':          { rateCategory: 'cloud_write', useAuth: true },
  'DELETE /api/cloud/webhooks/*':       { rateCategory: 'cloud_admin', useAuth: true },
  'POST /api/cloud/webhooks/*/test':    { rateCategory: 'cloud_write', useAuth: true },

  // AI Trust Desk — public intake form submission. No API key (like
  // /api/entities/register); IP-throttled because it triggers an LLM pipeline.
  'POST /api/trust-desk/intake':        { rateCategory: 'register', useAuth: false },
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
 * @returns {{ rateCategory: string|null, useAuth: boolean }}
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

/**
 * @param {import('next/server').NextRequest} request
 * @returns {string|null}
 */
function getApiKeyPrefix(request) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  // API keys are like ep_live_abc123... — use first 16 chars as identity
  return token ? token.slice(0, 16) : null;
}

/**
 * @param {import('next/server').NextRequest} request
 * @returns {number}
 */
function declaredApiBodyLimit(request) {
  const ctype = request.headers.get('content-type') || '';
  return ctype.includes('multipart/form-data')
    ? MULTIPART_API_BODY_LIMIT_BYTES
    : DEFAULT_API_BODY_LIMIT_BYTES;
}

/**
 * @param {number} limit
 */
function payloadTooLarge(limit) {
  return NextResponse.json(
    { error: 'Request body too large', code: 'payload_too_large', max_bytes: limit },
    { status: 413 },
  );
}

/**
 * @param {string} method
 * @param {string} pathname
 * @returns {boolean}
 */
function isReleaseLockBrowserMutation(method, pathname) {
  return method.toUpperCase() === 'POST'
    && RELEASE_LOCK_BROWSER_MUTATIONS.some((pattern) => pattern.test(pathname));
}

/**
 * @param {import('next/server').NextRequest} request
 * @returns {boolean}
 */
function releaseLockOriginAllowed(request) {
  const origin = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');
  if (!origin || origin === 'null' || (fetchSite && fetchSite !== 'same-origin')) {
    return false;
  }
  try {
    return new URL(origin).origin === request.nextUrl.origin;
  } catch {
    return false;
  }
}

/**
 * Global request-body cap for mutating API routes, enforced at the edge.
 *
 * Two layers, both fail-closed:
 *   1. Fast path — reject on a declared Content-Length over the cap without
 *      touching the stream.
 *   2. Stream path — a client can OMIT or understate Content-Length (chunked
 *      transfer), which slips past layer 1 and, on a self-hosted deploy with no
 *      reverse-proxy/platform cap, lets request.json() buffer an unbounded body
 *      into memory. We read a CLONE of the body and abort the moment the byte
 *      count exceeds the cap. The clone is independent of the original stream,
 *      so the downstream route handler still receives the intact request.
 *
 * @param {import('next/server').NextRequest} request
 * @returns {Promise<NextResponse|null>} a 413/400 response, or null to proceed.
 */
async function rejectOversizedApiBody(request) {
  if (!BODY_METHODS.has(request.method.toUpperCase())) return null;
  const limit = declaredApiBodyLimit(request);

  // Layer 1: declared Content-Length.
  const raw = request.headers.get('content-length');
  if (raw) {
    const length = Number(raw);
    if (!Number.isFinite(length) || length < 0) {
      return NextResponse.json(
        { error: 'Invalid Content-Length', code: 'invalid_content_length' },
        { status: 400 },
      );
    }
    if (length > limit) return payloadTooLarge(limit);
  }

  // Layer 2: byte-count the actual stream (covers chunked / absent / understated
  // Content-Length). Reading a clone leaves request.body intact for the handler.
  if (!request.body) return null;
  let reader;
  try {
    const clonedBody = request.clone().body;
    if (!clonedBody) return null;
    reader = clonedBody.getReader();
  } catch {
    // If the body can't be cloned we cannot safely enforce the stream cap here;
    // in-route readLimitedJson() remains the backstop. Do not fail the request.
    return null;
  }
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value?.byteLength || 0;
      if (total > limit) {
        reader.cancel().catch(() => {});
        return payloadTooLarge(limit);
      }
    }
  } catch {
    // A read error on the clone must not open the cap: fail closed only if we
    // already saw an over-limit count (handled above). A transient stream error
    // before the limit is reached falls through to the handler's own guard.
    return null;
  }
  return null;
}

// =============================================================================
// CSP nonce generator
// =============================================================================

/**
 * Build a per-request Content-Security-Policy header with a nonce.
 * The nonce replaces 'unsafe-inline' for script-src, satisfying the
 * HIGH-09 pentest finding while still supporting Next.js inline scripts.
 *
 * @param {string} nonce
 * @returns {string}
 */
function buildCSP(nonce) {
  // Development only: Next's dev runtime evaluates eval-source-maps, which a
  // nonce-only script-src blocks — hydration dies and every client component
  // is a dead button (bit the WebAuthn e2e). Production CSP is unchanged:
  // real builds don't eval. (HIGH-09 posture preserved where it matters.)
  const devEval = process.env.NODE_ENV === 'development' ? " 'unsafe-eval'" : '';
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${devEval}`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: blob:",
    "font-src 'self' https://fonts.gstatic.com",
    // connect-src wildcard `*.base.org` covers both mainnet.base.org and
    // sepolia.base.org without coupling the CSP to specific subdomains.
    // If blockchain config moves to a different chain, update both this
    // line and lib/blockchain.js BASE_CHAIN/BASE_SEPOLIA constants in
    // lockstep — silently dropping connect-src will block the browser
    // verifier without a console error visible to the operator.
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://*.base.org",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

// =============================================================================
// Middleware
// =============================================================================

/**
 * @param {import('next/server').NextRequest} request
 */
export async function middleware(request) {
  const { pathname } = request.nextUrl;

  // Phantom URLs that crawlers mis-extract from the rendered HTML and that were
  // never real links: /$ comes from React's streaming-SSR Suspense comment
  // markers (<!--/$-->), /& from an escaped inline code snippet
  // (<ep-trust-badge /&gt;). They correctly 404, but 410 Gone tells search
  // engines the URL is permanently gone so they drop it from coverage instead
  // of re-crawling. Exact match only — everything else falls through.
  if (pathname === '/$' || pathname === '/&') {
    return new NextResponse('410 Gone', {
      status: 410,
      headers: { 'content-type': 'text/plain', 'x-robots-tag': 'noindex' },
    });
  }

  // Non-API page requests: inject per-request nonce and CSP header.
  // The nonce is forwarded via x-nonce request header so server components
  // can read it (e.g. in app/layout.js) and pass it to <Script> tags.
  if (!pathname.startsWith('/api/')) {
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-nonce', nonce);
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set('Content-Security-Policy', buildCSP(nonce));
    if (pathname === '/cloud' || pathname.startsWith('/cloud/')) {
      response.headers.set('X-Robots-Tag', 'noindex, nofollow');
    }
    return response;
  }

  if (isReleaseLockBrowserMutation(request.method, pathname)
      && !releaseLockOriginAllowed(request)) {
    const response = NextResponse.json(
      {
        error: 'Release Lock browser mutations require a same-origin request.',
        code: 'release_lock_origin_denied',
      },
      { status: 403 },
    );
    response.headers.set('cache-control', 'no-store');
    return response;
  }

  const bodyLimitResponse = await rejectOversizedApiBody(request);
  if (bodyLimitResponse) return bodyLimitResponse;

  // Cloud routes: enforce origin allowlist to prevent cross-origin reads from
  // arbitrary websites. Public protocol routes intentionally have no CORS restriction.
  if (pathname.startsWith('/api/cloud/')) {
    const origin = request.headers.get('origin');
    if (origin) {
      // ALLOWED_ORIGINS is read directly here rather than via lib/env.js
      // because middleware.js runs in the Edge runtime and lib/env.js
      // pulls in pino via lib/logger.js, which is Node-only. The
      // protocol-discipline rule scopes "no direct process.env" to
      // EP_-prefixed keys; non-EP keys (CORS allowlist, NODE_ENV, etc.)
      // are unavoidable in edge code.
      const allowedOrigins = process.env.ALLOWED_ORIGINS
        ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
        : [];

      // Same-origin requests are always allowed: the browser sends an Origin
      // header on cross-site AND many same-site requests, so compare the
      // Origin's host to the request host rather than treating any Origin as
      // cross-origin. The app's own /cloud dashboard hitting /api/cloud/* is
      // same-origin and must never be blocked.
      let sameOrigin = false;
      try {
        sameOrigin = new URL(origin).host === request.headers.get('host');
      } catch {
        sameOrigin = false;
      }

      if (!sameOrigin) {
        if (allowedOrigins.length > 0) {
          // Explicit allowlist configured: deny anything not on it.
          if (!allowedOrigins.includes(origin)) {
            return NextResponse.json(
              { error: 'Origin not allowed', code: 'cors_denied' },
              { status: 403 }
            );
          }
        } else if (process.env.NODE_ENV === 'production') {
          // FAIL CLOSED: in production with no ALLOWED_ORIGINS configured, a
          // cross-origin request to the tenant cloud API is denied. Previously
          // this fell open (allow-all), letting any website read cloud data
          // whenever the operator forgot to set the allowlist. Dev keeps the
          // permissive path below so local tooling isn't blocked.
          return NextResponse.json(
            { error: 'Cross-origin requests are not permitted', code: 'cors_denied' },
            { status: 403 }
          );
        }
        // Development with no allowlist: fall through (permissive for local dev).
      }
    }
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

    const config = RATE_LIMITS[/** @type {keyof typeof RATE_LIMITS} */ (rateCategory)];
    // SIEM: rate limit exceeded — high severity for write categories
    siemEvent('RATE_LIMIT_EXCEEDED', {
      category: rateCategory,
      key: rateLimitKey.slice(0, 16), // truncate to avoid logging full key prefix
      pathname,
      method: request.method,
    });
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
  response.headers.set('X-RateLimit-Limit', String(RATE_LIMITS[/** @type {keyof typeof RATE_LIMITS} */ (rateCategory)].max));
  response.headers.set('X-RateLimit-Remaining', String(result.remaining));
  response.headers.set('X-RateLimit-Reset', String(result.reset));
  return response;
}

export const config = {
  matcher: [
    // Always run API middleware, even if a future API path contains an extension
    // excluded by the page/static matcher below.
    '/api/:path*',
    // Apply to all routes: page routes get nonce-based CSP; API routes get rate limiting.
    // Exclude Next.js internals and static files.
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
