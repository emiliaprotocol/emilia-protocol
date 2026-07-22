// SPDX-License-Identifier: Apache-2.0
//
// Continuous object-level-authorization sweep (regression guard).
//
// The 2026-07 authorization sweep found the recurring class was "authenticated
// but not authorized for the specific object" — a route that loads a resource by
// a URL path segment and acts on it without confirming the caller owns / is a
// party to / is in the tenant of that resource. Those were fixed one by one.
// This test makes the invariant CONTINUOUS: every dynamic-segment route under
// app/api MUST either carry an authorization signal, or be on a reviewed
// PUBLIC_BY_DESIGN allowlist. A new [id] route with neither fails CI, so the
// class cannot silently regress.
//
// This is a static, dependency-free heuristic — it proves an authz *gate is
// present*, not that it is *correct* (correctness is the adversarial sweep's
// job). Its value is catching the "someone added a [id] route with no gate at
// all" regression, which is exactly what produced the worst findings.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const API_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../app/api');

// Signals that a handler performs SOME object/tenant/role authorization. Presence
// is necessary, not sufficient — but absence on a resource route is the smell.
const AUTHZ_SIGNALS = [
  'authEntityId',            // caller stable id, used in ownership comparisons
  'auth.tenantId',           // cloud multi-tenant scoping
  'requirePermission',       // cloud RBAC
  'requireScimAuth',         // SCIM tenant-scoped token
  'authenticateOperator',    // named-operator gate
  'authorizeCommit',         // commit-auth helper (issuer/principal)
  'authorizeHandshake',      // handshake-party helper
  'hasPermission',           // procedural-justice role gate
  'is_operator',             // operator bypass check paired with owner check
  '.eq(\'tenant_id\'',       // explicit tenant-scoped query
  '.eq("tenant_id"',
  'organization_id',         // org-scoped query
  'handshake_parties',       // party-membership lookup
  'accountable_actor_ref',   // signoff actor binding
  'claimed_by',              // needs claimant gate
  'from_entity_id',          // needs owner gate
  'auth.entity.entity_id',   // direct ownership comparison (commit/receipt, auto-receipt)
  // Lib delegators that each enforce actor-binding (verified in the 2026-07
  // adversarial sweep): a thin route that hands the authenticated actor to one
  // of these is gated inside the helper, not in the route file.
  'handleSignoffDecision',   // guard-signoff.js: authEntityId + SoD (v1 signoffs)
  'createAttestation',       // signoff/attest.js: actor === accountable_actor_ref
  'consumeSignoff',          // signoff/consume.js: actor === human_entity_ref
  'denyChallenge',           // signoff/deny.js: actor === accountable_actor_ref
  'revokeChallenge',         // signoff/revoke.js: actor-bound
  'revokeAttestation',       // signoff/revoke.js: actor-bound
  'authenticateMobileToken', // mobile/store.js: active session plus entity, approver, app, and device scope
  'authenticateApprovalPollCapability', // EP-APPROVAL private bearer capability, hashed before exact request lookup
  'authenticateReleaseLockOrg', // Release Lock org + authenticated entity binding
  'releaseLockSessionCookie',   // host-only strict cookie; SQL binds lock + role + contact + optional round
];

// Reviewed public-by-design routes: intentionally unauthenticated OR intentionally
// broad, verified during the 2026-07 sweep. Each entry is a deliberate decision,
// not an oversight. Adding to this list is the explicit way to declare "public".
const PUBLIC_BY_DESIGN = new Set([
  'app/api/verify/[receiptId]/route.ts',              // public receipt verifier — explicit projection, no secret cols
  'app/api/disputes/[disputeId]/route.ts',            // public dispute transparency — redacted view
  'app/api/trust-desk/verify/[slug]/route.ts',        // buyer-facing verification page
  'app/api/trust-desk/status/[engagementId]/route.ts',// sanitized status behind a 96-bit capability id
  'app/api/delegations/[delegationId]/verify/route.ts',// public offline delegation spot-check
  'app/api/commit/[commitId]/route.ts',               // has authorizeCommitAccess (matched below too, belt+suspenders)
  'app/api/mcp/[transport]/route.ts',                 // public read-only MCP connector (4 verify tools)
  'app/api/identity/lineage/[entityId]/route.ts',     // owner/operator gated (matched below); listed as reviewed
  'app/api/r/[receiptId]/page.js',                    // public share page (not under api but guard scans api only)
  'app/api/badge/[entity]/route.ts',                  // public capability badge — boolean only, never a score/secret
  'app/api/demo/crash/[scenarioId]/route.ts',         // public, unauthenticated crash-test demo (self-signed sandbox)
  'app/api/score/[entityId]/route.ts',                // RETIRED — returns HTTP 410 Gone (score surface removed)
  'app/api/score/[entityId]/history/route.ts',        // RETIRED — returns HTTP 410 Gone
]);

// Match PUBLIC_BY_DESIGN regardless of route.js vs route.ts so this list doesn't
// need a lockstep edit every time a listed route is converted during the TS migration.
const PUBLIC_BY_DESIGN_NORMALIZED = new Set(
  Array.from(PUBLIC_BY_DESIGN, (p) => p.replace(/\.(js|ts)$/, ''))
);
function isPublicByDesign(rel) {
  return PUBLIC_BY_DESIGN_NORMALIZED.has(rel.replace(/\.(js|ts)$/, ''));
}

function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name === 'route.js' || e.name === 'route.ts') out.push(p);
  }
  return out;
}

// A route is "resource-bearing" if any path segment is a [dynamic] param — those
// are the IDOR-prone routes the invariant targets. Collection routes (no [param])
// are out of scope for object-level auth (they have their own tenant/list scoping).
function isDynamic(relPath) {
  return /\[[^\]]+\]/.test(relPath);
}

describe('object-authorization sweep — every dynamic route is gated or reviewed-public', () => {
  const files = walk(API_DIR)
    .map((f) => path.relative(path.resolve(API_DIR, '../..'), f))
    .filter(isDynamic)
    .sort();

  it('finds the dynamic route surface (sanity: the sweep scope is non-empty)', () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it.each(files)('%s carries an authorization gate or is reviewed-public', (rel) => {
    if (isPublicByDesign(rel)) return; // explicit, reviewed decision
    const src = fs.readFileSync(path.resolve(API_DIR, '../..', rel), 'utf8');
    const hasGate = AUTHZ_SIGNALS.some((sig) => src.includes(sig));
    expect(
      hasGate,
      `${rel} is a dynamic-segment (resource) route with NO authorization signal and is not on the reviewed PUBLIC_BY_DESIGN allowlist. ` +
      `Add an ownership/tenant/role check, or (if intentionally public) add it to PUBLIC_BY_DESIGN with a one-line rationale.`,
    ).toBe(true);
  });
});
