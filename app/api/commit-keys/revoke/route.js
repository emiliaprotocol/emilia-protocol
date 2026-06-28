// SPDX-License-Identifier: Apache-2.0
//
// POST /api/commit-keys/revoke — emergency commit SIGNING-KEY revocation (T6).
//
// @internal
// @access operator — per-operator HMAC token or legacy CRON_SECRET
//         (lib/operator-auth.js). NOT part of the public API.
//
// Commit signing keys live in env (EP_COMMIT_SIGNING_KEY + EP_COMMIT_SIGNING_KEYS),
// so there is no "rotate the env at runtime" call. The emergency response to a
// leaked/compromised key is to REVOKE its kid: once revoked, verifyCommit()
// rejects EVERY commit bearing that kid (reason: kid_revoked) regardless of an
// otherwise-valid signature, so a stolen key cannot continue to sustain
// authorizations.
//
// Operational runbook on suspected key compromise:
//   1. Generate a new keypair; set EP_COMMIT_SIGNING_KEY to the new seed and add
//      the new public key to EP_COMMIT_SIGNING_KEYS (new kid). Redeploy.
//   2. Re-issue any still-needed authorizations (they sign under the new kid).
//   3. POST here to revoke the OLD kid — old commits stop verifying immediately.
//
// Body: { "kid": "<compromised-kid>", "reason"?: "<free text>" }

export const runtime = 'nodejs';

import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { authenticateOperator } from '@/lib/operator-auth';
import { logger } from '@/lib/logger.js';

export async function POST(request) {
  const auth = authenticateOperator(request);
  if (!auth.valid) return epProblem(401, 'unauthorized', auth.error || 'Unauthorized');

  let body;
  try {
    body = await request.json();
  } catch {
    return epProblem(400, 'invalid_json', 'Body must be valid JSON');
  }

  const kid = typeof body?.kid === 'string' ? body.kid.trim() : '';
  if (!kid) return epProblem(400, 'missing_kid', 'kid is required');
  const reason = typeof body?.reason === 'string' ? body.reason.slice(0, 500) : null;

  const revoked_at = new Date().toISOString();
  const supabase = getGuardedClient();
  const { error } = await supabase
    .from('revoked_commit_keys')
    .upsert({ kid, reason, revoked_by: auth.operator_id, revoked_at }, { onConflict: 'kid' });

  if (error) {
    logger.error('[commit-keys/revoke] failed:', error);
    return epProblem(503, 'revoke_failed', 'Could not record key revocation');
  }

  // Loud by design — revoking a signing key is a high-consequence operation.
  logger.warn('[commit-keys/revoke] commit signing key REVOKED', { kid, operator: auth.operator_id });
  return NextResponse.json({ revoked: true, kid, revoked_at, revoked_by: auth.operator_id });
}
