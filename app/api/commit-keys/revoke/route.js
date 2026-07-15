// SPDX-License-Identifier: Apache-2.0
//
// POST /api/commit-keys/revoke — emergency commit SIGNING-KEY revocation (T6).
//
// @internal
// @access operator — named per-operator HMAC token once EP_OPERATOR_KEYS is
//         configured; legacy CRON_SECRET is migration-only. NOT public.
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
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '@/lib/logger.js';

const MAX_BODY_BYTES = 32 * 1024;

export async function POST(request) {
  const auth = authenticateOperator(request, { requireOperatorIdentity: true });
  if (!auth.valid) return epProblem(401, 'unauthorized', auth.error || 'Unauthorized');

  const parsed = await readEpJson(request, MAX_BODY_BYTES);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const kid = typeof body?.kid === 'string' ? body.kid.trim() : '';
  if (!kid) return epProblem(400, 'missing_kid', 'kid is required');
  const reason = typeof body?.reason === 'string' ? body.reason.slice(0, 500) : null;

  const supabase = getGuardedClient();
  const { data, error } = await supabase.rpc('revoke_commit_key_atomic', {
    p_kid: kid,
    p_reason: reason,
    p_revoked_by: auth.operator_id,
  });

  if (error) {
    logger.error('[commit-keys/revoke] failed:', error);
    return epProblem(503, 'revoke_failed', 'Could not record key revocation');
  }

  // Loud by design — revoking a signing key is a high-consequence operation.
  const revoked_at = data?.[0]?.revoked_at || data?.revoked_at;
  if (!revoked_at) {
    logger.error('[commit-keys/revoke] RPC returned no revocation record');
    return epProblem(503, 'revoke_failed', 'Could not record key revocation');
  }

  logger.warn('[commit-keys/revoke] commit signing key REVOKED', { kid, operator: auth.operator_id });
  return NextResponse.json({ revoked: true, kid, revoked_at, revoked_by: auth.operator_id });
}
