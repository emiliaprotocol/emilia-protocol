import { NextResponse } from 'next/server';
import { protocolWrite, COMMAND_TYPES, ProtocolWriteError } from '@/lib/protocol-write';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * POST /api/commit/verify
 *
 * Verify a commit's validity. Public — any relying system can call this
 * to check whether a commit is still valid before acting on it.
 *
 * Accepts { commit_id }. Verification is by commit_id against the
 * authoritative DB record (signature, status, expiry, nonce replay).
 * Token-level verification (offline) is planned for v2.
 *
 * Returns a verdict (valid/invalid + status), NOT the full commit payload.
 * The verifier gets a decision, not a window into the commit details.
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.commit_id) {
      return epProblem(400, 'missing_commit_id', 'Provide commit_id');
    }

    const result = await protocolWrite({
      type: COMMAND_TYPES.VERIFY_COMMIT,
      actor: 'public',
      input: { commit_id: body.commit_id },
    });

    // Minimum disclosure per PROTOCOL-STANDARD.md Section 18.4:
    // Verification MUST NOT expose the full commit payload — no scope,
    // no entity_id, no action_type, no context beyond validity.
    return NextResponse.json({
      valid: result.valid,
      status: result.status,
      decision: result.decision,
      expires_at: result.expires_at,
      reasons: result.reasons || [],
    });
  } catch (err) {
    if (err instanceof ProtocolWriteError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    logger.error('Commit verify error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
