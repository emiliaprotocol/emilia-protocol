import { NextResponse } from 'next/server';
import { verifyCommit } from '@/lib/commit';
import { epProblem } from '@/lib/errors';

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

    const result = await verifyCommit(body.commit_id);

    return NextResponse.json({
      valid: result.valid,
      status: result.status,
      decision: result.decision,
      expires_at: result.expires_at,
      entity_id: result.entity_id,
      action_type: result.action_type,
      scope: result.scope,
    });
  } catch (err) {
    console.error('Commit verify error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
