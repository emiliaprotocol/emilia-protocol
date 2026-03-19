import { NextResponse } from 'next/server';
import { verifyCommit } from '@/lib/commit';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/commit/verify
 *
 * Verify a commit's validity. Public — any relying system can call this
 * to check whether a commit is still valid before acting on it.
 *
 * Accepts { commit_id } or { token } (the full signed commit JSON).
 * Returns a verdict (valid/invalid + status), NOT the full commit payload.
 * The verifier gets a decision, not a window into the commit details.
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.commit_id && !body.token) {
      return epProblem(400, 'missing_input', 'Provide commit_id or token');
    }

    // verifyCommit accepts a commit_id string; for token-based verification
    // we parse the token to extract the commit_id and look it up.
    let lookupId = body.commit_id;
    if (!lookupId && body.token) {
      try {
        const parsed = typeof body.token === 'string' ? JSON.parse(body.token) : body.token;
        lookupId = parsed.commit_id;
      } catch {
        return epProblem(400, 'malformed_token', 'Token is not valid JSON');
      }
    }

    if (!lookupId) {
      return epProblem(400, 'missing_commit_id', 'Could not extract commit_id from input');
    }

    const result = await verifyCommit(lookupId);

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
