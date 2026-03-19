import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { revokeCommit, getCommitStatus, CommitError } from '@/lib/commit';
import { authorizeCommitAccess } from '@/lib/commit-auth';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/commit/[commitId]/revoke
 *
 * Revoke an active commit before fulfillment. Only the issuing entity
 * or the principal on the commit may revoke it. Terminal states
 * (fulfilled, revoked, expired) are immutable.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const { commitId } = await params;

    // === AUTHORIZATION: only issuing entity or principal may revoke ===
    const commit = await getCommitStatus(commitId);
    if (!commit) {
      return epProblem(404, 'commit_not_found', 'Commit not found');
    }

    const authz = authorizeCommitAccess(auth, commit, 'revoke');
    if (!authz.authorized) {
      return epProblem(403, 'not_authorized', authz.reason);
    }

    const body = await request.json();

    if (!body.reason) {
      return epProblem(400, 'missing_reason', 'reason is required');
    }

    const result = await revokeCommit(commitId, body.reason);

    return NextResponse.json({
      commit_id: result.commit_id,
      status: 'revoked',
      revoked_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    console.error('Commit revoke error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
