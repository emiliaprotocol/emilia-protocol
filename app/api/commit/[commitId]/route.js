import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getCommitStatus, CommitError } from '@/lib/commit';
import { authorizeCommitAccess } from '@/lib/commit-auth';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * GET /api/commit/[commitId]
 *
 * Retrieve full commit status and metadata. Auth required — only the
 * issuing entity or principal should access the complete commit record.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const { commitId } = await params;
    const commit = await getCommitStatus(commitId);

    if (!commit) {
      return epProblem(404, 'commit_not_found', 'Commit not found');
    }

    // === AUTHORIZATION: only issuing entity or principal may view ===
    const authz = authorizeCommitAccess(auth, commit, 'view');
    if (!authz.authorized) {
      return epProblem(403, 'not_authorized', authz.reason);
    }

    return NextResponse.json({ commit });
  } catch (err) {
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    logger.error('Commit status error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
