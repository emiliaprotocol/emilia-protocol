import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getCommitStatus, CommitError } from '@/lib/commit';
import { epProblem } from '@/lib/errors';

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

    return NextResponse.json({ commit });
  } catch (err) {
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    console.error('Commit status error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
