import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { bindReceiptToCommit, fulfillCommit, getCommitStatus, CommitError } from '@/lib/commit';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/commit/[commitId]/receipt
 *
 * Bind a receipt to a commit and mark it as fulfilled. This closes the
 * commit lifecycle — the pre-authorization has been acted upon and the
 * outcome is now recorded.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const { commitId } = await params;
    const body = await request.json();

    // === AUTHORIZATION: only the issuing entity can bind a receipt ===
    const commit = await getCommitStatus(commitId);
    if (!commit) {
      return epProblem(404, 'commit_not_found', 'Commit not found');
    }

    if (commit.entity_id !== auth.entity.entity_id) {
      return epProblem(403, 'not_authorized', 'Only the issuing entity can bind a receipt to this commit');
    }

    if (!body.receipt_id) {
      return epProblem(400, 'missing_receipt_id', 'receipt_id is required');
    }

    // Bind receipt to the commit
    const bindResult = await bindReceiptToCommit(commitId, body.receipt_id);

    // Mark the commit as fulfilled
    await fulfillCommit(commitId);

    return NextResponse.json({
      commit_id: bindResult.commit_id,
      status: 'fulfilled',
      receipt_id: bindResult.receipt_id,
    });
  } catch (err) {
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    console.error('Commit receipt error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
