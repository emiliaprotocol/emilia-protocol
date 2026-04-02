import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { CommitError } from '@/lib/commit';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * POST /api/commit/[commitId]/dispute
 *
 * Shortcut to open a dispute from a commit. Looks up the commit, finds
 * the bound receipt_id, and delegates to protocol write for dispute filing.
 *
 * The commit must have a bound receipt for a dispute to be filed against it.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const { commitId } = await params;
    const body = await request.json();
    const supabase = getGuardedClient();

    // Look up the commit
    const { data: commit, error: commitError } = await supabase
      .from('commits')
      .select('*')
      .eq('commit_id', commitId)
      .single();

    if (commitError || !commit) {
      return epProblem(404, 'commit_not_found', 'Commit not found');
    }

    // Must have a bound receipt to dispute
    if (!commit.receipt_id) {
      return epProblem(409, 'no_receipt_bound', 'This commit has no bound receipt. File a dispute against a receipt, not a pre-authorization.');
    }

    // Build the dispute body from the commit context
    const disputeBody = {
      receipt_id: commit.receipt_id,
      reason: body.reason || 'context_mismatch',
      description: body.description || `Dispute filed via commit ${commitId}`,
      evidence: {
        ...(body.evidence || {}),
        commit_id: commitId,
        commit_action_type: commit.action_type,
        commit_scope: commit.scope,
      },
    };

    // Delegate to protocol write for dispute filing
    const result = await protocolWrite({
      type: COMMAND_TYPES.FILE_DISPUTE,
      input: disputeBody,
      actor: auth.entity,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'dispute_filing_failed', result.error, {
        existing_dispute: result.existing_dispute,
      });
    }

    return NextResponse.json({
      ...result,
      commit_id: commitId,
      _message: 'Dispute filed from commit. The receipt submitter has 7 days to respond.',
    }, { status: 201 });
  } catch (err) {
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    logger.error('Commit dispute error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
