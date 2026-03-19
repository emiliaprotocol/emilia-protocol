import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { issueCommit, CommitError } from '@/lib/commit';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/commit/issue
 *
 * Issue a new EP Commit — a signed, auditable pre-authorization that records
 * EP's trust decision on whether an action should proceed.
 *
 * The commit is always returned (even on deny) so both parties have an
 * auditable record of the decision.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const body = await request.json();

    // === INPUT VALIDATION (route responsibility) ===
    if (!body.action_type) {
      return epProblem(400, 'missing_action_type', 'action_type is required');
    }

    const validActionTypes = ['install', 'connect', 'delegate', 'transact'];
    if (!validActionTypes.includes(body.action_type)) {
      return epProblem(400, 'invalid_action_type', `action_type must be one of: ${validActionTypes.join(', ')}`);
    }

    if (!body.entity_id) {
      return epProblem(400, 'missing_entity_id', 'entity_id is required');
    }

    // === ISSUE COMMIT ===
    const commit = await issueCommit({
      action_type: body.action_type,
      entity_id: body.entity_id,
      principal_id: body.principal_id,
      counterparty_entity_id: body.counterparty_entity_id,
      delegation_id: body.delegation_id,
      scope: body.scope,
      max_value_usd: body.max_value_usd,
      context: body.context,
      policy: body.policy,
    });

    return NextResponse.json({
      decision: commit.decision,
      commit,
    }, { status: 201 });
  } catch (err) {
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    console.error('Commit issue error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
