import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getCommitStatus, CommitError } from '@/lib/commit';
import { authorizeCommitAccess } from '@/lib/commit-auth';
import { protocolWrite, COMMAND_TYPES, ProtocolWriteError } from '@/lib/protocol-write';
import { epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 5 * 1024;

/**
 * POST /api/commit/[commitId]/revoke
 *
 * Revoke an active commit before fulfillment. Only the issuing entity
 * or the principal on the commit may revoke it. Terminal states
 * (fulfilled, revoked, expired) are immutable.
 */
export async function POST(request: NextRequest, { params }: { params: Promise<{ commitId: string }> }) {
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

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;

    if (!body.reason) {
      return epProblem(400, 'missing_reason', 'reason is required');
    }

    const result = await protocolWrite({
      type: COMMAND_TYPES.REVOKE_COMMIT,
      actor: auth,
      input: { commit_id: commitId, reason: body.reason },
    });

    return NextResponse.json({
      commit_id: result.commit_id,
      status: 'revoked',
      revoked_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err instanceof ProtocolWriteError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    logger.error('Commit revoke error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
