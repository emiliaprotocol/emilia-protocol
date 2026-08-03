// SPDX-License-Identifier: Apache-2.0
import { type NextRequest } from 'next/server';

import { adoptionError, adoptionJson } from '@/lib/agent-adoption/http';
import { authorizeAgentAdoptionRequest } from '../../session-cookie';

export const dynamic = 'force-dynamic';

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> | { sessionId: string } },
) {
  try {
    const { sessionId } = await context.params;
    const authorization = await authorizeAgentAdoptionRequest({ request, sessionId });
    const stored = authorization.session;
    return adoptionJson({
      session_id: sessionId,
      expires_at: stored.expires_at,
      authority_state: Number(stored.bond_count) > 0 ? 'asserted' : 'draft',
      passkey_asserted: Number(stored.bond_count) > 0,
      bond_id: stored.latest_bond_id ?? undefined,
      bond_digest: stored.latest_bond_digest ?? stored.bond_digest,
      recovery: {
        label: stored.operating_bond?.candidate?.label,
        source_kind: stored.operating_bond?.candidate?.source_kind,
        job_template_id: stored.operating_bond?.candidate?.job_template_id,
        allowance_template_id: stored.operating_bond?.candidate?.allowance_template_id,
      },
    });
  } catch (error) {
    return adoptionError(error, 'session_recovery');
  }
}

