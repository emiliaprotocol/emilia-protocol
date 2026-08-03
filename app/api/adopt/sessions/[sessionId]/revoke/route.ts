// SPDX-License-Identifier: Apache-2.0
import { type NextRequest } from 'next/server';

import { adoptionError, adoptionJson } from '@/lib/agent-adoption/http';
import {
  revokeAgentAdoption,
} from '@/lib/agent-adoption/service';
import {
  authorizeAgentAdoptionRequest,
  clearAgentAdoptionSessionCookie,
} from '../../../session-cookie';

export const dynamic = 'force-dynamic';

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> | { sessionId: string } },
) {
  try {
    const { sessionId } = await context.params;
    const authorization = await authorizeAgentAdoptionRequest({ request, sessionId });
    const response = adoptionJson(await revokeAgentAdoption({ authorization }));
    clearAgentAdoptionSessionCookie(response);
    return response;
  } catch (error) {
    return adoptionError(error, 'session_revoke');
  }
}
