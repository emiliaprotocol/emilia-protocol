// SPDX-License-Identifier: Apache-2.0
import type { NextRequest } from 'next/server';

import { adoptionError, adoptionJson } from '@/lib/agent-adoption/http';
import { createAgentRecord, AgentRecordServiceError } from '@/lib/agent-record/service';
import { epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { authorizeAgentAdoptionRequest } from '../../../session-cookie';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 8 * 1024;

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> | { sessionId: string } },
) {
  try {
    const { sessionId } = await context.params;
    // Authenticate before reading attacker-controlled bytes. Cookie recovery
    // also enforces an exact same-origin mutation.
    const authorization = await authorizeAgentAdoptionRequest({ request, sessionId });
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    return adoptionJson(await createAgentRecord({ authorization, input: parsed.value }), 201);
  } catch (error) {
    if (error instanceof AgentRecordServiceError) {
      return epProblem(error.status, error.code, error.message);
    }
    return adoptionError(error, 'agent_record_create');
  }
}
