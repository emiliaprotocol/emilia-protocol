// SPDX-License-Identifier: Apache-2.0
import { type NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import { adoptionError, adoptionJson } from '@/lib/agent-adoption/http';
import {
  completeAgentAdoptionRegistration,
} from '@/lib/agent-adoption/service';
import { readLimitedJson } from '@/lib/http/body-limit';
import { authorizeAgentAdoptionRequest } from '../../../../../session-cookie';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 300 * 1024;

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> | { sessionId: string } },
) {
  try {
    const { sessionId } = await context.params;
    const authorization = await authorizeAgentAdoptionRequest({ request, sessionId });
    const parsed: any = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    return adoptionJson(await completeAgentAdoptionRegistration({
      authorization,
      input: parsed.value,
    }), 201);
  } catch (error) {
    return adoptionError(error, 'registration_verify');
  }
}
