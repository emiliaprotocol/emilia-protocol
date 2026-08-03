// SPDX-License-Identifier: Apache-2.0
import { type NextRequest } from 'next/server';

import { createAgentAdoptionSession } from '@/lib/agent-adoption/service';
import { adoptionError, adoptionJson } from '@/lib/agent-adoption/http';
import { readLimitedJson } from '@/lib/http/body-limit';
import { epProblem } from '@/lib/errors';
import { setAgentAdoptionSessionCookie } from '../session-cookie';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 8 * 1024;

export async function POST(request: NextRequest) {
  try {
    const parsed: any = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const session = await createAgentAdoptionSession({ input: parsed.value });
    const response = adoptionJson(session, 201);
    setAgentAdoptionSessionCookie(response, session);
    return response;
  } catch (error) {
    return adoptionError(error, 'create_session');
  }
}
