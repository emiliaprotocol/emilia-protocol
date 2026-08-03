// SPDX-License-Identifier: Apache-2.0
import { type NextRequest } from 'next/server';

import { adoptionError, adoptionJson } from '@/lib/agent-adoption/http';
import {
  createAgentAdoptionRegistrationCeremony,
} from '@/lib/agent-adoption/service';
import { authorizeAgentAdoptionRequest } from '../../../../../session-cookie';

export const dynamic = 'force-dynamic';

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> | { sessionId: string } },
) {
  try {
    const { sessionId } = await context.params;
    const authorization = await authorizeAgentAdoptionRequest({ request, sessionId });
    return adoptionJson(await createAgentAdoptionRegistrationCeremony({ authorization }));
  } catch (error) {
    return adoptionError(error, 'registration_options');
  }
}
