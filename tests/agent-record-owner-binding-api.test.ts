// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authorize: vi.fn(),
  prepareSource: vi.fn(),
  readiness: vi.fn(),
  rpc: vi.fn(),
}));

vi.mock('../app/api/adopt/session-cookie', () => ({
  authorizeAgentAdoptionRequest: mocks.authorize,
}));

vi.mock('@/lib/agent-record/runtime-readiness', () => ({
  getAgentRecordRuntimeReadiness: mocks.readiness,
}));

vi.mock('@/lib/agent-record/source', () => ({
  AgentRecordSourceError: class AgentRecordSourceError extends Error {
    constructor(public status: number, public code: string, message = code) {
      super(message);
    }
  },
  prepareAgentRecordRefusalSource: mocks.prepareSource,
}));

vi.mock('@/lib/supabase', () => ({
  getServiceClient: () => ({ rpc: mocks.rpc }),
}));

const CreateRoute = await import(
  '../app/api/adopt/sessions/[sessionId]/records/route'
);

const SESSION_ID = '11111111-1111-4111-8111-111111111111';
const OWNER_TOKEN = `ear1_${'3'.repeat(64)}`;

describe('Agent Record owner binding API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.readiness.mockResolvedValue({ ready: true });
    mocks.authorize.mockResolvedValue({
      sessionId: SESSION_ID,
      sessionToken: `eaa1_${'1'.repeat(64)}`,
      session: { adoption_id: SESSION_ID, status: 'active' },
    });
  });

  it('rejects a well-shaped record id paired with a different owner token', async () => {
    const response = await CreateRoute.POST(
      new Request(`https://www.emiliaprotocol.ai/api/adopt/sessions/${SESSION_ID}/records`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          trial_token: `epenc:v1:${'A'.repeat(64)}`,
          attempt_id: `arena_attempt_${'b'.repeat(32)}`,
          record_id: `agent_record_${'0'.repeat(40)}`,
          owner_token: OWNER_TOKEN,
        }),
      }) as never,
      { params: { sessionId: SESSION_ID } },
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/agent_record_creation_invalid',
      status: 400,
    });
    expect(mocks.prepareSource).not.toHaveBeenCalled();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });
});
