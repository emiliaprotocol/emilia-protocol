// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetGuardedClient = vi.fn();
const publicArtifactMocks = vi.hoisted(() => ({
  loadArena: vi.fn(),
  loadAdoption: vi.fn(),
  loadAgentRecord: vi.fn(),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args: unknown[]) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('@/lib/arena/service', () => ({
  loadPublicArenaRefusal: publicArtifactMocks.loadArena,
}));

vi.mock('@/lib/agent-adoption/service', () => ({
  loadPublicAgentAdoptionBond: publicArtifactMocks.loadAdoption,
}));

vi.mock('@/lib/agent-record/service', () => ({
  loadPublicAgentRecord: publicArtifactMocks.loadAgentRecord,
}));

const { POST } = await import('../app/api/pilot/request/route.ts');

function request(body: Record<string, unknown>): Request {
  return new Request('https://www.emiliaprotocol.ai/api/pilot/request', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      name: 'Ada Lovelace',
      org: 'Analytical Engines',
      email: 'ada@example.com',
      workflow: 'beneficiary_change',
      ...body,
    }),
  });
}

function sentEmails(): Array<{ to: string; subject: string; text: string }> {
  return vi.mocked(fetch).mock.calls.map(([, init]) => {
    const payload = JSON.parse(String(init?.body));
    return { to: payload.to, subject: payload.subject, text: payload.text };
  });
}

describe('pilot request commercial offer routing', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockClear();
    vi.stubEnv('RESEND_API_KEY', 'test-resend-key');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 202 })));
    mockGetGuardedClient.mockReturnValue({
      from: () => ({
        insert: vi.fn(async () => ({ error: null })),
      }),
    });
    publicArtifactMocks.loadArena.mockReset();
    publicArtifactMocks.loadAdoption.mockReset();
    publicArtifactMocks.loadAgentRecord.mockReset();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('routes the canonical protected-workflow pilot to the internal team only', async () => {
    const response = await POST(request({
      offer_id: 'protected_workflow_pilot_v1',
    }) as never);

    expect(response.status).toBe(200);
    const emails = sentEmails();
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe('team@emiliaprotocol.ai');
    expect(emails[0].text).toContain('Protected-workflow pilot');
    expect(emails[0].text).toContain('90 days');
    expect(emails[0].text).toContain('$25,000');
    expect(emails[0].text).toContain('1 protected workflow');
    expect(emails[0].text).toContain('Finance operations vendor bank-detail change or payment release');
    expect(emails[0].text).toContain('No accepted exact-action authority and required evidence, no provider entry');
  });

  it('keeps non-payer workflows eligible under the same offer', async () => {
    const response = await POST(request({
      offer_id: 'protected_workflow_pilot_v1',
      workflow: 'other',
    }) as never);

    expect(response.status).toBe(200);
    const emails = sentEmails();
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe('team@emiliaprotocol.ai');
    expect(emails[0].text).toContain('Protected-workflow pilot');
    expect(emails[0].text).toContain('90 days');
    expect(emails[0].text).toContain('$25,000');
    expect(emails[0].text).toContain('1 protected workflow');
    expect(emails[0].text).not.toContain('provider rail');

    vi.mocked(fetch).mockClear();
    const arenaId = `arena_share_${'a'.repeat(40)}`;
    publicArtifactMocks.loadArena.mockResolvedValue({
      share_id: arenaId,
      verification: { integrity_verified: true },
    });
    const arenaResponse = await POST(request({ artifact_id: arenaId }) as never);
    expect(arenaResponse.status).toBe(200);
    expect(publicArtifactMocks.loadArena).toHaveBeenCalledWith(arenaId);
    expect(sentEmails()[0].text).toContain(`Validated public record: ${arenaId}`);
    expect(sentEmails()[0].text).toContain('Arena refusal record');

    vi.mocked(fetch).mockClear();
    const adoptionId = `agent_share_${'b'.repeat(40)}`;
    publicArtifactMocks.loadAdoption.mockResolvedValue({ share_id: adoptionId, revoked: false });
    const adoptionResponse = await POST(request({ artifact_id: adoptionId }) as never);
    expect(adoptionResponse.status).toBe(200);
    expect(publicArtifactMocks.loadAdoption).toHaveBeenCalledWith({ shareId: adoptionId });
    expect(sentEmails()[0].text).toContain(`Validated public record: ${adoptionId}`);
    expect(sentEmails()[0].text).toContain('Operating Bond');

    vi.mocked(fetch).mockClear();
    const recordId = `agent_record_${'d'.repeat(40)}`;
    publicArtifactMocks.loadAgentRecord.mockResolvedValue({
      record_id: recordId,
      verification: { integrity_verified: true, currently_public: true },
    });
    const recordResponse = await POST(request({ artifact_id: recordId }) as never);
    expect(recordResponse.status).toBe(200);
    expect(publicArtifactMocks.loadAgentRecord).toHaveBeenCalledWith({ recordId });
    expect(sentEmails()[0].text).toContain(`Validated public record: ${recordId}`);
    expect(sentEmails()[0].text).toContain('Agent Record observation');
  });

  it('ignores caller-supplied commercial terms for a recognized offer', async () => {
    const response = await POST(request({
      offer_id: 'protected_workflow_pilot_v1',
      price: '$1',
      price_usd: 1,
      duration_days: 1,
      workflow_count: 99,
      provider_rail_count: 99,
    }) as never);

    expect(response.status).toBe(200);
    const sent = sentEmails();
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe('team@emiliaprotocol.ai');
    const allEmailText = sent.map((email) => email.text).join('\n');
    expect(allEmailText).toContain('$25,000');
    expect(allEmailText).toContain('90 days');
    expect(allEmailText).not.toContain('$1');
    expect(allEmailText).not.toContain('1 day');
    expect(allEmailText).not.toContain('99');
  });

  it('uses the canonical pilot by default and rejects old or unknown offer ids', async () => {
    const defaultResponse = await POST(request({}) as never);
    expect(defaultResponse.status).toBe(200);
    const defaultMessages = sentEmails();
    expect(defaultMessages).toHaveLength(1);
    expect(defaultMessages[0].to).toBe('team@emiliaprotocol.ai');
    expect(defaultMessages[0].text).toContain('90 days');
    expect(defaultMessages[0].text).toContain('1 protected workflow');

    vi.mocked(fetch).mockClear();
    mockGetGuardedClient.mockClear();
    for (const offer_id of [
      'financial_authority_design_partner_v1',
      'agent_adoption_design_partner_v1',
      'caller_defined_offer',
    ]) {
      const unknownResponse = await POST(request({ offer_id }) as never);
      expect(unknownResponse.status).toBe(400);
      expect(fetch).not.toHaveBeenCalled();
      expect(mockGetGuardedClient).not.toHaveBeenCalled();
    }

    for (const body of [
      { artifact_id: 'receipt:caller-claimed' },
      { evidence: 'I have a signed approval' },
      { artifact_url: 'https://example.test/not-a-public-record' },
    ]) {
      const response = await POST(request(body) as never);
      expect(response.status).toBe(400);
    }
    expect(publicArtifactMocks.loadArena).not.toHaveBeenCalled();
    expect(publicArtifactMocks.loadAdoption).not.toHaveBeenCalled();
    expect(publicArtifactMocks.loadAgentRecord).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(mockGetGuardedClient).not.toHaveBeenCalled();

    const unknownId = `arena_share_${'c'.repeat(40)}`;
    publicArtifactMocks.loadArena.mockResolvedValue(null);
    const unknown = await POST(request({ artifact_id: unknownId }) as never);
    expect(unknown.status).toBe(400);
    expect(publicArtifactMocks.loadArena).toHaveBeenCalledWith(unknownId);
    expect(fetch).not.toHaveBeenCalled();
    expect(mockGetGuardedClient).not.toHaveBeenCalled();

    publicArtifactMocks.loadArena.mockResolvedValue({
      share_id: unknownId,
      verification: { integrity_verified: false },
    });
    const unverifiable = await POST(request({ artifact_id: unknownId }) as never);
    expect(unverifiable.status).toBe(400);
    expect(fetch).not.toHaveBeenCalled();
    expect(mockGetGuardedClient).not.toHaveBeenCalled();

    const inactiveRecordId = `agent_record_${'e'.repeat(40)}`;
    publicArtifactMocks.loadAgentRecord.mockResolvedValue(null);
    const inactiveRecord = await POST(request({ artifact_id: inactiveRecordId }) as never);
    expect(inactiveRecord.status).toBe(400);
    expect(publicArtifactMocks.loadAgentRecord).toHaveBeenCalledWith({ recordId: inactiveRecordId });
    expect(fetch).not.toHaveBeenCalled();
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });
});
