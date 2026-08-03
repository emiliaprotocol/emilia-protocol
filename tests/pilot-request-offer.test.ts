// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args: unknown[]) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
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
      workflow: 'wire_release',
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
    vi.stubEnv('RESEND_API_KEY', 'test-resend-key');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 202 })));
    mockGetGuardedClient.mockReturnValue({
      from: () => ({
        insert: vi.fn(async () => ({ error: null })),
      }),
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('routes the fixed Financial Authority offer id to the internal team only', async () => {
    const response = await POST(request({
      offer_id: 'financial_authority_design_partner_v1',
    }) as never);

    expect(response.status).toBe(200);
    const emails = sentEmails();
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe('team@emiliaprotocol.ai');
    expect(emails[0].text).toContain('Financial Authority design-partner pilot');
    expect(emails[0].text).toContain('90 days');
    expect(emails[0].text).toContain('$25,000');
    expect(emails[0].text).toContain('1 protected workflow');
    expect(emails[0].text).toContain('1 provider rail');
  });

  it('routes Agent Adoption graduates to its own protected-workflow offer', async () => {
    const response = await POST(request({
      offer_id: 'agent_adoption_design_partner_v1',
      workflow: 'other',
    }) as never);

    expect(response.status).toBe(200);
    const emails = sentEmails();
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe('team@emiliaprotocol.ai');
    expect(emails[0].text).toContain('Agent Adoption protected-workflow pilot');
    expect(emails[0].text).toContain('90 days');
    expect(emails[0].text).toContain('$25,000');
    expect(emails[0].text).toContain('1 protected agent workflow');
    expect(emails[0].text).not.toContain('provider rail');
  });

  it('ignores caller-supplied commercial terms for a recognized offer', async () => {
    const response = await POST(request({
      offer_id: 'financial_authority_design_partner_v1',
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

  it('preserves the Signal default and rejects unknown offer ids', async () => {
    const defaultResponse = await POST(request({}) as never);
    expect(defaultResponse.status).toBe(200);
    const defaultMessages = sentEmails();
    expect(defaultMessages).toHaveLength(1);
    expect(defaultMessages[0].to).toBe('team@emiliaprotocol.ai');
    expect(defaultMessages[0].text).toContain('60 days');
    expect(defaultMessages[0].text).toContain('1 read-only workflow diagnostic');

    vi.mocked(fetch).mockClear();
    mockGetGuardedClient.mockClear();
    const unknownResponse = await POST(request({ offer_id: 'caller_defined_offer' }) as never);
    expect(unknownResponse.status).toBe(400);
    expect(fetch).not.toHaveBeenCalled();
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });
});
