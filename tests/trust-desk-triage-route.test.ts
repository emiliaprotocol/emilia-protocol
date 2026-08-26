// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  rateLimit: vi.fn(),
  extract: vi.fn(),
  classify: vi.fn(),
}));

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: mocks.rateLimit,
  getClientIP: () => '203.0.113.25',
}));

vi.mock('@/lib/trust-desk/extractor', () => ({
  extractQuestions: mocks.extract,
  ExtractionUnsupportedError: class ExtractionUnsupportedError extends Error {
    format: string;

    constructor(format: string) {
      super(format);
      this.format = format;
    }
  },
}));

vi.mock('@/lib/trust-desk/classifier', () => ({
  BUCKET: {
    SOC2_OVERLAP: 'soc2_overlap',
    AI_TEMPLATE_MATCH: 'ai_template_match',
    AI_SPECIFIC: 'ai_specific',
    CUSTOMER_SPECIFIC: 'customer_specific',
    NOVEL: 'novel',
  },
  classifyQuestions: mocks.classify,
}));

const { POST } = await import('../app/api/trust-desk/triage/route.ts');

function jsonRequest(body: unknown, extraHeaders: Record<string, string> = {}): Request {
  return new Request('https://www.emiliaprotocol.ai/api/trust-desk/triage', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });
}

describe('Trust Desk passive triage route', () => {
  beforeEach(() => {
    mocks.rateLimit.mockReset();
    mocks.extract.mockReset();
    mocks.classify.mockReset();
    mocks.rateLimit.mockResolvedValue({ allowed: true, remaining: 4, reset: 60 });
    mocks.extract.mockResolvedValue({
      total_questions: 1,
      source_format: 'text',
      warnings: [],
      questions: [{ id: 'q1', text: 'Do you govern AI systems?' }],
    });
    mocks.classify.mockResolvedValue([
      { id: 'q1', text: 'Do you govern AI systems?', bucket: 'ai_specific' },
    ]);
  });

  it('rate-limits before parsing or classifying attacker-controlled input', async () => {
    mocks.rateLimit.mockResolvedValue({ allowed: false, remaining: 0, reset: 17 });

    const response = await POST(jsonRequest({ text: 'question' }) as any);

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('17');
    expect(mocks.rateLimit).toHaveBeenCalledWith('ip:203.0.113.25', 'trust_desk_triage');
    expect(mocks.extract).not.toHaveBeenCalled();
    expect(mocks.classify).not.toHaveBeenCalled();
  });

  it('rejects an oversized declared envelope before request.json buffers it', async () => {
    const response = await POST(jsonRequest(
      { text: 'small body with a hostile declared length' },
      { 'content-length': String(6 * 1024 * 1024 + 1) },
    ) as any);

    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/payload_too_large',
    });
    expect(mocks.extract).not.toHaveBeenCalled();
    expect(mocks.classify).not.toHaveBeenCalled();
  });

  it('classifies a bounded questionnaire without answering or storing it', async () => {
    const response = await POST(jsonRequest({ text: 'Do you govern AI systems?' }) as any);
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      total_questions: 1,
      counts: { total: 1, ai_specific: 1 },
      scope: {
        what_this_is: 'A classification of the questions in this document. Nothing was answered.',
        retention: 'Parsed in memory and discarded. Nothing was stored and no account was created.',
      },
    });
    expect(mocks.extract).toHaveBeenCalledOnce();
    expect(mocks.classify).toHaveBeenCalledOnce();
    const budget = mocks.classify.mock.calls[0][2].llmBudget;
    expect(budget.snapshot()).toMatchObject({
      maxCalls: 6,
      maxEstimatedTokens: 12_000,
    });
    expect(budget.snapshot().remainingMs).toBeLessThanOrEqual(20_000);
  });

  it('refuses an over-limit questionnaire before classification can invoke a model', async () => {
    const questions = Array.from({ length: 201 }, (_, index) => ({
      id: `q${index}`,
      text: `Do you govern AI system ${index}?`,
    }));
    mocks.extract.mockResolvedValue({
      total_questions: questions.length,
      source_format: 'text',
      warnings: [],
      questions,
    });

    const response = await POST(jsonRequest({ text: 'bounded envelope, too many questions' }) as any);

    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/questionnaire_budget_exceeded',
    });
    expect(mocks.classify).not.toHaveBeenCalled();
  });
});
