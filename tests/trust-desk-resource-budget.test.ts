// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  assertQuestionnaireWithinBudget,
  createTrustDeskLlmBudget,
  TRUST_DESK_RESOURCE_LIMITS,
  TrustDeskResourceLimitError,
} from '../lib/trust-desk/resource-budget.js';
import { llmJSON } from '../lib/trust-desk/llm.js';
import { classifyQuestions } from '../lib/trust-desk/classifier.js';
import { answerAll } from '../lib/trust-desk/answerer.js';

afterEach(() => {
  delete process.env.OPENAI_API_KEY;
  vi.unstubAllGlobals();
});

describe('Trust Desk questionnaire resource budget', () => {
  it('accepts the exact questionnaire boundary', () => {
    const questions = Array.from(
      { length: TRUST_DESK_RESOURCE_LIMITS.maxQuestions },
      (_, index) => ({ id: `q${index}`, text: `Question ${index}?` }),
    );

    expect(() => assertQuestionnaireWithinBudget(questions)).not.toThrow();
  });

  it('refuses an over-limit questionnaire before any model work can begin', () => {
    const questions = Array.from(
      { length: TRUST_DESK_RESOURCE_LIMITS.maxQuestions + 1 },
      (_, index) => ({ id: `q${index}`, text: `Question ${index}?` }),
    );

    expect(() => assertQuestionnaireWithinBudget(questions)).toThrowError(
      expect.objectContaining<Partial<TrustDeskResourceLimitError>>({
        code: 'question_count_exceeded',
      }),
    );
  });

  it('reserves the request call budget before invoking the provider', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const provider = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      choices: [{ message: { content: '{"answer":"ok"}' } }],
      usage: { prompt_tokens: 4, completion_tokens: 3 },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', provider);

    const budget = createTrustDeskLlmBudget({ maxCalls: 1, maxEstimatedTokens: 10_000 });
    const request = {
      system: 'Return JSON.',
      user: 'Question?',
      maxTokens: 10,
      validate: (value: any) => value?.answer === 'ok',
      budget,
    };

    expect((await llmJSON(request)).ok).toBe(true);
    expect(await llmJSON(request)).toMatchObject({
      ok: false,
      reason: 'budget_exhausted:llm_call_limit',
    });
    expect(provider).toHaveBeenCalledTimes(1);
    expect(budget.snapshot()).toMatchObject({ calls: 1 });
  });

  it('refuses an unaccounted provider call before invoking the provider', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const provider = vi.fn();
    vi.stubGlobal('fetch', provider);

    expect(await llmJSON({ system: 'Return JSON.', user: 'Question?' })).toMatchObject({
      ok: false,
      reason: 'budget_required',
    });
    expect(provider).not.toHaveBeenCalled();
  });

  it('reserves estimated input plus requested output tokens before invoking the provider', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const provider = vi.fn();
    vi.stubGlobal('fetch', provider);

    const budget = createTrustDeskLlmBudget({ maxCalls: 5, maxEstimatedTokens: 20 });
    const result = await llmJSON({
      system: 'Return JSON.',
      user: 'A'.repeat(120),
      maxTokens: 10,
      budget,
    });

    expect(result).toMatchObject({
      ok: false,
      reason: 'budget_exhausted:llm_token_limit',
    });
    expect(provider).not.toHaveBeenCalled();
  });

  it('refuses new provider work after the shared wall-clock deadline', () => {
    let now = 1_000;
    const budget = createTrustDeskLlmBudget({
      maxCalls: 5,
      maxEstimatedTokens: 10_000,
      maxWallClockMs: 50,
      now: () => now,
    });
    expect(budget.reserve({ user: 'first', maxTokens: 10 })).toMatchObject({ ok: true });
    now = 1_050;
    expect(budget.reserve({ user: 'second', maxTokens: 10 })).toMatchObject({
      ok: false,
      reason: 'llm_deadline',
    });
    expect(budget.snapshot().remainingMs).toBe(0);
  });

  it('aborts an in-flight provider at the remaining shared deadline', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const provider = vi.fn((_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }));
    vi.stubGlobal('fetch', provider);

    const budget = createTrustDeskLlmBudget({
      maxCalls: 5,
      maxEstimatedTokens: 10_000,
      maxWallClockMs: 20,
    });
    const started = Date.now();
    const result = await llmJSON({ system: 'Return JSON.', user: 'Question?', maxTokens: 10, budget });

    expect(Date.now() - started).toBeLessThan(500);
    expect(result).toMatchObject({ ok: false, reason: 'budget_exhausted:llm_deadline' });
    expect(provider).toHaveBeenCalledOnce();
  });

  it('keeps the deadline active after headers while the provider body stalls', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const provider = vi.fn((_url, init) => Promise.resolve({
      ok: true,
      status: 200,
      json: () => new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      }),
    }));
    vi.stubGlobal('fetch', provider);

    const budget = createTrustDeskLlmBudget({
      maxCalls: 5,
      maxEstimatedTokens: 10_000,
      maxWallClockMs: 20,
    });
    const result = await llmJSON({ system: 'Return JSON.', user: 'Question?', maxTokens: 10, budget });

    expect(result).toMatchObject({ ok: false, reason: 'budget_exhausted:llm_deadline' });
    expect(provider).toHaveBeenCalledOnce();
  });

  it('shares one call budget across classification and answering', async () => {
    process.env.OPENAI_API_KEY = 'test-only-key';
    const provider = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      choices: [{ message: { content: JSON.stringify({
        bucket: 'ai_specific',
        matched_template: null,
        confidence: 0.9,
      }) } }],
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', provider);

    const budget = createTrustDeskLlmBudget({ maxCalls: 1, maxEstimatedTokens: 10_000 });
    const classified = await classifyQuestions([
      { id: 'q1', text: 'How do models behave when conditions change?', section: 'AI' },
    ], {}, { llmBudget: budget });
    const [answer] = await answerAll(classified, {
      intake: {},
      policyVars: {},
      llmBudget: budget,
    });

    expect(provider).toHaveBeenCalledTimes(1);
    expect(answer).toMatchObject({
      status: 'escalated',
      escalation_reason: 'llm_budget_exhausted:llm_call_limit',
    });
  });
});
