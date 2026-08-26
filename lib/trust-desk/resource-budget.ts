/**
 * AI Trust Desk request-scoped resource accounting.
 *
 * @license Apache-2.0
 *
 * Concurrency limits bound simultaneous work, but they do not bound the total
 * work created by one questionnaire. This module puts deterministic ceilings
 * around both the questionnaire and every LLM call made while processing it.
 * A caller creates one budget and shares it across classification and answering.
 */

export const TRUST_DESK_RESOURCE_LIMITS = Object.freeze({
  maxQuestions: 200,
  maxQuestionChars: 8_000,
  maxTotalQuestionChars: 200_000,
  maxLlmCalls: 48,
  // Leaves ten seconds inside the 60-second route contract for parsing,
  // persistence, response serialization, and platform scheduling variance.
  maxLlmWallClockMs: 50_000,
  // Conservative cost-style unit: estimated input tokens plus the provider's
  // requested maximum output tokens. It is intentionally model-neutral.
  maxEstimatedTokens: 100_000,
});

/**
 * Anonymous product surfaces use one small refinement batch. The broader
 * default above is reserved for controlled engagement/reviewer workflows.
 */
export const TRUST_DESK_PUBLIC_LLM_LIMITS = Object.freeze({
  maxCalls: 6,
  maxEstimatedTokens: 12_000,
  maxWallClockMs: 20_000,
});

export type TrustDeskResourceLimitCode =
  | 'question_count_exceeded'
  | 'question_length_exceeded'
  | 'question_text_budget_exceeded';

export class TrustDeskResourceLimitError extends Error {
  code: TrustDeskResourceLimitCode;
  limit: number;
  observed: number;

  constructor(code: TrustDeskResourceLimitCode, message: string, limit: number, observed: number) {
    super(message);
    this.name = 'TrustDeskResourceLimitError';
    this.code = code;
    this.limit = limit;
    this.observed = observed;
  }
}

export function assertQuestionnaireWithinBudget(questions: any[]): void {
  const count = Array.isArray(questions) ? questions.length : 0;
  if (count > TRUST_DESK_RESOURCE_LIMITS.maxQuestions) {
    throw new TrustDeskResourceLimitError(
      'question_count_exceeded',
      `questionnaire has ${count} questions; maximum is ${TRUST_DESK_RESOURCE_LIMITS.maxQuestions}`,
      TRUST_DESK_RESOURCE_LIMITS.maxQuestions,
      count,
    );
  }

  let totalChars = 0;
  for (const question of questions || []) {
    const chars = String(question?.text || '').length;
    if (chars > TRUST_DESK_RESOURCE_LIMITS.maxQuestionChars) {
      throw new TrustDeskResourceLimitError(
        'question_length_exceeded',
        `one question has ${chars} characters; maximum is ${TRUST_DESK_RESOURCE_LIMITS.maxQuestionChars}`,
        TRUST_DESK_RESOURCE_LIMITS.maxQuestionChars,
        chars,
      );
    }
    totalChars += chars;
    if (totalChars > TRUST_DESK_RESOURCE_LIMITS.maxTotalQuestionChars) {
      throw new TrustDeskResourceLimitError(
        'question_text_budget_exceeded',
        `question text totals ${totalChars} characters; maximum is ${TRUST_DESK_RESOURCE_LIMITS.maxTotalQuestionChars}`,
        TRUST_DESK_RESOURCE_LIMITS.maxTotalQuestionChars,
        totalChars,
      );
    }
  }
}

export type LlmReservation =
  | { ok: true; estimatedTokens: number }
  | { ok: false; reason: 'llm_call_limit' | 'llm_token_limit' | 'llm_deadline'; estimatedTokens: number };

export type TrustDeskLlmBudget = {
  reserve(input: { system?: string; user?: string; maxTokens?: number }): LlmReservation;
  remainingMs(): number;
  snapshot(): {
    calls: number;
    estimatedTokens: number;
    maxCalls: number;
    maxEstimatedTokens: number;
    remainingMs: number;
  };
};

export interface TrustDeskLlmBudgetOptions {
  maxCalls?: number;
  maxEstimatedTokens?: number;
  maxWallClockMs?: number;
  now?: () => number;
}

export function createTrustDeskLlmBudget({
  maxCalls = TRUST_DESK_RESOURCE_LIMITS.maxLlmCalls,
  maxEstimatedTokens = TRUST_DESK_RESOURCE_LIMITS.maxEstimatedTokens,
  maxWallClockMs = TRUST_DESK_RESOURCE_LIMITS.maxLlmWallClockMs,
  now = Date.now,
}: TrustDeskLlmBudgetOptions = {}): TrustDeskLlmBudget {
  const callLimit = positiveInteger(maxCalls, 'maxCalls');
  const tokenLimit = positiveInteger(maxEstimatedTokens, 'maxEstimatedTokens');
  const wallClockLimit = positiveInteger(maxWallClockMs, 'maxWallClockMs');
  const deadlineAt = now() + wallClockLimit;
  let calls = 0;
  let estimatedTokens = 0;

  const remainingMs = () => Math.max(0, deadlineAt - now());

  return {
    reserve({ system = '', user = '', maxTokens = 900 } = {}): LlmReservation {
      const requestedOutputTokens = positiveInteger(maxTokens, 'maxTokens');
      const nextCallTokens = estimateInputTokens(system, user) + requestedOutputTokens;
      if (remainingMs() <= 0) {
        return { ok: false, reason: 'llm_deadline', estimatedTokens: nextCallTokens };
      }
      if (calls + 1 > callLimit) {
        return { ok: false, reason: 'llm_call_limit', estimatedTokens: nextCallTokens };
      }
      if (estimatedTokens + nextCallTokens > tokenLimit) {
        return { ok: false, reason: 'llm_token_limit', estimatedTokens: nextCallTokens };
      }
      calls += 1;
      estimatedTokens += nextCallTokens;
      return { ok: true, estimatedTokens: nextCallTokens };
    },
    remainingMs,
    snapshot() {
      return {
        calls,
        estimatedTokens,
        maxCalls: callLimit,
        maxEstimatedTokens: tokenLimit,
        remainingMs: remainingMs(),
      };
    },
  };
}

function estimateInputTokens(system: string, user: string): number {
  // UTF-8 bytes / 3 is deliberately more conservative than the common English
  // approximation of characters / 4, while remaining deterministic across
  // providers. Requested output tokens are added separately by reserve().
  return Math.ceil(Buffer.byteLength(`${String(system)}\n${String(user)}`, 'utf8') / 3);
}

function positiveInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${field} must be a positive safe integer`);
  }
  return value;
}
