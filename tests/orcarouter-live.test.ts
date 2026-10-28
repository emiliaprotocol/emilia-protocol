// SPDX-License-Identifier: Apache-2.0
//
// Live connectivity check. Runs only when ORCAROUTER_API_KEY is present in the
// environment; otherwise every case is skipped, and the suite still passes.
//
// It exercises the same code path as production (discoverOrcaRouterModels and
// orcaRouterChatCompletion), not a hand-written fetch. DeepSeek is used here
// only as an internal connectivity fallback when an account is not verified
// for the cyber models — never as a product default or user-facing fallback.

import { describe, it, expect } from 'vitest';

import { getOrcaRouterEnv } from '../lib/env.js';
import {
  ORCAROUTER_CYBER_MODELS,
  discoverOrcaRouterModels,
  orcaRouterChatCompletion,
  resolveOrcaRouterOrigins,
} from '../lib/providers/orcarouter.js';

const apiKey = getOrcaRouterEnv().apiKey;
const hasKey = typeof apiKey === 'string' && apiKey.length > 0;

describe.skipIf(!hasKey)('OrcaRouter live connectivity', () => {
  const credential = hasKey
    ? { key: apiKey as string, generation: 'env', source: 'env' as const }
    : null;

  it('discovers a non-empty live chat catalog from the real endpoint', async () => {
    const catalog = await discoverOrcaRouterModels({
      credential,
      capability: 'chat',
      useCache: false,
    });
    expect(catalog.source).toBe('live');
    expect(catalog.degraded).toBe(false);
    expect(catalog.models.length).toBeGreaterThan(0);
    expect(catalog.catalog_source).toBe('https://api.orcarouter.ai/v1/models?capability=chat');
    expect(catalog.models.every((entry) => entry.id.length > 0)).toBe(true);
  }, 60_000);

  it('completes one chat request through the provider, preferring the cyber models', async () => {
    const origins = resolveOrcaRouterOrigins();
    const candidates = [...ORCAROUTER_CYBER_MODELS, 'deepseek/deepseek-v4.1-flash'];
    let lastStatus: number | null = null;
    for (const model of candidates) {
      try {
        const result = await orcaRouterChatCompletion({
          apiKey: apiKey as string,
          origins,
          model,
          system: 'Reply with exactly the word OK.',
          user: 'Connectivity check.',
          maxTokens: 64,
          temperature: 0,
          signal: AbortSignal.timeout(45_000),
        });
        expect(typeof result.raw).toBe('string');
        if (!result.raw.length) {
          // A reasoning model can spend the whole small budget before emitting
          // content; try the next cyber model rather than treating that as a
          // transport failure.
          if (model !== 'deepseek/deepseek-v4.1-flash') continue;
          throw new Error(`empty chat content (finish=${result.finishReason ?? 'unknown'})`);
        }
        return;
      } catch (error: any) {
        lastStatus = typeof error?.status === 'number' ? error.status : null;
        // A rejected key is terminal: another model would only repeat the same
        // failing credential. An entitlement failure falls through to the next
        // candidate (and only those candidates, never a product default).
        if (lastStatus === 401) throw error;
        if (lastStatus === 403) {
          if (model === 'deepseek/deepseek-v4.1-flash') throw error;
          continue;
        }
        throw error;
      }
    }
    throw new Error(`no chat model responded (last status ${lastStatus ?? 'none'})`);
  }, 120_000);
});

describe.skipIf(hasKey)('OrcaRouter live connectivity (skipped)', () => {
  it('is skipped without ORCAROUTER_API_KEY', () => {
    expect(hasKey).toBe(false);
  });
});
