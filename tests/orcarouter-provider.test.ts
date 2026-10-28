// SPDX-License-Identifier: Apache-2.0
//
// OrcaRouter Cyber Inference provider wiring: origins, capability filters,
// catalog discovery, and the chat relay. The catalog is the only source of
// truth, so these tests feed synthetic catalogs and assert that a name never
// implies a capability.

import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  ORCAROUTER_DEFAULT_API_ORIGIN,
  ORCAROUTER_DEFAULT_AUTH_ORIGIN,
  ORCAROUTER_DISPLAY_NAME,
  discoverOrcaRouterModels,
  modelMatches,
  normalizeOrcaOrigin,
  orcaRouterChatCompletion,
  resetOrcaRouterCatalogCache,
  resolveOrcaRouterOrigins,
  seedModels,
} from '../lib/providers/orcarouter.js';
import { logger } from '../lib/logger.js';

const hostileRepoReminder = 'orcarouter-provider';

const envWith = (overrides: Record<string, string | null>) => {
  const base = {
    apiKey: null,
    authBaseOverride: null,
    apiBaseOverride: null,
    sharedBaseOverride: null,
    modelOverride: null,
    stateDir: null,
    settingsSurfaceEnabled: false,
  };
  return { ...base, ...overrides };
};

const model = (overrides: Record<string, unknown> = {}) => ({
  id: 'provider/model-a',
  name: 'Model A',
  context_length: 128000,
  architecture: { input_modalities: ['text'], output_modalities: ['text'] },
  supported_endpoint_types: ['openai'],
  ...overrides,
});

const jsonResponse = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });

const tmpStateDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'orca-provider-'));

afterEach(() => {
  resetOrcaRouterCatalogCache();
  vi.restoreAllMocks();
});

describe(hostileRepoReminder, () => {
  describe('origins', () => {
    it('defaults to distinct auth and inference origins', () => {
      expect(resolveOrcaRouterOrigins(envWith({}))).toEqual({
        auth: ORCAROUTER_DEFAULT_AUTH_ORIGIN,
        api: ORCAROUTER_DEFAULT_API_ORIGIN,
      });
      expect(ORCAROUTER_DEFAULT_AUTH_ORIGIN).toBe('https://www.orcarouter.ai');
      expect(ORCAROUTER_DEFAULT_API_ORIGIN).toBe('https://api.orcarouter.ai/v1');
      expect(ORCAROUTER_DISPLAY_NAME).toBe('OrcaRouter Cyber Inference');
    });

    it('derives inference under /v1 from a shared self-hosted base', () => {
      const origins = resolveOrcaRouterOrigins(envWith({ sharedBaseOverride: 'https://gateway.example.test' }));
      expect(origins).toEqual({
        auth: 'https://gateway.example.test',
        api: 'https://gateway.example.test/v1',
      });
    });

    it('lets explicit overrides win over the shared base, independently', () => {
      expect(resolveOrcaRouterOrigins(envWith({
        sharedBaseOverride: 'https://shared.example.test',
        authBaseOverride: 'https://login.example.test',
      }))).toEqual({
        auth: 'https://login.example.test',
        api: 'https://shared.example.test/v1',
      });
      expect(resolveOrcaRouterOrigins(envWith({
        sharedBaseOverride: 'https://shared.example.test',
        apiBaseOverride: 'https://inference.example.test/v1',
      }))).toEqual({
        auth: 'https://shared.example.test',
        api: 'https://inference.example.test/v1',
      });
    });

    it('accepts HTTP only for loopback', () => {
      expect(normalizeOrcaOrigin('http://localhost:8787', 'test')).toBe('http://localhost:8787');
      expect(normalizeOrcaOrigin('http://127.0.0.1:8787/', 'test')).toBe('http://127.0.0.1:8787');
      expect(() => normalizeOrcaOrigin('http://api.orcarouter.ai/v1', 'test')).toThrow(/HTTPS/);
    });

    it('rejects credentials, queries, and fragments in origins', () => {
      expect(() => normalizeOrcaOrigin('https://user:pass@api.example.test/v1', 'test')).toThrow(/credentials/);
      expect(() => normalizeOrcaOrigin('https://api.example.test/v1?x=1', 'test')).toThrow(/query/);
      expect(() => normalizeOrcaOrigin('https://api.example.test/v1#frag', 'test')).toThrow(/query/);
      expect(() => normalizeOrcaOrigin('not a url', 'test')).toThrow(/valid URL/);
    });
  });

  describe('capability filters', () => {
    const chat = seedModels('chat')[0];

    it('accepts text chat on a text endpoint', () => {
      expect(modelMatches(chat, 'chat')).toBe(true);
    });

    it('rejects a model that explicitly declares non-text output', () => {
      expect(modelMatches({ ...chat, output_modalities: ['image'] }, 'chat')).toBe(false);
      expect(modelMatches({ ...chat, output_modalities: [] }, 'chat')).toBe(true);
    });

    it('rejects every non-chat endpoint from the chat capability', () => {
      for (const endpoint of ['embeddings', 'image-generation', 'openai-video', 'jina-rerank']) {
        expect(modelMatches({ ...chat, endpoint_types: [endpoint] }, 'chat')).toBe(false);
      }
      expect(modelMatches({ ...chat, endpoint_types: [] }, 'chat')).toBe(false);
    });

    it('fails closed on an unverifiable multimodal requirement', () => {
      expect(modelMatches({ ...chat, input_modalities: [] }, 'chat', 'image')).toBe(false);
      expect(modelMatches({ ...chat, input_modalities: ['text'] }, 'chat', 'image')).toBe(false);
      expect(modelMatches({ ...chat, input_modalities: ['text', 'image'] }, 'chat', 'image')).toBe(true);
    });

    it('requires the exact endpoint per non-chat capability', () => {
      expect(modelMatches({ ...chat, endpoint_types: ['embeddings'] }, 'embedding')).toBe(true);
      expect(modelMatches({ ...chat, endpoint_types: ['openai'] }, 'embedding')).toBe(false);
      expect(modelMatches({ ...chat, endpoint_types: ['image-generation'] }, 'image')).toBe(true);
      expect(modelMatches({ ...chat, endpoint_types: ['openai-video'] }, 'video')).toBe(true);
      expect(modelMatches({ ...chat, endpoint_types: ['jina-rerank'] }, 'rerank')).toBe(true);
    });
  });

  describe('discovery', () => {
    it('uses the live catalog and filters entries by metadata, not name', async () => {
      const stateDir = tmpStateDir();
      const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe('https://api.orcarouter.ai/v1/models?capability=chat');
        expect((init.headers as Record<string, string>).authorization).toBe('Bearer sk-orca-testkey12345678');
        return jsonResponse({
          data: [
            model({ id: 'provider/text-chat', name: 'DeepSeek Chatty' }),
            model({ id: 'provider/image-gen', name: 'Something Chat', supported_endpoint_types: ['image-generation'] }),
            model({ id: 'provider/image-out', architecture: { input_modalities: ['text'], output_modalities: ['image'] } }),
          ],
        });
      });

      const catalog = await discoverOrcaRouterModels({
        env: envWith({}),
        credential: { key: 'sk-orca-testkey12345678', generation: 'test', source: 'api_key' },
        fetchImpl: fetchImpl as any,
        stateDir,
        useCache: false,
      });

      expect(catalog.source).toBe('live');
      expect(catalog.degraded).toBe(false);
      expect(catalog.models.map((entry) => entry.id)).toEqual(['provider/text-chat']);
      expect(catalog.catalog_source).toBe('https://api.orcarouter.ai/v1/models?capability=chat');
    });

    it('never merges the seed into a successful live response', async () => {
      const stateDir = tmpStateDir();
      const catalog = await discoverOrcaRouterModels({
        env: envWith({}),
        credential: { key: 'sk-orca-testkey12345678', generation: 'test', source: 'api_key' },
        fetchImpl: (async () => jsonResponse({ data: [model({ id: 'provider/only-live' })] })) as any,
        stateDir,
        useCache: false,
      });
      expect(catalog.models.map((entry) => entry.id)).toEqual(['provider/only-live']);
      expect(catalog.models.some((entry) => entry.verified_seed)).toBe(false);
    });

    it('falls back to the marked seed only when live discovery fails', async () => {
      const stateDir = tmpStateDir();
      const catalog = await discoverOrcaRouterModels({
        env: envWith({}),
        credential: { key: 'sk-orca-testkey12345678', generation: 'test', source: 'api_key' },
        fetchImpl: (async () => new Response('nope', { status: 503 })) as any,
        stateDir,
        useCache: false,
      });
      expect(catalog.source).toBe('seed');
      expect(catalog.degraded).toBe(true);
      expect(catalog.error).toBe('provider_unavailable');
      expect(catalog.models.length).toBeGreaterThan(0);
      expect(catalog.models.every((entry) => entry.verified_seed)).toBe(true);
    });

    it('reports not_configured without a credential and still offers the seed', async () => {
      const catalog = await discoverOrcaRouterModels({
        env: envWith({}),
        stateDir: tmpStateDir(),
        useCache: false,
      });
      expect(catalog.source).toBe('seed');
      expect(catalog.error).toBe('not_configured');
    });

    it('treats a malformed or empty live body as degraded, not as success', async () => {
      const stateDir = tmpStateDir();
      const malformed = await discoverOrcaRouterModels({
        env: envWith({}),
        credential: { key: 'sk-orca-testkey12345678', generation: 't', source: 'api_key' },
        fetchImpl: (async () => jsonResponse({ models: [] })) as any,
        stateDir,
        useCache: false,
      });
      expect(malformed.source).toBe('seed');
      expect(malformed.error).toBe('catalog_malformed');

      resetOrcaRouterCatalogCache();
      const empty = await discoverOrcaRouterModels({
        env: envWith({}),
        credential: { key: 'sk-orca-testkey12345678', generation: 't', source: 'api_key' },
        fetchImpl: (async () => jsonResponse({ data: [] })) as any,
        stateDir,
        useCache: false,
      });
      expect(empty.source).toBe('seed');
      expect(empty.error).toBe('catalog_empty');
    });

    it('maps 401 and 429 into bounded, credential-free reasons', async () => {
      for (const [status, reason] of [[401, 'authentication_failed'], [429, 'rate_limited']] as const) {
        resetOrcaRouterCatalogCache();
        const catalog = await discoverOrcaRouterModels({
          env: envWith({}),
          credential: { key: 'sk-orca-testkey12345678', generation: 't', source: 'api_key' },
          fetchImpl: (async () => new Response('', { status })) as any,
          stateDir: tmpStateDir(),
          useCache: false,
        });
        expect(catalog.error).toBe(reason);
      }
    });

    it('applies the image modality to a live response', async () => {
      const catalog = await discoverOrcaRouterModels({
        env: envWith({}),
        capability: 'chat',
        modality: 'image',
        credential: { key: 'sk-orca-testkey12345678', generation: 't', source: 'api_key' },
        fetchImpl: (async () => jsonResponse({
          data: [
            model({ id: 'provider/text-only', architecture: { input_modalities: ['text'], output_modalities: ['text'] } }),
            model({ id: 'provider/vision', architecture: { input_modalities: ['text', 'image'], output_modalities: ['text'] } }),
            model({ id: 'provider/unstated', architecture: {} }),
          ],
        })) as any,
        stateDir: tmpStateDir(),
        useCache: false,
      });
      expect(catalog.models.map((entry) => entry.id)).toEqual(['provider/vision']);
    });

    it('keeps the bearer key out of logs and out of the returned catalog', async () => {
      const warn = vi.spyOn(logger, 'warn');
      const error = vi.spyOn(logger, 'error');
      const info = vi.spyOn(logger, 'info');
      const key = 'sk-orca-supersecretvalue9876';
      const catalog = await discoverOrcaRouterModels({
        env: envWith({}),
        credential: { key, generation: 't', source: 'api_key' },
        fetchImpl: (async () => new Response('denied', { status: 401 })) as any,
        stateDir: tmpStateDir(),
        useCache: false,
      });
      expect(JSON.stringify(catalog)).not.toContain(key);
      const logged = JSON.stringify([warn.mock.calls, error.mock.calls, info.mock.calls]);
      expect(logged).not.toContain(key);
    });
  });

  describe('chat relay', () => {
    it('posts an OpenAI-compatible request to the inference origin', async () => {
      const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe('https://api.orcarouter.ai/v1/chat/completions');
        expect((init.headers as Record<string, string>).authorization).toBe('Bearer sk-orca-key12345678');
        const body = JSON.parse(String(init.body));
        expect(body.model).toBe('orcarouter/auto');
        expect(body.messages).toEqual([
          { role: 'system', content: 'system' },
          { role: 'user', content: 'user' },
        ]);
        return jsonResponse({ choices: [{ message: { content: '{"ok":true}' } }], usage: { total_tokens: 3 } });
      });
      const result = await orcaRouterChatCompletion({
        apiKey: 'sk-orca-key12345678',
        origins: resolveOrcaRouterOrigins(envWith({})),
        model: 'orcarouter/auto',
        system: 'system',
        user: 'user',
        maxTokens: 64,
        temperature: 0,
        signal: new AbortController().signal,
        fetchImpl: fetchImpl as any,
      });
      expect(result.raw).toBe('{"ok":true}');
      expect(result.usage).toEqual({ total_tokens: 3 });
    });

    it('surfaces the HTTP status so the caller can mark exactly one generation', async () => {
      await expect(orcaRouterChatCompletion({
        apiKey: 'sk-orca-key12345678',
        origins: resolveOrcaRouterOrigins(envWith({})),
        model: 'orcarouter/auto',
        user: 'user',
        maxTokens: 16,
        temperature: 0,
        signal: new AbortController().signal,
        fetchImpl: (async () => new Response('', { status: 401 })) as any,
      })).rejects.toMatchObject({ status: 401 });
    });
  });
});
