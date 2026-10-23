// SPDX-License-Identifier: Apache-2.0
//
// OrcaRouter credential store: both auth adapters land here. These tests pin
// the properties the deployment depends on — sealed at rest, masked on read,
// env never mutated, and reauthentication scoped to exactly one generation.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  ORCAROUTER_MASKED_KEY,
  clearOrcaRouterCredential,
  getOrcaRouterModel,
  getOrcaRouterModelFor,
  getOrcaRouterModelSelection,
  orcaRouterCredentialFence,
  hasOrcaRouterCredential,
  looksLikeOrcaRouterKey,
  markOrcaRouterNeedsReauth,
  orcaRouterCredentialStatus,
  resolveOrcaRouterCredential,
  saveOrcaRouterApiKey,
  saveOrcaRouterPkceKey,
  saveOrcaRouterPkceKeyIfCurrent,
  setOrcaRouterModel,
  setOrcaRouterModelFor,
} from '../lib/providers/orcarouter-credentials.js';

const KEY = 'sk-orca-abcdef1234567890';

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-credentials-'));
  vi.stubEnv('ORCAROUTER_API_KEY', '');
  vi.stubEnv('TRUST_DESK_ORCAROUTER_MODEL', '');
  vi.stubEnv('TRUST_DESK_ORCAROUTER_EMBEDDING_MODEL', '');
  vi.stubEnv('ORCAROUTER_STATE_DIR', '');
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  fs.rmSync(stateDir, { recursive: true, force: true });
});

describe('OrcaRouter credential store', () => {
  it('recognizes only sk-orca- keys', () => {
    expect(looksLikeOrcaRouterKey(KEY)).toBe(true);
    expect(looksLikeOrcaRouterKey('sk-orca-')).toBe(false);
    expect(looksLikeOrcaRouterKey('sk-openai-abcdef1234567890')).toBe(false);
    expect(looksLikeOrcaRouterKey('Bearer sk-orca-abcdef1234567890')).toBe(false);
  });

  it('seals the key at rest and never stores plaintext', async () => {
    const status = await saveOrcaRouterApiKey(KEY, stateDir);
    expect(status.configured).toBe(true);
    expect(status.source).toBe('api_key');
    expect(status.masked).toBe(ORCAROUTER_MASKED_KEY);

    const file = path.join(stateDir, 'credential.json');
    const raw = fs.readFileSync(file, 'utf8');
    expect(raw).not.toContain(KEY);
    expect(raw).not.toContain('abcdef1234567890');
    expect(raw).toContain('epenc:v1:');
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);

    const resolved = await resolveOrcaRouterCredential(stateDir);
    expect(resolved).toMatchObject({ ok: true, key: KEY, source: 'api_key', scope: 'api' });
    expect(resolved.ok && resolved.generation).toMatch(/^[0-9a-f]{32}$/);
  });

  it('rejects a malformed key instead of persisting it', async () => {
    await expect(saveOrcaRouterApiKey('not-a-key', stateDir)).rejects.toThrow('invalid_key_format');
    expect(fs.existsSync(path.join(stateDir, 'credential.json'))).toBe(false);
  });

  it('prefers a stored credential over the environment', async () => {
    vi.stubEnv('ORCAROUTER_API_KEY', 'sk-orca-fromenvironment1234');
    const before = await resolveOrcaRouterCredential(stateDir);
    expect(before).toMatchObject({ ok: true, source: 'env' });

    await saveOrcaRouterApiKey(KEY, stateDir);
    const after = await resolveOrcaRouterCredential(stateDir);
    expect(after).toMatchObject({ ok: true, key: KEY, source: 'api_key' });
  });

  it('clearing removes only the stored credential, never the environment', async () => {
    vi.stubEnv('ORCAROUTER_API_KEY', 'sk-orca-fromenvironment1234');
    await saveOrcaRouterApiKey(KEY, stateDir);
    expect(hasOrcaRouterCredential(stateDir)).toBe(true);

    const status = await clearOrcaRouterCredential(stateDir);
    expect(fs.existsSync(path.join(stateDir, 'credential.json'))).toBe(false);
    expect(status.source).toBe('env');
    expect(status.configured).toBe(true);
    const resolved = await resolveOrcaRouterCredential(stateDir);
    expect(resolved).toMatchObject({ ok: true, source: 'env', key: 'sk-orca-fromenvironment1234' });
  });

  it('reports not_configured when neither source exists', async () => {
    const status = await orcaRouterCredentialStatus(stateDir);
    expect(status).toMatchObject({ configured: false, masked: null, error: 'not_configured' });
    expect(await resolveOrcaRouterCredential(stateDir)).toMatchObject({ ok: false, reason: 'not_configured' });
  });

  it('marks exactly the rejected generation as needing reauth', async () => {
    const first = await saveOrcaRouterApiKey(KEY, stateDir);
    const generation = first.generation as string;

    await markOrcaRouterNeedsReauth('a-different-generation', stateDir);
    expect(await resolveOrcaRouterCredential(stateDir)).toMatchObject({ ok: true });

    await markOrcaRouterNeedsReauth(generation, stateDir);
    const blocked = await resolveOrcaRouterCredential(stateDir);
    expect(blocked).toMatchObject({ ok: false, reason: 'needs_reauth' });

    // A later credential is a new generation and is unaffected by the old mark.
    const second = await saveOrcaRouterPkceKey(KEY, 'api', stateDir);
    expect(second.generation).not.toBe(generation);
    expect(await resolveOrcaRouterCredential(stateDir)).toMatchObject({ ok: true, source: 'pkce' });

    // Late 401 from the first generation cannot poison the current credential.
    await markOrcaRouterNeedsReauth(generation, stateDir);
    expect(await resolveOrcaRouterCredential(stateDir)).toMatchObject({ ok: true, source: 'pkce' });

    // The environment source is not a stored generation.
    await markOrcaRouterNeedsReauth('env', stateDir);
    expect(await resolveOrcaRouterCredential(stateDir)).toMatchObject({ ok: true });
  });

  it('fails closed on a tampered or malformed stored record', async () => {
    await saveOrcaRouterApiKey(KEY, stateDir);
    const file = path.join(stateDir, 'credential.json');
    const record = JSON.parse(fs.readFileSync(file, 'utf8'));
    record.sealed_key = `${String(record.sealed_key).slice(0, -4)}AAAA`;
    fs.writeFileSync(file, JSON.stringify(record));

    const tampered = await resolveOrcaRouterCredential(stateDir);
    expect(tampered).toMatchObject({ ok: false, reason: 'unreadable' });
    expect(JSON.stringify(tampered)).not.toContain(KEY);

    fs.writeFileSync(file, '{not json');
    expect(await resolveOrcaRouterCredential(stateDir)).toMatchObject({ ok: false, reason: 'unreadable' });
    // A broken file must not silently resolve to "no credential configured".
    const broken = await orcaRouterCredentialStatus(stateDir);
    expect(broken.configured).toBe(false);
    expect(broken.error).toBe('unreadable');
  });

  it('keeps the masked status free of any key material', async () => {
    await saveOrcaRouterApiKey(KEY, stateDir);
    const status = await orcaRouterCredentialStatus(stateDir);
    expect(JSON.stringify(status)).not.toContain(KEY);
    expect(status.masked).toBe('sk-orca-…');
  });

  describe('model preference', () => {
    it('defaults to the brand default and falls back to the env override', async () => {
      expect(await getOrcaRouterModel(stateDir)).toBe('orcarouter/auto');
      vi.stubEnv('TRUST_DESK_ORCAROUTER_MODEL', 'orcacyber-ultra-1.0');
      expect(await getOrcaRouterModel(stateDir)).toBe('orcacyber-ultra-1.0');
    });

    it('prefers an explicit selection over the env override', async () => {
      vi.stubEnv('TRUST_DESK_ORCAROUTER_MODEL', 'orcacyber-ultra-1.0');
      await setOrcaRouterModel('orcacyber-zero-1.5', stateDir);
      expect(await getOrcaRouterModel(stateDir)).toBe('orcacyber-zero-1.5');
      expect(fs.statSync(path.join(stateDir, 'settings.json')).mode & 0o777).toBe(0o600);
    });


    it('stores chat and embedding selections independently', async () => {
      await setOrcaRouterModelFor('chat', 'orcarouter/auto', stateDir);
      await setOrcaRouterModelFor('embedding', 'openai/text-embedding-3-small', stateDir);

      expect(await getOrcaRouterModelSelection('chat', stateDir)).toBe('orcarouter/auto');
      expect(await getOrcaRouterModelSelection('embedding', stateDir)).toBe('openai/text-embedding-3-small');
      expect(await getOrcaRouterModelFor('embedding', stateDir)).toBe('openai/text-embedding-3-small');

      // Changing the chat model must not move the embedding selection.
      await setOrcaRouterModelFor('chat', 'orcacyber-ultra-1.0', stateDir);
      expect(await getOrcaRouterModelFor('chat', stateDir)).toBe('orcacyber-ultra-1.0');
      expect(await getOrcaRouterModelFor('embedding', stateDir)).toBe('openai/text-embedding-3-small');
    });

    it('defaults embeddings separately from chat and honours the embedding override', async () => {
      expect(await getOrcaRouterModelFor('embedding', stateDir)).toBe('openai/text-embedding-3-small');
      vi.stubEnv('TRUST_DESK_ORCAROUTER_EMBEDDING_MODEL', 'acme/embed-large');
      expect(await getOrcaRouterModelFor('embedding', stateDir)).toBe('acme/embed-large');
      // The chat default is unaffected by the embedding override.
      expect(await getOrcaRouterModelFor('chat', stateDir)).toBe('orcarouter/auto');
    });

    it('reads a legacy single-model settings file as the chat selection only', async () => {
      fs.writeFileSync(path.join(stateDir, 'settings.json'), JSON.stringify({ model: 'orcacyber-zero-1.5' }));
      expect(await getOrcaRouterModelSelection('chat', stateDir)).toBe('orcacyber-zero-1.5');
      expect(await getOrcaRouterModelSelection('embedding', stateDir)).toBeNull();
    });

    it('rejects an unknown capability', async () => {
      await expect(setOrcaRouterModelFor('telepathy' as any, 'orcarouter/auto', stateDir))
        .rejects.toThrow('invalid_capability');
    });

    it('rejects a malformed model id', async () => {
      await expect(setOrcaRouterModel('bad model with spaces', stateDir)).rejects.toThrow('invalid_model_id');
      await expect(setOrcaRouterModel('', stateDir)).rejects.toThrow('invalid_model_id');
    });
  });

  describe('credential write fence', () => {
    it('refuses a PKCE write when a newer credential was stored meanwhile', async () => {
      const fenceAtStart = orcaRouterCredentialFence(stateDir);
      expect(fenceAtStart).toBe('none');

      const newer = await saveOrcaRouterApiKey(KEY, stateDir);
      expect(() => saveOrcaRouterPkceKeyIfCurrent(KEY, 'api', fenceAtStart, stateDir))
        .toThrow('credential_superseded');

      const current = await resolveOrcaRouterCredential(stateDir);
      expect(current).toMatchObject({ ok: true, source: 'api_key', generation: newer.generation });
    });

    it('writes when the fence still matches and then advances it', async () => {
      const fenceAtStart = orcaRouterCredentialFence(stateDir);
      const saved = saveOrcaRouterPkceKeyIfCurrent(KEY, 'api', fenceAtStart, stateDir);
      expect(saved.source).toBe('pkce');
      expect(saved.generation).not.toBe(fenceAtStart);
      // The same attempt cannot be replayed against the new generation.
      expect(() => saveOrcaRouterPkceKeyIfCurrent(KEY, 'api', fenceAtStart, stateDir))
        .toThrow('credential_superseded');
    });
  });
});
