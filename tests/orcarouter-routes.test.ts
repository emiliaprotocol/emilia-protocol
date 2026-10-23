// SPDX-License-Identifier: Apache-2.0
//
// Route-level guards for the OrcaRouter provider settings API.
//
// Every route must authenticate an internal administrator session. The feature
// flag only decides whether the surface exists; it is not an identity. PKCE
// attempts are bound to the administrator that started them, and mutations
// require an explicit same-origin Origin header. These tests exercise the real
// route handlers, not a reimplementation of the guards.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NextRequest } from 'next/server';

import { GET as statusGET } from '../app/api/orcarouter/status/route.js';
import { GET as modelsGET } from '../app/api/orcarouter/models/route.js';
import { GET as preferencesGET, POST as preferencesPOST } from '../app/api/orcarouter/preferences/route.js';
import {
  DELETE as credentialDELETE,
  GET as credentialGET,
  POST as credentialPOST,
} from '../app/api/orcarouter/credential/route.js';
import { POST as startPOST } from '../app/api/orcarouter/connect/start/route.js';
import { POST as completePOST } from '../app/api/orcarouter/connect/complete/route.js';
import { POST as cancelPOST } from '../app/api/orcarouter/connect/cancel/route.js';
import {
  getOrcaRouterModelSelection,
  setOrcaRouterModelFor,
} from '../lib/providers/orcarouter-credentials.js';

const SESSION_SECRET = 'route-test-session-secret-0123456789abcdef';
const ADMIN_A = 'admin-a@example.test';
const ADMIN_B = 'admin-b@example.test';
const KEY = 'sk-orca-routekey1234567890';
const ORIGIN = 'http://localhost:3000';

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-routes-'));
  vi.stubEnv('ORCAROUTER_PROVIDER_ADMIN', '1');
  vi.stubEnv('ORCAROUTER_STATE_DIR', stateDir);
  vi.stubEnv('ORCAROUTER_API_KEY', '');
  vi.stubEnv('TRUST_DESK_SESSION_SECRET', SESSION_SECRET);
  vi.stubEnv('TRUST_DESK_REVIEWER_ID', ADMIN_A);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  fs.rmSync(stateDir, { recursive: true, force: true });
});

function signSession(reviewerId: string): string {
  const payload = Buffer.from(JSON.stringify({
    purpose: 'trust-desk-reviewer',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: crypto.randomBytes(24).toString('base64url'),
    reviewer_id: reviewerId,
  }), 'utf8').toString('base64url');
  const mac = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `tds1.${payload}.${mac}`;
}

function request(
  url: string,
  options: { method?: string; reviewer?: string | null; origin?: string | null; body?: unknown } = {},
): NextRequest {
  const headers: Record<string, string> = { host: 'localhost:3000' };
  if (options.reviewer !== null) {
    headers.cookie = `td_internal=${signSession(options.reviewer || ADMIN_A)}`;
  }
  if (options.origin) headers.origin = options.origin;
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  return new NextRequest(`${ORIGIN}${url}`, {
    method: options.method || 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
}

describe('OrcaRouter settings routes', () => {
  it('rejects every route without an authenticated administrator session', async () => {
    const anonymous = { reviewer: null as null };
    const responses = await Promise.all([
      statusGET(request('/api/orcarouter/status', anonymous)),
      modelsGET(request('/api/orcarouter/models', anonymous)),
      preferencesGET(request('/api/orcarouter/preferences', anonymous)),
      credentialGET(request('/api/orcarouter/credential', anonymous)),
      credentialPOST(request('/api/orcarouter/credential', { ...anonymous, method: 'POST', origin: ORIGIN, body: { api_key: KEY } })),
      credentialDELETE(request('/api/orcarouter/credential', { ...anonymous, method: 'DELETE', origin: ORIGIN })),
      startPOST(request('/api/orcarouter/connect/start', { ...anonymous, method: 'POST', origin: ORIGIN })),
      completePOST(request('/api/orcarouter/connect/complete', { ...anonymous, method: 'POST', origin: ORIGIN, body: { attempt_id: 'x'.repeat(24), code: 'c' } })),
      cancelPOST(request('/api/orcarouter/connect/cancel', { ...anonymous, method: 'POST', origin: ORIGIN, body: { attempt_id: 'x'.repeat(24) } })),
      preferencesPOST(request('/api/orcarouter/preferences', { ...anonymous, method: 'POST', origin: ORIGIN, body: { capability: 'chat', model: 'orcarouter/auto' } })),
    ]);
    for (const response of responses) {
      expect(response.status).toBe(401);
    }
    // Nothing was written while unauthenticated.
    expect(fs.existsSync(path.join(stateDir, 'credential.json'))).toBe(false);
  });

  it('keeps the feature flag as a 404 gate, separate from authentication', async () => {
    vi.stubEnv('ORCAROUTER_PROVIDER_ADMIN', '0');
    const response = await statusGET(request('/api/orcarouter/status'));
    expect(response.status).toBe(404);
  });

  it('returns masked provider status to an authenticated administrator', async () => {
    vi.stubEnv('ORCAROUTER_API_KEY', KEY);
    const response = await statusGET(request('/api/orcarouter/status'));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.credential).toMatchObject({ configured: true, source: 'env', masked: 'sk-orca-…' });
    expect(body.models.selections).toHaveProperty('chat');
    expect(JSON.stringify(body)).not.toContain(KEY);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('requires an explicit same-origin Origin on mutations', async () => {
    const missing = await credentialPOST(request('/api/orcarouter/credential', {
      method: 'POST',
      body: { api_key: KEY },
    }));
    expect(missing.status).toBe(403);
    expect((await missing.json()).type).toMatch(/origin_required$/);

    const cross = await credentialPOST(request('/api/orcarouter/credential', {
      method: 'POST',
      origin: 'http://evil.test',
      body: { api_key: KEY },
    }));
    expect(cross.status).toBe(403);

    const accepted = await credentialPOST(request('/api/orcarouter/credential', {
      method: 'POST',
      origin: ORIGIN,
      body: { api_key: KEY },
    }));
    expect(accepted.status).toBe(201);
    const body = await accepted.json();
    expect(body.credential).toMatchObject({ configured: true, source: 'api_key', masked: 'sk-orca-…' });
    expect(JSON.stringify(body)).not.toContain(KEY);

    const cleared = await credentialDELETE(request('/api/orcarouter/credential', {
      method: 'DELETE',
      origin: ORIGIN,
    }));
    expect(cleared.status).toBe(200);
    expect(fs.existsSync(path.join(stateDir, 'credential.json'))).toBe(false);
  });

  it('stores and reads model selections per capability', async () => {
    await setOrcaRouterModelFor('chat', 'orcarouter/auto', stateDir);
    await setOrcaRouterModelFor('embedding', 'openai/text-embedding-3-small', stateDir);

    const chat = await preferencesGET(request('/api/orcarouter/preferences?capability=chat'));
    const embedding = await preferencesGET(request('/api/orcarouter/preferences?capability=embedding'));
    expect(chat.status).toBe(200);
    expect(embedding.status).toBe(200);
    expect(await chat.json()).toMatchObject({ capability: 'chat', model: 'orcarouter/auto' });
    expect(await embedding.json()).toMatchObject({ capability: 'embedding', model: 'openai/text-embedding-3-small' });

    // A chat write never disturbs the embedding selection.
    await setOrcaRouterModelFor('chat', 'orcacyber-ultra-1.0', stateDir);
    expect(await getOrcaRouterModelSelection('embedding', stateDir)).toBe('openai/text-embedding-3-small');
  });

  it('rejects an unknown capability instead of defaulting it to chat', async () => {
    const post = await preferencesPOST(request('/api/orcarouter/preferences', {
      method: 'POST',
      origin: ORIGIN,
      body: { capability: 'telepathy', model: 'orcarouter/auto' },
    }));
    expect(post.status).toBe(400);

    const get = await preferencesGET(request('/api/orcarouter/preferences?capability=telepathy'));
    expect(get.status).toBe(400);
  });

  it('binds PKCE attempts to the starting administrator end to end', async () => {
    const started = await startPOST(request('/api/orcarouter/connect/start', {
      method: 'POST',
      origin: ORIGIN,
      reviewer: ADMIN_A,
    }));
    expect(started.status).toBe(201);
    const { attempt_id } = await started.json();
    expect(typeof attempt_id).toBe('string');

    const stolen = await completePOST(request('/api/orcarouter/connect/complete', {
      method: 'POST',
      origin: ORIGIN,
      reviewer: ADMIN_B,
      body: { attempt_id, code: 'displayed-code' },
    }));
    expect(stolen.status).toBe(403);
    expect((await stolen.json()).type).toMatch(/wrong_principal$/);

    const stolenCancel = await cancelPOST(request('/api/orcarouter/connect/cancel', {
      method: 'POST',
      origin: ORIGIN,
      reviewer: ADMIN_B,
      body: { attempt_id },
    }));
    expect(stolenCancel.status).toBe(403);

    const ownedCancel = await cancelPOST(request('/api/orcarouter/connect/cancel', {
      method: 'POST',
      origin: ORIGIN,
      reviewer: ADMIN_A,
      body: { attempt_id },
    }));
    expect(ownedCancel.status).toBe(200);
    expect(await ownedCancel.json()).toMatchObject({ cancelled: true });
  });
});
