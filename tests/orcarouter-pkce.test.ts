// SPDX-License-Identifier: Apache-2.0
//
// OAuth 2.0 + PKCE (Flow B, out-of-band) adapter. A local HTTP server stands in
// for the OrcaRouter authorization service so the exchange URL, body, scope
// handling, single-use code, and generation rules are asserted end to end.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';

import {
  ORCAROUTER_AUTHZ_PATH,
  ORCAROUTER_EXCHANGE_PATH,
  OrcaRouterPkceError,
  cancelOrcaRouterAuthorization,
  completeOrcaRouterAuthorization,
  createPkceChallenge,
  pendingOrcaRouterAuthorizations,
  safeStateEqual,
  startOrcaRouterAuthorization,
} from '../lib/providers/orcarouter-pkce.js';
import { logger } from '../lib/logger.js';

const KEY = 'sk-orca-pkceissued1234567890';

interface Recorded {
  url: string;
  method: string;
  body: any;
  headers: http.IncomingHttpHeaders;
}

let stateDir: string;
let server: http.Server;
let origin: string;
let recorded: Recorded[];
let respond: (req: Recorded, res: http.ServerResponse) => void;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-pkce-'));
  recorded = [];
  respond = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ key: KEY, scope: 'api' }));
  };
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const entry: Recorded = {
        url: req.url || '',
        method: req.method || '',
        body: chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null,
        headers: req.headers,
      };
      recorded.push(entry);
      respond(entry, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  vi.stubEnv('ORCAROUTER_STATE_DIR', '');
});

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  fs.rmSync(stateDir, { recursive: true, force: true });
});

const pendingPath = (attemptId: string) => path.join(stateDir, 'pending', `${attemptId}.json`);
const readPending = (attemptId: string) => JSON.parse(fs.readFileSync(pendingPath(attemptId), 'utf8'));

const save = vi.fn(async () => ({ masked: 'sk-orca-…', generation: 'gen-1' }));

describe('OrcaRouter PKCE adapter', () => {
  it('creates a fresh verifier, S256 challenge, and state every call', () => {
    const first = createPkceChallenge();
    const second = createPkceChallenge();
    expect(first.verifier).not.toBe(second.verifier);
    expect(first.state).not.toBe(second.state);
    expect(first.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.state).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(first.challenge).toBe(
      crypto.createHash('sha256').update(first.verifier, 'utf8').digest('base64url'),
    );
    expect(first.verifier).not.toContain('=');
    expect(first.challenge).not.toContain('=');
  });

  it('compares state in constant time without throwing on length mismatch', () => {
    expect(safeStateEqual('abc', 'abc')).toBe(true);
    expect(safeStateEqual('abc', 'abd')).toBe(false);
    expect(safeStateEqual('abc', 'abcdef')).toBe(false);
    expect(safeStateEqual('', '')).toBe(true);
  });

  it('authorizes against the auth origin and never puts the verifier in the URL', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    expect(started.delivery).toBe('oob');
    expect(started.scope).toBe('api');
    expect(started.auth_origin).toBe(origin);

    const url = new URL(started.authorize_url);
    expect(url.origin + url.pathname).toBe(`${origin}${ORCAROUTER_AUTHZ_PATH}`);
    expect(url.searchParams.get('callback_url')).toBe('oob');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('scope')).toBe('api');
    expect(url.searchParams.get('app_name')).toBe('EMILIA Protocol');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const pending = readPending(started.attempt_id);
    expect(url.searchParams.get('state')).toBe(pending.state);
    expect(fs.readFileSync(pendingPath(started.attempt_id), 'utf8')).not.toContain(
      Buffer.from(String(pending.state), 'base64url').toString('hex'),
    );
    expect(pending.sealed_verifier).toMatch(/^epenc:v1:/);
    expect(JSON.stringify(started)).not.toContain('verifier');
    expect(JSON.stringify(pending)).not.toContain('code_verifier');

    // The S256 challenge in the URL must correspond to the sealed verifier.
    const verifier = (await import('../lib/crypto/secret-box.js')).open(pending.sealed_verifier);
    expect(crypto.createHash('sha256').update(verifier).digest('base64url'))
      .toBe(url.searchParams.get('code_challenge'));
  });

  it('exchanges the code at /api/v1/auth/keys on the auth origin', async () => {
    save.mockClear();
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const pending = readPending(started.attempt_id);

    const completed = await completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: '  displayed-code  ',
      state: pending.state,
      principalId: 'admin-a',
      stateDir,
      save,
    });

    expect(recorded).toHaveLength(1);
    expect(recorded[0].method).toBe('POST');
    expect(recorded[0].url).toBe(ORCAROUTER_EXCHANGE_PATH);
    expect(recorded[0].url).toBe('/api/v1/auth/keys');
    expect(recorded[0].body).toMatchObject({ code: 'displayed-code', code_challenge_method: 'S256' });
    expect(recorded[0].body.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(recorded[0].body).not.toHaveProperty('client_secret');
    expect(recorded[0].body).not.toHaveProperty('redirect_uri');

    expect(save).toHaveBeenCalledWith(KEY, 'api', expect.any(String));
    expect(completed).toEqual({ source: 'pkce', masked: 'sk-orca-…', scope: 'api', generation: 'gen-1' });
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(0);
  });

  it('consumes the attempt before exchanging, so a replay cannot mint a second key', async () => {
    save.mockClear();
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const pending = readPending(started.attempt_id);
    await completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      state: pending.state,
      principalId: 'admin-a',
      stateDir,
      save,
    });

    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      state: pending.state,
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'unknown_attempt' });
    expect(recorded).toHaveLength(1);
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('rejects a state mismatch and burns the attempt', async () => {
    save.mockClear();
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      state: 'attacker-state',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'state_mismatch' });
    expect(recorded).toHaveLength(0);
    expect(save).not.toHaveBeenCalled();
    expect(fs.existsSync(pendingPath(started.attempt_id))).toBe(false);
  });

  it('rejects an expired attempt before contacting the service', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const pending = readPending(started.attempt_id);
    fs.writeFileSync(pendingPath(started.attempt_id), JSON.stringify({
      ...pending,
      expires_at: new Date(Date.now() - 1_000).toISOString(),
    }));

    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'expired' });
    expect(recorded).toHaveLength(0);
  });

  it('maps denial, rate limiting, and server failure without leaking the verifier', async () => {
    const warn = vi.spyOn(logger, 'warn');
    const cases: Array<[number, string]> = [
      [403, 'code_rejected'],
      [400, 'invalid_request'],
      [429, 'rate_limited'],
      [500, 'server_error'],
    ];
    for (const [status, code] of cases) {
      const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
      respond = (_req, res) => {
        res.writeHead(status, { 'content-type': 'text/plain' });
        res.end('denied');
      };
      await expect(completeOrcaRouterAuthorization({
        origins: { auth: origin, api: 'https://api.example.test/v1' },
        attemptId: started.attempt_id,
        code: 'code',
        principalId: 'admin-a',
        stateDir,
        save,
      })).rejects.toMatchObject({ code });
    }
    const logged = JSON.stringify(warn.mock.calls);
    expect(logged).toContain('authorization exchange rejected');
    expect(logged).not.toMatch(/[A-Za-z0-9_-]{43}/);
  });

  it('reports a network failure as network_error', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const deadOrigin = origin;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: deadOrigin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'network_error' });
    // Re-open a listener so afterEach's close() has something to close.
    server = http.createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  });

  it('requires the api scope actually granted by the approval', async () => {
    save.mockClear();
    respond = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ key: KEY, scope: 'read' }));
    };
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'scope_not_granted' });
    expect(save).not.toHaveBeenCalled();
  });

  it('rejects a response that does not carry a usable key', async () => {
    for (const payload of [{ scope: 'api' }, { key: 'not-a-key', scope: 'api' }, { key: KEY }]) {
      respond = (_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
      await expect(completeOrcaRouterAuthorization({
        origins: { auth: origin, api: 'https://api.example.test/v1' },
        attemptId: started.attempt_id,
        code: 'code',
        principalId: 'admin-a',
        stateDir,
        save,
      })).rejects.toBeInstanceOf(OrcaRouterPkceError);
    }
    // A body that is not JSON at all.
    respond = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('not json');
    };
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'invalid_grant_response' });
  });

  it('requires a non-empty displayed code before consuming the attempt', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: '   ',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'invalid_request' });
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(1);
  });

  it('cancels idempotently and refuses malformed attempt ids', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(1);
    cancelOrcaRouterAuthorization(started.attempt_id, 'admin-a', stateDir);
    cancelOrcaRouterAuthorization(started.attempt_id, 'admin-a', stateDir);
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(0);
    expect(() => cancelOrcaRouterAuthorization('../../etc/passwd', 'admin-a', stateDir)).not.toThrow();
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: '../../etc/passwd',
      code: 'code',
      principalId: 'admin-a',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'invalid_request' });
  });

  it('binds a pending attempt to the administrator that started it', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const pending = readPending(started.attempt_id);

    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      state: pending.state,
      principalId: 'admin-b',
      stateDir,
      save,
    })).rejects.toMatchObject({ code: 'wrong_principal' });

    // The rightful owner can still finish it; the failed attempt did not burn it.
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(1);
    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      state: pending.state,
      principalId: 'admin-a',
      stateDir,
      save,
    })).resolves.toMatchObject({ source: 'pkce' });
  });

  it('passes the start-time credential fence to the save and reports supersession', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const pending = readPending(started.attempt_id);
    const rejecting = vi.fn(async () => {
      throw new Error('credential_superseded');
    });

    await expect(completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'code',
      state: pending.state,
      principalId: 'admin-a',
      stateDir,
      save: rejecting,
    })).rejects.toMatchObject({ code: 'superseded' });
    expect(rejecting).toHaveBeenCalledWith(KEY, 'api', pending.credential_generation);
  });

  it('refuses cancellation by another administrator', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    expect(() => cancelOrcaRouterAuthorization(started.attempt_id, 'admin-b', stateDir))
      .toThrow(/another administrator/);
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(1);
    expect(cancelOrcaRouterAuthorization(started.attempt_id, 'admin-a', stateDir)).toBe(true);
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(0);
  });

  it('refuses to save when the attempt is cancelled during the exchange', async () => {
    const started = await startOrcaRouterAuthorization({ origins: { auth: origin, api: 'https://api.example.test/v1' }, principalId: 'admin-a', stateDir });
    const pending = readPending(started.attempt_id);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const delayedFetch = (async () => {
      await gate;
      return new Response(JSON.stringify({ key: KEY, scope: 'api' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as any;
    const saving = vi.fn(async () => ({ masked: 'sk-orca-…', generation: 'gen-1' }));

    const completion = completeOrcaRouterAuthorization({
      origins: { auth: origin, api: 'https://api.example.test/v1' },
      attemptId: started.attempt_id,
      code: 'displayed-code',
      state: pending.state,
      principalId: 'admin-a',
      fetchImpl: delayedFetch,
      stateDir,
      save: saving,
    });

    // The attempt is consumed and the exchange is in flight; cancel now.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(cancelOrcaRouterAuthorization(started.attempt_id, 'admin-a', stateDir)).toBe(true);
    release();

    await expect(completion).rejects.toMatchObject({ code: 'cancelled' });
    expect(saving).not.toHaveBeenCalled();
    expect(pendingOrcaRouterAuthorizations(stateDir)).toBe(0);
  });
});
