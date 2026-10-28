/**
 * OrcaRouter OAuth 2.0 + PKCE — out-of-band (Flow B) connect adapter.
 *
 * @license Apache-2.0
 *
 * Why Flow B: this is a self-hosted deployment whose install address differs
 * per operator, and the browser that approves consent is not guaranteed to
 * share a loopback listener with the server that holds the credential. The
 * consent screen therefore displays a short code, and the operator pastes it
 * into the settings surface. Flow A (loopback redirect) and Flow C (device
 * grant) are deliberately not implemented.
 *
 * Properties that must not regress:
 *   - verifier and state are fresh cryptographic randomness per attempt;
 *   - only base64url(sha256(verifier)) travels on the authorize URL;
 *   - the verifier never appears in a URL, log, error, or telemetry event;
 *   - the exchange POST goes to the AUTH origin at /api/v1/auth/keys — never
 *     the inference origin and never /v1/auth/keys;
 *   - a code is single-use, and the pending attempt is consumed before the
 *     exchange so a replay can never mint a second key;
 *   - the granted scope is read back and must satisfy this integration;
 *   - no client secret, no pre-registered redirect URI.
 *
 * The exchange returns a durable OrcaRouter API key, not a refresh token.
 * There is no refresh grant and none is invented here.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { logger } from '../logger.js';
import { open as openSecret, seal } from '../crypto/secret-box.js';
import type { OrcaRouterOrigins } from './orcarouter.js';
import { orcaRouterCredentialFence, orcaRouterStateDir, withOrcaRouterCredentialLock } from './orcarouter-credentials.js';

export const ORCAROUTER_AUTHZ_PATH = '/auth';
export const ORCAROUTER_EXCHANGE_PATH = '/api/v1/auth/keys';
export const ORCAROUTER_PKCE_ATTEMPT_TTL_MS = 10 * 60 * 1000;
const MAX_EXCHANGE_BYTES = 64 * 1024;
const ATTEMPT_ID_FORMAT = /^[A-Za-z0-9_-]{16,64}$/;

export type OrcaRouterPkceErrorCode =
  | 'invalid_request'
  | 'state_mismatch'
  | 'expired'
  | 'unknown_attempt'
  | 'attempt_unreadable'
  | 'code_rejected'
  | 'invalid_grant_response'
  | 'scope_not_granted'
  | 'wrong_principal'
  | 'superseded'
  | 'credential_busy'
  | 'cancelled'
  | 'rate_limited'
  | 'network_error'
  | 'server_error';

export class OrcaRouterPkceError extends Error {
  code: OrcaRouterPkceErrorCode;

  constructor(code: OrcaRouterPkceErrorCode, message: string) {
    super(message);
    this.name = 'OrcaRouterPkceError';
    this.code = code;
  }
}

export interface PkceChallenge {
  verifier: string;
  challenge: string;
  state: string;
}

interface PendingAttempt {
  version: 1;
  attempt_id: string;
  sealed_verifier: string;
  state: string;
  app_name: string;
  /** Authenticated administrator that started this attempt; completion and cancellation must match. */
  principal_id: string;
  /** Credential generation at start; the write is fenced against it. */
  credential_generation: string;
  /** Set when the code has been taken for exchange; a replay must be refused. */
  consumed_at?: string;
  created_at: string;
  expires_at: string;
}

export interface StartedAuthorization {
  attempt_id: string;
  authorize_url: string;
  expires_at: string;
  scope: 'api';
  auth_origin: string;
  delivery: 'oob';
}

export interface CompletedAuthorization {
  source: 'pkce';
  masked: string;
  scope: string;
  generation: string;
}

function b64url(bytes: Buffer): string {
  return bytes.toString('base64url');
}

/** Fresh verifier, S256 challenge, and opaque state — cryptographic RNG per call. */
export function createPkceChallenge(): PkceChallenge {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier, 'utf8').digest());
  const state = b64url(crypto.randomBytes(16));
  return { verifier, challenge, state };
}

/** Constant-time comparison of two opaque strings. */
export function safeStateEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function pendingDir(stateDir?: string): string {
  return path.join(orcaRouterStateDir(stateDir), 'pending');
}

function attemptPath(attemptId: string, stateDir?: string): string {
  if (!ATTEMPT_ID_FORMAT.test(attemptId)) {
    throw new OrcaRouterPkceError('invalid_request', 'malformed attempt id');
  }
  return path.join(pendingDir(stateDir), `${attemptId}.json`);
}

function writePrivateJson(target: string, value: unknown): void {
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(temporary, target);
}

function readAttempt(attemptId: string, stateDir?: string, strict = false): PendingAttempt {
  const target = attemptPath(attemptId, stateDir);
  let parsed: any;
  try {
    parsed = JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (error: any) {
    if (strict && error?.code !== 'ENOENT') {
      throw new OrcaRouterPkceError('attempt_unreadable', 'authorization attempt state is unavailable');
    }
    throw new OrcaRouterPkceError('unknown_attempt', 'authorization attempt not found or already used');
  }
  if (!parsed || typeof parsed !== 'object' || parsed.attempt_id !== attemptId) {
    if (strict) throw new OrcaRouterPkceError('attempt_unreadable', 'authorization attempt state is unavailable');
    throw new OrcaRouterPkceError('unknown_attempt', 'authorization attempt is malformed');
  }
  return parsed as PendingAttempt;
}

/**
 * Take the attempt for exchange without deleting it. The record stays on disk
 * (marked consumed) so the exchange can be cancelled while it is in flight;
 * a replay is refused by the consumed marker.
 */
function consumeAttempt(attemptId: string, stateDir?: string): PendingAttempt {
  return withOrcaRouterCredentialLock(stateDir, () => {
    const attempt = readAttempt(attemptId, stateDir);
    if (attempt.consumed_at) {
      throw new OrcaRouterPkceError('unknown_attempt', 'authorization attempt not found or already used');
    }
    const consumed: PendingAttempt = { ...attempt, consumed_at: new Date().toISOString() };
    writePrivateJson(attemptPath(attemptId, stateDir), consumed);
    return consumed;
  });
}

/** True while the consumed attempt is still on disk (i.e. not cancelled/completed). */
function attemptStillLive(attemptId: string, stateDir?: string): boolean {
  try {
    readAttempt(attemptId, stateDir, true);
    return true;
  } catch (error) {
    if (error instanceof OrcaRouterPkceError && error.code === 'unknown_attempt') return false;
    throw error;
  }
}

function discardAttempt(attemptId: string, stateDir?: string): void {
  try {
    fs.unlinkSync(attemptPath(attemptId, stateDir));
  } catch {
    /* already gone */
  }
}

/** Called synchronously by the credential store while it holds the shared lock. */
function finalizeAttempt(attemptId: string, stateDir?: string): void {
  let attempt: PendingAttempt;
  try {
    attempt = readAttempt(attemptId, stateDir, true);
  } catch (error) {
    if (error instanceof OrcaRouterPkceError && error.code === 'unknown_attempt') throw new Error('credential_cancelled');
    throw error;
  }
  const expiry = Date.parse(attempt.expires_at);
  if (!Number.isFinite(expiry) || expiry <= Date.now()) throw new Error('credential_expired');
  try {
    fs.unlinkSync(attemptPath(attemptId, stateDir));
  } catch (error: any) {
    if (error?.code === 'ENOENT') throw new Error('credential_cancelled');
    throw new OrcaRouterPkceError('attempt_unreadable', 'authorization attempt state is unavailable');
  }
}

function boundedBody(raw: string): string {
  return raw.length > 300 ? `${raw.slice(0, 300)}…` : raw;
}

/**
 * Start an authorization. Returns the URL the operator opens; the verifier
 * stays in the sealed pending record and is never returned.
 */
export async function startOrcaRouterAuthorization({
  origins,
  appName = 'EMILIA Protocol',
  principalId,
  stateDir,
}: {
  origins: OrcaRouterOrigins;
  appName?: string;
  principalId: string;
  stateDir?: string;
}): Promise<StartedAuthorization> {
  if (typeof principalId !== 'string' || !principalId.trim() || principalId.length > 200) {
    throw new OrcaRouterPkceError('invalid_request', 'an authenticated administrator is required');
  }
  const { verifier, challenge, state } = createPkceChallenge();
  const attemptId = b64url(crypto.randomBytes(18));
  const now = Date.now();
  const expiresAt = new Date(now + ORCAROUTER_PKCE_ATTEMPT_TTL_MS).toISOString();
  const record: PendingAttempt = {
    version: 1,
    attempt_id: attemptId,
    sealed_verifier: String(seal(verifier)),
    state,
    app_name: appName,
    principal_id: principalId,
    credential_generation: orcaRouterCredentialFence(stateDir),
    created_at: new Date(now).toISOString(),
    expires_at: expiresAt,
  };
  writePrivateJson(attemptPath(attemptId, stateDir), record);

  const url = new URL(`${origins.auth.replace(/\/+$/, '')}${ORCAROUTER_AUTHZ_PATH}`);
  url.searchParams.set('callback_url', 'oob');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  url.searchParams.set('app_name', appName);
  url.searchParams.set('scope', 'api');

  return {
    attempt_id: attemptId,
    authorize_url: url.toString(),
    expires_at: expiresAt,
    scope: 'api',
    auth_origin: origins.auth,
    delivery: 'oob',
  };
}

async function readBounded(res: Response, maxBytes: number): Promise<string> {
  const text = await res.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new OrcaRouterPkceError('invalid_grant_response', 'exchange response too large');
  }
  return text;
}

/**
 * Exchange the displayed code at the AUTH origin, then hand the resulting key
 * to the credential store. The pending attempt is consumed first, so the code
 * cannot be replayed through this adapter.
 */
export async function completeOrcaRouterAuthorization({
  origins,
  attemptId,
  code,
  state,
  principalId,
  fetchImpl = fetch,
  stateDir,
  save,
}: {
  origins: OrcaRouterOrigins;
  attemptId: string;
  code: string;
  state?: string | null;
  principalId: string;
  fetchImpl?: typeof fetch;
  stateDir?: string;
  /** Must invoke finalizeAttempt synchronously under the same credential lock before installation. */
  save: (
    key: string,
    scope: string,
    expectedGeneration: string,
    finalizeAttempt: () => void,
  ) => Promise<{ masked: string; generation: string }>;
}): Promise<CompletedAuthorization> {
  if (typeof code !== 'string' || !code.trim() || code.length > 4096) {
    throw new OrcaRouterPkceError('invalid_request', 'a displayed authorization code is required');
  }
  if (typeof principalId !== 'string' || !principalId.trim()) {
    throw new OrcaRouterPkceError('wrong_principal', 'an authenticated administrator is required');
  }
  const attempt = readAttempt(attemptId, stateDir);
  // Bind the attempt to the principal that started it. A different signed-in
  // administrator holding the id must not be able to finish (or steal) it.
  if (typeof attempt.principal_id !== 'string' || !attempt.principal_id) {
    throw new OrcaRouterPkceError('unknown_attempt', 'authorization attempt is malformed');
  }
  if (attempt.principal_id !== principalId) {
    throw new OrcaRouterPkceError('wrong_principal', 'this authorization attempt belongs to another administrator');
  }
  try {
    consumeAttempt(attemptId, stateDir);
  } catch (error: any) {
    if (error?.message === 'credential_write_locked') {
      throw new OrcaRouterPkceError('credential_busy', 'another credential update is in progress; retry the authorization');
    }
    throw error;
  }

  try {
    const expiry = Date.parse(attempt.expires_at);
    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      throw new OrcaRouterPkceError('expired', 'authorization window closed; start a new connection');
    }
    if (state != null && !safeStateEqual(String(state), String(attempt.state))) {
      throw new OrcaRouterPkceError('state_mismatch', 'authorization state did not match this attempt');
    }

    let verifier: string;
    try {
      verifier = openSecret(attempt.sealed_verifier);
    } catch {
      throw new OrcaRouterPkceError('unknown_attempt', 'authorization attempt is unreadable');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    let res: Response;
    try {
      res = await fetchImpl(`${origins.auth.replace(/\/+$/, '')}${ORCAROUTER_EXCHANGE_PATH}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          code: code.trim(),
          code_verifier: verifier,
          code_challenge_method: 'S256',
        }),
        redirect: 'error',
        signal: controller.signal,
      });
    } catch {
      throw new OrcaRouterPkceError('network_error', 'could not reach the OrcaRouter authorization service');
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      // Read at most a bounded error body for diagnosis; never include a
      // credential. Bodies describe the code, never the verifier.
      const detail = boundedBody(await readBounded(res, MAX_EXCHANGE_BYTES).catch(() => ''));
      logger.warn('orcarouter: authorization exchange rejected', { status: res.status });
      if (res.status === 400) throw new OrcaRouterPkceError('invalid_request', 'authorization request rejected');
      if (res.status === 401 || res.status === 403) {
        throw new OrcaRouterPkceError('code_rejected', 'the code is unknown, expired, or already used');
      }
      if (res.status === 429) {
        throw new OrcaRouterPkceError('rate_limited', 'too many key grants in 24 hours; try again later');
      }
      if (res.status >= 500) throw new OrcaRouterPkceError('server_error', 'authorization service is unavailable');
      throw new OrcaRouterPkceError('invalid_grant_response', detail ? 'authorization exchange failed' : 'authorization exchange failed');
    }

    let payload: any;
    try {
      payload = JSON.parse(await readBounded(res, MAX_EXCHANGE_BYTES));
    } catch {
      throw new OrcaRouterPkceError('invalid_grant_response', 'authorization service returned an unreadable response');
    }
    const key = payload?.key;
    const grantedScope = payload?.scope;
    if (typeof key !== 'string' || !/^sk-orca-[A-Za-z0-9_-]{8,}$/.test(key)) {
      throw new OrcaRouterPkceError('invalid_grant_response', 'authorization service did not return a usable key');
    }
    // Read the granted scope, not the requested one. This integration needs api.
    if (grantedScope !== 'api') {
      throw new OrcaRouterPkceError('scope_not_granted', 'the approval did not grant the api scope');
    }

    // A cancellation during the exchange removes or invalidates the attempt.
    // Refuse the write instead of storing a key for a connection the operator
    // cancelled.
    if (!attemptStillLive(attemptId, stateDir)) {
      throw new OrcaRouterPkceError('cancelled', 'authorization was cancelled before the key could be stored');
    }

    // The write is fenced against the credential generation captured when the
    // attempt started. If the credential changed while the exchange was in
    // flight (cancel, API-key replacement, or a competing approval), the older
    // approval is discarded rather than overwriting the newer key.
    let stored: { masked: string; generation: string };
    try {
      stored = await save(key, grantedScope, attempt.credential_generation || 'none', () => finalizeAttempt(attemptId, stateDir));
    } catch (error: any) {
      if (error?.message === 'credential_superseded') {
        throw new OrcaRouterPkceError('superseded', 'a newer OrcaRouter credential was stored while this approval was in flight');
      }
      if (error?.message === 'credential_write_locked') {
        throw new OrcaRouterPkceError('credential_busy', 'another credential update is in progress; start a new authorization');
      }
      if (error?.message === 'credential_cancelled') {
        throw new OrcaRouterPkceError('cancelled', 'authorization was cancelled before the key could be stored');
      }
      if (error?.message === 'credential_expired') {
        throw new OrcaRouterPkceError('expired', 'authorization window closed before the key could be stored');
      }
      throw error;
    }
    return {
      source: 'pkce',
      masked: stored.masked,
      scope: grantedScope,
      generation: stored.generation,
    };
  } finally {
    discardAttempt(attemptId, stateDir);
  }
}

/**
 * Cancel a pending attempt. Idempotent, and bound to the principal that
 * started it: another administrator cannot release someone else's attempt.
 * Returns true when a pending attempt was removed.
 */
export function cancelOrcaRouterAuthorization(
  attemptId: string,
  principalId: string,
  stateDir?: string,
): boolean {
  return withOrcaRouterCredentialLock(stateDir, () => {
    let attempt: PendingAttempt;
    try {
      attempt = readAttempt(attemptId, stateDir, true);
    } catch (error) {
      if (error instanceof OrcaRouterPkceError && (error.code === 'unknown_attempt' || error.code === 'invalid_request')) return false;
      throw error;
    }
    if (typeof attempt.principal_id !== 'string' || attempt.principal_id !== principalId) {
      throw new OrcaRouterPkceError('wrong_principal', 'this authorization attempt belongs to another administrator');
    }
    try {
      fs.unlinkSync(attemptPath(attemptId, stateDir));
      return true;
    } catch (error: any) {
      if (error?.code === 'ENOENT') return false;
      throw new OrcaRouterPkceError('attempt_unreadable', 'authorization attempt state is unavailable');
    }
  });
}

/** Number of live pending attempts (diagnostics and tests). */
export function pendingOrcaRouterAuthorizations(stateDir?: string): number {
  try {
    return fs.readdirSync(pendingDir(stateDir)).filter((name) => name.endsWith('.json')).length;
  } catch {
    return 0;
  }
}
