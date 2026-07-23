// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { digestAeb } from '../../../packages/verify/aeb-adapter-contract.js';
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const DEFAULT_BASE_URL = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 512 * 1024;
const SAFE_SEGMENT = /^[A-Za-z0-9_.-]{1,100}$/;
const EXACT_ACTION_KEYS = Object.freeze([
  'action_type', 'owner', 'repo', 'issue_number', 'title', 'body',
]);

type JsonObject = Record<string, any>;

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: unknown, expected: readonly string[]): value is JsonObject {
  if (!plainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function requiredInteger(value: unknown, name: string): number {
  const number = typeof value === 'string' && /^[1-9][0-9]*$/.test(value)
    ? Number(value) : value;
  if (!Number.isSafeInteger(number) || (number as number) < 1) {
    throw new TypeError(`${name}_invalid`);
  }
  return number as number;
}

function requiredSegment(value: unknown, name: string): string {
  if (typeof value !== 'string' || !SAFE_SEGMENT.test(value) || value === '.' || value === '..') {
    throw new TypeError(`${name}_invalid`);
  }
  return value;
}

function requiredText(value: unknown, name: string, max = 65_536): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || value.includes('\0')) {
    throw new TypeError(`${name}_invalid`);
  }
  return value;
}

function normalizedBaseUrl(value: unknown): string {
  let url: URL;
  try {
    url = new URL(typeof value === 'string' ? value : DEFAULT_BASE_URL);
  } catch {
    throw new TypeError('github_base_url_invalid');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new TypeError('github_base_url_invalid');
  }
  return url.href.replace(/\/$/, '');
}

function cancelBody(body: any) {
  try { Promise.resolve(body?.cancel?.()).catch(() => {}); } catch { /* best effort */ }
}

async function boundedJson(response: any): Promise<JsonObject> {
  const announced = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(announced) && announced > MAX_RESPONSE_BYTES) {
    cancelBody(response?.body);
    throw new Error('github_response_too_large');
  }
  if (!response?.body || typeof response.body.getReader !== 'function') {
    throw new Error('github_response_invalid');
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (!chunk || chunk.done === true) break;
      if (!(chunk.value instanceof Uint8Array)) throw new Error('github_response_invalid');
      total += chunk.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) throw new Error('github_response_too_large');
      chunks.push(Buffer.from(chunk.value));
    }
  } catch (error) {
    try { await reader.cancel(); } catch { /* best effort */ }
    throw error;
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total));
  } catch {
    throw new Error('github_response_invalid');
  }
  if (!strictJsonGate(text).ok) throw new Error('github_response_invalid');
  const parsed = JSON.parse(text);
  if (!plainObject(parsed)) throw new Error('github_response_invalid');
  return parsed;
}

function createAppJwt(appId: string, privateKey: crypto.KeyObject, nowMs: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const seconds = Math.floor(nowMs / 1000);
  const payload = Buffer.from(JSON.stringify({
    iat: seconds - 60,
    exp: seconds + 540,
    iss: appId,
  })).toString('base64url');
  const signingInput = `${header}.${payload}`;
  const signature = crypto.sign(
    'RSA-SHA256',
    Buffer.from(signingInput),
    privateKey,
  ).toString('base64url');
  return `${signingInput}.${signature}`;
}

export function createGitHubAppInstallationTokenProvider({
  appId,
  installationId,
  privateKeyPem,
  baseUrl,
  fetchImpl = globalThis.fetch,
  now = Date.now,
}: any = {}) {
  const app = String(requiredInteger(appId, 'github_app_id'));
  const installation = String(requiredInteger(installationId, 'github_installation_id'));
  requiredText(privateKeyPem, 'github_private_key', 32 * 1024);
  if (typeof fetchImpl !== 'function' || typeof now !== 'function') {
    throw new TypeError('github_app_dependencies_invalid');
  }
  let privateKey: crypto.KeyObject;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
    if (privateKey.asymmetricKeyType !== 'rsa') throw new Error('RSA required');
  } catch {
    throw new TypeError('github_private_key_invalid');
  }
  const apiBase = normalizedBaseUrl(baseUrl);
  let cached: { token: string; refreshAt: number } | null = null;
  let pending: Promise<string> | null = null;

  async function mintToken(): Promise<string> {
    const current = Number(now());
    if (!Number.isFinite(current)) throw new Error('github_app_clock_invalid');
    const response = await fetchImpl(
      `${apiBase}/app/installations/${installation}/access_tokens`,
      {
        method: 'POST',
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${createAppJwt(app, privateKey, current)}`,
          'User-Agent': 'emilia-consequence-control/0.1.0',
          'X-GitHub-Api-Version': API_VERSION,
        },
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (response?.status !== 201) {
      cancelBody(response?.body);
      throw new Error('github_installation_token_refused');
    }
    const body = await boundedJson(response);
    const token = requiredText(body.token, 'github_installation_token', 4096);
    const expiresAt = Date.parse(body.expires_at);
    if (!Number.isFinite(expiresAt) || expiresAt <= current + 120_000) {
      throw new Error('github_installation_token_expiry_invalid');
    }
    cached = { token, refreshAt: expiresAt - 60_000 };
    return token;
  }

  return Object.freeze({
    async getToken() {
      const current = Number(now());
      if (cached && current < cached.refreshAt) return cached.token;
      if (!pending) pending = mintToken().finally(() => { pending = null; });
      return pending;
    },
  });
}

function githubHeaders(token: string, extra: Record<string, string> = {}) {
  requiredText(token, 'github_installation_token', 4096);
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'User-Agent': 'emilia-consequence-control/0.1.0',
    'X-GitHub-Api-Version': API_VERSION,
    ...extra,
  };
}

function requireAction(
  value: unknown,
  target: { owner: string; repo: string; issueNumber: number },
): JsonObject {
  if (!exactKeys(value, EXACT_ACTION_KEYS)
      || value.action_type !== 'github.issue.update.1'
      || value.owner !== target.owner
      || value.repo !== target.repo
      || value.issue_number !== target.issueNumber
      || typeof value.title !== 'string' || value.title.length < 1 || value.title.length > 256
      || typeof value.body !== 'string' || value.body.length > 65_536
      || value.title.includes('\0') || value.body.includes('\0')) {
    throw new Error('github_issue_action_refused');
  }
  return structuredClone(value);
}

export function createGitHubIssueEffectProvider({
  owner,
  repo,
  issueNumber,
  tokenProvider,
  forceIndeterminateAfterCommit = false,
  baseUrl,
  fetchImpl = globalThis.fetch,
  now = Date.now,
}: any = {}) {
  const target = Object.freeze({
    owner: requiredSegment(owner, 'github_owner'),
    repo: requiredSegment(repo, 'github_repo'),
    issueNumber: requiredInteger(issueNumber, 'github_issue_number'),
  });
  if (!tokenProvider || typeof tokenProvider.getToken !== 'function'
      || typeof fetchImpl !== 'function' || typeof now !== 'function'
      || typeof forceIndeterminateAfterCommit !== 'boolean') {
    throw new TypeError('github_issue_provider_config_invalid');
  }
  const apiBase = normalizedBaseUrl(baseUrl);
  const endpoint = `${apiBase}/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/issues/${target.issueNumber}`;

  async function request(method: 'GET' | 'PATCH', action: JsonObject, attemptId?: string) {
    const token = await tokenProvider.getToken();
    const response = await fetchImpl(endpoint, {
      method,
      headers: githubHeaders(token, attemptId ? { 'X-EMILIA-Attempt-ID': attemptId } : {}),
      ...(method === 'PATCH' ? { body: JSON.stringify({ title: action.title, body: action.body }) } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
    if (response?.status !== 200) {
      cancelBody(response?.body);
      throw new Error(method === 'PATCH'
        ? 'github_issue_outcome_indeterminate' : 'github_issue_observation_failed');
    }
    return boundedJson(response);
  }

  return Object.freeze({
    async effect({ action: candidate, attempt }: any = {}) {
      const action = requireAction(candidate, target);
      if (!plainObject(attempt) || typeof attempt.attempt_id !== 'string') {
        throw new Error('github_issue_attempt_refused');
      }
      const result = await request('PATCH', action, attempt.attempt_id);
      if (result.number !== target.issueNumber
          || result.title !== action.title
          || (result.body ?? '') !== action.body) {
        throw new Error('github_issue_outcome_indeterminate');
      }
      if (forceIndeterminateAfterCommit) {
        const error: any = new Error('github_issue_outcome_indeterminate');
        error.code = 'github_issue_outcome_indeterminate';
        throw error;
      }
      return {
        provider_status: 200,
        provider_reference: `github:issue:${target.owner}/${target.repo}#${target.issueNumber}`,
      };
    },

    async verifyProviderEvidence({ evidence, expected, action: candidate }: any = {}) {
      const action = requireAction(candidate, target);
      if (!exactKeys(evidence, ['kind']) || evidence.kind !== 'github-issue-observation-v1'
          || !plainObject(expected)) {
        return { valid: false, reason: 'provider_evidence_shape_invalid' };
      }
      let observed: JsonObject;
      try {
        observed = await request('GET', action);
      } catch {
        return { valid: false, reason: 'provider_evidence_unavailable' };
      }
      const stateMatchesRequestedEffect = observed.number === target.issueNumber
        && observed.title === action.title
        && (observed.body ?? '') === action.body;
      const observedAt = new Date(Number(now())).toISOString();
      // GitHub accepts the attempt ID as a request header but does not persist
      // it as immutable issue evidence. An authenticated GET therefore proves
      // current state, not which attempt caused that state. Reconciliation must
      // remain fail-closed even when the requested bytes currently match.
      const outcome = 'ESCALATED';
      const reason = stateMatchesRequestedEffect
        ? 'github_attempt_attribution_unavailable'
        : 'github_issue_state_mismatch';
      const evidenceDigest = digestAeb({
        provider: 'github',
        repository: `${target.owner}/${target.repo}`,
        issue_number: target.issueNumber,
        title: observed.title ?? null,
        body: observed.body ?? null,
        state_matches_requested_effect: stateMatchesRequestedEffect,
        outcome,
        reason,
        observed_at: observedAt,
        tenant_id: expected.tenant_id,
        request_digest: expected.request_digest,
        provider_id: expected.provider_id,
        provider_account_id: expected.provider_account_id,
        environment: expected.environment,
        attempt_id: expected.attempt_id,
        operation_id: expected.operation_id,
        caid: expected.caid,
        action_digest: expected.action_digest,
      });
      return {
        valid: true,
        outcome,
        reason,
        evidence_id: `github-observation:${target.owner}:${target.repo}:${target.issueNumber}:${Date.parse(observedAt)}`,
        observed_at: observedAt,
        tenant_id: expected.tenant_id,
        request_digest: expected.request_digest,
        provider_id: expected.provider_id,
        provider_account_id: expected.provider_account_id,
        environment: expected.environment,
        attempt_id: expected.attempt_id,
        operation_id: expected.operation_id,
        caid: expected.caid,
        action_digest: expected.action_digest,
        evidence_digest: evidenceDigest,
      };
    },
  });
}

export default Object.freeze({
  createGitHubAppInstallationTokenProvider,
  createGitHubIssueEffectProvider,
});
