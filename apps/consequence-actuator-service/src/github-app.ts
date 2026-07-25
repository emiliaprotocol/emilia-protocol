// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { canonicalize } from '@emilia-protocol/gate';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const DEFAULT_BASE_URL = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_GITHUB_BODY_BYTES = 65_536;
const MAX_ATTRIBUTION_MARKER_BYTES = 16 * 1024;
const MAX_COMMENT_SCAN_PAGES = 10;
const SAFE_SEGMENT = /^[A-Za-z0-9_.-]{1,100}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const CAID =
  /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const PROVIDER_ATTRIBUTION_VERSION =
  'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1';
const PROVIDER_RECORD_VERSION =
  'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v1';
const PROVIDER_RECORD_SIGNATURE_DOMAIN =
  'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v1';
const ATTRIBUTION_MARKER_PREFIX =
  '<!-- emilia-provider-attribution-v1:';
const ATTRIBUTION_MARKER_SUFFIX = ' -->';
const ATTRIBUTION_BINDING_KEYS = Object.freeze([
  '@version',
  'issuer_id',
  'tenant_id',
  'provider_id',
  'provider_account_id',
  'environment',
  'request_digest',
  'attempt_id',
  'operation_id',
  'caid',
  'action_digest',
  'target_digest',
  'operation',
  'envelope_digest',
  'effect_digest',
  'issued_at',
]);
const PROVIDER_RECORD_PAYLOAD_KEYS = Object.freeze([
  '@version',
  'state',
  'provider_record_id',
  'recorded_at',
  'binding',
]);
const SIGNATURE_KEYS = Object.freeze(['algorithm', 'key_id', 'value']);
const SIGNED_RECORD_KEYS = Object.freeze(['@version', 'payload', 'signature']);
const DEFINITIVE_NOT_COMMITTED_STATUSES = new Set([401, 403, 404, 409, 422]);
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

async function boundedJson(response: any): Promise<any> {
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
  return JSON.parse(text);
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
    if (response?.redirected === true) {
      cancelBody(response?.body);
      throw new Error('github_redirect_refused');
    }
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

function normalizeAttributionPrivateKey(value: unknown): crypto.KeyObject {
  let key: crypto.KeyObject;
  try {
    key = value instanceof crypto.KeyObject
      ? value
      : crypto.createPrivateKey(value as crypto.PrivateKeyInput);
  } catch {
    throw new TypeError('github_attribution_private_key_invalid');
  }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('github_attribution_private_key_invalid');
  }
  return key;
}

function canonicalInstant(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isSafeInteger(timestamp)
    && timestamp >= 0
    && new Date(timestamp).toISOString() === value;
}

function githubIssueEffectDigest({
  action,
  binding,
  target,
  targetDigest,
}: {
  action: JsonObject;
  binding: JsonObject;
  target: { owner: string; repo: string; issueNumber: number };
  targetDigest: string;
}) {
  return digestAeb({
    domain: 'EP-GITHUB-ISSUE-EFFECT-v1',
    tenant_id: binding.tenant_id,
    provider_id: binding.provider_id,
    provider_account_id: binding.provider_account_id,
    environment: binding.environment,
    target_digest: targetDigest,
    target: {
      owner: target.owner,
      repo: target.repo,
      issue_number: target.issueNumber,
    },
    effect: {
      title: action.title,
      body: action.body,
    },
  });
}

function requireAttributionBinding(
  value: unknown,
  {
    action,
    target,
    targetDigest,
    issuerId,
  }: {
    action: JsonObject;
    target: { owner: string; repo: string; issueNumber: number };
    targetDigest: string;
    issuerId: string;
  },
): JsonObject {
  if (!exactKeys(value, ATTRIBUTION_BINDING_KEYS)
      || value['@version'] !== PROVIDER_ATTRIBUTION_VERSION
      || value.issuer_id !== issuerId
      || !IDENTIFIER.test(value.tenant_id)
      || value.provider_id !== 'github'
      || !IDENTIFIER.test(value.provider_account_id)
      || value.provider_account_id !== target.owner
      || !IDENTIFIER.test(value.environment)
      || !DIGEST.test(value.request_digest)
      || !IDENTIFIER.test(value.attempt_id)
      || !IDENTIFIER.test(value.operation_id)
      || !CAID.test(value.caid)
      || !DIGEST.test(value.action_digest)
      || value.action_digest !== digestAeb(action)
      || value.target_digest !== targetDigest
      || !IDENTIFIER.test(value.operation)
      || !DIGEST.test(value.envelope_digest)
      || !DIGEST.test(value.effect_digest)
      || !canonicalInstant(value.issued_at)
      || value.effect_digest !== githubIssueEffectDigest({
        action,
        binding: value,
        target,
        targetDigest,
      })) {
    throw new Error('github_issue_attribution_refused');
  }
  return structuredClone(value);
}

function recordSignatureInput(payload: JsonObject): Buffer {
  return Buffer.concat([
    Buffer.from(PROVIDER_RECORD_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalize(payload), 'utf8'),
  ]);
}

function markerForRecord(record: JsonObject): string {
  const encoded = Buffer.from(canonicalize(record), 'utf8').toString('base64url');
  if (encoded.length > MAX_ATTRIBUTION_MARKER_BYTES) {
    throw new Error('github_attribution_marker_too_large');
  }
  return `${ATTRIBUTION_MARKER_PREFIX}${encoded}${ATTRIBUTION_MARKER_SUFFIX}`;
}

function commentForRecord(record: JsonObject): string {
  return [
    'EMILIA consequence actuator provider-attribution record.',
    '',
    markerForRecord(record),
  ].join('\n');
}

function parseRecordMarkers(
  value: unknown,
  {
    keyId,
    publicKey,
  }: {
    keyId: string;
    publicKey: crypto.KeyObject;
  },
): JsonObject[] {
  if (typeof value !== 'string' || value.length > MAX_GITHUB_BODY_BYTES * 2) {
    return [];
  }
  const records: JsonObject[] = [];
  const pattern =
    /<!-- emilia-provider-attribution-v1:([A-Za-z0-9_-]{1,16384}) -->/g;
  for (const match of value.matchAll(pattern)) {
    const encoded = match[1];
    let decoded: string;
    try {
      const bytes = Buffer.from(encoded, 'base64url');
      if (bytes.toString('base64url') !== encoded) continue;
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      if (!strictJsonGate(decoded).ok) continue;
    } catch {
      continue;
    }
    let candidate: JsonObject;
    try {
      candidate = JSON.parse(decoded);
      if (canonicalize(candidate) !== decoded) continue;
    } catch {
      continue;
    }
    if (!exactKeys(candidate, SIGNED_RECORD_KEYS)
        || candidate['@version'] !== PROVIDER_RECORD_VERSION
        || !exactKeys(candidate.payload, PROVIDER_RECORD_PAYLOAD_KEYS)
        || candidate.payload['@version'] !== PROVIDER_RECORD_VERSION
        || !['PREPARED', 'COMMITTED', 'NOT_COMMITTED']
          .includes(candidate.payload.state)
        || (candidate.payload.provider_record_id !== null
          && !IDENTIFIER.test(candidate.payload.provider_record_id))
        || ((candidate.payload.state === 'PREPARED')
          !== (candidate.payload.provider_record_id === null))
        || !canonicalInstant(candidate.payload.recorded_at)
        || !plainObject(candidate.payload.binding)
        || !exactKeys(candidate.signature, SIGNATURE_KEYS)
        || candidate.signature.algorithm !== 'Ed25519'
        || candidate.signature.key_id !== keyId
        || typeof candidate.signature.value !== 'string'
        || !BASE64URL.test(candidate.signature.value)) {
      continue;
    }
    let signature: Buffer;
    try {
      signature = Buffer.from(candidate.signature.value, 'base64url');
    } catch {
      continue;
    }
    if (signature.byteLength !== 64
        || signature.toString('base64url') !== candidate.signature.value
        || !crypto.verify(
          null,
          recordSignatureInput(candidate.payload),
          publicKey,
          signature,
        )) {
      continue;
    }
    records.push(structuredClone(candidate));
  }
  return records;
}

export function createGitHubIssueEffectProvider({
  owner,
  repo,
  issueNumber,
  tokenProvider,
  attributionIssuerId,
  attributionKeyId,
  attributionPrivateKey,
  targetDigest,
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
  const issuerId = requiredText(
    attributionIssuerId,
    'github_attribution_issuer_id',
    256,
  );
  const keyId = requiredText(
    attributionKeyId,
    'github_attribution_key_id',
    256,
  );
  if (!IDENTIFIER.test(issuerId) || !IDENTIFIER.test(keyId)
      || typeof targetDigest !== 'string' || !DIGEST.test(targetDigest)) {
    throw new TypeError('github_issue_provider_config_invalid');
  }
  const signingKey = normalizeAttributionPrivateKey(attributionPrivateKey);
  const verificationKey = crypto.createPublicKey(signingKey);
  if (!tokenProvider || typeof tokenProvider.getToken !== 'function'
      || typeof fetchImpl !== 'function' || typeof now !== 'function'
      || typeof forceIndeterminateAfterCommit !== 'boolean') {
    throw new TypeError('github_issue_provider_config_invalid');
  }
  const apiBase = normalizedBaseUrl(baseUrl);
  const repositoryEndpoint =
    `${apiBase}/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}`;
  const issueEndpoint = `${repositoryEndpoint}/issues/${target.issueNumber}`;
  const commentsEndpoint = `${issueEndpoint}/comments`;

  function outcomeError(code: string) {
    const error: any = new Error(code);
    error.code = code;
    return error;
  }

  function signRecord(
    state: 'PREPARED' | 'COMMITTED' | 'NOT_COMMITTED',
    binding: JsonObject,
    providerRecordId: string | null,
  ) {
    const timestamp = Number(now());
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
      throw new Error('github_attribution_clock_invalid');
    }
    const payload = JSON.parse(canonicalize({
      '@version': PROVIDER_RECORD_VERSION,
      state,
      provider_record_id: providerRecordId,
      recorded_at: new Date(timestamp).toISOString(),
      binding,
    }));
    return JSON.parse(canonicalize({
      '@version': PROVIDER_RECORD_VERSION,
      payload,
      signature: {
        algorithm: 'Ed25519',
        key_id: keyId,
        value: crypto.sign(
          null,
          recordSignatureInput(payload),
          signingKey,
        ).toString('base64url'),
      },
    }));
  }

  async function request(
    method: 'GET' | 'POST' | 'PATCH',
    endpoint: string,
    body?: JsonObject,
    attemptId?: string,
  ) {
    const token = await tokenProvider.getToken();
    const response = await fetchImpl(endpoint, {
      method,
      headers: githubHeaders(token, attemptId ? { 'X-EMILIA-Attempt-ID': attemptId } : {}),
      ...(body ? { body: JSON.stringify(body) } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
    if (response?.redirected === true) {
      cancelBody(response?.body);
      throw new Error('github_redirect_refused');
    }
    return response;
  }

  async function confirmedTerminalComment(
    commentId: number,
    record: JsonObject,
    attemptId: string,
  ): Promise<boolean> {
    try {
      const response = await request(
        'PATCH',
        `${repositoryEndpoint}/issues/comments/${commentId}`,
        { body: commentForRecord(record) },
        attemptId,
      );
      if (response?.status !== 200) {
        cancelBody(response?.body);
        return false;
      }
      const body = await boundedJson(response);
      return plainObject(body)
        && body.id === commentId
        && body.body === commentForRecord(record);
    } catch {
      return false;
    }
  }

  function bindingMatchesExpected(
    record: JsonObject,
    expected: JsonObject,
    action: JsonObject,
    operation: string,
  ): boolean {
    let binding: JsonObject;
    try {
      binding = requireAttributionBinding(record.payload.binding, {
        action,
        target,
        targetDigest,
        issuerId,
      });
    } catch {
      return false;
    }
    return binding.tenant_id === expected.tenant_id
      && binding.provider_id === expected.provider_id
      && binding.provider_account_id === expected.provider_account_id
      && binding.environment === expected.environment
      && binding.request_digest === expected.request_digest
      && binding.attempt_id === expected.attempt_id
      && binding.operation_id === expected.operation_id
      && binding.caid === expected.caid
      && binding.action_digest === expected.action_digest
      && binding.operation === operation;
  }

  async function readIssue(): Promise<JsonObject> {
    const response = await request('GET', issueEndpoint);
    if (response?.status !== 200) {
      cancelBody(response?.body);
      throw new Error('github_issue_observation_failed');
    }
    const body = await boundedJson(response);
    if (!plainObject(body)) throw new Error('github_issue_observation_failed');
    return body;
  }

  async function readAttemptRecords(
    expected: JsonObject,
    action: JsonObject,
    operation: string,
  ): Promise<Array<{ record: JsonObject; commentId: number }>> {
    const records: Array<{ record: JsonObject; commentId: number }> = [];
    for (let page = 1; page <= MAX_COMMENT_SCAN_PAGES; page += 1) {
      const response = await request(
        'GET',
        `${commentsEndpoint}?per_page=100&sort=created&direction=desc&page=${page}`,
      );
      if (response?.status !== 200) {
        cancelBody(response?.body);
        throw new Error('github_comment_observation_failed');
      }
      const body = await boundedJson(response);
      if (!Array.isArray(body)) throw new Error('github_comment_observation_failed');
      for (const comment of body) {
        if (!plainObject(comment)
            || !Number.isSafeInteger(comment.id)
            || comment.id < 1) continue;
        for (const record of parseRecordMarkers(comment.body, {
          keyId,
          publicKey: verificationKey,
        })) {
          if (!bindingMatchesExpected(record, expected, action, operation)) continue;
          const recordId = record.payload.provider_record_id;
          if (recordId !== null
              && recordId !== `github:issue-comment:${comment.id}`) continue;
          records.push({ record, commentId: comment.id });
        }
      }
      if (body.length < 100) break;
    }
    return records;
  }

  return Object.freeze({
    async effect({ action: candidate, attempt }: any = {}) {
      const action = requireAction(candidate, target);
      const binding = requireAttributionBinding(attempt, {
        action,
        target,
        targetDigest,
        issuerId,
      });
      const prepared = signRecord('PREPARED', binding, null);
      let commentId: number;
      try {
        const response = await request(
          'POST',
          commentsEndpoint,
          { body: commentForRecord(prepared) },
          binding.attempt_id,
        );
        if (response?.status !== 201) {
          cancelBody(response?.body);
          throw outcomeError('github_issue_outcome_indeterminate');
        }
        const body = await boundedJson(response);
        if (!plainObject(body)
            || !Number.isSafeInteger(body.id)
            || body.id < 1
            || body.body !== commentForRecord(prepared)) {
          throw outcomeError('github_issue_outcome_indeterminate');
        }
        commentId = body.id;
      } catch (error: any) {
        if (error?.code === 'github_issue_outcome_indeterminate') throw error;
        if (['github_redirect_refused', 'github_response_too_large',
          'github_response_invalid'].includes(error?.message)) {
          throw error;
        }
        throw outcomeError('github_issue_outcome_indeterminate');
      }

      const providerRecordId = `github:issue-comment:${commentId}`;
      let response: any;
      try {
        response = await request(
          'PATCH',
          issueEndpoint,
          { title: action.title, body: action.body },
          binding.attempt_id,
        );
      } catch {
        throw outcomeError('github_issue_outcome_indeterminate');
      }
      if (response?.status !== 200) {
        const status = response?.status;
        cancelBody(response?.body);
        if (DEFINITIVE_NOT_COMMITTED_STATUSES.has(status)) {
          const notCommittedRecord = signRecord(
            'NOT_COMMITTED',
            binding,
            providerRecordId,
          );
          if (await confirmedTerminalComment(
            commentId,
            notCommittedRecord,
            binding.attempt_id,
          )) {
            throw outcomeError('github_issue_not_committed');
          }
        }
        throw outcomeError('github_issue_outcome_indeterminate');
      }
      const result = await boundedJson(response);
      if (result.number !== target.issueNumber
          || result.title !== action.title
          || (result.body ?? '') !== action.body) {
        throw outcomeError('github_issue_outcome_indeterminate');
      }
      const committedRecord = signRecord(
        'COMMITTED',
        binding,
        providerRecordId,
      );
      await confirmedTerminalComment(
        commentId,
        committedRecord,
        binding.attempt_id,
      );
      if (forceIndeterminateAfterCommit) {
        throw outcomeError('github_issue_outcome_indeterminate');
      }
      return {
        provider_status: 200,
        provider_reference: `github:issue:${target.owner}/${target.repo}#${target.issueNumber}`,
        provider_effect_digest: binding.effect_digest,
        provider_record_id: providerRecordId,
      };
    },

    async verifyProviderEvidence({
      evidence,
      expected,
      action: candidate,
      operation,
    }: any = {}) {
      const action = requireAction(candidate, target);
      if (!exactKeys(evidence, ['kind']) || evidence.kind !== 'github-issue-observation-v1'
          || !plainObject(expected)
          || typeof operation !== 'string'
          || !IDENTIFIER.test(operation)) {
        return { valid: false, reason: 'provider_evidence_shape_invalid' };
      }
      let observed: JsonObject;
      try {
        observed = await readIssue();
      } catch {
        return { valid: false, reason: 'provider_evidence_unavailable' };
      }
      let commentRecords: Array<{ record: JsonObject; commentId: number }> = [];
      let commentsAvailable = true;
      try {
        commentRecords = await readAttemptRecords(expected, action, operation);
      } catch {
        commentsAvailable = false;
      }
      const states = new Set(commentRecords.map(({ record }) => record.payload.state));
      const conflictingTerminalRecords =
        states.has('COMMITTED') && states.has('NOT_COMMITTED');
      let outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'ESCALATED';
      let reason: string;
      if (conflictingTerminalRecords) {
        outcome = 'ESCALATED';
        reason = 'github_attempt_attribution_conflict';
      } else if (states.has('COMMITTED')) {
        outcome = 'COMMITTED';
        reason = 'github_exact_attempt_committed';
      } else if (states.has('NOT_COMMITTED')) {
        outcome = 'NOT_COMMITTED';
        reason = 'github_provider_refused_before_effect';
      } else if (states.has('PREPARED')) {
        outcome = 'ESCALATED';
        reason = 'github_attempt_outcome_indeterminate';
      } else {
        outcome = 'ESCALATED';
        reason = commentsAvailable
          ? 'github_attempt_attribution_unavailable'
          : 'github_attempt_record_unavailable';
      }
      const observedAt = new Date(Number(now())).toISOString();
      const evidenceDigest = digestAeb({
        provider: 'github',
        repository: `${target.owner}/${target.repo}`,
        issue_number: target.issueNumber,
        title: observed.title ?? null,
        body: observed.body ?? null,
        attempt_record_digests: commentRecords
          .map(({ record }) => digestAeb(record))
          .sort(),
        comments_available: commentsAvailable,
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
