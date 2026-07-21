// SPDX-License-Identifier: Apache-2.0
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const DEFAULT_BASE_URL = 'https://api.github.com';
const DEFAULT_API_VERSION = '2026-03-10';
const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
const SAFE_HEADER_VALUE = /^[\x20-\x7e]+$/;

function isAbort(error: unknown): boolean {
  const err = error as any;
  return err?.name === 'AbortError' || err?.name === 'TimeoutError' || err?.code === 'ABORT_ERR';
}

function requireText(value: unknown, field: string, max: number = 256): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max
      || !SAFE_HEADER_VALUE.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value;
}

function requirePathSegment(value: unknown, field: string): string {
  const text = requireText(value, field, 100);
  if (text === '.' || text === '..') throw new TypeError(`${field} is invalid`);
  return text;
}

function repositoryUrl(baseUrl: string, owner: string, repo: string): string {
  return `${baseUrl}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
}

async function readBoundedJson(response: any, maxBytes: number): Promise<Record<string, any>> {
  const announced = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(announced) && announced > maxBytes) {
    cancelBody(response?.body);
    throw new GithubConnectorError('github_response_too_large');
  }
  if (!response?.body || typeof response.body.getReader !== 'function') {
    throw new GithubConnectorError('github_response_invalid');
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (!chunk || chunk.done === true) break;
      if (!(chunk.value instanceof Uint8Array)) {
        throw new GithubConnectorError('github_response_invalid');
      }
      total += chunk.value.byteLength;
      if (total > maxBytes) {
        throw new GithubConnectorError('github_response_too_large');
      }
      chunks.push(Buffer.from(chunk.value.buffer, chunk.value.byteOffset, chunk.value.byteLength));
    }
  } catch (error) {
    cancelBody(null, reader);
    throw error;
  } finally {
    try { reader.releaseLock?.(); } catch { /* no-op */ }
  }

  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total));
  } catch {
    throw new GithubConnectorError('github_response_invalid');
  }
  if (!strictJsonGate(text).ok) throw new GithubConnectorError('github_response_invalid');
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('object required');
    }
    return parsed;
  } catch {
    throw new GithubConnectorError('github_response_invalid');
  }
}

/**
 * @param {ReadableStream<Uint8Array> | null | undefined} body
 * @param {ReadableStreamDefaultReader<Uint8Array> | null} [reader]
 */
function cancelBody(body: any, reader: any = null): void {
  try {
    const result = reader?.cancel?.() ?? body?.cancel?.();
    Promise.resolve(result).catch(() => {});
  } catch {
    // Cancellation is best effort; the connector still returns the closed error.
  }
}

export class GithubConnectorError extends Error {
  name: string = 'GithubConnectorError';
  code: string;
  status: number | null;
  ambiguous: boolean;
  timeout: boolean;

  constructor(code: string, { status = null, ambiguous = false, timeout = false }: any = {}) {
    super(code);
    this.name = 'GithubConnectorError';
    this.code = code;
    this.status = status;
    this.ambiguous = ambiguous;
    this.timeout = timeout;
  }
}

/**
 * @param {{
 *   token?: string,
 *   baseUrl?: string,
 *   apiVersion?: string,
 *   userAgent?: string,
 *   fetchImpl?: typeof fetch,
 *   maxResponseBytes?: number
 * }} [options]
 */
export function createGithubRestConnector({
  token,
  baseUrl = DEFAULT_BASE_URL,
  apiVersion = DEFAULT_API_VERSION,
  userAgent = 'emilia-gate-service/0.1.0',
  fetchImpl = globalThis.fetch,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
}: any = {}) {
  requireText(token, 'token', 4096);
  requireText(apiVersion, 'apiVersion', 32);
  requireText(userAgent, 'userAgent', 256);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(apiVersion)) throw new TypeError('apiVersion is invalid');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl is required');
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1024
      || maxResponseBytes > 4 * 1024 * 1024) {
    throw new TypeError('maxResponseBytes is invalid');
  }

  let parsedBase;
  try {
    parsedBase = new URL(baseUrl);
  } catch {
    throw new TypeError('baseUrl is invalid');
  }
  if (!['http:', 'https:'].includes(parsedBase.protocol) || parsedBase.username
      || parsedBase.password || parsedBase.search || parsedBase.hash) {
    throw new TypeError('baseUrl is invalid');
  }
  const normalizedBase = parsedBase.href.replace(/\/$/, '');

  function headers(extra = {}) {
    return {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': userAgent,
      'X-GitHub-Api-Version': apiVersion,
      ...extra,
    };
  }

  return Object.freeze({
    async getRepository(args: any = {}) {
      const { owner, repo, signal } = args;
      requirePathSegment(owner, 'owner');
      requirePathSegment(repo, 'repo');
      let response;
      try {
        response = await fetchImpl(repositoryUrl(normalizedBase, owner, repo), {
          method: 'GET',
          headers: headers({ 'Cache-Control': 'no-store' }),
          redirect: 'error',
          signal,
        });
        if (response?.status !== 200) {
          cancelBody(response?.body);
          throw new GithubConnectorError('github_get_rejected', { status: response?.status ?? null });
        }
        return await readBoundedJson(response, maxResponseBytes);
      } catch (error) {
        if (error instanceof GithubConnectorError) throw error;
        throw new GithubConnectorError('github_get_failed', { timeout: isAbort(error) });
      }
    },

    async deleteRepository(args: any = {}) {
      const { owner, repo, idempotencyKey, actionId, signal } = args;
      requirePathSegment(owner, 'owner');
      requirePathSegment(repo, 'repo');
      requireText(idempotencyKey, 'idempotencyKey', 256);
      requireText(actionId, 'actionId', 128);

      let response;
      try {
        response = await fetchImpl(repositoryUrl(normalizedBase, owner, repo), {
          method: 'DELETE',
          headers: headers({
            'Idempotency-Key': idempotencyKey,
            'X-EMILIA-Action-ID': actionId,
          }),
          redirect: 'error',
          signal,
        });
      } catch (error) {
        throw new GithubConnectorError('github_delete_outcome_unknown', {
          ambiguous: true,
          timeout: isAbort(error),
        });
      }
      if (response?.status !== 204) {
        cancelBody(response?.body);
        throw new GithubConnectorError('github_delete_outcome_unknown', {
          status: response?.status ?? null,
          ambiguous: true,
        });
      }
      cancelBody(response?.body);
      return { status: 204 };
    },
  });
}
