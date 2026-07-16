// SPDX-License-Identifier: Apache-2.0
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const DEFAULT_BASE_URL = 'https://api.github.com';
const DEFAULT_API_VERSION = '2026-03-10';
const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
const SAFE_HEADER_VALUE = /^[\x20-\x7e]+$/;

function isAbort(error) {
  return error?.name === 'AbortError' || error?.name === 'TimeoutError' || error?.code === 'ABORT_ERR';
}

function requireText(value, field, max = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max
      || !SAFE_HEADER_VALUE.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value;
}

function requirePathSegment(value, field) {
  const text = requireText(value, field, 100);
  if (text === '.' || text === '..') throw new TypeError(`${field} is invalid`);
  return text;
}

function repositoryUrl(baseUrl, owner, repo) {
  return `${baseUrl}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
}

async function readBoundedJson(response, maxBytes) {
  const announced = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(announced) && announced > maxBytes) {
    throw new GithubConnectorError('github_response_too_large');
  }
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes || !strictJsonGate(text).ok) {
    throw new GithubConnectorError('github_response_invalid');
  }
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

export class GithubConnectorError extends Error {
  constructor(code, { status = null, ambiguous = false, timeout = false } = {}) {
    super(code);
    this.name = 'GithubConnectorError';
    this.code = code;
    this.status = status;
    this.ambiguous = ambiguous;
    this.timeout = timeout;
  }
}

export function createGithubRestConnector({
  token,
  baseUrl = DEFAULT_BASE_URL,
  apiVersion = DEFAULT_API_VERSION,
  userAgent = 'emilia-gate-service/0.1.0',
  fetchImpl = globalThis.fetch,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
} = {}) {
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
    async getRepository({ owner, repo, signal } = {}) {
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
      } catch (error) {
        throw new GithubConnectorError('github_get_failed', { timeout: isAbort(error) });
      }
      if (response?.status !== 200) {
        throw new GithubConnectorError('github_get_rejected', { status: response?.status ?? null });
      }
      return readBoundedJson(response, maxResponseBytes);
    },

    async deleteRepository({ owner, repo, idempotencyKey, actionId, signal } = {}) {
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
        throw new GithubConnectorError('github_delete_outcome_unknown', {
          status: response?.status ?? null,
          ambiguous: true,
        });
      }
      return { status: 204 };
    },
  });
}
