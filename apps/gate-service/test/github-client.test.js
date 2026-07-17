// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGithubRestConnector } from '../src/github-client.js';
import { REPOSITORY } from './helpers.js';

test('GitHub REST connector performs one GET and one idempotency-aware DELETE with mocked fetch', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (options.method === 'GET') {
      return new Response(JSON.stringify(REPOSITORY), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(null, { status: 204 });
  };
  const connector = createGithubRestConnector({
    token: 'github-test-secret',
    apiVersion: '2026-03-10',
    fetchImpl,
  });

  const repository = await connector.getRepository({ owner: 'acme', repo: 'prod' });
  assert.equal(repository.node_id, REPOSITORY.node_id);
  const deleted = await connector.deleteRepository({
    owner: 'Acme',
    repo: 'Prod',
    idempotencyKey: 'emilia-abcdefghijklmnopqrstuvwxyz0123456789ABCDE',
    actionId: 'test-action-0000000000000001',
  });

  assert.equal(deleted.status, 204);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.method, 'GET');
  assert.equal(calls[1].options.method, 'DELETE');
  assert.equal(calls[1].options.headers['Idempotency-Key'], 'emilia-abcdefghijklmnopqrstuvwxyz0123456789ABCDE');
  assert.equal(calls[1].options.headers.Authorization, 'Bearer github-test-secret');
  assert.equal(Object.values(calls[1].options.headers).some((value) => /EP-RECEIPT/.test(value)), false);
});

test('GitHub REST connector does not retry an ambiguous DELETE timeout', async () => {
  let calls = 0;
  const connector = createGithubRestConnector({
    token: 'github-test-secret',
    fetchImpl: async () => {
      calls += 1;
      throw new DOMException('timed out', 'TimeoutError');
    },
  });

  await assert.rejects(
    () => connector.deleteRepository({
      owner: 'Acme',
      repo: 'Prod',
      idempotencyKey: 'emilia-abcdefghijklmnopqrstuvwxyz0123456789ABCDE',
      actionId: 'test-action-0000000000000001',
    }),
    (error) => error.code === 'github_delete_outcome_unknown'
      && error.ambiguous === true
      && error.timeout === true,
  );
  assert.equal(calls, 1);
});

test('GitHub REST connector incrementally reads JSON without calling response.text()', async () => {
  const bytes = Buffer.from(JSON.stringify(REPOSITORY), 'utf8');
  let offset = 0;
  let textCalled = false;
  const response = {
    status: 200,
    headers: new Headers(),
    text() {
      textCalled = true;
      throw new Error('response.text must not be called');
    },
    body: {
      getReader() {
        return {
          async read() {
            if (offset >= bytes.length) return { done: true };
            const chunk = bytes.subarray(offset, Math.min(offset + 7, bytes.length));
            offset += chunk.length;
            return { done: false, value: chunk };
          },
          async cancel() {},
        };
      },
    },
  };
  const connector = createGithubRestConnector({
    token: 'github-test-secret',
    maxResponseBytes: 1024,
    fetchImpl: async () => response,
  });

  assert.deepEqual(await connector.getRepository({ owner: 'acme', repo: 'prod' }), REPOSITORY);
  assert.equal(textCalled, false);
});

test('GitHub REST connector cancels immediately when a streamed body crosses the hard byte limit', async () => {
  let reads = 0;
  let cancels = 0;
  const response = {
    status: 200,
    headers: new Headers(),
    text() { throw new Error('response.text must not be called'); },
    body: {
      getReader() {
        return {
          async read() {
            reads += 1;
            return { done: false, value: new Uint8Array(700) };
          },
          async cancel() { cancels += 1; },
        };
      },
    },
  };
  const connector = createGithubRestConnector({
    token: 'github-test-secret',
    maxResponseBytes: 1024,
    fetchImpl: async () => response,
  });

  await assert.rejects(
    () => connector.getRepository({ owner: 'acme', repo: 'prod' }),
    (error) => error.code === 'github_response_too_large',
  );
  assert.equal(reads, 2);
  assert.equal(cancels, 1);
});

test('GitHub REST connector cancels announced oversize and aborted response streams', async () => {
  let announcedCancels = 0;
  const announced = createGithubRestConnector({
    token: 'github-test-secret',
    maxResponseBytes: 1024,
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'Content-Length': '2048' }),
      body: { async cancel() { announcedCancels += 1; } },
      text() { throw new Error('response.text must not be called'); },
    }),
  });
  await assert.rejects(
    () => announced.getRepository({ owner: 'acme', repo: 'prod' }),
    (error) => error.code === 'github_response_too_large',
  );
  assert.equal(announcedCancels, 1);

  let streamCancels = 0;
  const controller = new AbortController();
  const aborted = createGithubRestConnector({
    token: 'github-test-secret',
    maxResponseBytes: 1024,
    fetchImpl: async (_url, { signal }) => ({
      status: 200,
      headers: new Headers(),
      body: {
        getReader() {
          return {
            read() {
              return new Promise((_resolve, reject) => {
                if (signal.aborted) {
                  reject(new DOMException('aborted', 'AbortError'));
                  return;
                }
                signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
              });
            },
            async cancel() { streamCancels += 1; },
          };
        },
      },
      text() { throw new Error('response.text must not be called'); },
    }),
  });
  const pending = aborted.getRepository({ owner: 'acme', repo: 'prod', signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    (error) => error.code === 'github_get_failed' && error.timeout === true,
  );
  assert.equal(streamCancels, 1);
});
