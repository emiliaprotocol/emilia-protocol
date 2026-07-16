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
