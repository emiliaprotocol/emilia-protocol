// SPDX-License-Identifier: Apache-2.0
//
// Hostile cases for the external-authorization core. Each one is a way an
// attacker gets a real, validly signed, unexpired receipt and tries to spend it
// on a request it never authorized.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RECEIPT_REQUIRED_STATUS,
  authorizeAndForward,
  createExternalAuthorizer,
} from './authz.mjs';
import { carrierFor, mintReceipt, spyStore } from './fixtures.mjs';

const TARGET = 'payments.internal.example:443';
const APPROVED_BODY = new Uint8Array(Buffer.from('{"beneficiary":"acct_A","amount":25000}', 'utf8'));
const SUBSTITUTED_BODY = new Uint8Array(Buffer.from('{"beneficiary":"acct_B","amount":25000}', 'utf8'));

function newAuthorizer(overrides = {}) {
  const store = spyStore();
  const authorizer = createExternalAuthorizer({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store,
    ...overrides,
  });
  return { authorizer, store };
}

const request = (receipt, overrides = {}) => ({
  method: 'POST',
  path: '/v1/payments',
  query: '',
  target: TARGET,
  bodyBytes: APPROVED_BODY,
  ...overrides,
  headers: {
    ...(receipt === null ? {} : { 'x-emilia-receipt': carrierFor(receipt) }),
    ...(overrides.headers ?? {}),
  },
});

function approvedFor(authorizer, overrides = {}) {
  const binding = authorizer.bindingFor(request(null, overrides));
  return mintReceipt(binding.boundAction, binding.canonicalAction);
}

test('a receipt bound to this exact request authorizes it', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const decision = await authorizer.authorize(request(receipt));
  assert.equal(decision.ok, true);
  assert.equal(decision.status, 200);
  assert.equal(decision.receiptId, receipt.payload.receipt_id);
  assert.equal(decision.setHeaders['x-emilia-verified-receipt-id'], receipt.payload.receipt_id);
  assert.deepEqual(decision.removeHeaders, ['x-emilia-receipt']);
  assert.deepEqual(store.verbs(), ['reserve']);
});

test('HOSTILE: a valid receipt replayed against a DIFFERENT body is refused', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);

  // Same method, same path, same target, same receipt. Only the body — the
  // beneficiary of the payment — is different.
  const decision = await authorizer.authorize(request(receipt, { bodyBytes: SUBSTITUTED_BODY }));

  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
  assert.equal(decision.headers['x-ep-refusal-reason'], 'action_mismatch');
  assert.deepEqual(store.verbs(), [], 'a substituted body must never reach the consumption store');

  const honest = await authorizer.authorize(request(receipt));
  assert.equal(honest.ok, true, 'the receipt is genuine; only the binding refused it');
});

test('HOSTILE: a receipt for a different path is refused', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer, { path: '/v1/payments/preview' });
  const decision = await authorizer.authorize(request(receipt, { path: '/v1/payments' }));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
});

test('HOSTILE: a receipt for a different method is refused', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer, { method: 'PATCH' });
  const decision = await authorizer.authorize(request(receipt, { method: 'POST' }));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
});

test('HOSTILE: a receipt for a different query string is refused', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer, { query: 'dryRun=true' });
  const decision = await authorizer.authorize(request(receipt, { query: 'dryRun=false' }));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
});

test('HOSTILE: a receipt for a different target is refused', async () => {
  const { authorizer } = newAuthorizer();
  const elsewhere = createExternalAuthorizer({
    baseAction: 'payments.release',
    target: 'payments.staging.example:443',
    allowInlineKey: true,
    store: spyStore(),
  });
  const receipt = mintReceipt(
    elsewhere.bindingFor(request(null, { target: 'payments.staging.example:443' })).boundAction,
    elsewhere.bindingFor(request(null, { target: 'payments.staging.example:443' })).canonicalAction,
  );
  const decision = await authorizer.authorize(request(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
});

test('HOSTILE: a missing receipt is refused with a 428 challenge', async () => {
  const { authorizer, store } = newAuthorizer();
  const decision = await authorizer.authorize(request(null));
  assert.equal(decision.ok, false);
  assert.equal(decision.status, RECEIPT_REQUIRED_STATUS);
  assert.equal(decision.reason, 'receipt_required');
  assert.equal(decision.headers['content-type'], 'application/problem+json');
  assert.equal(decision.body.required.action, decision.boundAction);
  assert.deepEqual(store.verbs(), []);
});

test('HOSTILE: replaying the same receipt is refused', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);

  const first = await authorizeAndForward(authorizer, request(receipt));
  assert.equal(first.ok, true);

  const replay = await authorizeAndForward(authorizer, request(receipt));
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replay_refused');
  assert.deepEqual(store.verbs(), ['reserve', 'commit', 'reserve']);
});

test('HOSTILE: an in-flight replay loses the reservation race', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const [a, b] = await Promise.all([
    authorizer.authorize(request(receipt)),
    authorizer.authorize(request(receipt)),
  ]);
  assert.equal([a.ok, b.ok].filter(Boolean).length, 1);
  assert.equal((a.ok ? b : a).reason, 'replay_refused');
});

test('HOSTILE: a forged receipt is refused', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  receipt.payload.claim.canonical_action.body_sha256 = `sha256:${'0'.repeat(64)}`;
  const decision = await authorizer.authorize(request(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'untrusted_or_invalid_signature');
});

test('HOSTILE: a validly signed receipt that binds no canonical action is refused', async () => {
  const { authorizer } = newAuthorizer();
  const binding = authorizer.bindingFor(request(null));
  const receipt = mintReceipt(binding.boundAction, binding.canonicalAction, {
    omitCanonicalAction: true,
  });
  const decision = await authorizer.authorize(request(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'signed_action_required');
});

test('HOSTILE: a garbage carrier is refused, not parsed', async () => {
  const { authorizer } = newAuthorizer();
  for (const carrier of ['not base64 !!', 'e30', Buffer.from('{}').toString('base64')]) {
    const decision = await authorizer.authorize(
      request(null, { headers: { 'x-emilia-receipt': carrier } }),
    );
    assert.equal(decision.ok, false, `accepted carrier ${carrier}`);
  }
});

test('every refusal is a returned reason, never a thrown crash', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const cases = [
    ['no receipt', request(null)],
    ['substituted body', request(receipt, { bodyBytes: SUBSTITUTED_BODY })],
    ['no buffered body', request(receipt, { bodyBytes: undefined })],
    ['truncated body', request(receipt, { bodyTruncated: true })],
    ['summarized body', request(receipt, { bodyBytes: '{"amount":1}' })],
    ['unbindable path', request(receipt, { path: 'v1/payments' })],
    ['ambiguous proof header', {
      ...request(null),
      headers: { 'x-emilia-receipt': [carrierFor(receipt), carrierFor(receipt)] },
    }],
    ['content-length lie', request(receipt, { headers: { 'content-length': '1' } })],
  ];
  for (const [label, input] of cases) {
    const decision = await authorizer.authorize(input);
    assert.equal(decision.ok, false, `${label} was allowed`);
    assert.equal(typeof decision.reason, 'string', `${label} produced no reason`);
    assert.ok(decision.reason.length > 0, `${label} produced an empty reason`);
    assert.equal(decision.headers['x-ep-refusal-reason'], decision.reason);
    assert.equal(decision.body.rejected.reason, decision.reason);
    assert.equal(typeof decision.status, 'number');
    assert.ok(decision.status >= 400, `${label} did not deny`);
  }
});

test('a deployment that did not buffer the body fails LOUDLY, not as caller error', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const decision = await authorizer.authorize(request(receipt, { bodyBytes: undefined }));
  assert.equal(decision.reason, 'request_body_not_buffered');
  assert.equal(decision.status, 500, 'a misconfigured gateway must not look like a 4xx client error');
  assert.deepEqual(store.verbs(), []);
});

test('a truncated body fails the same way as an absent one', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const decision = await authorizer.authorize(request(receipt, { bodyTruncated: true }));
  assert.equal(decision.reason, 'request_body_truncated');
  assert.equal(decision.status, 500);
});

test('an oversized body denies with 413 and is never hashed', async () => {
  const { authorizer } = newAuthorizer({ maxBodyBytes: 16 });
  const decision = await authorizer.authorize(request(null, { bodyBytes: new Uint8Array(17) }));
  assert.equal(decision.reason, 'request_body_too_large');
  assert.equal(decision.status, 413);
});

test('a consumption store that cannot answer denies with 503', async () => {
  const authorizer = createExternalAuthorizer({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store: {
      async reserve() { throw new Error('store down'); },
      async commit() { return true; },
      async release() { return true; },
    },
  });
  const receipt = approvedFor(authorizer);
  const decision = await authorizer.authorize(request(receipt));
  assert.equal(decision.reason, 'consumption_store_unavailable');
  assert.equal(decision.status, 503);
});

test('INDETERMINATE: forwarding consumes, because the outcome is unobservable', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);

  const decision = await authorizer.authorize(request(receipt));
  assert.equal(decision.ok, true);
  // The gateway hands the request to an upstream it cannot observe. From this
  // point "the upstream refused" and "the upstream acted and the answer was
  // lost" are the same observation, so the approval must not survive.
  const forwarded = await decision.commitOnForward();
  assert.equal(forwarded.ok, true);
  assert.equal(forwarded.authority, 'consumed');
  assert.deepEqual(store.verbs(), ['reserve', 'commit']);

  const late = await decision.abandon();
  assert.equal(late.ok, false);
  assert.equal(late.reason, 'authority_not_releasable');
  assert.equal(store.verbs().filter((verb) => verb === 'release').length, 0);

  const replay = await authorizer.authorize(request(receipt));
  assert.equal(replay.reason, 'replay_refused');
});

test('the authority can be released only before the request is forwarded', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);

  const abandoned = await authorizer.authorize(request(receipt));
  assert.equal((await abandoned.abandon()).ok, true);
  assert.deepEqual(store.verbs(), ['reserve', 'release']);

  const retried = await authorizer.authorize(request(receipt));
  assert.equal(retried.ok, true, 'a released receipt was never spent');
  assert.equal((await retried.commitOnForward()).ok, true);
  assert.equal((await retried.commitOnForward()).reason, 'authority_already_settled');
});

test('a commit that fails leaves the reservation standing, so replay still loses', async () => {
  const brokenCommit = {
    reserved: new Set(),
    async reserve(id) { if (this.reserved.has(id)) return false; this.reserved.add(id); return true; },
    async commit() { throw new Error('commit unavailable'); },
    async release() { return true; },
  };
  const authorizer = createExternalAuthorizer({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store: brokenCommit,
  });
  const receipt = approvedFor(authorizer);
  const decision = await authorizeAndForward(authorizer, request(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'consumption_commit_failed');
  assert.equal(decision.status, 500);

  const replay = await authorizer.authorize(request(receipt));
  assert.equal(replay.reason, 'replay_refused');
});

test('pinned material headers are part of the approval', async () => {
  const { authorizer } = newAuthorizer({ materialHeaders: ['idempotency-key'] });
  const binding = authorizer.bindingFor(
    request(null, { headers: { 'idempotency-key': 'req-1' } }),
  );
  const receipt = mintReceipt(binding.boundAction, binding.canonicalAction);

  const honest = await authorizer.authorize(request(receipt, {
    headers: { 'idempotency-key': 'req-1' },
  }));
  assert.equal(honest.ok, true);

  const swapped = await authorizer.authorize(request(receipt, {
    headers: { 'idempotency-key': 'req-2' },
  }));
  assert.equal(swapped.ok, false);
  assert.equal(swapped.reason, 'action_mismatch');

  const dropped = await authorizer.authorize(request(receipt));
  assert.equal(dropped.ok, false);
  assert.equal(dropped.reason, 'action_mismatch');
});

test('pinning the carrier as a material header is refused at construction', () => {
  // Unsatisfiable rather than merely wrong: the receipt would have to contain
  // its own digest. A deployment must not discover this as a permanent
  // action_mismatch in production.
  assert.throws(
    () => createExternalAuthorizer({
      baseAction: 'payments.release',
      target: TARGET,
      materialHeaders: ['X-EMILIA-Receipt'],
    }),
    /carrier cannot be pinned as a material header/u,
  );
});

test('the proof carrier never travels to the upstream', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const decision = await authorizer.authorize(request(receipt));
  assert.deepEqual(decision.removeHeaders, ['x-emilia-receipt']);
  assert.equal(
    Object.values(decision.setHeaders).some((value) => value.includes(carrierFor(receipt))),
    false,
  );
});
