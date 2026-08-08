// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  GatewayBindingError,
  httpActionBinding,
  normalizeRequestDescriptor,
  readSingleHeader,
  selectMaterialHeaders,
} from './descriptor.mjs';

const BODY = new Uint8Array(Buffer.from('{"beneficiary":"acct_A","amount":25000}', 'utf8'));

const descriptor = (overrides = {}) => ({
  method: 'POST',
  path: '/v1/payments',
  query: '',
  target: 'payments.internal.example:443',
  headers: {},
  bodyBytes: BODY,
  ...overrides,
});

const bind = (overrides = {}, options = {}) => httpActionBinding({
  baseAction: 'payments.release',
  descriptor: descriptor(overrides),
  ...options,
});

test('the same method, path, target and body produce the same action', () => {
  assert.equal(bind().boundAction, bind().boundAction);
  assert.match(bind().boundAction, /^payments\.release:sha256:[0-9a-f]{64}$/u);
});

test('one changed body byte is a different action', () => {
  const other = new Uint8Array(Buffer.from('{"beneficiary":"acct_B","amount":25000}', 'utf8'));
  assert.notEqual(bind().boundAction, bind({ bodyBytes: other }).boundAction);
});

test('method, path, query and target are each bound', () => {
  assert.notEqual(bind().boundAction, bind({ method: 'PUT' }).boundAction);
  assert.notEqual(bind().boundAction, bind({ path: '/v1/payments/urgent' }).boundAction);
  assert.notEqual(bind().boundAction, bind({ query: 'dryRun=false' }).boundAction);
  assert.notEqual(bind().boundAction, bind({ target: 'payments.staging.example:443' }).boundAction);
});

test('THE LIMITATION: a descriptor with no body cannot be bound', () => {
  assert.throws(
    () => bind({ bodyBytes: undefined }),
    (error) => error instanceof GatewayBindingError && error.reason === 'request_body_not_buffered',
  );
  assert.throws(
    () => bind({ bodyBytes: null }),
    (error) => error.reason === 'request_body_not_buffered',
  );
});

test('THE LIMITATION: a truncated body is refused, not hashed as a prefix', () => {
  assert.throws(
    () => bind({ bodyTruncated: true }),
    (error) => error.reason === 'request_body_truncated',
  );
});

test('a caller-supplied summary of the body cannot be bound', () => {
  for (const impostor of ['{"beneficiary":"acct_A"}', { beneficiary: 'acct_A' }, 42, ['bytes']]) {
    assert.throws(
      () => bind({ bodyBytes: impostor }),
      (error) => error.reason === 'request_body_invalid',
      `accepted ${JSON.stringify(impostor)} in place of body bytes`,
    );
  }
});

test('an empty body is bindable and distinct from a one-byte body', () => {
  const empty = bind({ bodyBytes: new Uint8Array(0) });
  assert.equal(empty.bodyByteLength, 0);
  assert.notEqual(empty.boundAction, bind({ bodyBytes: new Uint8Array(1) }).boundAction);
});

test('a content-length that disagrees with the bytes in hand is refused', () => {
  assert.throws(
    () => bind({ headers: { 'content-length': '9999' } }),
    (error) => error.reason === 'content_length_mismatch',
  );
  assert.equal(
    bind({ headers: { 'content-length': String(BODY.byteLength) } }).bodyByteLength,
    BODY.byteLength,
  );
});

test('an oversized body is refused rather than hashed', () => {
  assert.throws(
    () => bind({ bodyBytes: new Uint8Array(1025) }, { maxBodyBytes: 1024 }),
    (error) => error.reason === 'request_body_too_large',
  );
});

test('a malformed method, path, query or target is refused', () => {
  assert.throws(() => bind({ method: 'PO ST' }), (e) => e.reason === 'request_method_invalid');
  assert.throws(() => bind({ path: 'v1/payments' }), (e) => e.reason === 'request_path_invalid');
  assert.throws(() => bind({ path: '/v1/payments?a=1' }), (e) => e.reason === 'request_path_invalid');
  assert.throws(() => bind({ query: 'a=1#frag' }), (e) => e.reason === 'request_query_invalid');
  assert.throws(() => bind({ target: 'payments internal' }), (e) => e.reason === 'request_target_invalid');
});

test('the method is normalized to upper case before it is bound', () => {
  assert.equal(normalizeRequestDescriptor(descriptor({ method: 'post' })).method, 'POST');
  assert.equal(bind({ method: 'post' }).boundAction, bind({ method: 'POST' }).boundAction);
});

test('a pinned material header is bound as absent when it is absent', () => {
  const withHeader = bind(
    { headers: { 'idempotency-key': 'req-1' } },
    { materialHeaders: ['idempotency-key'] },
  );
  const without = bind({}, { materialHeaders: ['idempotency-key'] });
  assert.deepEqual(withHeader.canonicalAction.headers, { 'idempotency-key': 'req-1' });
  assert.deepEqual(without.canonicalAction.headers, { 'idempotency-key': null });
  assert.notEqual(withHeader.boundAction, without.boundAction);
});

test('an unpinned header is outside the approval', () => {
  const a = bind({ headers: { 'x-request-id': 'one' } });
  const b = bind({ headers: { 'x-request-id': 'two' } });
  assert.equal(a.boundAction, b.boundAction);
  assert.equal(a.canonicalAction.headers, undefined);
});

test('duplicate or case-colliding headers are ambiguous, never "the first one"', () => {
  assert.throws(
    () => readSingleHeader({ 'x-emilia-receipt': ['a', 'b'] }, 'x-emilia-receipt'),
    (error) => error.reason === 'header_ambiguous',
  );
  assert.throws(
    () => readSingleHeader({ 'X-Emilia-Receipt': 'a', 'x-emilia-receipt': 'b' }, 'x-emilia-receipt'),
    (error) => error.reason === 'header_ambiguous',
  );
  assert.throws(
    () => selectMaterialHeaders({ 'Idempotency-Key': 'a', 'idempotency-key': 'b' }, ['idempotency-key']),
    (error) => error.reason === 'header_ambiguous',
  );
});

test('a non-string header value is refused rather than coerced', () => {
  assert.throws(
    () => readSingleHeader({ 'content-length': 39 }, 'content-length'),
    (error) => error.reason === 'header_value_invalid',
  );
});
