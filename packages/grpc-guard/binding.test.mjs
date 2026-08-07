// SPDX-License-Identifier: Apache-2.0
//
// The binding is the whole security argument. These tests pin the properties
// that make a carried receipt into a bound one.

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  GrpcBindingError,
  grpcActionBinding,
  readSingleMetadataValue,
  resolveRequestBytes,
  selectMaterialMetadata,
} from './binding.mjs';

const METHOD = '/emilia.payments.v1.Payments/ReleasePayment';
const TARGET = 'payments.internal.example:443';

const bind = (overrides = {}) => grpcActionBinding({
  baseAction: 'payments.release',
  methodPath: METHOD,
  target: TARGET,
  requestBytes: Buffer.from([0x0a, 0x03, 0x61, 0x62, 0x63]),
  ...overrides,
});

test('the same bytes, method and target produce the same action', () => {
  assert.equal(bind().boundAction, bind().boundAction);
  assert.match(bind().boundAction, /^payments\.release:sha256:[0-9a-f]{64}$/u);
});

test('one changed request byte is a different action', () => {
  const original = bind();
  const tampered = bind({ requestBytes: Buffer.from([0x0a, 0x03, 0x61, 0x62, 0x64]) });
  assert.notEqual(original.boundAction, tampered.boundAction);
  assert.notEqual(original.requestSha256, tampered.requestSha256);
});

test('a different method path is a different action', () => {
  assert.notEqual(
    bind().boundAction,
    bind({ methodPath: '/emilia.payments.v1.Payments/CancelPayment' }).boundAction,
  );
});

test('a different target is a different action', () => {
  assert.notEqual(bind().boundAction, bind({ target: 'payments.staging.example:443' }).boundAction);
});

test('the request length is bound, so truncation is a different action', () => {
  const full = bind({ requestBytes: Buffer.from([1, 2, 3, 4]) });
  const short = bind({ requestBytes: Buffer.from([1, 2, 3]) });
  assert.notEqual(full.boundAction, short.boundAction);
  assert.equal(full.canonicalAction.request_bytes, 4);
});

test('a caller-supplied summary of the request cannot be bound', () => {
  for (const impostor of [
    'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    { amount: 1, currency: 'USD' },
    ['not', 'bytes'],
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => bind({ requestBytes: impostor }),
      (error) => error instanceof GrpcBindingError && error.reason === 'request_bytes_invalid',
      `accepted ${JSON.stringify(impostor)} in place of request bytes`,
    );
  }
});

test('an empty request message is bindable and distinct from a one-byte one', () => {
  const empty = bind({ requestBytes: new Uint8Array(0) });
  assert.equal(empty.canonicalAction.request_bytes, 0);
  assert.notEqual(empty.boundAction, bind({ requestBytes: new Uint8Array(1) }).boundAction);
});

test('an oversized request is refused rather than hashed', () => {
  assert.throws(
    () => bind({ requestBytes: new Uint8Array(1025), maxRequestBytes: 1024 }),
    (error) => error.reason === 'request_too_large',
  );
});

test('a malformed method path or target is refused', () => {
  assert.throws(() => bind({ methodPath: 'ReleasePayment' }), (e) => e.reason === 'method_path_invalid');
  assert.throws(() => bind({ methodPath: '/Svc/Method/Extra' }), (e) => e.reason === 'method_path_invalid');
  assert.throws(() => bind({ target: 'payments internal:443' }), (e) => e.reason === 'target_invalid');
  assert.throws(() => bind({ target: '' }), (e) => e.reason === 'target_invalid');
});

test('the binding source is part of the action, so a downgrade cannot reuse an approval', () => {
  const wire = bind({ requestBindingSource: 'wire' });
  const reserialized = bind({ requestBindingSource: 'reserialized' });
  assert.notEqual(wire.boundAction, reserialized.boundAction);
  assert.throws(
    () => bind({ requestBindingSource: 'trust_me' }),
    (error) => error.reason === 'request_binding_source_invalid',
  );
});

test('re-serialization is refused unless it is explicitly permitted', () => {
  const message = { amount: 1 };
  const serializeRequest = () => Buffer.from('serialized');
  assert.throws(
    () => resolveRequestBytes(message, { serializeRequest }),
    (error) => error.reason === 'request_bytes_reserialization_not_permitted',
  );
  assert.throws(
    () => resolveRequestBytes(message, {}),
    (error) => error.reason === 'request_bytes_unavailable',
  );
  assert.deepEqual(
    resolveRequestBytes(message, { serializeRequest, allowReserializedRequestBinding: true }),
    { bytes: Buffer.from('serialized'), source: 'reserialized' },
  );
  assert.equal(resolveRequestBytes(Buffer.from('raw')).source, 'wire');
});

test('a pinned material metadata key is bound as absent when it is absent', () => {
  const present = selectMaterialMetadata({ 'x-tenant-id': 'acme' }, ['x-tenant-id']);
  const absent = selectMaterialMetadata({}, ['x-tenant-id']);
  assert.deepEqual(present, { 'x-tenant-id': 'acme' });
  assert.deepEqual(absent, { 'x-tenant-id': null });
  assert.notEqual(
    bind({ materialMetadata: present }).boundAction,
    bind({ materialMetadata: absent }).boundAction,
  );
});

test('duplicate or case-colliding metadata is ambiguous, never "the first one"', () => {
  assert.throws(
    () => readSingleMetadataValue({ 'x-emilia-receipt': ['a', 'b'] }, 'x-emilia-receipt'),
    (error) => error.reason === 'metadata_ambiguous',
  );
  assert.throws(
    () => readSingleMetadataValue({ 'X-EMILIA-Receipt': 'a', 'x-emilia-receipt': 'b' }, 'x-emilia-receipt'),
    (error) => error.reason === 'metadata_ambiguous',
  );
});

test('a binary metadata value is refused rather than coerced to a string', () => {
  assert.throws(
    () => readSingleMetadataValue({ 'x-emilia-receipt': Buffer.from('abc') }, 'x-emilia-receipt'),
    (error) => error.reason === 'metadata_value_invalid',
  );
});

test('a `-bin` metadata key is refused: it carries bytes, not an ASCII value', () => {
  assert.throws(
    () => readSingleMetadataValue({ 'x-emilia-receipt-bin': 'abc' }, 'x-emilia-receipt-bin'),
    (error) => error.reason === 'metadata_key_invalid',
  );
  assert.throws(
    () => selectMaterialMetadata({}, ['x-tenant-bin']),
    (error) => error.reason === 'material_metadata_invalid',
  );
});

test('a grpc-js style Metadata object is read through its own accessor', () => {
  const metadata = { get: (key) => (key === 'x-emilia-receipt' ? ['carried'] : []) };
  assert.equal(readSingleMetadataValue(metadata, 'x-emilia-receipt'), 'carried');
  assert.equal(readSingleMetadataValue(metadata, 'x-tenant-id'), undefined);
});
