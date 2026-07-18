// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseReceiptCarrier } from './index.js';
import { strictJsonGate } from './strict-json.js';

function carrier(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

test('parseReceiptCarrier accepts a canonical base64 JSON object', () => {
  assert.deepEqual(parseReceiptCarrier(carrier('{"@version":"EP-RECEIPT-v1","payload":{}}')), {
    '@version': 'EP-RECEIPT-v1',
    payload: {},
  });
});

test('parseReceiptCarrier refuses duplicate members and non-object roots', () => {
  assert.equal(parseReceiptCarrier(carrier('{"payload":{},"payload":{"forged":true}}')), null);
  assert.equal(parseReceiptCarrier(carrier('[{"@version":"EP-RECEIPT-v1"}]')), null);
});

test('parseReceiptCarrier refuses malformed UTF-8, non-canonical encoding, and oversize input', () => {
  assert.equal(parseReceiptCarrier(Buffer.from([0xc3, 0x28]).toString('base64')), null);
  assert.equal(parseReceiptCarrier(`${carrier('{}')}=`), null);
  assert.equal(parseReceiptCarrier(carrier('{"payload":{}}'), { maxBytes: 4 }), null);
});

test('the strict JSON gate refuses literal unpaired UTF-16 surrogates', () => {
  assert.deepEqual(strictJsonGate('{"value":"\ud800"}'), {
    ok: false,
    reason: 'unpaired Unicode surrogate',
  });
});
