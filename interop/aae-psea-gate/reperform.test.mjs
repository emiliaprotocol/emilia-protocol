// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { canonicalize, verifyActionBinding, verifyPinnedSource } from './reperform.mjs';

const RETURN_PATH = fileURLToPath(new URL('./independent-return.v1.json', import.meta.url));

test('the checked-in return preserves the bounded accepted result', async () => {
  const returned = JSON.parse(await readFile(RETURN_PATH, 'utf8'));
  assert.equal(returned.verification.exact_source_bytes, 'VERIFIED');
  assert.equal(returned.verification.authenticated_action_binding, 'MATCH');
  assert.equal(returned.accepted_result.action_linkage, 'EQUIVALENT');
  assert.equal(returned.accepted_result.principal_linkage, 'PROPOSED');
  assert.equal(returned.accepted_result.psea_conformance, 'NOT_ESTABLISHED');
  assert.equal(returned.accepted_result.provider_effect, 'INDETERMINATE');
});

test('the independent JCS implementation reproduces the pinned payload order', () => {
  assert.equal(
    canonicalize({
      operation: 'transfer',
      target: 'iban:CH9300762011623852957',
      amount_minor: 250000,
      currency: 'CHF',
      sequence: 1,
    }),
    '{"amount_minor":250000,"currency":"CHF","operation":"transfer","sequence":1,"target":"iban:CH9300762011623852957"}',
  );
});

test('re-performance refuses when the exact upstream bytes are absent', () => {
  assert.throws(() => verifyPinnedSource({}, {}), /source file is missing/);
});

test('C6: a missing authenticated action binding cannot produce WHAT equivalence', () => {
  const payload = Buffer.from('{"amount_minor":250000}', 'utf8');
  assert.throws(
    () => verifyActionBinding(payload, { credentialSubject: { aae: { mandate: {} } } }),
    /authenticated action_binding is missing/,
  );
});

test('C7: a mismatched authenticated action binding cannot produce WHAT equivalence', () => {
  const payload = Buffer.from('{"amount_minor":250000}', 'utf8');
  assert.throws(
    () => verifyActionBinding(payload, {
      credentialSubject: {
        aae: {
          mandate: {
            action_binding: {
              alg: 'sha-256',
              canonicalization: 'JCS (RFC 8785)',
              payload_digest: 'sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            },
          },
        },
      },
    }),
    /action_binding digest/,
  );
});
