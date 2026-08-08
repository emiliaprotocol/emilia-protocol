// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  canonicalize,
  verifyActionBinding,
  verifyConfirmedVectorDelta,
  verifyPinnedSource,
} from './reperform.mjs';

const RETURN_PATH = fileURLToPath(new URL('./independent-return.v1.json', import.meta.url));
const LIVE_STATE_PATH = fileURLToPath(new URL('./confirmed-live-state.v1.json', import.meta.url));

test('the checked-in return preserves the bounded accepted result', async () => {
  const returned = JSON.parse(await readFile(RETURN_PATH, 'utf8'));
  assert.equal(returned.verification.exact_source_bytes, 'VERIFIED');
  assert.equal(returned.verification.authenticated_action_binding, 'MATCH');
  assert.equal(returned.accepted_result.action_linkage, 'EQUIVALENT');
  assert.equal(returned.accepted_result.principal_linkage, 'PROPOSED');
  assert.equal(returned.accepted_result.psea_conformance, 'NOT_ESTABLISHED');
  assert.equal(returned.accepted_result.provider_effect, 'INDETERMINATE');
});

test('the checked-in live state preserves the historical return and confirms only WHO', async () => {
  const live = JSON.parse(await readFile(LIVE_STATE_PATH, 'utf8'));
  assert.equal(live.historical_return.source_commit, 'e8c00e5014c52a4cb4ff51d24c360db5c82d599e');
  assert.equal(live.historical_return.principal_linkage_status, 'PROPOSED');
  assert.equal(live.verification.frozen_fixture_files, 'BYTE_IDENTICAL');
  assert.equal(live.verification.historical_to_live_delta, 'TWO_STATUS_FIELDS_ONLY');
  assert.equal(live.confirmed_state.principal_linkage, 'SAME');
  assert.equal(live.confirmed_state.principal_linkage_status, 'CONFIRMED');
  assert.equal(live.confirmed_state.principal_mapping_basis, 'SUPPLIED_NOT_DERIVED');
  assert.equal(live.confirmed_state.psea_conformance, 'NOT_ESTABLISHED');
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

test('the live-state verifier permits only the two confirmed-status changes', () => {
  const historical = {
    status: 'proposed',
    input: {
      join_who: {
        status: 'proposed convention, pending cross-run confirmation',
      },
    },
    expected: {
      stages: {
        action_linkage: { value: 'EQUIVALENT' },
        principal_linkage: { value: 'SAME' },
      },
    },
  };
  const live = JSON.parse(JSON.stringify(historical));
  live.status = 'confirmed';
  live.input.join_who.status =
    'confirmed at head 8bed788 (Mohamad Khalil-Yossif); WHO linkage established, PSEA conformance not established, kid-to-principal mapping supplied not derived';

  assert.deepEqual(
    verifyConfirmedVectorDelta(
      Buffer.from(JSON.stringify(historical)),
      Buffer.from(JSON.stringify(live)),
    ),
    { action_linkage: 'EQUIVALENT', principal_linkage: 'SAME' },
  );

  live.input.join_what = { changed: true };
  assert.throws(
    () => verifyConfirmedVectorDelta(
      Buffer.from(JSON.stringify(historical)),
      Buffer.from(JSON.stringify(live)),
    ),
    /historical-to-live vector delta/,
  );
});
