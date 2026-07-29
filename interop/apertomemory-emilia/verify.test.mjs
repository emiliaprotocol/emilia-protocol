// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  verifyProjectionRecord,
  verifyTrustCustodyResult,
} from './verify.mjs';

const VECTOR_PATH = fileURLToPath(new URL('./apertomemory-emilia.v1.json', import.meta.url));
const GENERATOR_PATH = fileURLToPath(new URL('./generate.mjs', import.meta.url));
const bundle = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const adapterKeys = {
  [bundle.adapter_pin.key_id]: bundle.adapter_pin.public_key_spki_b64u,
};
const projectionBytes = Buffer.from(
  bundle.projection.verification_material.projection_utf8_b64u,
  'base64url',
);
const fragmentBytesByPosition = bundle.projection.verification_material.fragment_utf8_b64u.map(
  (value) => Buffer.from(value, 'base64url'),
);
const clone = (value) => structuredClone(value);

test('generated vectors are byte-current', () => {
  execFileSync(process.execPath, [GENERATOR_PATH, '--check'], { stdio: 'pipe' });
});

test('trust-and-custody result verifies under the pinned adapter key', () => {
  const result = verifyTrustCustodyResult(bundle.trust_custody.record, { adapterKeys });
  assert.deepEqual(result, {
    valid: true,
    record_id: 'urn:apertomemory:trust-result:composition-01',
    derived_trust: 'trusted',
  });
  assert.equal(bundle.trust_custody.record.verification.authorship, 'attested');
  assert.notEqual(
    bundle.trust_custody.record.verification.author_key_id_b64u,
    bundle.trust_custody.record.verification.signer_key_id_b64u,
    'custody must report the proven original author, not the resealing vault owner',
  );
});

test('memory-projection record verifies exact ordered bytes and fragment commitments', () => {
  const result = verifyProjectionRecord(bundle.projection.record, {
    adapterKeys,
    projectionBytes,
    fragmentBytesByPosition,
  });
  assert.deepEqual(result, {
    valid: true,
    projection_id: 'urn:apertomemory:projection:composition-01',
    delivered_count: 2,
    excluded_count: 2,
  });
});

test('trust result refuses a derived-trust mutation', () => {
  const tampered = clone(bundle.trust_custody.record);
  tampered.verification.derived_trust = 'self';
  assert.throws(
    () => verifyTrustCustodyResult(tampered, { adapterKeys }),
    /resealed custody result cannot derive self trust/,
  );
});

test('trust result refuses a custody-author mutation', () => {
  const tampered = clone(bundle.trust_custody.record);
  tampered.verification.custody.proven_author_key_id_b64u = tampered.verification.signer_key_id_b64u;
  assert.throws(
    () => verifyTrustCustodyResult(tampered, { adapterKeys }),
    /attested custody must report the proven author key/,
  );
});

test('trust result refuses altered nonclaims', () => {
  const tampered = clone(bundle.trust_custody.record);
  tampered.nonclaims.model_use = 'ESTABLISHED';
  assert.throws(
    () => verifyTrustCustodyResult(tampered, { adapterKeys }),
    /model_use must be NOT_ESTABLISHED/,
  );
});

test('trust result refuses an unpinned adapter key', () => {
  assert.throws(
    () => verifyTrustCustodyResult(bundle.trust_custody.record, { adapterKeys: {} }),
    /is not pinned by the relying party/,
  );
});

test('trust result refuses an impostor pinned key', () => {
  const impostor = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
  assert.throws(
    () =>
      verifyTrustCustodyResult(bundle.trust_custody.record, {
        adapterKeys: { [bundle.adapter_pin.key_id]: Buffer.from(impostor).toString('base64url') },
      }),
    /record signature is invalid/,
  );
});

test('projection refuses an exclusion-count mutation', () => {
  const tampered = clone(bundle.projection.record);
  tampered.exclusions.total += 1;
  assert.throws(
    () => verifyProjectionRecord(tampered, { adapterKeys }),
    /must equal the sum of by_reason counts/,
  );
});

test('projection refuses non-sequential delivered ordering', () => {
  const tampered = clone(bundle.projection.record);
  tampered.delivered[1].position = 7;
  assert.throws(
    () => verifyProjectionRecord(tampered, { adapterKeys }),
    /position must equal 1/,
  );
});

test('projection refuses bytes that do not match the signed projection digest', () => {
  const tamperedBytes = Buffer.concat([projectionBytes, Buffer.from('tampered', 'utf8')]);
  assert.throws(
    () => verifyProjectionRecord(bundle.projection.record, { adapterKeys, projectionBytes: tamperedBytes }),
    /projection bytes do not match byte_length/,
  );
});

test('projection refuses fragment bytes that do not match the signed fragment commitment', () => {
  const fragments = [...fragmentBytesByPosition];
  fragments[0] = Buffer.from('different fragment', 'utf8');
  assert.throws(
    () =>
      verifyProjectionRecord(bundle.projection.record, {
        adapterKeys,
        projectionBytes,
        fragmentBytesByPosition: fragments,
      }),
    /position 0 do not match context_fragment_digest/,
  );
});

test('projection refuses unsigned extension fields outside the strict record shape', () => {
  const tampered = clone(bundle.projection.record);
  tampered.caid = 'caid:must-not-appear-here';
  assert.throws(
    () => verifyProjectionRecord(tampered, { adapterKeys }),
    /record fields must be exactly/,
  );
});

test('both records make the four required nonclaims and no action claim', () => {
  const expected = {
    model_use: 'NOT_ESTABLISHED',
    action_linkage: 'NOT_ESTABLISHED',
    action_authorization: 'NOT_ESTABLISHED',
    execution_outcome: 'NOT_ESTABLISHED',
  };
  assert.deepEqual(bundle.trust_custody.record.nonclaims, expected);
  assert.deepEqual(bundle.projection.record.nonclaims, expected);
  assert.equal('caid' in bundle.trust_custody.record, false);
  assert.equal('caid' in bundle.projection.record, false);
});
