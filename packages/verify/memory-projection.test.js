// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  MEMORY_PROJECTION_RECORD_DOMAIN,
  MEMORY_PROJECTION_RECORD_VERSION,
  MemoryProjectionVerificationError,
  memoryProjectionRecordDigest,
  verifyMemoryProjectionRecordV1,
  verifyMemoryProjectionRecordV1Envelope,
} from './memory-projection.js';

const VECTOR_PATH = fileURLToPath(new URL(
  '../../interop/apertomemory-emilia/memory-projection-record.v1.vectors.json',
  import.meta.url,
));
const GENERATOR_PATH = fileURLToPath(new URL(
  '../../interop/apertomemory-emilia/generate-memory-projection-v1.mjs',
  import.meta.url,
));
const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const clone = (value) => structuredClone(value);

function deterministicEd25519(label) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      crypto.createHash('sha256').update(label).digest(),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(',')}}`;
}

function material() {
  const source = vector.projection.verification_material;
  const native = clone(source.native_source_results_by_position);
  return {
    recallRequestBytes: Buffer.from(source.recall_request_b64u, 'base64url'),
    selectionPolicyBytes: Buffer.from(source.selection_policy_b64u, 'base64url'),
    trustSnapshotBytes: Buffer.from(source.trust_snapshot_b64u, 'base64url'),
    sourceObjectBytesByPosition: source.source_object_b64u_by_position
      .map((value) => Buffer.from(value, 'base64url')),
    fragmentBytesByPosition: source.fragment_b64u_by_position
      .map((value) => Buffer.from(value, 'base64url')),
    projectionBytes: Buffer.from(source.projection_b64u, 'base64url'),
    native,
    verifySourceEntry({ position }) {
      return native[position];
    },
  };
}

function policy() {
  const source = vector.verification_policy;
  const pin = vector.adapter_pin;
  return {
    adapterKeys: {
      [pin.key_id]: {
        public_key_spki_b64u: pin.public_key_spki_b64u,
        status: pin.status,
        valid_from: pin.valid_from,
        valid_to: pin.valid_to,
        revoked_at: pin.revoked_at,
      },
    },
    verificationTime: source.verification_time,
    maxProjectionAgeSec: source.max_projection_age_sec,
    maxTrustAgeSec: source.max_trust_age_sec,
    expectedSourceProfile: source.expected_source_profile,
    expectedContextFrameProfile: source.expected_context_frame_profile,
  };
}

function assertCode(callback, code) {
  assert.throws(callback, (error) => {
    assert.equal(error instanceof MemoryProjectionVerificationError, true);
    assert.equal(error.code, code, error.message);
    return true;
  });
}

function verify(record, verificationMaterial, activePolicy, options) {
  return verifyMemoryProjectionRecordV1(record, verificationMaterial, activePolicy, options);
}

test('reciprocal vector generator is byte-current', () => {
  execFileSync(process.execPath, [GENERATOR_PATH, '--check'], { stdio: 'pipe' });
});

test('published v1 domain and record version are exact', () => {
  assert.equal(MEMORY_PROJECTION_RECORD_VERSION, 'MEMORY-PROJECTION-RECORD-v1');
  assert.equal(MEMORY_PROJECTION_RECORD_DOMAIN, 'MEMORY-PROJECTION-RECORD-v1\0');
  assert.equal(vector.record_version, MEMORY_PROJECTION_RECORD_VERSION);
});

test('normative ApertoMemory source-profile vectors freeze deterministic bytes', () => {
  assert.equal(
    Buffer.from(
      vector.projection.verification_material.trust_snapshot_b64u,
      'base64url',
    ).toString('hex'),
    'a2014863c1e89c009c5ad7028148d05309cbd3b55f3b',
  );
  assert.equal(
    vector.projection.record.selection_context.trust_snapshot_digest,
    'sha256:ad677e36d1ac311f758cefeb41069704d1bc995612db0bc1029e239ecfcc2b5d',
  );

  const edges = vector.source_profile_edge_cases;
  assert.deepEqual(Object.keys(edges).sort(), [
    'empty_accepted_key_set',
    'multiple_accepted_keys',
    'null_author',
  ]);

  const nullAuthor = edges.null_author;
  assert.equal(nullAuthor.status, 'NORMATIVE_APERTOMEMORY_CONTEXT_FRAME_V0');
  assert.equal(
    Buffer.from(nullAuthor.fragment_b64u, 'base64url').toString('utf8'),
    '[ApertoMemory trust=unverified authorship=unknown author_key=none custody=false]\n'
      + 'Source edge: native verification did not resolve an author.\n'
      + '[/ApertoMemory]\n',
  );
  assert.deepEqual(nullAuthor.native_source_result, {
    derived_trust: 'unverified',
    authorship: 'unknown',
    author_key_id_b64u: null,
    custody_present: false,
  });

  const empty = edges.empty_accepted_key_set;
  assert.equal(empty.status, 'NORMATIVE_APERTOMEMORY_TRUST_SNAPSHOT_V0');
  assert.equal(empty.trust_snapshot_profile, 'urn:apertomemory:trust-snapshot:v0');
  assert.equal(
    Buffer.from(empty.trust_snapshot_b64u, 'base64url').toString('hex'),
    'a2014863c1e89c009c5ad70280',
  );
  assert.equal(
    empty.trust_snapshot_digest,
    'sha256:eddde59fb79cca10fdadf0c5bfc7c3b7e466cab79dcb95a5c4ea165fc8eb5bf0',
  );

  const multiple = edges.multiple_accepted_keys;
  assert.equal(multiple.ordering, 'RAW_KEY_ID_BYTES_ASCENDING');
  assert.notDeepEqual(multiple.input_accepted_key_ids_hex, multiple.accepted_key_ids_hex);
  assert.deepEqual(
    multiple.accepted_key_ids_hex,
    ['0000000000000001', 'd000000000000000'],
  );
  assert.equal(
    Buffer.from(multiple.trust_snapshot_b64u, 'base64url').toString('hex'),
    'a201480102030405060708028248000000000000000148d000000000000000',
  );
  assert.equal(
    multiple.trust_snapshot_digest,
    'sha256:a6cec9a790d68dda6df60477c802cd3738650cd8f1b38fcc21125de51762e231',
  );
});

test('envelope-only verification states its narrower evidence boundary', () => {
  const result = verifyMemoryProjectionRecordV1Envelope(vector.projection.record, policy());
  assert.deepEqual(result, {
    valid: true,
    verification_scope: 'SIGNED_ENVELOPE_ONLY',
    projection_id: 'urn:memory-projection:apertomemory:composition-01',
    projection_digest: vector.projection.record.projection.digest,
    delivered_count: 2,
    excluded_count: 2,
    created_at: '2026-07-29T17:00:01.000Z',
    trust_evaluated_at: '2026-07-29T17:00:00.000Z',
  });
  assert.match(memoryProjectionRecordDigest(vector.projection.record), /^sha256:[0-9a-f]{64}$/);
});

test('full verification rehashes all selection, source, fragment, and projection bytes', () => {
  const result = verify(vector.projection.record, material(), policy());
  assert.deepEqual(result, {
    valid: true,
    verification_scope: 'FULL_PROJECTION_AND_NATIVE_SOURCE_RESULTS',
    projection_id: 'urn:memory-projection:apertomemory:composition-01',
    projection_digest: vector.projection.record.projection.digest,
    delivered_count: 2,
    excluded_count: 2,
  });
});

test('all reciprocal hostile cases fail with the named closed reason', () => {
  assert.equal(vector.cases.length, 19);
  for (const testCase of vector.cases.slice(1)) {
    const record = clone(vector.projection.record);
    const verificationMaterial = material();
    const activePolicy = policy();
    const mutation = testCase.mutation;
    let options;

    if (mutation === 'add_unknown_top_level_member') record.caid = 'caid:must-not-appear';
    if (mutation === 'sign_with_legacy_v0_domain') {
      const { proof: _proof, ...unsigned } = record;
      const signer = deterministicEd25519('apertomemory-emilia/v0/adapter');
      record.proof.signature_b64u = crypto.sign(
        null,
        Buffer.concat([
          Buffer.from('AMEM-EMILIA-PROJECTION-RECORD-v0\0', 'utf8'),
          Buffer.from(canonicalize(unsigned), 'utf8'),
        ]),
        signer.privateKey,
      ).toString('base64url');
    }
    if (mutation === 'swap_delivered_entries') {
      [record.delivered[0], record.delivered[1]] = [record.delivered[1], record.delivered[0]];
    }
    if (mutation === 'omit_delivered_entry') record.delivered.pop();
    if (mutation === 'duplicate_delivered_position') record.delivered[1].position = 0;
    if (mutation === 'mutate_source_object_bytes') {
      verificationMaterial.sourceObjectBytesByPosition[0] = Buffer.concat([
        verificationMaterial.sourceObjectBytesByPosition[0],
        Buffer.from([0]),
      ]);
    }
    if (mutation === 'mutate_fragment_bytes') {
      verificationMaterial.fragmentBytesByPosition[0] = Buffer.from('different fragment', 'utf8');
    }
    if (mutation === 'substitute_projection_bytes_only') {
      verificationMaterial.projectionBytes = Buffer.from('different projection', 'utf8');
    }
    if (mutation === 'mutate_recall_request_bytes') {
      verificationMaterial.recallRequestBytes = Buffer.from('different recall request', 'utf8');
    }
    if (mutation === 'mutate_selection_policy_bytes') {
      verificationMaterial.selectionPolicyBytes = Buffer.from('different selection policy', 'utf8');
    }
    if (mutation === 'mutate_trust_snapshot_bytes') {
      verificationMaterial.trustSnapshotBytes = Buffer.from('different trust snapshot', 'utf8');
    }
    if (mutation === 'increment_exclusions_total') record.exclusions.total += 1;
    if (mutation === 'set_model_use_established') record.nonclaims.model_use = 'ESTABLISHED';
    if (mutation === 'remove_adapter_pin') activePolicy.adapterKeys = {};
    if (mutation === 'revoke_adapter_key') {
      activePolicy.adapterKeys[vector.adapter_pin.key_id].status = 'revoked';
      activePolicy.adapterKeys[vector.adapter_pin.key_id].revoked_at =
        '2026-07-29T17:00:30.000Z';
    }
    if (mutation === 'advance_verification_time') {
      activePolicy.verificationTime = '2026-07-29T18:00:00.000Z';
      activePolicy.maxProjectionAgeSec = 7200;
    }
    if (mutation === 'relabel_native_source_result') {
      verificationMaterial.native[0].derivedTrust = 'unverified';
    }
    if (mutation === 'register_projection_twice') {
      const seen = new Set();
      const registry = {
        register(projectionId) {
          if (seen.has(projectionId)) return false;
          seen.add(projectionId);
          return true;
        },
      };
      options = { requireSingleUse: true, projectionIdRegistry: registry };
      verify(record, verificationMaterial, activePolicy, options);
    }

    assertCode(
      () => verify(record, verificationMaterial, activePolicy, options),
      testCase.expect.result,
    );
  }
});
