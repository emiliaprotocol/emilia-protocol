// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../lib/canonical-json.js';
import {
  sha256Digest,
  signProjectionRecord,
  signTrustCustodyResult,
} from './verify.mjs';

const OUTPUT = fileURLToPath(new URL('./apertomemory-emilia.v1.json', import.meta.url));
const SOURCE_FIXTURES_PATH = fileURLToPath(
  new URL('./apertomemory-source-fixtures.v2.json', import.meta.url),
);
const sourceFixtures = JSON.parse(readFileSync(SOURCE_FIXTURES_PATH, 'utf8'));
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const keyIdB64u = (hex) => (hex === null ? null : b64u(Buffer.from(hex, 'hex')));

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

const ADAPTER = deterministicEd25519('apertomemory-emilia/v0/adapter');
const ADAPTER_KEY_ID = 'apertomemory-adapter-key-2026-07';
const ADAPTER_ID = 'urn:apertomemory:adapter:reference-01';
const OWNER_KEY_ID_HEX = '63c1e89c009c5ad7';
const OWNER_KEY_ID = keyIdB64u(OWNER_KEY_ID_HEX);
const EVALUATED_AT = '2026-07-29T17:00:00.000Z';

const acceptedKeysByVector = Object.freeze({
  '007-custody-attested': ['d05309cbd3b55f3b'],
  '008-custody-unproven': [],
  '011-custody-from-non-owner-MUST-NOT-BE-HONOURED': ['d05309cbd3b55f3b'],
  '012-custody-naming-an-unaccepted-key': [],
  '014-empty-custody-map': [],
});

const nonclaims = Object.freeze({
  model_use: 'NOT_ESTABLISHED',
  action_linkage: 'NOT_ESTABLISHED',
  action_authorization: 'NOT_ESTABLISHED',
  execution_outcome: 'NOT_ESTABLISHED',
});

function keyringContext(sourceVector) {
  const acceptedKeyIds = acceptedKeysByVector[sourceVector].map(keyIdB64u).sort();
  const snapshot = {
    owner_key_id_b64u: OWNER_KEY_ID,
    accepted_key_ids_b64u: acceptedKeyIds,
  };
  return {
    evaluated_at: EVALUATED_AT,
    owner_key_id_b64u: OWNER_KEY_ID,
    keyring_snapshot_digest: sha256Digest(Buffer.from(canonicalize(snapshot), 'utf8')),
    accepted_key_ids_digest: sha256Digest(Buffer.from(canonicalize(acceptedKeyIds), 'utf8')),
  };
}

function objectCommitment(fixture) {
  const exactSealedObjectBytes = Buffer.from(fixture.sealed_object_hex, 'hex');
  return {
    object: {
      format_version: 2,
      sealed_object_digest: sha256Digest(exactSealedObjectBytes),
    },
    sealed_object_byte_length: exactSealedObjectBytes.length,
  };
}

function sourceRecord(sourceVector, fixture) {
  const positive = sourceVector === '007-custody-attested';
  const emptyCustody = sourceVector === '014-empty-custody-map';
  const { object } = objectCommitment(fixture);
  const authorKey = keyIdB64u(fixture.native_expect.author_key_id ?? null);
  const claimedAuthorKey = keyIdB64u(fixture.claimed_author_key_id_hex);
  const provenAuthorKey = keyIdB64u(fixture.proven_author_key_id_hex);

  return signTrustCustodyResult(
    {
      '@version': 'AMEM-TRUST-CUSTODY-RESULT-v0',
      source_profile: 'draft-ferro-apertomemory-02',
      record_id: `urn:apertomemory:trust-result:${sourceVector}`,
      recorded_at: EVALUATED_AT,
      adapter: { id: ADAPTER_ID, key_id: ADAPTER_KEY_ID },
      object,
      verification: {
        signature_verified: true,
        signer_key_id_b64u: keyIdB64u(fixture.signer_key_id_hex),
        derived_trust: fixture.native_expect.trust,
        trust_basis: positive ? 'accepted_key' : 'none',
        authorship: fixture.native_expect.authorship,
        author_key_id_b64u: authorKey,
        claimed_author_key_id_b64u: claimedAuthorKey,
        custody: {
          present: true,
          from_format_version: emptyCustody ? null : 1,
          claimed_author_key_id_b64u: claimedAuthorKey,
          proven_author_key_id_b64u: provenAuthorKey,
        },
      },
      trust_context: keyringContext(sourceVector),
      ai_boundary: {
        eligible_to_cross: positive,
        crossing_label: positive ? 'trusted-data' : 'withheld',
        excluded_object_count: positive ? 0 : 1,
        validation_flags: positive
          ? ['authentication_valid', 'schema_valid', 'trust_derived_at_read_time']
          : ['authentication_valid', 'trust_degraded_at_read_time'],
      },
      nonclaims,
    },
    ADAPTER.privateKey,
  );
}

const sourceCases = Object.entries(sourceFixtures.vectors).map(([sourceVector, fixture]) => {
  const commitment = objectCommitment(fixture);
  return {
    source_vector: sourceVector,
    source_sealed_object_byte_length: commitment.sealed_object_byte_length,
    source_sealed_object_digest: commitment.object.sealed_object_digest,
    native_expect: fixture.native_expect,
    record: sourceRecord(sourceVector, fixture),
    expect: {
      valid: true,
      derived_trust: fixture.native_expect.trust,
      authorship: fixture.native_expect.authorship,
      eligible_to_cross: sourceVector === '007-custody-attested',
    },
  };
});

const positiveCase = sourceCases.find((entry) => entry.source_vector === '007-custody-attested');
const firstObject = positiveCase.record.object;
const originalAuthorKeyId = positiveCase.record.verification.author_key_id_b64u;
const directOwnerFixture = sourceFixtures.projection_support['003-sealed-object-v2'];
const secondObject = objectCommitment(directOwnerFixture).object;
const firstFragment = Buffer.from(
  `[ApertoMemory trust=trusted authorship=attested author_key=${originalAuthorKeyId} custody=true]\n` +
    `Source vector 007: fact authored by a third party and re-sealed by the vault owner.\n` +
    `[/ApertoMemory]\n`,
  'utf8',
);
const secondFragment = Buffer.from(
  `[ApertoMemory trust=self authorship=signed author_key=${OWNER_KEY_ID} custody=false]\n` +
    `Source vector 003: prefers formal B2B emails.\n` +
    `[/ApertoMemory]\n`,
  'utf8',
);
const projectionBytes = Buffer.concat([firstFragment, secondFragment]);

const projectionRecord = signProjectionRecord(
  {
    '@version': 'AMEM-PROJECTION-RECORD-v0',
    profile_status: 'EMILIA_DISCUSSION_INPUT_NOT_APERTOMEMORY_CONFORMANCE',
    source_profile: 'draft-ferro-apertomemory-02',
    projection_id: 'urn:apertomemory:projection:composition-01',
    created_at: '2026-07-29T17:00:01.000Z',
    adapter: { id: ADAPTER_ID, key_id: ADAPTER_KEY_ID },
    selection_context: {
      recall_request_digest: sha256Digest(
        Buffer.from('private recall request fixture; cleartext deliberately not carried', 'utf8'),
      ),
      selection_policy_digest: sha256Digest(
        Buffer.from('include trusted data; isolate labels; withhold unverified objects', 'utf8'),
      ),
      keyring_snapshot_digest: positiveCase.record.trust_context.keyring_snapshot_digest,
      trust_evaluated_at: EVALUATED_AT,
      context_frame_profile: 'AMEM-CONTEXT-FRAME-v0',
    },
    delivered: [
      {
        position: 0,
        object: firstObject,
        context_fragment_digest: sha256Digest(firstFragment),
        derived_trust: 'trusted',
        authorship: 'attested',
        author_key_id_b64u: originalAuthorKeyId,
        custody_present: true,
      },
      {
        position: 1,
        object: secondObject,
        context_fragment_digest: sha256Digest(secondFragment),
        derived_trust: 'self',
        authorship: 'signed',
        author_key_id_b64u: OWNER_KEY_ID,
        custody_present: false,
      },
    ],
    exclusions: {
      total: 2,
      by_reason: {
        authentication_failed: 1,
        schema_invalid: 0,
        policy_filtered: 0,
        context_limit: 1,
      },
    },
    projection: {
      encoding: 'utf-8',
      byte_length: projectionBytes.length,
      digest: sha256Digest(projectionBytes),
    },
    nonclaims,
  },
  ADAPTER.privateKey,
);

const bundle = {
  '@version': 'AMEM-EMILIA-COMPOSITION-VECTORS-v1',
  source_profile: 'draft-ferro-apertomemory-02',
  source_fidelity: {
    fixture_source: sourceFixtures.source,
    commitment_method: sourceFixtures.commitment_method,
    key_id_representation: sourceFixtures.key_id_representation,
  },
  adapter_pin: {
    adapter_id: ADAPTER_ID,
    key_id: ADAPTER_KEY_ID,
    alg: 'Ed25519',
    public_key_spki_b64u: b64u(ADAPTER.publicKey.export({ type: 'spki', format: 'der' })),
  },
  source_cases: sourceCases,
  trust_custody: {
    description:
      'Official vector 007: a vault-owner reseal preserves an accepted proven author. The adapter reports trusted/attested custody evidence and no model-use or action claim.',
    source_vector: positiveCase.source_vector,
    record: positiveCase.record,
    expect: positiveCase.expect,
  },
  projection: {
    description:
      'The adapter commits to two ordered, explicitly labelled context fragments from official vectors 007 and 003. The negative custody cases are checked separately and do not cross the AI boundary.',
    record: projectionRecord,
    verification_material: {
      projection_utf8_b64u: b64u(projectionBytes),
      fragment_utf8_b64u: [b64u(firstFragment), b64u(secondFragment)],
    },
    expect: { valid: true, delivered_count: 2, excluded_count: 2 },
  },
};

const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
if (process.argv.includes('--check')) {
  let current;
  try {
    current = readFileSync(OUTPUT, 'utf8');
  } catch {
    console.error(`missing generated vector: ${OUTPUT}`);
    process.exit(1);
  }
  if (current !== serialized) {
    console.error('apertomemory-emilia.v1.json is stale; run generate.mjs');
    process.exit(1);
  }
  console.log('ApertoMemory / EMILIA vectors are current');
} else {
  writeFileSync(OUTPUT, serialized);
  console.log(`wrote ${OUTPUT}`);
}
