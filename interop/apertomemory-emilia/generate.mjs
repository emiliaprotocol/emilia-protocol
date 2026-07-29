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
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const keyId8 = (label) => b64u(crypto.createHash('sha256').update(label).digest().subarray(0, 8));
const id16 = (label) => b64u(crypto.createHash('sha256').update(label).digest().subarray(0, 16));

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
const OWNER_KEY_ID = keyId8('apertomemory/vault-owner');
const ORIGINAL_AUTHOR_KEY_ID = keyId8('apertomemory/original-author');
const OBJECT_ID = id16('apertomemory/object/custody-example');
const SECOND_OBJECT_ID = id16('apertomemory/object/owner-example');
const SCOPE_ID = id16('apertomemory/scope/personal-preferences');
const EVALUATED_AT = '2026-07-29T17:00:00.000Z';

const acceptedKeyIds = [ORIGINAL_AUTHOR_KEY_ID].sort();
const keyringSnapshot = {
  owner_key_id_b64u: OWNER_KEY_ID,
  accepted_key_ids_b64u: acceptedKeyIds,
};
const KEYRING_SNAPSHOT_DIGEST = sha256Digest(Buffer.from(canonicalize(keyringSnapshot), 'utf8'));
const ACCEPTED_KEY_IDS_DIGEST = sha256Digest(Buffer.from(canonicalize(acceptedKeyIds), 'utf8'));

const firstObject = {
  id_b64u: OBJECT_ID,
  scope_id_b64u: SCOPE_ID,
  format_version: 2,
  sealed_object_digest: sha256Digest(
    Buffer.from('deterministic ApertoMemory COSE_Sign1+COSE_Encrypt0 fixture: custody object', 'utf8'),
  ),
};

const secondObject = {
  id_b64u: SECOND_OBJECT_ID,
  scope_id_b64u: SCOPE_ID,
  format_version: 2,
  sealed_object_digest: sha256Digest(
    Buffer.from('deterministic ApertoMemory COSE_Sign1+COSE_Encrypt0 fixture: owner object', 'utf8'),
  ),
};

const nonclaims = Object.freeze({
  model_use: 'NOT_ESTABLISHED',
  action_linkage: 'NOT_ESTABLISHED',
  action_authorization: 'NOT_ESTABLISHED',
  execution_outcome: 'NOT_ESTABLISHED',
});

const trustCustodyResult = signTrustCustodyResult(
  {
    '@version': 'AMEM-TRUST-CUSTODY-RESULT-v0',
    source_profile: 'draft-ferro-apertomemory-02',
    record_id: 'urn:apertomemory:trust-result:composition-01',
    recorded_at: EVALUATED_AT,
    adapter: { id: ADAPTER_ID, key_id: ADAPTER_KEY_ID },
    object: firstObject,
    verification: {
      signature_verified: true,
      signer_key_id_b64u: OWNER_KEY_ID,
      derived_trust: 'trusted',
      trust_basis: 'accepted_key',
      authorship: 'attested',
      author_key_id_b64u: ORIGINAL_AUTHOR_KEY_ID,
      claimed_author_key_id_b64u: ORIGINAL_AUTHOR_KEY_ID,
      custody: {
        present: true,
        from_format_version: 1,
        resealed_at: '2026-07-28T18:30:00.000Z',
        claimed_author_key_id_b64u: ORIGINAL_AUTHOR_KEY_ID,
        proven_author_key_id_b64u: ORIGINAL_AUTHOR_KEY_ID,
      },
    },
    trust_context: {
      evaluated_at: EVALUATED_AT,
      owner_key_id_b64u: OWNER_KEY_ID,
      keyring_snapshot_digest: KEYRING_SNAPSHOT_DIGEST,
      accepted_key_ids_digest: ACCEPTED_KEY_IDS_DIGEST,
    },
    ai_boundary: {
      eligible_to_cross: true,
      crossing_label: 'trusted-data',
      excluded_object_count: 1,
      validation_flags: [
        'authentication_valid',
        'schema_valid',
        'trust_derived_at_read_time',
      ],
    },
    nonclaims,
  },
  ADAPTER.privateKey,
);

const firstFragment = Buffer.from(
  `[ApertoMemory trust=trusted authorship=attested author_key=${ORIGINAL_AUTHOR_KEY_ID} custody=true]\n` +
    `Preference: when planning deep work, reserve a quiet ninety-minute block before noon.\n` +
    `[/ApertoMemory]\n`,
  'utf8',
);
const secondFragment = Buffer.from(
  `[ApertoMemory trust=self authorship=signed author_key=${OWNER_KEY_ID} custody=false]\n` +
    `Preference: ask before moving a calendar commitment.\n` +
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
        Buffer.from('include self and trusted data; isolate labels; fail closed on authentication', 'utf8'),
      ),
      keyring_snapshot_digest: KEYRING_SNAPSHOT_DIGEST,
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
        author_key_id_b64u: ORIGINAL_AUTHOR_KEY_ID,
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
  adapter_pin: {
    adapter_id: ADAPTER_ID,
    key_id: ADAPTER_KEY_ID,
    alg: 'Ed25519',
    public_key_spki_b64u: b64u(ADAPTER.publicKey.export({ type: 'spki', format: 'der' })),
  },
  trust_custody: {
    description:
      'A vault-owner reseal preserves an accepted proven author. The adapter emits trusted/attested custody evidence and no model-use or action claim.',
    record: trustCustodyResult,
    expect: { valid: true, derived_trust: 'trusted', authorship: 'attested' },
  },
  projection: {
    description:
      'The adapter commits to two ordered, explicitly labelled context fragments and two exclusions without claiming that a model used the bytes.',
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
