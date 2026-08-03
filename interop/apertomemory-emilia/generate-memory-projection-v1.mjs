// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../lib/canonical-json.js';
import {
  createMemoryProjectionRecordV1,
  MEMORY_PROJECTION_RECORD_VERSION,
} from '../../packages/verify/memory-projection.js';

const OUTPUT = fileURLToPath(
  new URL('./memory-projection-record.v1.vectors.json', import.meta.url),
);
const LEGACY_BUNDLE_PATH = fileURLToPath(
  new URL('./apertomemory-emilia.v1.json', import.meta.url),
);
const SOURCE_FIXTURES_PATH = fileURLToPath(
  new URL('./apertomemory-source-fixtures.v2.json', import.meta.url),
);
const legacyBundle = JSON.parse(readFileSync(LEGACY_BUNDLE_PATH, 'utf8'));
const sourceFixtures = JSON.parse(readFileSync(SOURCE_FIXTURES_PATH, 'utf8'));
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const keyIdB64u = (hex) => b64u(Buffer.from(hex, 'hex'));
const sha256 = (bytes) => `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;

function keyIdBytes(hex) {
  if (!/^[0-9a-f]{16}$/.test(hex)) {
    throw new Error(`ApertoMemory key-id must be 8 lowercase-hex bytes: ${hex}`);
  }
  return Buffer.from(hex, 'hex');
}

function canonicalCborArrayHeader(length) {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error('CBOR array length must be a non-negative safe integer');
  }
  if (length < 24) return Buffer.from([0x80 + length]);
  if (length < 0x100) return Buffer.from([0x98, length]);
  if (length < 0x10000) {
    const header = Buffer.alloc(3);
    header[0] = 0x99;
    header.writeUInt16BE(length, 1);
    return header;
  }
  throw new Error('test-vector keyring is too large for this canonical CBOR encoder');
}

function trustSnapshotBytes(ownerKeyIdHex, acceptedKeyIdsHex) {
  const owner = keyIdBytes(ownerKeyIdHex);
  const accepted = [...new Map(
    acceptedKeyIdsHex.map((hex) => [hex, keyIdBytes(hex)]),
  ).values()].sort(Buffer.compare);

  // ApertoMemory Trust-Snapshot Profile v0:
  // canonical CBOR {1: owner-bstr8, 2: [accepted-bstr8...]}, with raw-byte sort.
  return Buffer.concat([
    Buffer.from([0xa2, 0x01, 0x48]),
    owner,
    Buffer.from([0x02]),
    canonicalCborArrayHeader(accepted.length),
    ...accepted.flatMap((keyId) => [Buffer.from([0x48]), keyId]),
  ]);
}

function contextFragmentBytes({ trust, authorship, authorKeyIdB64u, custodyPresent, body }) {
  const authorKey = authorKeyIdB64u ?? 'none';
  return Buffer.from(
    `[ApertoMemory trust=${trust} authorship=${authorship} author_key=${authorKey}`
      + ` custody=${custodyPresent ? 'true' : 'false'}]\n`
      + `${body}\n`
      + '[/ApertoMemory]\n',
    'utf8',
  );
}

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

const adapter = deterministicEd25519('apertomemory-emilia/v0/adapter');
const adapterPublicKey = b64u(adapter.publicKey.export({ type: 'spki', format: 'der' }));
if (adapterPublicKey !== legacyBundle.adapter_pin.public_key_spki_b64u) {
  throw new Error('deterministic adapter key no longer matches the pinned v0 fixture');
}

const source007 = sourceFixtures.vectors['007-custody-attested'];
const source003 = sourceFixtures.projection_support['003-sealed-object-v2'];
const ownerKeyHex = '63c1e89c009c5ad7';
const originalAuthorKeyHex = 'd05309cbd3b55f3b';
const ownerKey = keyIdB64u(ownerKeyHex);
const originalAuthorKey = keyIdB64u(originalAuthorKeyHex);
const recallRequestBytes = Buffer.from(
  'private recall request fixture; cleartext deliberately not carried',
  'utf8',
);
const selectionPolicyBytes = Buffer.from(
  'include trusted data; isolate labels; withhold unverified objects',
  'utf8',
);
const positiveTrustSnapshotBytes = trustSnapshotBytes(ownerKeyHex, [originalAuthorKeyHex]);
const firstFragment = contextFragmentBytes({
  trust: 'trusted',
  authorship: 'attested',
  authorKeyIdB64u: originalAuthorKey,
  custodyPresent: true,
  body: 'Source vector 007: fact authored by a third party and re-sealed by the vault owner.',
});
const secondFragment = contextFragmentBytes({
  trust: 'self',
  authorship: 'signed',
  authorKeyIdB64u: ownerKey,
  custodyPresent: false,
  body: 'Source vector 003: prefers formal B2B emails.',
});
const nullAuthorFragment = contextFragmentBytes({
  trust: 'unverified',
  authorship: 'unknown',
  authorKeyIdB64u: null,
  custodyPresent: false,
  body: 'Source edge: native verification did not resolve an author.',
});
const emptyAcceptedKeySnapshot = trustSnapshotBytes(ownerKeyHex, []);
const orderingOwnerKeyHex = '0102030405060708';
const multipleAcceptedKeyInputHex = ['d000000000000000', '0000000000000001'];
const multipleAcceptedKeysHex = [...multipleAcceptedKeyInputHex]
  .sort((left, right) => Buffer.compare(keyIdBytes(left), keyIdBytes(right)));
const multipleAcceptedKeySnapshot = trustSnapshotBytes(
  orderingOwnerKeyHex,
  multipleAcceptedKeyInputHex,
);

const produced = createMemoryProjectionRecordV1({
  sourceProfile: 'draft-ferro-apertomemory-02',
  projectionId: 'urn:memory-projection:apertomemory:composition-01',
  createdAt: '2026-07-29T17:00:01.000Z',
  adapter: {
    id: legacyBundle.adapter_pin.adapter_id,
    keyId: legacyBundle.adapter_pin.key_id,
  },
  selectionContext: {
    recallRequestBytes,
    selectionPolicyBytes,
    trustSnapshotBytes: positiveTrustSnapshotBytes,
    trustEvaluatedAt: '2026-07-29T17:00:00.000Z',
    contextFrameProfile: 'urn:apertomemory:context-frame:v0',
  },
  delivered: [
    {
      formatVersion: 2,
      sealedObjectBytes: Buffer.from(source007.sealed_object_hex, 'hex'),
      contextFragmentBytes: firstFragment,
      derivedTrust: 'trusted',
      authorship: 'attested',
      authorKeyIdB64u: originalAuthorKey,
      custodyPresent: true,
    },
    {
      formatVersion: 2,
      sealedObjectBytes: Buffer.from(source003.sealed_object_hex, 'hex'),
      contextFragmentBytes: secondFragment,
      derivedTrust: 'self',
      authorship: 'signed',
      authorKeyIdB64u: ownerKey,
      custodyPresent: false,
    },
  ],
  exclusions: {
    authenticationFailed: 1,
    schemaInvalid: 0,
    policyFiltered: 0,
    contextLimit: 1,
  },
  privateKey: adapter.privateKey,
});

const nativeResultsByPosition = produced.record.delivered.map((entry) => ({
  valid: true,
  formatVersion: entry.object.format_version,
  sealedObjectDigest: entry.object.sealed_object_digest,
  derivedTrust: entry.derived_trust,
  authorship: entry.authorship,
  authorKeyIdB64u: entry.author_key_id_b64u,
  custodyPresent: entry.custody_present,
}));

const cases = [
  ['accept_full_projection', null, 'VALID'],
  ['refuse_unknown_member', 'add_unknown_top_level_member', 'record_invalid'],
  ['refuse_wrong_domain_signature', 'sign_with_legacy_v0_domain', 'signature_invalid'],
  ['refuse_entry_reordering', 'swap_delivered_entries', 'delivered_order_invalid'],
  ['refuse_entry_omission', 'omit_delivered_entry', 'signature_invalid'],
  ['refuse_duplicate_position', 'duplicate_delivered_position', 'delivered_order_invalid'],
  ['refuse_source_object_mutation', 'mutate_source_object_bytes', 'source_object_digest_mismatch'],
  ['refuse_fragment_mutation', 'mutate_fragment_bytes', 'fragment_digest_mismatch'],
  [
    'refuse_projection_not_equal_to_fragment_concatenation',
    'substitute_projection_bytes_only',
    'projection_fragment_concatenation_mismatch',
  ],
  ['refuse_recall_request_mutation', 'mutate_recall_request_bytes', 'recall_request_digest_mismatch'],
  ['refuse_selection_policy_mutation', 'mutate_selection_policy_bytes', 'selection_policy_digest_mismatch'],
  ['refuse_trust_snapshot_mutation', 'mutate_trust_snapshot_bytes', 'trust_snapshot_digest_mismatch'],
  ['refuse_exclusion_count_mutation', 'increment_exclusions_total', 'exclusion_count_mismatch'],
  ['refuse_nonclaim_upgrade', 'set_model_use_established', 'nonclaim_invalid'],
  ['refuse_unpinned_adapter', 'remove_adapter_pin', 'adapter_key_not_pinned'],
  ['refuse_revoked_adapter', 'revoke_adapter_key', 'adapter_key_revoked'],
  ['refuse_stale_trust_snapshot', 'advance_verification_time', 'trust_snapshot_stale'],
  ['refuse_native_source_result_relabel', 'relabel_native_source_result', 'native_source_result_mismatch'],
  ['refuse_projection_replay', 'register_projection_twice', 'projection_replay'],
].map(([id, mutation, result]) => ({ id, mutation, expect: { result } }));

const bundle = {
  '@version': 'MEMORY-PROJECTION-RECIPROCAL-VECTORS-v1',
  record_version: MEMORY_PROJECTION_RECORD_VERSION,
  contract: {
    draft: 'draft-ferro-schrock-memory-projection-record-00',
    status: 'RECIPROCAL_PROFILE_REVIEWED_AT_APERTOMEMORY_48BE525',
    source_profile: 'draft-ferro-apertomemory-02',
    trust_snapshot_profile: 'urn:apertomemory:trust-snapshot:v0',
    context_frame_profile: 'urn:apertomemory:context-frame:v0',
  },
  adapter_pin: {
    adapter_id: legacyBundle.adapter_pin.adapter_id,
    key_id: legacyBundle.adapter_pin.key_id,
    alg: 'Ed25519',
    public_key_spki_b64u: adapterPublicKey,
    status: 'active',
    valid_from: '2026-07-29T00:00:00.000Z',
    valid_to: '2027-07-29T00:00:00.000Z',
    revoked_at: null,
  },
  verification_policy: {
    verification_time: '2026-07-29T17:01:00.000Z',
    max_projection_age_sec: 300,
    max_trust_age_sec: 300,
    expected_source_profile: 'draft-ferro-apertomemory-02',
    expected_context_frame_profile: 'urn:apertomemory:context-frame:v0',
  },
  projection: {
    record: produced.record,
    verification_material: {
      recall_request_b64u: b64u(produced.verificationMaterial.recallRequestBytes),
      selection_policy_b64u: b64u(produced.verificationMaterial.selectionPolicyBytes),
      trust_snapshot_b64u: b64u(produced.verificationMaterial.trustSnapshotBytes),
      source_object_b64u_by_position:
        produced.verificationMaterial.sourceObjectBytesByPosition.map(b64u),
      fragment_b64u_by_position:
        produced.verificationMaterial.fragmentBytesByPosition.map(b64u),
      projection_b64u: b64u(produced.verificationMaterial.projectionBytes),
      native_source_results_by_position: nativeResultsByPosition,
    },
    expect: {
      valid: true,
      verification_scope: 'FULL_PROJECTION_AND_NATIVE_SOURCE_RESULTS',
      delivered_count: 2,
      excluded_count: 2,
    },
  },
  source_profile_edge_cases: {
    null_author: {
      status: 'NORMATIVE_APERTOMEMORY_CONTEXT_FRAME_V0',
      context_frame_profile: 'urn:apertomemory:context-frame:v0',
      fragment_b64u: b64u(nullAuthorFragment),
      fragment_digest: sha256(nullAuthorFragment),
      native_source_result: {
        derived_trust: 'unverified',
        authorship: 'unknown',
        author_key_id_b64u: null,
        custody_present: false,
      },
    },
    empty_accepted_key_set: {
      status: 'NORMATIVE_APERTOMEMORY_TRUST_SNAPSHOT_V0',
      trust_snapshot_profile: 'urn:apertomemory:trust-snapshot:v0',
      container: 'CANONICAL_CBOR_RFC8949_SECTION_4_2',
      owner_key_id_hex: ownerKeyHex,
      accepted_key_ids_hex: [],
      trust_snapshot_b64u: b64u(emptyAcceptedKeySnapshot),
      trust_snapshot_digest: sha256(emptyAcceptedKeySnapshot),
    },
    multiple_accepted_keys: {
      status: 'NORMATIVE_APERTOMEMORY_TRUST_SNAPSHOT_V0',
      trust_snapshot_profile: 'urn:apertomemory:trust-snapshot:v0',
      container: 'CANONICAL_CBOR_RFC8949_SECTION_4_2',
      owner_key_id_hex: orderingOwnerKeyHex,
      input_accepted_key_ids_hex: multipleAcceptedKeyInputHex,
      accepted_key_ids_hex: multipleAcceptedKeysHex,
      ordering: 'RAW_KEY_ID_BYTES_ASCENDING',
      trust_snapshot_b64u: b64u(multipleAcceptedKeySnapshot),
      trust_snapshot_digest: sha256(multipleAcceptedKeySnapshot),
    },
  },
  cases,
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
    console.error('memory-projection-record.v1.vectors.json is stale; run the generator');
    process.exit(1);
  }
  console.log('Memory Projection Record v1 reciprocal vectors are current');
} else {
  writeFileSync(OUTPUT, serialized);
  console.log(`wrote ${OUTPUT}`);
}
