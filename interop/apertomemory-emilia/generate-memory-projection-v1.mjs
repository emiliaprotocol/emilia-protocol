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
const ownerKey = keyIdB64u('63c1e89c009c5ad7');
const originalAuthorKey = keyIdB64u('d05309cbd3b55f3b');
const recallRequestBytes = Buffer.from(
  'private recall request fixture; cleartext deliberately not carried',
  'utf8',
);
const selectionPolicyBytes = Buffer.from(
  'include trusted data; isolate labels; withhold unverified objects',
  'utf8',
);
const trustSnapshotBytes = Buffer.from(canonicalize({
  owner_key_id_b64u: ownerKey,
  accepted_key_ids_b64u: [originalAuthorKey],
}), 'utf8');
const firstFragment = Buffer.from(
  `[ApertoMemory trust=trusted authorship=attested author_key=${originalAuthorKey} custody=true]\n`
    + 'Source vector 007: fact authored by a third party and re-sealed by the vault owner.\n'
    + '[/ApertoMemory]\n',
  'utf8',
);
const secondFragment = Buffer.from(
  `[ApertoMemory trust=self authorship=signed author_key=${ownerKey} custody=false]\n`
    + 'Source vector 003: prefers formal B2B emails.\n'
    + '[/ApertoMemory]\n',
  'utf8',
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
    trustSnapshotBytes,
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
    status: 'EMILIA_SIDE_IMPLEMENTATION_CANDIDATE_PENDING_RECIPROCAL_REVIEW',
    source_profile: 'draft-ferro-apertomemory-02',
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
