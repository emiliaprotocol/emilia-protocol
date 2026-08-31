// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import {
  AEB_NATIVE_DESCRIPTOR_VERSION,
  aebNativeDescriptorDigest,
  compileAebNativeEvidence,
} from '../../packages/verify/aeb-native-compiler.js';
import {
  adapterPinDigest,
  canonicalizeAeb,
  digestAeb,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '../../packages/verify/aeb-adapter-contract.js';

const NOW = '2026-08-31T18:00:00.000Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}`;
const ACTION = {
  action_type: 'payment.release.1',
  amount: '725.00',
  currency: 'USD',
  beneficiary: 'vendor:acme',
};

function spki(key) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function registryEntry(id, kind, definition) {
  const entry = { kind, version: '1', status: 'active', definition };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

const issuer = crypto.generateKeyPairSync('ed25519');
const nativePayload = {
  protocol: 'ACME-DELEGATION/v7',
  authorization_id: 'acme-authz-42',
  principal: 'workload:buyer-agent',
  action: ACTION,
  caid: CAID,
  issued_at: '2026-08-31T17:55:00.000Z',
  expires_at: '2026-08-31T18:05:00.000Z',
};
const nativeArtifact = {
  payload: nativePayload,
  signature: {
    key_id: 'acme:issuer:1',
    alg: 'Ed25519',
    value: crypto.sign(
      null,
      Buffer.from(canonicalizeAeb(nativePayload), 'utf8'),
      issuer.privateKey,
    ).toString('base64url'),
  },
};
const nativeWireBeforeCompilation = canonicalizeAeb(nativeArtifact);

const adapter = Object.freeze({
  id: 'native:acme-delegation',
  version: '7',
  verifyNative({ artifact, status, trust_roots, adapter_config }) {
    const root = trust_roots.find((candidate) => (
      candidate.key_id === artifact.signature.key_id
    ));
    let verified = false;
    try {
      verified = Boolean(root) && crypto.verify(
        null,
        Buffer.from(canonicalizeAeb(artifact.payload), 'utf8'),
        crypto.createPublicKey({
          key: Buffer.from(root.public_key, 'base64url'),
          type: 'spki',
          format: 'der',
        }),
        Buffer.from(artifact.signature.value, 'base64url'),
      );
    } catch {
      verified = false;
    }
    return {
      native_verification: verified ? 'VERIFIED' : 'FAILED',
      acceptance: verified ? 'ACCEPTED' : 'REJECTED',
      evidence_digest: digestAeb(artifact),
      status_digest: digestAeb({ ...status, unavailable: status.unavailable === true }),
      evidence_role: adapter_config.evidence_role,
      subject: { id: artifact.payload.principal, kind: 'workload' },
      replay_unit: digestAeb({
        protocol: artifact.payload.protocol,
        authorization_id: artifact.payload.authorization_id,
      }),
      reasons: verified ? [] : ['acme_native_signature_invalid'],
    };
  },
  mapAction({ artifact, expected_action, native }) {
    if (native.native_verification !== 'VERIFIED' || native.acceptance !== 'ACCEPTED') {
      return {
        mapping: 'INDETERMINATE', caid: null, action_digest: null,
        reasons: ['native_acceptance_required'],
      };
    }
    const nativeDigest = digestAeb(artifact.payload.action);
    if (nativeDigest !== digestAeb(expected_action)) {
      return {
        mapping: 'MISMATCH', caid: artifact.payload.caid,
        action_digest: nativeDigest, reasons: ['acme_action_mismatch'],
      };
    }
    return {
      mapping: 'MATCH',
      caid: artifact.payload.caid,
      action_digest: nativeDigest,
      reasons: [],
    };
  },
});

const profileId = 'profile:acme-delegation-to-caid';
const profile = {
  version: '1',
  definition: {
    native_protocol: 'ACME-DELEGATION/v7',
    projection: 'payload.action-to-payment.release.1',
  },
  registry_entry_ref: `mapping:${profileId}`,
  mapper_id: 'mapper:acme-delegation-to-caid',
  resolver: {
    id: 'resolver:acme-delegation-to-caid',
    version: '1',
    implementation_digest: digestAeb({ source: 'demo.mjs', resolver: 'exact-payload-action' }),
  },
  semantic_equivalence: {
    assertion: 'EQUIVALENT_UNDER_PROFILE',
    loss_policy: 'NO_MATERIAL_FIELD_LOSS',
    omitted_material_fields: [],
    omitted_nonmaterial_fields: ['issued_at'],
  },
};
profile.profile_digest = mappingProfileDigest(profileId, profile);
const descriptorId = 'descriptor:acme-delegation-v7';
const descriptor = {
  '@version': AEB_NATIVE_DESCRIPTOR_VERSION,
  protocol: { id: 'ACME-DELEGATION', revision: 'v7' },
  source: {
    media_type: 'application/vnd.acme.delegation+json',
    schema: { id: 'https://acme.example/schemas/delegation', revision: '7' },
  },
  verifier: {
    implementation_id: 'example:acme-delegation-verifier',
    implementation_revision: '1',
    implementation_digest: digestAeb({ source: 'demo.mjs', verifier: 'native-acme-ed25519-v1' }),
  },
  adapter: { id: adapter.id, revision: adapter.version },
  mapping_profile: {
    id: profileId,
    revision: profile.version,
    digest: profile.profile_digest,
  },
  target_action_type: ACTION.action_type,
  replay_scope: 'per-relying-party-native-authorization',
};
descriptor.descriptor_digest = aebNativeDescriptorDigest(descriptorId, descriptor);

const entries = {
  [profile.registry_entry_ref]: registryEntry(
    profile.registry_entry_ref,
    'mapping-profile',
    { profile_digest: profile.profile_digest },
  ),
  'role:delegated-authority': registryEntry(
    'role:delegated-authority',
    'evidence-role',
    { role: 'delegated-authority', subject_kinds: ['workload'] },
  ),
};
const registry = {
  '@version': 'EP-EVIDENCE-REGISTRY-v1',
  registry_id: 'registry:acme-demo',
  epoch: 1,
  entries,
};
registry.registry_digest = unifiedRegistryDigest(registry);

const adapterPin = {
  version: adapter.version,
  trust_roots: [{ key_id: 'acme:issuer:1', public_key: spki(issuer.publicKey) }],
  config: {
    native_protocol: 'ACME-DELEGATION/v7',
    evidence_role: 'delegated-authority',
  },
  max_status_age_sec: 120,
};
adapterPin.config_digest = adapterPinDigest(adapter.id, adapterPin);
const requirement = {
  '@version': 'AEB-REQUIREMENT-v1',
  all_of: ['delegated-authority'],
  terms: [{ type: 'one-time-consumption' }],
};
const pins = {
  '@version': 'AEB-ADAPTER-v1',
  relying_party_id: 'rp:acme-demo',
  evaluator_keys: {},
  registry,
  accepted_mappers: [profile.mapper_id],
  adapters: { [adapter.id]: adapterPin },
  profiles: { [profileId]: profile },
  requirements: { 'requirement:delegated-payment': requirement },
};

const report = compileAebNativeEvidence({
  pins,
  adapters: { [adapter.id]: adapter },
  native_descriptors: {
    pins: { [descriptorId]: descriptor.descriptor_digest },
    registry: { [descriptorId]: descriptor },
  },
  native_legs: [{
    native_descriptor_id: descriptorId,
    adapter_id: adapter.id,
    profile_id: profileId,
    artifact_ref: 'urn:acme:wrapper:42',
    artifact: nativeArtifact,
    status: {
      checked_at: '2026-08-31T17:59:30.000Z',
      expires_at: nativePayload.expires_at,
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
  }],
  expected_action: { caid: CAID, value: ACTION },
  requirement: { ref: 'requirement:delegated-payment', definition: requirement },
  initiator_id: nativePayload.principal,
  executor_id: 'system:payment-provider',
  evaluated_at: NOW,
  local_policy_input: {
    policy_id: 'policy:demo-payment-window',
    policy_version: '1',
    decision: 'ALLOW',
    reasons: ['demo_payment_window_open'],
  },
});

if (canonicalizeAeb(nativeArtifact) !== nativeWireBeforeCompilation) {
  throw new Error('compiler changed the native artifact');
}
for (const [axis, expected] of Object.entries({
  verified: 'VERIFIED',
  accepted: 'ACCEPTED',
  match: 'MATCH',
  satisfied: 'SATISFIED',
  policy_input: 'ALLOW',
  local_authorization: 'NOT_EVALUATED',
})) {
  if (report.axes[axis].result !== expected) {
    throw new Error(`${axis} was ${report.axes[axis].result}: ${report.axes[axis].reasons.join(', ')}`);
  }
}

console.log(JSON.stringify({
  native_protocol: nativePayload.protocol,
  native_artifact_unchanged: true,
  report_is_credential: report.report_is_credential,
  expected_action_provenance: report.expected_action.provenance,
  policy_input_provenance: report.local_policy_input.provenance,
  local_authorization_established: report.claims.local_authorization_established,
  axes: Object.fromEntries(Object.entries(report.axes).map(([name, axis]) => [name, axis.result])),
  semantic_loss: report.semantic_loss,
  lifecycle: Object.fromEntries(
    Object.entries(report.lifecycle).map(([name, axis]) => [name, axis.result]),
  ),
  report_digest: report.report_digest,
}, null, 2));
