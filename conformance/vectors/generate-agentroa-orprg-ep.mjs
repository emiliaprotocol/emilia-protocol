#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Real-crypto fixtures joining:
//   * draft-nivalto-agentroa-route-authorization-01 AER evidence,
//   * the concrete ORPRG-JSON-JCS-ED25519-v1 profile, and
//   * an EP Class-A WebAuthn quorum.
//
// Native verification and CAID correlation remain separate. A valid machine
// permit never substitutes for the relying party's required human artifact.
// P-256 ECDSA signatures use fresh randomness on regeneration; --check
// normalizes only those signatures while checking every signed input and all
// deterministic signatures byte-for-byte.

import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { mappingProfileHash } from '../../caid/impl/js/mapping.mjs';
import { canonicalize } from '../../packages/verify/index.js';
import {
  computeOrprgActionDigest,
  ORPRG_ACTION_PROFILE,
  ORPRG_JSON_JCS_PROFILE,
} from '../../packages/verify/orprg.js';

const SUITE = 'jcs-sha256';
const VERIFY_AT = '2026-07-19T12:00:00Z';
const POLICY_DIGEST = `sha256:${'a'.repeat(64)}`;
const INPUT_HASH = `sha256:${'c'.repeat(64)}`;
const OTHER_INPUT_HASH = `sha256:${'d'.repeat(64)}`;
const AGENTROA_TYPE = 'agentroa';
const ORPRG_TYPE = 'orprg-json-jcs';
const EP_TYPE = 'ep-quorum';
const REQUIREMENT = `${AGENTROA_TYPE} AND ${ORPRG_TYPE} AND ${EP_TYPE}`;
const RP_ID = 'rp.emilia.example';
const ORIGIN = 'https://rp.emilia.example';

const TYPE_DEFINITION = {
  action_type: 'agent.capability.invoke.1',
  status: 'active',
  risk_class: 'consequential-external-effect',
  summary: 'Invoke one exact capability with one exact input commitment.',
  required_fields: [
    { name: 'capability', type: 'string' },
    { name: 'target_service_id', type: 'string' },
    { name: 'operation', type: 'string' },
    { name: 'input_hash', type: 'digest' },
  ],
  optional_fields: [],
  digest_notes: 'input_hash is the native input commitment; no semantic expansion is inferred.',
  references: [],
};

const MATERIAL_ACTION = {
  action_type: TYPE_DEFINITION.action_type,
  capability: 'api:payments.transfer',
  target_service_id: 'payments-service',
  operation: 'transfer',
  input_hash: INPUT_HASH,
};
const computed = computeCaid(MATERIAL_ACTION, { suite: SUITE, definitions: [TYPE_DEFINITION] });
if (!computed.caid) throw new Error(`CAID generation failed: ${computed.refusals?.join(', ')}`);

const AGENTROA_PROFILE = {
  '@version': 'CAID-MAPPING-PROFILE-v1',
  profile_id: 'agentroa-aer-action-to-agent-capability-invoke-v1',
  source_format: {
    media_type: 'application/agentroa-aer+json',
    schema: 'draft-nivalto-agentroa-route-authorization-01#aer-action',
    version: '1.0',
  },
  target_action_type: TYPE_DEFINITION.action_type,
  loss_policy: 'no-material-field-loss',
  material_source_paths: ['/capability', '/target_service_id', '/operation', '/input_hash'],
  rules: [
    { source_path: '/capability', target_field: 'capability', transform: 'copy' },
    { source_path: '/target_service_id', target_field: 'target_service_id', transform: 'copy' },
    { source_path: '/operation', target_field: 'operation', transform: 'copy' },
    { source_path: '/input_hash', target_field: 'input_hash', transform: 'copy' },
  ],
};

const ORPRG_PROFILE = {
  '@version': 'CAID-MAPPING-PROFILE-v1',
  profile_id: 'orprg-action-to-agent-capability-invoke-v1',
  source_format: {
    media_type: 'application/orprg-action+json',
    schema: ORPRG_ACTION_PROFILE,
    version: '1',
  },
  target_action_type: TYPE_DEFINITION.action_type,
  loss_policy: 'no-material-field-loss',
  material_source_paths: ['/effect_type', '/interface_id', '/target_id', '/request/input_hash'],
  rules: [
    { source_path: '/effect_type', target_field: 'capability', transform: 'copy' },
    { source_path: '/interface_id', target_field: 'target_service_id', transform: 'copy' },
    { source_path: '/target_id', target_field: 'operation', transform: 'copy' },
    { source_path: '/request/input_hash', target_field: 'input_hash', transform: 'copy' },
  ],
};

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function ed25519(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return {
    privateKey,
    publicKey: crypto.createPublicKey(/** @type {any} */ (privateKey)),
    spki: crypto.createPublicKey(/** @type {any} */ (privateKey))
      .export({ type: 'spki', format: 'der' })
      .toString('base64url'),
  };
}

function p256(seedByte) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.alloc(32, seedByte));
  const point = ecdh.getPublicKey(null, 'uncompressed');
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    d: Buffer.alloc(32, seedByte).toString('base64url'),
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33, 65).toString('base64url'),
  };
  const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const publicKey = crypto.createPublicKey(/** @type {any} */ (privateKey));
  return {
    privateKey,
    publicKey,
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

const rootKey = ed25519(0x11);
const gatewayKey = ed25519(0x22);
const orprgKey = ed25519(0x33);
const approverOne = p256(0x41);
const approverTwo = p256(0x42);

const clone = (value) => structuredClone(value);
const sha256 = (value) =>
  `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;

function signAgentRoa(body, signer, key) {
  const sig = crypto.sign(
    null,
    Buffer.from(canonicalize(body), 'utf8'),
    key.privateKey,
  ).toString('base64url');
  return { ...clone(body), signatures: [{ signer, alg: 'EdDSA', sig }] };
}

function buildAgentRoa() {
  const root = signAgentRoa({
    schema_version: '1.0',
    envelope_id: 'env:4a7c9f2b1e8d3a6f',
    issued_at: '2026-07-19T11:55:00Z',
    expires_at: '2026-07-19T12:05:00Z',
    session: {
      session_id: 'sess:8b3d0e7f2a1c9b4e',
      channel: 'api',
      agent_id: 'aha:acme/ops/root-agent',
    },
    authorized_scope: {
      capabilities: [MATERIAL_ACTION.capability],
      max_delegation_depth: 1,
      cross_org_permitted: false,
    },
    policy: {
      policy_id: 'payments-v4',
      policy_version: '4.2.1',
      policy_digest: POLICY_DIGEST,
    },
    authorization: {
      auth_strength: 'dual_control',
      approval_state: 'granted',
      approval_artifact_ref: `caid:${computed.caid}`,
    },
    evidence: {
      session_hash: `sha256:${'b'.repeat(64)}`,
      model_provenance: ['example:model:v1'],
    },
  }, 'policy-engine:prod', rootKey);

  const ara = signAgentRoa({
    schema_version: '1.0',
    ara_id: 'ara:9c4e1f8a2b7d3e0f',
    issued_at: '2026-07-19T11:57:00Z',
    upstream_ref: {
      ref_type: 'roa_envelope',
      ref_id: root.envelope_id,
      ref_digest: sha256(root),
    },
    delegating_agent: {
      agent_id: root.session.agent_id,
      session_id: root.session.session_id,
    },
    delegated_agent: { agent_id: 'aha:acme/ops/payment-agent' },
    delegated_scope: {
      capabilities: [MATERIAL_ACTION.capability],
      max_delegation_depth: 0,
    },
    policy: {
      policy_digest: POLICY_DIGEST,
      policy_version: '4.2.1',
    },
  }, root.session.agent_id, rootKey);

  const chain = [root, ara];
  const action = {
    capability: MATERIAL_ACTION.capability,
    target_service_id: MATERIAL_ACTION.target_service_id,
    operation: MATERIAL_ACTION.operation,
    input_hash: MATERIAL_ACTION.input_hash,
  };
  const aer = signAgentRoa({
    schema_version: '1.0',
    aer_id: 'aer:2f5a8c1d4e7b0f3a',
    produced_at: '2026-07-19T11:58:00Z',
    enforcement_outcome: 'permit',
    enforcement_mode: 'normal',
    deployment_topology: 'topology_d_domain_boundary',
    session: {
      session_id: root.session.session_id,
      agent_id: ara.delegated_agent.agent_id,
    },
    action,
    policy: { policy_id: root.policy.policy_id, policy_digest: POLICY_DIGEST },
    chain_summary: {
      chain_depth: 1,
      root_envelope_id: root.envelope_id,
      chain_digest: sha256(chain),
    },
    border_gateway: {
      gateway_id: 'gateway:prod-us-east-1',
      gateway_version: '1.1.0',
    },
  }, 'gateway:prod-us-east-1', gatewayKey);

  return {
    evidence: { chain, aer },
    keys_by_type: {
      agentroa: {
        roa: { 'policy-engine:prod': rootKey.spki },
        ara: { [root.session.agent_id]: rootKey.spki },
        aer: { 'gateway:prod-us-east-1': gatewayKey.spki },
      },
    },
    policies_by_type: {
      agentroa: {
        expected_policy_id: root.policy.policy_id,
        expected_policy_version: root.policy.policy_version,
        expected_policy_digest: POLICY_DIGEST,
        allow_degraded: false,
        allowed_topologies: ['topology_d_domain_boundary'],
        capability_manifest: {},
      },
    },
  };
}

function orprgAction(inputHash = INPUT_HASH) {
  return {
    effect_type: MATERIAL_ACTION.capability,
    interface_id: MATERIAL_ACTION.target_service_id,
    target_id: MATERIAL_ACTION.operation,
    audience: 'https://payments.example/commit',
    request: { input_hash: inputHash },
  };
}

function signOrprg(receipt, key = orprgKey) {
  const signed = {
    '@version': receipt['@version'],
    receipt_core: receipt.receipt_core,
    status: receipt.status,
    authenticity: {
      issuer_id: receipt.authenticity.issuer_id,
      key_id: receipt.authenticity.key_id,
      algorithm: receipt.authenticity.algorithm,
    },
  };
  receipt.authenticity.signature = crypto.sign(
    null,
    Buffer.from(canonicalize(signed), 'utf8'),
    key.privateKey,
  ).toString('base64url');
  return receipt;
}

function buildOrprg(action = orprgAction()) {
  const issuerId = 'https://policy.example/issuers/primary';
  const keyId = 'orprg-ed25519-2026-07';
  const receipt = signOrprg({
    '@version': ORPRG_JSON_JCS_PROFILE,
    receipt_core: {
      policy_digest: POLICY_DIGEST,
      epoch_id: 'policy-epoch-42',
      valid_from: '2026-07-19T11:55:00Z',
      valid_to: '2026-07-19T12:05:00Z',
      action_digest: computeOrprgActionDigest(action),
      canonicalization_profile: ORPRG_ACTION_PROFILE,
      scope: {
        effect_type: action.effect_type,
        interface_id: action.interface_id,
        target_id: action.target_id,
        audience: action.audience,
      },
      anti_replay: {
        mode: 'single-use',
        nonce: 'S1ngleUseNonce_20260719_0001',
      },
    },
    status: {
      state: 'good',
      checked_at: '2026-07-19T11:59:00Z',
      next_update: '2026-07-19T12:03:00Z',
    },
    authenticity: {
      issuer_id: issuerId,
      key_id: keyId,
      algorithm: 'Ed25519',
      signature: '',
    },
  });
  return {
    action,
    receipt,
    issuer_keys: { [issuerId]: { [keyId]: orprgKey.spki } },
    options: {
      expectedPolicyDigest: POLICY_DIGEST,
      expectedEpoch: 'policy-epoch-42',
      verificationTime: VERIFY_AT,
      maxReceiptAgeSeconds: 600,
      maxStatusAgeSeconds: 180,
    },
  };
}

function webauthnMember({ role, approver, key, nonce }) {
  const context = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash: computed.digest.slice('sha256:'.length),
    policy: 'policy_cross_standard_quorum',
    nonce,
    approver,
    initiator: 'aha:acme/ops/payment-agent',
    issued_at: '2026-07-19T11:58:30.000Z',
    expires_at: '2026-07-19T12:03:30.000Z',
  };
  const challenge = crypto.createHash('sha256')
    .update(canonicalize(context), 'utf8')
    .digest()
    .toString('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: ORIGIN,
  }), 'utf8');
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signed = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
  return {
    role,
    approver_public_key: key.spki,
    signoff: {
      '@type': 'ep.signoff',
      context,
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: crypto.sign('sha256', signed, key.privateKey).toString('base64url'),
      },
    },
  };
}

function buildEpQuorum() {
  const roster = [
    { role: 'treasury_controller', approver: 'ep:approver:rivera' },
    { role: 'risk_officer', approver: 'ep:approver:chen' },
  ];
  const policy = {
    mode: 'threshold',
    required: 2,
    approvers: roster,
    distinct_humans: true,
    window_sec: 300,
  };
  const members = [
    webauthnMember({ ...roster[0], key: approverOne, nonce: 'class_a_rivera_20260719' }),
    webauthnMember({ ...roster[1], key: approverTwo, nonce: 'class_a_chen_20260719' }),
  ];
  return {
    quorum: {
      '@type': 'ep.quorum',
      action_hash: computed.digest.slice('sha256:'.length),
      policy,
      members,
    },
    profile: {
      policy,
      rp_id: RP_ID,
      allowed_origins: [ORIGIN],
      approvers: {
        [approverOne.spki]: {
          approver_id: roster[0].approver,
          roles: [roster[0].role],
          status: 'active',
        },
        [approverTwo.spki]: {
          approver_id: roster[1].approver,
          roles: [roster[1].role],
          status: 'active',
        },
      },
    },
  };
}

function baseVector(id, description) {
  const agentroa = buildAgentRoa();
  const orprg = buildOrprg();
  return {
    id,
    description,
    expected_action: clone(MATERIAL_ACTION),
    expected_caid: { value: computed.caid, digest: computed.digest },
    relying_party_requirement: REQUIREMENT,
    presentations: 1,
    agentroa,
    orprg,
    ep: buildEpQuorum(),
    mapping: {
      agentroa: {
        profile: clone(AGENTROA_PROFILE),
        source_descriptor: clone(AGENTROA_PROFILE.source_format),
        expected_profile_hash: mappingProfileHash(AGENTROA_PROFILE),
      },
      orprg: {
        profile: clone(ORPRG_PROFILE),
        source_descriptor: clone(ORPRG_PROFILE.source_format),
        expected_profile_hash: mappingProfileHash(ORPRG_PROFILE),
      },
    },
    expect: { valid: true, first_valid: true, reason: null },
  };
}

const valid = baseVector(
  'accept_agentroa_orprg_ep_same_caid',
  'A real AgentROA AER, concrete ORPRG PermitReceipt, and two-device EP quorum verify natively and bind the same relying-party-pinned CAID.',
);

const actionSubstitution = baseVector(
  'reject_action_substitution',
  'The ORPRG receipt is genuinely reissued for a different invocation input; native verification succeeds but CAID correlation refuses the splice.',
);
actionSubstitution.orprg = buildOrprg(orprgAction(OTHER_INPUT_HASH));
actionSubstitution.expect = { valid: false, first_valid: false, reason: 'material_action_mismatch' };

const wrongProfile = baseVector(
  'reject_wrong_mapping_profile',
  'All native signatures verify, but the relying party pins a different ORPRG-to-CAID mapping profile hash.',
);
wrongProfile.mapping.orprg.expected_profile_hash = `sha256:${'0'.repeat(64)}`;
wrongProfile.expect = { valid: false, first_valid: false, reason: 'mapping_profile_refused' };

const untrustedIssuer = baseVector(
  'reject_untrusted_issuer',
  'The ORPRG receipt carries a mathematically valid Ed25519 signature, but its issuer key is not in the relying party trust pins.',
);
untrustedIssuer.orprg.issuer_keys = /** @type {any} */ ({});
untrustedIssuer.expect = { valid: false, first_valid: false, reason: 'untrusted_issuer' };

const approvalStateOnly = baseVector(
  'reject_approval_state_only_substitution',
  'The signed AgentROA root says approval_state=granted, but no EP Class-A/quorum artifact is present to fill the human requirement.',
);
approvalStateOnly.ep = { quorum: null, profile: valid.ep.profile };
approvalStateOnly.expect = { valid: false, first_valid: false, reason: 'human_evidence_missing' };

const replay = baseVector(
  'reject_orprg_replay',
  'The exact same ORPRG single-use nonce is presented twice to one atomic durable replay domain; only the first presentation can verify.',
);
replay.presentations = 2;
replay.expect = { valid: false, first_valid: true, reason: 'replay_refused' };

const missingRequirement = baseVector(
  'reject_missing_relying_party_requirement',
  'All artifacts verify and match, but presenter-carried evidence cannot choose its own sufficiency bar when the relying party supplied no requirement.',
);
missingRequirement.relying_party_requirement = null;
missingRequirement.expect = { valid: false, first_valid: false, reason: 'relying_party_requirement_missing' };

const vectors = [
  valid,
  actionSubstitution,
  wrongProfile,
  untrustedIssuer,
  approvalStateOnly,
  replay,
  missingRequirement,
];

const output = {
  suite: 'AGENTROA-ORPRG-EP-CAID-v1',
  vectors_version: '1.0.0',
  generated_from: {
    agentroa: 'draft-nivalto-agentroa-route-authorization-01',
    orprg: 'draft-lee-orprg-permit-receipts-00 with ORPRG-JSON-JCS-ED25519-v1',
    ep: 'EP-QUORUM-v1 and CAID-MAPPING-PROFILE-v1',
  },
  algorithm: 'Ed25519/JCS for AgentROA and ORPRG; P-256 WebAuthn assertions for EP quorum; SHA-256/JCS CAID mapping',
  security_boundary: 'Native verification, material-action matching, human evidence, and relying-party sufficiency are independently fail-closed.',
  required_component_types: [AGENTROA_TYPE, ORPRG_TYPE, EP_TYPE],
  count: vectors.length,
  definitions: [TYPE_DEFINITION],
  vectors,
};

function normalizeP256Signatures(value, parentKey = null) {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeP256Signatures(item));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        parentKey === 'webauthn' && key === 'signature'
          ? '<fresh-p256-ecdsa-signature>'
          : normalizeP256Signatures(item, key),
      ]),
    );
  }
  return value;
}

const outputUrl = new URL('./agentroa-orprg-ep.v1.json', import.meta.url);
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
  throw new Error('usage: generate-agentroa-orprg-ep.mjs [--check]');
}

if (args[0] === '--check') {
  const checkedIn = JSON.parse(readFileSync(outputUrl, 'utf8'));
  const expected = canonicalize(normalizeP256Signatures(output));
  const actual = canonicalize(normalizeP256Signatures(checkedIn));
  if (actual !== expected) {
    console.error('agentroa-orprg-ep.v1.json is stale');
    process.exitCode = 1;
  } else {
    console.log(`checked agentroa-orprg-ep.v1.json — ${vectors.length} real-crypto vectors`);
  }
} else {
  writeFileSync(outputUrl, `${JSON.stringify(output, null, 2)}\n`);
  console.log(`wrote agentroa-orprg-ep.v1.json — ${vectors.length} real-crypto vectors`);
}
