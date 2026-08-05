// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import test from 'node:test';

// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- independently cross-checked in this test.
import { computeCaid } from './vendor/caid.mjs';
import {
  AEB_ADAPTER_VERSION,
  AEB_REGISTRY_VERSION,
  AEB_REQUIREMENT_VERSION,
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebAdapterInput,
  type AebPinnedAdapter,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRegistryEntry,
} from './aeb-adapter-contract.js';
import {
  POLICY_DECISION_EVIDENCE_ADAPTER_ID,
  POLICY_DECISION_EVIDENCE_ADAPTER_VERSION,
  POLICY_DECISION_EVIDENCE_CONFIG_VERSION,
  POLICY_DECISION_EVIDENCE_MAPPING_VERSION,
  POLICY_DECISION_EVIDENCE_MAPPER_ID,
  POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION,
  createPolicyDecisionEvidenceActionDefinition,
  createPolicyDecisionEvidenceAdapter,
  projectCerbosPolicyDecision,
  projectOpaPolicyDecision,
  signPolicyDecisionEvidence,
  type PolicyDecisionEvidenceAdapterConfig,
  type PolicyDecisionEvidenceTrustRoot,
} from './policy-decision-evidence.js';

const NOW = '2026-08-04T20:00:00Z';
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const ACTION_TYPE = 'payment.release.1';
const ISSUER = 'https://policy-bridge.example';
const AUDIENCE = 'https://gate.example/admit';
const POLICY_DIGEST = digestAeb({ bundle: 'payments-v7' });

function spki(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function profile(): AebPinnedProfile {
  const pin: AebPinnedProfile = {
    version: POLICY_DECISION_EVIDENCE_MAPPING_VERSION,
    definition: createPolicyDecisionEvidenceActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:policy-decision-payment-release',
    mapper_id: POLICY_DECISION_EVIDENCE_MAPPER_ID,
    resolver: {
      id: POLICY_DECISION_EVIDENCE_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({
        implementation: POLICY_DECISION_EVIDENCE_MAPPER_ID,
        version: '1',
      }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'engine', 'policy_id',
        'policy_digest', 'policy_decision', 'native_decision_ref', 'native_result_digest',
      ],
    },
    profile_digest: digestAeb(null),
  };
  pin.profile_digest = mappingProfileDigest('policy-decision', pin);
  return pin;
}

function fixture() {
  const signer = crypto.generateKeyPairSync('ed25519');
  const attacker = crypto.generateKeyPairSync('ed25519');
  const config: PolicyDecisionEvidenceAdapterConfig = {
    '@version': POLICY_DECISION_EVIDENCE_CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:local-policy-engine', kind: 'system' },
    issuer: ISSUER,
    audience: AUDIENCE,
    action_type: ACTION_TYPE,
    allowed_engines: ['opa', 'cerbos'],
    allowed_policy_digests: [POLICY_DIGEST],
    clock_skew_seconds: 2,
    max_decision_age_seconds: 300,
  };
  const root: PolicyDecisionEvidenceTrustRoot = {
    '@version': POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION,
    issuer: ISSUER,
    key_id: 'policy-bridge-ed25519-1',
    algorithm: 'EdDSA',
    public_key: spki(signer.publicKey),
  };
  const action = {
    action_type: ACTION_TYPE,
    parameters: { amount_minor: 12550, currency: 'USD', payee: 'merchant:7' },
  };
  const projection = {
    issuer: ISSUER,
    subject: 'workload:overnight-agent',
    audience: AUDIENCE,
    issued_at: NOW_SECONDS - 10,
    expires_at: NOW_SECONDS + 120,
    decision_id: 'opa-decision-0001',
    policy_id: 'opa:payments/allow',
    policy_digest: POLICY_DIGEST,
    action,
    native_decision_ref: 'opa:decision:0001',
  };
  const claims = projectOpaPolicyDecision({
    ...projection,
    result: true,
  });
  const artifact = signPolicyDecisionEvidence(claims, {
    key_id: root.key_id,
    private_key: signer.privateKey,
  });
  const adapter = createPolicyDecisionEvidenceAdapter({ config, trust_roots: [root] });
  const input = {
    artifact,
    artifact_ref: 'artifact:policy-decision-0001',
    status: {
      checked_at: NOW,
      expires_at: '2026-08-04T20:05:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: [root],
    adapter_config: config,
    expected_action: action,
    now: NOW,
  } satisfies Omit<AebAdapterInput, 'profile'>;
  return { signer, attacker, config, root, action, projection, claims, artifact, adapter, input };
}

test('OPA ALLOW becomes accepted machine-policy evidence bound to the exact action', () => {
  const f = fixture();
  assert.equal(POLICY_DECISION_EVIDENCE_ADAPTER_ID, 'native:policy-decision-evidence');
  assert.equal(POLICY_DECISION_EVIDENCE_ADAPTER_VERSION, '1');
  const native = f.adapter.verifyNative(f.input);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal(native.evidence_role, 'machine-policy-decision');
  const mapping = f.adapter.mapAction({ ...f.input, profile: profile(), native });
  assert.equal(mapping.mapping, 'MATCH');
  assert.equal(mapping.action_digest, digestAeb(f.action));
  const computed = computeCaid(f.action, {
    suite: 'jcs-sha256',
    definitions: (profile().definition as any).definitions,
  });
  assert.equal(mapping.caid, computed.caid);
});

test('Cerbos EFFECT_ALLOW projects to the same bounded evidence shape', () => {
  const f = fixture();
  const claims = projectCerbosPolicyDecision({
    issuer: ISSUER,
    subject: 'workload:overnight-agent',
    audience: AUDIENCE,
    issued_at: NOW_SECONDS - 10,
    expires_at: NOW_SECONDS + 120,
    decision_id: 'cerbos-request-0001',
    policy_id: 'cerbos:resource-policy:payments',
    policy_digest: POLICY_DIGEST,
    action: f.action,
    native_decision_ref: 'cerbos:request:0001#release',
    effect: 'EFFECT_ALLOW',
  });
  const artifact = signPolicyDecisionEvidence(claims, {
    key_id: f.root.key_id,
    private_key: f.signer.privateKey,
  });
  const native = f.adapter.verifyNative({ ...f.input, artifact });
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
});

test('native deny and unknown outcomes never become accepted evidence', () => {
  const f = fixture();
  for (const [result, acceptance] of [[false, 'REJECTED'], [{ unexpected: true }, 'INDETERMINATE']] as const) {
    const claims = projectOpaPolicyDecision({
      ...f.projection,
      decision_id: `opa-${String(acceptance).toLowerCase()}`,
      native_decision_ref: `opa:${String(acceptance).toLowerCase()}`,
      result,
    });
    const artifact = signPolicyDecisionEvidence(claims, {
      key_id: f.root.key_id,
      private_key: f.signer.privateKey,
    });
    const native = f.adapter.verifyNative({ ...f.input, artifact });
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, acceptance);
  }
});

test('tampering, an unpinned signer, and an unpinned policy fail closed', () => {
  const f = fixture();
  const parts = f.artifact.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  payload.policy_digest = digestAeb({ bundle: 'attacker-policy' });
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  assert.equal(f.adapter.verifyNative({ ...f.input, artifact: parts.join('.') }).acceptance, 'REJECTED');

  const attackerArtifact = signPolicyDecisionEvidence(f.claims, {
    key_id: 'attacker-key',
    private_key: f.attacker.privateKey,
  });
  assert.equal(f.adapter.verifyNative({ ...f.input, artifact: attackerArtifact }).acceptance, 'REJECTED');

  const unpinned = projectOpaPolicyDecision({
    ...f.projection,
    policy_digest: digestAeb({ bundle: 'not-pinned' }),
    result: true,
  });
  const unpinnedArtifact = signPolicyDecisionEvidence(unpinned, {
    key_id: f.root.key_id,
    private_key: f.signer.privateKey,
  });
  assert.equal(f.adapter.verifyNative({ ...f.input, artifact: unpinnedArtifact }).acceptance, 'REJECTED');
});

test('an accepted machine decision cannot be remapped onto another action', () => {
  const f = fixture();
  const native = f.adapter.verifyNative(f.input);
  const expected_action = {
    ...f.action,
    parameters: { ...f.action.parameters, amount_minor: 9999999 },
  };
  const mapping = f.adapter.mapAction({
    ...f.input,
    expected_action,
    profile: profile(),
    native,
  });
  assert.equal(mapping.mapping, 'MISMATCH');
  assert.match(mapping.reasons.join(','), /exact_action_projection_mismatch/);
});

test('expired evidence and unavailable status remain indeterminate rather than allowed', () => {
  const f = fixture();
  const claims = projectOpaPolicyDecision({
    ...f.projection,
    issued_at: NOW_SECONDS - 1000,
    expires_at: NOW_SECONDS - 500,
    result: true,
  });
  const artifact = signPolicyDecisionEvidence(claims, {
    key_id: f.root.key_id,
    private_key: f.signer.privateKey,
  });
  const expired = f.adapter.verifyNative({ ...f.input, artifact });
  assert.equal(expired.acceptance, 'REJECTED');

  const unavailable = f.adapter.verifyNative({
    ...f.input,
    status: { ...f.input.status, unavailable: true },
  });
  assert.equal(unavailable.acceptance, 'INDETERMINATE');
});

test('the signer rejects executable or non-JSON action values', () => {
  const f = fixture();
  const action = { ...f.action, hidden: Symbol('not-signed') };
  assert.throws(() => projectOpaPolicyDecision({ ...f.projection, action, result: true }), /canonical JSON|strict/i);
});

test('a machine-policy ALLOW cannot satisfy a requirement that also requires human authorization', () => {
  const f = fixture();
  const mappingProfile = profile();
  const computed = computeCaid(f.action, {
    suite: 'jcs-sha256',
    definitions: (mappingProfile.definition as any).definitions,
  });
  function entry(id: string, kind: AebRegistryEntry['kind'], definition: unknown): AebRegistryEntry {
    const value = { kind, version: '1', status: 'active' as const, definition } as AebRegistryEntry;
    value.definition_digest = registryEntryDigest(id, value);
    return value;
  }
  const entries = {
    'mapping:policy-decision-payment-release': entry(
      'mapping:policy-decision-payment-release', 'mapping-profile',
      { profile_digest: mappingProfile.profile_digest },
    ),
    'role:machine-policy-decision': entry(
      'role:machine-policy-decision', 'evidence-role',
      { role: 'machine-policy-decision', subject_kinds: ['system'] },
    ),
    'role:human-authorization': entry(
      'role:human-authorization', 'evidence-role',
      { role: 'human-authorization', subject_kinds: ['human'] },
    ),
  };
  const registry = {
    '@version': AEB_REGISTRY_VERSION,
    registry_id: 'registry:policy-decision-test',
    epoch: 1,
    entries,
    registry_digest: digestAeb(null),
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const adapterPin: AebPinnedAdapter = {
    version: POLICY_DECISION_EVIDENCE_ADAPTER_VERSION,
    trust_roots: [f.root],
    config: f.config,
    config_digest: digestAeb(null),
    max_status_age_sec: 120,
  };
  adapterPin.config_digest = adapterPinDigest(POLICY_DECISION_EVIDENCE_ADAPTER_ID, adapterPin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const config: AebPinnedConfig = {
    '@version': AEB_ADAPTER_VERSION,
    relying_party_id: 'rp:gate-example',
    evaluator_keys: { 'evaluator:gate': { public_key: spki(evaluator.publicKey) } },
    registry,
    accepted_mappers: [POLICY_DECISION_EVIDENCE_MAPPER_ID],
    adapters: { [POLICY_DECISION_EVIDENCE_ADAPTER_ID]: adapterPin },
    profiles: { 'policy-decision': mappingProfile },
    requirements: {
      'requirement:human-plus-machine-policy': {
        '@version': AEB_REQUIREMENT_VERSION,
        all_of: ['human-authorization', 'machine-policy-decision'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  const result = evaluateAebEvidence({
    config,
    adapters: { [POLICY_DECISION_EVIDENCE_ADAPTER_ID]: f.adapter },
    operation_id: 'operation:machine-policy-only',
    consumption_nonce: 'consumption:machine-policy-only',
    initiator_id: 'workload:overnight-agent',
    executor_id: 'workload:gate',
    requirement_ref: 'requirement:human-plus-machine-policy',
    caid: computed.caid,
    expected_action: f.action,
    evaluated_at: NOW,
    signer: { key_id: 'evaluator:gate', private_key: evaluator.privateKey },
    legs: [{
      adapter_id: POLICY_DECISION_EVIDENCE_ADAPTER_ID,
      profile_id: 'policy-decision',
      artifact_ref: f.input.artifact_ref,
      artifact: f.artifact,
      status: f.input.status,
    }],
  });
  assert.equal(result.valid, false, JSON.stringify(result, null, 2));
  assert.equal(result.record.legs[0].verdict, 'SATISFIED');
  assert.equal(result.record.verdict, 'UNSATISFIED');
  assert.match(result.record.reasons.join(','), /human-authorization AND machine-policy-decision/);
});
