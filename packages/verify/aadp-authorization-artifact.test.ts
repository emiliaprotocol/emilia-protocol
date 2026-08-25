// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  AADP_ACTION_MAPPING_CONFIG_VERSION,
  AADP_AUTHORIZATION_ARTIFACT_VERSION,
  AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
  AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION,
  deriveAadpEpAuthorizationArtifact,
  matchAadpAuthorizationArtifact,
  parseAadpAuthorizationArtifact,
  verifyAadpEpAuthorizationArtifact,
} from './src/aadp-authorization-artifact.js';
import { digestAeb } from './src/aeb-adapter-contract.js';

const vectors = JSON.parse(fs.readFileSync(
  new URL('../../conformance/vectors/authorization-bundle.v1.json', import.meta.url),
  'utf8',
));
const fixture = vectors.cases.find((entry: any) => entry.id === 'valid-non-oauth-native-binding');
const aadpAction = {
  action_type: fixture.expected_action.action_type,
  params: {
    initiator: fixture.expected_action.initiator,
    ...fixture.expected_action.parameters,
  },
};
const mappingProfile = 'https://emiliaprotocol.ai/profiles/aadp-ep-payment-release-v1';
const mappingConfiguration = {
  profile: AADP_ACTION_MAPPING_CONFIG_VERSION,
  mapping_profile: mappingProfile,
  source_action_type: fixture.expected_action.action_type,
  mapped_action_type: fixture.expected_action.action_type,
  implementation: {
    id: 'urn:emilia:repository-source:aadp-authorization-artifact',
    version: 'source-lock-v1',
    digest: `sha256:${'1'.repeat(64)}`,
  },
  resolver: {
    id: 'urn:emilia:mapping-resolver:closed-json-v1',
    version: '1.0.0',
    digest: `sha256:${'3'.repeat(64)}`,
  },
  material_field_map: [
    { source_param: 'initiator', mapped_path: 'initiator' },
    { source_param: 'amount_minor', mapped_path: 'parameters.amount_minor' },
    { source_param: 'currency', mapped_path: 'parameters.currency' },
    { source_param: 'payee', mapped_path: 'parameters.payee' },
  ],
  no_material_field_loss: true,
};
const verifierDescriptor = {
  profile: AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION,
  artifact_profile: 'EP-AUTHORIZATION-BUNDLE-v1',
  implementation: {
    id: 'pkg:npm/%40emilia-protocol/verify',
    version: '3.20.3',
    digest: `sha256:${'2'.repeat(64)}`,
  },
};
const expectedMappedAction = {
  action_type: aadpAction.action_type,
  initiator: aadpAction.params.initiator,
  parameters: {
    amount_minor: aadpAction.params.amount_minor,
    currency: aadpAction.params.currency,
    payee: aadpAction.params.payee,
  },
};
const bundleOptions = {
  now: fixture.now,
  audience: fixture.audience,
  approverKeys: fixture.approver_keys,
  expectedApprovers: fixture.expected_approvers,
  acceptedKeyClasses: fixture.accepted_key_classes,
  currentPolicy: fixture.current_policy,
  expectedAuthorizationInstance: fixture.expected_authorization_instance,
  expectedAuthorizationBinding: fixture.expected_authorization_binding,
  requireAuthorizationBinding: true,
};

function derive(overrides: Record<string, unknown> = {}) {
  return deriveAadpEpAuthorizationArtifact({
    bundle: fixture.bundle,
    aadpAction,
    mapping: mappingConfiguration,
    verifier: verifierDescriptor,
    bundleOptions,
    ...overrides,
  });
}

test('AADP hook is closed, profile-neutral, and safely normalized', () => {
  const derived = derive();
  assert.equal(derived.verdict, 'VERIFIED', JSON.stringify(derived, null, 2));
  const hook = derived.artifact;
  assert.ok(hook);
  assert.equal(hook.profile, AADP_AUTHORIZATION_ARTIFACT_VERSION);
  assert.equal(hook.artifact_profile, AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE);
  assert.deepEqual(parseAadpAuthorizationArtifact(hook), hook);
  assert.equal(
    parseAadpAuthorizationArtifact({ ...hook, artifact_profile: 'example-native-authorization-v1' })
      ?.artifact_profile,
    'example-native-authorization-v1',
  );
  assert.equal(parseAadpAuthorizationArtifact({ ...hook, permit_id: 'permit:smuggled' }), null);
  assert.equal(parseAadpAuthorizationArtifact({
    ...hook,
    action_mapping: { ...hook.action_mapping, no_material_field_loss: false },
  }), null);
  assert.equal(parseAadpAuthorizationArtifact({
    ...hook,
    verification_record_digest: `sha256:${'A'.repeat(64)}`,
  }), null);
});

test('generic hook matching distinguishes mismatch from unavailable native input', () => {
  const derived = derive();
  assert.ok(derived.artifact);
  const hook = derived.artifact;
  assert.equal(matchAadpAuthorizationArtifact(hook, structuredClone(hook)).verdict, 'MATCH');
  assert.equal(matchAadpAuthorizationArtifact({
    ...hook,
    action_mapping: {
      ...hook.action_mapping,
      mapped_action_digest: `sha256:${'c'.repeat(64)}`,
    },
  }, hook).verdict, 'MISMATCH');
  assert.equal(matchAadpAuthorizationArtifact(hook, undefined).verdict, 'INDETERMINATE');
});

test('native verification, EP satisfaction, and authorization stay distinct and fully pinned', () => {
  const result = derive();
  assert.equal(result.verdict, 'VERIFIED');
  assert.equal(result.native_verification, 'VERIFIED');
  assert.equal(result.evidence_satisfaction, 'SATISFIED');
  assert.equal(result.authorization_decision, false);
  assert.equal(result.artifact?.native_verification, 'VERIFIED');
  assert.equal(result.artifact?.evidence_satisfaction, 'SATISFIED');
  assert.equal(result.artifact?.action_mapping.source_action_digest, digestAeb(aadpAction));
  assert.equal(result.artifact?.action_mapping.mapped_action_digest, digestAeb(expectedMappedAction));
  assert.equal(result.artifact?.action_mapping.no_material_field_loss, true);
  assert.match(result.artifact?.action_mapping.resolver.configuration_digest ?? '', /^sha256:[0-9a-f]{64}$/);
  assert.match(result.artifact?.verification_record_digest ?? '', /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.artifact?.verification_record_digest, result.verification_record?.record_digest);
  assert.match(result.verification_record?.trust_configuration_digest ?? '', /^sha256:[0-9a-f]{64}$/);
  assert.match(result.verification_record?.status_policy_digest ?? '', /^sha256:[0-9a-f]{64}$/);
  assert.match(result.verification_record?.verification_result_digest ?? '', /^sha256:[0-9a-f]{64}$/);
});

test('EP profile refuses substitution and tampering instead of blessing a digest', () => {
  const substituted = derive({
    aadpAction: {
      ...aadpAction,
      params: { ...aadpAction.params, amount_minor: 999_999 },
    },
  });
  assert.equal(substituted.verdict, 'REFUSE');
  assert.equal(substituted.native_verification, 'REFUSED');
  assert.equal(substituted.evidence_satisfaction, 'REFUSE');
  assert.ok(substituted.reasons.includes('action_mismatch'));

  const tampered = structuredClone(fixture.bundle);
  tampered.contexts[0].audience = 'https://attacker.example';
  const result = derive({ bundle: tampered });
  assert.equal(result.verdict, 'REFUSE');
  assert.equal(result.native_verification, 'REFUSED');
  assert.equal(result.evidence_satisfaction, 'REFUSE');
});

test('current-policy unavailability preserves verified bytes but not satisfied evidence', () => {
  const result = derive({
    bundleOptions: {
      ...bundleOptions,
      currentPolicy: { ...fixture.current_policy, unavailable: true },
    },
  });
  assert.equal(result.verdict, 'INDETERMINATE');
  assert.equal(result.native_verification, 'VERIFIED');
  assert.equal(result.evidence_satisfaction, 'INDETERMINATE');
  assert.equal(result.artifact?.native_verification, 'VERIFIED');
  assert.equal(result.artifact?.evidence_satisfaction, 'INDETERMINATE');
  assert.ok(result.reasons.includes('current_policy_unavailable_or_stale'));
});

test('unavailable mapping stays indeterminate and a changed presented hook refuses', () => {
  const unavailable = derive({ mapping: undefined });
  assert.equal(unavailable.verdict, 'INDETERMINATE');
  assert.equal(unavailable.native_verification, 'NOT_RUN');
  assert.equal(unavailable.evidence_satisfaction, 'NOT_EVALUATED');
  assert.deepEqual(unavailable.reasons, ['aadp_action_mapping_unavailable']);

  const derived = derive();
  assert.equal(derived.verdict, 'VERIFIED');
  const changed = {
    ...derived.artifact,
    action_mapping: {
      ...derived.artifact?.action_mapping,
      mapping_profile: 'https://attacker.example/mapping',
    },
  };
  const verified = verifyAadpEpAuthorizationArtifact(changed, {
    bundle: fixture.bundle,
    aadpAction,
    mapping: mappingConfiguration,
    verifier: verifierDescriptor,
    bundleOptions,
  });
  assert.equal(verified.verdict, 'REFUSE');
  assert.equal(verified.native_verification, 'VERIFIED');
  assert.equal(verified.evidence_satisfaction, 'SATISFIED');
  assert.deepEqual(verified.reasons, ['authorization_artifact_mismatch']);
  assert.equal(verified.authorization_decision, false);
});

test('an unmapped debit_account material parameter refuses before EP verification', () => {
  const result = derive({
    aadpAction: {
      ...aadpAction,
      params: { ...aadpAction.params, debit_account: 'acct:attacker-controlled' },
    },
  });
  assert.equal(result.verdict, 'REFUSE');
  assert.equal(result.native_verification, 'NOT_RUN');
  assert.equal(result.evidence_satisfaction, 'NOT_EVALUATED');
  assert.deepEqual(result.reasons, ['aadp_action_material_fields_unmapped:debit_account']);
  assert.equal(result.authorization_decision, false);
});

test('closed resolver retains every field and rejects ambiguous or dangerous mapped paths', () => {
  const result = derive({
    mapping: {
      ...mappingConfiguration,
      material_field_map: [
        ...mappingConfiguration.material_field_map,
        { source_param: 'duplicate', mapped_path: 'parameters.payee.account' },
      ],
    },
  });
  assert.equal(result.verdict, 'INDETERMINATE');
  assert.equal(result.native_verification, 'NOT_RUN');
  assert.deepEqual(result.reasons, ['aadp_action_mapping_unavailable']);

  const dangerous = derive({
    mapping: {
      ...mappingConfiguration,
      material_field_map: mappingConfiguration.material_field_map.map((entry) => (
        entry.source_param === 'payee'
          ? { ...entry, mapped_path: '__proto__.polluted' }
          : entry
      )),
    },
  });
  assert.equal(dangerous.verdict, 'INDETERMINATE');
  assert.equal(dangerous.native_verification, 'NOT_RUN');
  assert.deepEqual(dangerous.reasons, ['aadp_action_mapping_unavailable']);
});

test('a definitive native failure remains refused when policy is also stale', () => {
  const changedAction = {
    ...aadpAction,
    params: { ...aadpAction.params, amount_minor: 999_999 },
  };
  const result = derive({
    aadpAction: changedAction,
    bundleOptions: {
      ...bundleOptions,
      currentPolicy: { ...fixture.current_policy, unavailable: true },
    },
  });
  assert.equal(result.verdict, 'REFUSE');
  assert.equal(result.native_verification, 'REFUSED');
  assert.equal(result.evidence_satisfaction, 'REFUSE');
  assert.ok(result.reasons.includes('action_mismatch'));
  assert.ok(result.reasons.includes('current_policy_unavailable_or_stale'));
});

test('verifier identity and all serializable trust and status inputs are record-bound', () => {
  const first = derive();
  const second = derive({
    verifier: {
      ...verifierDescriptor,
      implementation: { ...verifierDescriptor.implementation, version: '3.20.4' },
    },
  });
  assert.equal(first.verdict, 'VERIFIED');
  assert.equal(second.verdict, 'VERIFIED');
  assert.notEqual(first.verification_record?.record_digest, second.verification_record?.record_digest);

  const unbound = derive({
    bundleOptions: {
      ...bundleOptions,
      verifyPresentationEvidence: () => true,
    },
  });
  assert.equal(unbound.verdict, 'REFUSE');
  assert.deepEqual(unbound.reasons, [
    'native_verifier_extension_unbound:verifyPresentationEvidence',
  ]);
});

test('hostile accessors and proxies produce verdicts without executing getters', () => {
  const accessor = Object.create(null);
  Object.defineProperty(accessor, 'profile', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  assert.doesNotThrow(() => parseAadpAuthorizationArtifact(accessor));
  assert.equal(parseAadpAuthorizationArtifact(accessor), null);

  const proxy = new Proxy({}, {
    getPrototypeOf() { throw new Error('must not escape'); },
  });
  assert.doesNotThrow(() => matchAadpAuthorizationArtifact(proxy, proxy));
  assert.equal(matchAadpAuthorizationArtifact(proxy, proxy).verdict, 'MISMATCH');
  assert.doesNotThrow(() => deriveAadpEpAuthorizationArtifact(proxy as any));
  assert.equal(deriveAadpEpAuthorizationArtifact(proxy as any).verdict, 'REFUSE');

  const derived = derive();
  assert.ok(derived.artifact);
  const protoKey = structuredClone(derived.artifact);
  Object.defineProperty(protoKey, '__proto__', {
    enumerable: true,
    value: { polluted: true },
  });
  assert.equal(parseAadpAuthorizationArtifact(protoKey), null);
  assert.equal(({} as { polluted?: boolean }).polluted, undefined);
});
