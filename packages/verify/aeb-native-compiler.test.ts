// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AEB_NATIVE_DESCRIPTOR_VERSION,
  AEB_NATIVE_COMPILER_VERSION,
  aebNativeDescriptorDigest,
  compileAebNativeEvidence,
  type AebNativeCompilerInput,
  type AebNativeDescriptor,
} from './aeb-native-compiler.js';
import {
  adapterPinDigest,
  digestAeb,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebAdapter,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRegistryEntry,
  type AebUnifiedRegistry,
} from './aeb-adapter-contract.js';

const NOW = '2026-08-31T18:00:00.000Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  amount: '725.00',
  currency: 'USD',
  beneficiary: 'vendor:acme',
});

function status() {
  return {
    checked_at: '2026-08-31T17:59:30.000Z',
    expires_at: '2026-08-31T18:05:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
}

function statusDigest(value: ReturnType<typeof status>) {
  return digestAeb({ ...value, unavailable: false });
}

function nativeAdapter(id: string, version: string): AebAdapter {
  return Object.freeze({
    id,
    version,
    verifyNative({ artifact, status: currentStatus, trust_roots }) {
      const candidate = artifact as Record<string, any>;
      const trusted = trust_roots.includes(candidate.root);
      return {
        native_verification: trusted ? 'VERIFIED' : 'FAILED',
        acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
        evidence_digest: digestAeb(candidate),
        status_digest: statusDigest(currentStatus as ReturnType<typeof status>),
        evidence_role: candidate.role,
        subject: candidate.subject,
        // This identity comes from the native authorization. It deliberately
        // excludes the AEB artifact_ref wrapper.
        replay_unit: digestAeb({ protocol: id, authorization_id: candidate.authorization_id }),
        reasons: trusted ? [] : ['native_trust_root_not_pinned'],
      };
    },
    mapAction({ artifact, expected_action, native }) {
      const candidate = artifact as Record<string, any>;
      if (native.native_verification !== 'VERIFIED' || native.acceptance !== 'ACCEPTED') {
        return {
          mapping: 'INDETERMINATE', caid: null, action_digest: null,
          reasons: ['native_acceptance_required'],
        };
      }
      const normalizedDigest = digestAeb(candidate.action);
      if (normalizedDigest !== digestAeb(expected_action)) {
        return {
          mapping: 'MISMATCH', caid: candidate.caid, action_digest: normalizedDigest,
          reasons: ['native_action_mismatch'],
        };
      }
      return {
        mapping: 'MATCH',
        caid: candidate.caid,
        action_digest: normalizedDigest,
        reasons: [],
      };
    },
  });
}

function registryEntry(
  id: string,
  kind: AebRegistryEntry['kind'],
  definition: unknown,
): AebRegistryEntry {
  const entry = {
    kind,
    version: '1',
    status: 'active' as const,
    definition,
  } as AebRegistryEntry;
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

function profile(
  id: string,
  mapperId: string,
  omittedNonmaterialFields: string[] = [],
): AebPinnedProfile {
  const value = {
    version: 'native-mapping-v1',
    definition: { source: id, projection: 'exact-native-action' },
    registry_entry_ref: `mapping:${id}`,
    mapper_id: mapperId,
    resolver: {
      id: `resolver:${id}`,
      version: '1',
      implementation_digest: digestAeb({ resolver: id, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE' as const,
      loss_policy: 'NO_MATERIAL_FIELD_LOSS' as const,
      omitted_material_fields: [] as string[],
      omitted_nonmaterial_fields: omittedNonmaterialFields,
    },
    profile_digest: '' as AebPinnedProfile['profile_digest'],
  };
  value.profile_digest = mappingProfileDigest(id, value);
  return value;
}

function refreshProfile(config: AebPinnedConfig, id: string) {
  const pinned = config.profiles[id];
  pinned.profile_digest = mappingProfileDigest(id, pinned);
  const entryId = pinned.registry_entry_ref;
  config.registry.entries[entryId] = registryEntry(
    entryId,
    'mapping-profile',
    { profile_digest: pinned.profile_digest },
  );
  config.registry.registry_digest = unifiedRegistryDigest(config.registry);
}

function nativeDescriptor(
  id: string,
  adapter: AebAdapter,
  profileId: string,
  pinnedProfile: AebPinnedProfile,
  protocolId: string,
  protocolRevision: string,
): AebNativeDescriptor {
  const value = {
    '@version': AEB_NATIVE_DESCRIPTOR_VERSION,
    protocol: { id: protocolId, revision: protocolRevision },
    source: {
      media_type: 'application/example+json',
      schema: { id: `schema:${protocolId}`, revision: protocolRevision },
    },
    verifier: {
      implementation_id: `verifier:${protocolId}`,
      implementation_revision: '2026.08.31',
      implementation_digest: digestAeb({ implementation: `verifier:${protocolId}`, revision: '2026.08.31' }),
    },
    adapter: { id: adapter.id, revision: adapter.version },
    mapping_profile: {
      id: profileId,
      revision: pinnedProfile.version,
      digest: pinnedProfile.profile_digest,
    },
    target_action_type: 'payment.release.1',
    replay_scope: 'per-relying-party-native-authorization',
    descriptor_digest: '' as AebNativeDescriptor['descriptor_digest'],
  };
  value.descriptor_digest = aebNativeDescriptorDigest(id, value);
  return value;
}

function refreshDescriptor(input: AebNativeCompilerInput, id: string) {
  const descriptor = input.native_descriptors.registry[id];
  descriptor.descriptor_digest = aebNativeDescriptorDigest(id, descriptor);
  input.native_descriptors.pins[id] = descriptor.descriptor_digest;
}

function fixture(): AebNativeCompilerInput {
  const delegationAdapter = nativeAdapter('native:delegation', 'draft-07');
  const approvalAdapter = nativeAdapter('native:approval', 'spec-2.1');
  const delegationProfile = profile('profile:delegation', 'mapper:delegation', ['native_trace_id']);
  const approvalProfile = profile('profile:approval', 'mapper:approval');
  const delegationDescriptorId = 'descriptor:native-delegation-draft-07';
  const approvalDescriptorId = 'descriptor:native-approval-spec-2.1';
  const delegationDescriptor = nativeDescriptor(
    delegationDescriptorId,
    delegationAdapter,
    'profile:delegation',
    delegationProfile,
    'example-delegation',
    'draft-07',
  );
  const approvalDescriptor = nativeDescriptor(
    approvalDescriptorId,
    approvalAdapter,
    'profile:approval',
    approvalProfile,
    'example-approval',
    'spec-2.1',
  );
  const entries: Record<string, AebRegistryEntry> = {
    [delegationProfile.registry_entry_ref]: registryEntry(
      delegationProfile.registry_entry_ref,
      'mapping-profile',
      { profile_digest: delegationProfile.profile_digest },
    ),
    [approvalProfile.registry_entry_ref]: registryEntry(
      approvalProfile.registry_entry_ref,
      'mapping-profile',
      { profile_digest: approvalProfile.profile_digest },
    ),
    'role:delegated-authority': registryEntry(
      'role:delegated-authority',
      'evidence-role',
      { role: 'delegated-authority', subject_kinds: ['workload'] },
    ),
    'role:human-authorization': registryEntry(
      'role:human-authorization',
      'evidence-role',
      { role: 'human-authorization', subject_kinds: ['human'] },
    ),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1' as const,
    registry_id: 'registry:compiler-test',
    epoch: 1,
    entries,
    registry_digest: '' as AebUnifiedRegistry['registry_digest'],
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const requirement = {
    '@version': 'AEB-REQUIREMENT-v1' as const,
    all_of: ['delegated-authority', 'human-authorization'],
    terms: [{ type: 'one-time-consumption' as const }],
  };
  const delegationPin = {
    version: delegationAdapter.version,
    trust_roots: ['root:delegation'],
    config: { native_profile: 'delegation-draft-07' },
    config_digest: '' as `sha256:${string}`,
    max_status_age_sec: 60,
  };
  delegationPin.config_digest = adapterPinDigest(delegationAdapter.id, delegationPin);
  const approvalPin = {
    version: approvalAdapter.version,
    trust_roots: ['root:approval'],
    config: { native_profile: 'approval-spec-2.1' },
    config_digest: '' as `sha256:${string}`,
    max_status_age_sec: 60,
  };
  approvalPin.config_digest = adapterPinDigest(approvalAdapter.id, approvalPin);
  const pins: AebPinnedConfig = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:compiler-test',
    evaluator_keys: {},
    registry,
    accepted_mappers: [delegationProfile.mapper_id, approvalProfile.mapper_id],
    adapters: {
      [delegationAdapter.id]: delegationPin,
      [approvalAdapter.id]: approvalPin,
    },
    profiles: {
      'profile:delegation': delegationProfile,
      'profile:approval': approvalProfile,
    },
    requirements: { 'requirement:payment-release': requirement },
  };
  return {
    pins,
    adapters: {
      [delegationAdapter.id]: delegationAdapter,
      [approvalAdapter.id]: approvalAdapter,
    },
    native_descriptors: {
      pins: {
        [delegationDescriptorId]: delegationDescriptor.descriptor_digest,
        [approvalDescriptorId]: approvalDescriptor.descriptor_digest,
      },
      registry: {
        [delegationDescriptorId]: delegationDescriptor,
        [approvalDescriptorId]: approvalDescriptor,
      },
    },
    native_legs: [
      {
        native_descriptor_id: delegationDescriptorId,
        adapter_id: delegationAdapter.id,
        profile_id: 'profile:delegation',
        artifact_ref: 'urn:wrapper:delegation:one',
        artifact: {
          root: 'root:delegation',
          authorization_id: 'delegation:42',
          role: 'delegated-authority',
          subject: { id: 'workload:buyer-agent', kind: 'workload' },
          caid: CAID,
          action: ACTION,
          native_trace_id: 'trace-not-material',
        },
        status: status(),
      },
      {
        native_descriptor_id: approvalDescriptorId,
        adapter_id: approvalAdapter.id,
        profile_id: 'profile:approval',
        artifact_ref: 'urn:wrapper:approval:one',
        artifact: {
          root: 'root:approval',
          authorization_id: 'approval:99',
          role: 'human-authorization',
          subject: { id: 'human:alice', kind: 'human' },
          caid: CAID,
          action: ACTION,
        },
        status: status(),
      },
    ],
    expected_action: { caid: CAID, value: ACTION },
    requirement: {
      ref: 'requirement:payment-release',
      definition: requirement,
    },
    initiator_id: 'workload:buyer-agent',
    executor_id: 'system:payment-provider',
    evaluated_at: NOW,
    local_policy_input: {
      policy_id: 'policy:release-window',
      policy_version: '3',
      decision: 'ALLOW',
      reasons: ['release_window_open'],
    },
  };
}

test('compiles two native legs without changing native wire artifacts', () => {
  const input = fixture();
  const before = structuredClone(input.native_legs.map((leg) => leg.artifact));
  const report = compileAebNativeEvidence(input);

  assert.equal(report['@version'], AEB_NATIVE_COMPILER_VERSION);
  assert.deepEqual(report.axes, {
    verified: { result: 'VERIFIED', reasons: [] },
    accepted: { result: 'ACCEPTED', reasons: [] },
    match: { result: 'MATCH', reasons: [] },
    satisfied: { result: 'SATISFIED', reasons: [] },
    policy_input: { result: 'ALLOW', reasons: ['release_window_open'] },
    local_authorization: {
      result: 'NOT_EVALUATED',
      reasons: ['compiler_does_not_evaluate_local_authorization'],
    },
  });
  assert.equal(report.legs.length, 2);
  assert.equal(report.legs[0].native_profile.adapter_revision, 'draft-07');
  assert.equal(report.legs[1].native_profile.mapping_profile_revision, 'native-mapping-v1');
  assert.equal(report.legs[0].native_descriptor.pinned, true);
  assert.equal(report.legs[0].native_descriptor.protocol.id, 'example-delegation');
  assert.equal(report.legs[0].native_descriptor.protocol.revision, 'draft-07');
  assert.equal(report.legs[0].native_descriptor.source.media_type, 'application/example+json');
  assert.equal(report.legs[0].native_descriptor.source.schema?.revision, 'draft-07');
  assert.equal(report.legs[0].native_descriptor.verifier.implementation_id, 'verifier:example-delegation');
  assert.match(report.legs[0].native_descriptor.verifier.implementation_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(report.legs[0].artifact_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(report.legs[0].native_result.verification, 'VERIFIED');
  assert.equal(report.legs[0].native_result.acceptance, 'ACCEPTED');
  assert.equal(report.legs[0].pins.mapper_id, 'mapper:delegation');
  assert.equal(report.legs[0].action.mapping, 'MATCH');
  assert.equal(report.legs[0].action.caid, CAID);
  assert.equal(report.legs[0].action.normalized_action_digest, digestAeb(ACTION));
  assert.equal(report.legs[0].action.native_raw_mapping, 'MATCH');
  assert.equal(report.legs[0].action.native_raw_caid, CAID);
  assert.equal(report.legs[0].action.native_raw_normalized_action_digest, digestAeb(ACTION));
  assert.equal(report.legs[0].evidence.role, 'delegated-authority');
  assert.equal(report.legs[0].semantic_loss.status, 'NON_MATERIAL_ONLY');
  assert.deepEqual(report.legs[0].semantic_loss.omitted_nonmaterial_fields, ['native_trace_id']);
  assert.deepEqual(report.legs[0].semantic_loss.omissions, [{
    path: 'native_trace_id',
    classification: 'non_material',
    basis: {
      profile_id: 'profile:delegation',
      profile_digest: input.pins.profiles['profile:delegation'].profile_digest,
      profile_pinned: true,
      declaration: 'omitted_nonmaterial_fields',
      binding_digest: report.legs[0].semantic_loss.omissions[0].basis.binding_digest,
    },
  }]);
  assert.match(
    report.legs[0].semantic_loss.omissions[0].basis.binding_digest,
    /^sha256:[0-9a-f]{64}$/,
  );
  const omission = report.legs[0].semantic_loss.omissions[0];
  const { binding_digest: omissionBindingDigest, ...omissionBasis } = omission.basis;
  assert.equal(omissionBindingDigest, digestAeb({
    '@version': 'EP-AEB-SEMANTIC-OMISSION-BASIS-v1',
    path: omission.path,
    classification: omission.classification,
    ...omissionBasis,
  }));
  assert.deepEqual(report.expected_action, {
    caid: CAID,
    value: ACTION,
    digest: digestAeb(ACTION),
    provenance: 'RELYING_PARTY_INPUT',
  });
  assert.notEqual(report.expected_action.value, input.expected_action.value);
  assert.deepEqual(report.local_policy_input, {
    policy_id: 'policy:release-window',
    policy_version: '3',
    decision: 'ALLOW',
    reasons: ['release_window_open'],
    provenance: 'RELYING_PARTY_INPUT',
    verification: 'NOT_EVALUATED',
    input_digest: report.local_policy_input.input_digest,
  });
  assert.match(report.local_policy_input.input_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(report.replay_unit, /^sha256:[0-9a-f]{64}$/);
  assert.equal(report.claims.local_authorization_established, false);
  assert.equal(report.claims.provider_entry_established, false);
  assert.equal(report.claims.execution_established, false);
  assert.equal(report.claims.outcome_established, false);
  assert.equal(report.claims.verifier_runtime_measurement_established, false);
  assert.deepEqual(report.lifecycle, {
    reservation: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_reserve_authority'] },
    consumption: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_consume_authority'] },
    provider_entry: { result: 'NOT_ESTABLISHED', reasons: ['compiler_has_no_provider_entry_evidence'] },
    provider_outcome: { result: 'NOT_ESTABLISHED', reasons: ['compiler_has_no_provider_outcome_evidence'] },
    observed_effect: { result: 'NOT_ESTABLISHED', reasons: ['compiler_has_no_observed_effect_evidence'] },
    retry: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_determine_retry'] },
    reconciliation: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_reconcile_outcomes'] },
  });
  assert.equal(report.report_is_credential, false);
  assert.deepEqual(input.native_legs.map((leg) => leg.artifact), before);
  assert.deepEqual(report.reasons, []);
});

test('omitted material field fails closed', () => {
  const input = fixture();
  const profile = input.pins.profiles['profile:delegation'];
  profile.semantic_equivalence.omitted_material_fields = ['purpose'];
  refreshProfile(input.pins, 'profile:delegation');
  const descriptor = input.native_descriptors.registry['descriptor:native-delegation-draft-07'];
  descriptor.mapping_profile.digest = profile.profile_digest;
  refreshDescriptor(input, 'descriptor:native-delegation-draft-07');
  const approvalArtifact = input.native_legs[1].artifact as Record<string, any>;
  approvalArtifact.action = { ...ACTION, amount: '726.00' };

  const report = compileAebNativeEvidence(input);

  assert.equal(report.semantic_loss.status, 'MATERIAL');
  assert.equal(report.legs[0].action.native_raw_mapping, 'MATCH');
  assert.equal(report.legs[0].action.mapping, 'INDETERMINATE');
  assert.equal(report.legs[0].action.caid, null);
  assert.equal(report.legs[0].action.normalized_action_digest, null);
  assert.equal(report.legs[1].action.native_raw_mapping, 'MISMATCH');
  assert.equal(report.legs[1].action.mapping, 'MISMATCH');
  assert.equal(report.axes.match.result, 'INDETERMINATE');
  assert.deepEqual(report.legs[0].semantic_loss.omissions.map((omission) => ({
    path: omission.path,
    classification: omission.classification,
    profile_digest: omission.basis.profile_digest,
    profile_pinned: omission.basis.profile_pinned,
  })), [{
    path: 'purpose',
    classification: 'material',
    profile_digest: profile.profile_digest,
    profile_pinned: true,
  }, {
    path: 'native_trace_id',
    classification: 'non_material',
    profile_digest: profile.profile_digest,
    profile_pinned: true,
  }]);
  assert.equal(report.axes.satisfied.result, 'UNSATISFIED');
  assert.equal(report.axes.local_authorization.result, 'NOT_EVALUATED');
  assert.ok(report.reasons.includes('semantic_loss_material:profile:delegation'));
});

test('unpinned adapter and profile remain indeterminate', () => {
  const input = fixture();
  input.native_legs[0] = {
    ...input.native_legs[0],
    adapter_id: 'native:not-pinned',
    profile_id: 'profile:not-pinned',
  };

  const report = compileAebNativeEvidence(input);

  assert.equal(report.legs[0].semantic_loss.status, 'UNKNOWN');
  assert.equal(report.axes.verified.result, 'FAILED');
  assert.equal(report.axes.accepted.result, 'INDETERMINATE');
  assert.equal(report.axes.match.result, 'INDETERMINATE');
  assert.equal(report.axes.satisfied.result, 'INDETERMINATE');
  assert.equal(report.axes.local_authorization.result, 'NOT_EVALUATED');
  assert.ok(report.reasons.includes('adapter_or_profile_not_pinned'));
  assert.ok(report.reasons.includes('semantic_loss_unknown:profile:not-pinned'));
});

test('native replay unit is stable across AEB wrapper references', () => {
  const first = fixture();
  const second = fixture();
  second.native_legs = second.native_legs.map((leg, index) => ({
    ...leg,
    artifact_ref: `urn:another-wrapper:${index}`,
  }));

  const firstReport = compileAebNativeEvidence(first);
  const secondReport = compileAebNativeEvidence(second);

  assert.equal(firstReport.replay_unit, secondReport.replay_unit);
  assert.deepEqual(
    firstReport.legs.map((leg) => leg.replay_unit),
    secondReport.legs.map((leg) => leg.replay_unit),
  );
});

test('missing native descriptor fails closed before acceptance or matching', () => {
  const input = fixture();
  input.native_legs[0] = {
    ...input.native_legs[0],
    native_descriptor_id: 'descriptor:not-registered',
  };
  const approvalArtifact = input.native_legs[1].artifact as Record<string, any>;
  approvalArtifact.action = { ...ACTION, amount: '726.00' };

  const report = compileAebNativeEvidence(input);

  assert.equal(report.legs[0].native_descriptor.pinned, false);
  assert.equal(report.legs[0].native_result.verification, 'VERIFIED');
  assert.equal(report.legs[0].native_result.acceptance, 'INDETERMINATE');
  assert.equal(report.legs[0].semantic_loss.status, 'UNKNOWN');
  assert.equal(report.legs[0].action.native_raw_mapping, 'MATCH');
  assert.equal(report.legs[0].action.mapping, 'INDETERMINATE');
  assert.equal(report.legs[0].semantic_loss.omissions[0].path, '$');
  assert.equal(report.legs[0].semantic_loss.omissions[0].classification, 'unknown');
  assert.equal(report.legs[0].semantic_loss.omissions[0].basis.profile_pinned, true);
  assert.equal(
    report.legs[0].semantic_loss.omissions[0].basis.declaration,
    'native_profile_binding_unestablished',
  );
  assert.equal(report.legs[1].action.mapping, 'MISMATCH');
  assert.equal(report.axes.match.result, 'INDETERMINATE');
  assert.equal(report.axes.satisfied.result, 'INDETERMINATE');
  assert.equal(report.axes.local_authorization.result, 'NOT_EVALUATED');
  assert.ok(report.reasons.includes('native_descriptor_not_registered:descriptor:not-registered'));
});

test('native descriptor substitution is detected against the relying-party pin', () => {
  const input = fixture();
  const id = 'descriptor:native-delegation-draft-07';
  const descriptor = input.native_descriptors.registry[id];
  descriptor.verifier.implementation_digest = digestAeb({ substituted: true });
  // An attacker can repair the descriptor's self-digest, but not the separate
  // relying-party pin.
  descriptor.descriptor_digest = aebNativeDescriptorDigest(id, descriptor);

  const report = compileAebNativeEvidence(input);

  assert.equal(report.legs[0].native_descriptor.pinned, false);
  assert.equal(report.axes.accepted.result, 'INDETERMINATE');
  assert.equal(report.axes.match.result, 'INDETERMINATE');
  assert.equal(report.axes.satisfied.result, 'INDETERMINATE');
  assert.ok(report.reasons.includes(`native_descriptor_pin_mismatch:${id}`));
});

test('relying-party expected action mismatch refuses the match axis', () => {
  const input = fixture();
  const artifact = input.native_legs[0].artifact as Record<string, any>;
  artifact.action = { ...ACTION, amount: '726.00' };

  const report = compileAebNativeEvidence(input);

  assert.equal(report.axes.verified.result, 'VERIFIED');
  assert.equal(report.axes.accepted.result, 'ACCEPTED');
  assert.equal(report.axes.match.result, 'MISMATCH');
  assert.equal(report.axes.satisfied.result, 'UNSATISFIED');
  assert.equal(report.axes.local_authorization.result, 'NOT_EVALUATED');
  assert.ok(report.reasons.includes('native_action_mismatch'));
});

test('local policy input stays separate from satisfied evidence and cannot authorize', () => {
  const input = fixture();
  input.local_policy_input = {
    policy_id: 'policy:release-window',
    policy_version: '3',
    decision: 'DENY',
    reasons: ['release_window_closed'],
  };

  const report = compileAebNativeEvidence(input);

  assert.equal(report.axes.verified.result, 'VERIFIED');
  assert.equal(report.axes.accepted.result, 'ACCEPTED');
  assert.equal(report.axes.match.result, 'MATCH');
  assert.equal(report.axes.satisfied.result, 'SATISFIED');
  assert.deepEqual(report.axes.policy_input, {
    result: 'DENY',
    reasons: ['release_window_closed'],
  });
  assert.deepEqual(report.axes.local_authorization, {
    result: 'NOT_EVALUATED',
    reasons: ['compiler_does_not_evaluate_local_authorization'],
  });
  assert.equal(report.claims.local_authorization_established, false);
  assert.deepEqual(report.reasons, []);
});

test('invalid local policy input is indeterminate and still cannot authorize', () => {
  const input = fixture();
  input.local_policy_input = {
    ...input.local_policy_input,
    policy_id: '',
  };

  const report = compileAebNativeEvidence(input);

  assert.deepEqual(report.axes.policy_input, {
    result: 'INDETERMINATE',
    reasons: ['local_policy_input_invalid'],
  });
  assert.deepEqual(report.axes.local_authorization, {
    result: 'NOT_EVALUATED',
    reasons: ['compiler_does_not_evaluate_local_authorization'],
  });
  assert.equal(report.local_policy_input.decision, 'INDETERMINATE');
  assert.equal(report.local_policy_input.provenance, 'RELYING_PARTY_INPUT');
  assert.equal(report.local_policy_input.verification, 'NOT_EVALUATED');
  assert.equal(report.claims.local_authorization_established, false);
  assert.ok(report.reasons.includes('local_policy_input_invalid'));
});
