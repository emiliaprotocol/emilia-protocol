// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID,
  PINNED_MAPPING_PROFILE_DIGEST,
  PROFILE,
  buildAuthzenNativeCompilerFixture,
  runSuite,
  verifySourceLock,
} from './run.mjs';
import {
  digestAeb,
} from '../../../packages/verify/dist/aeb-adapter-contract.js';
import {
  AEB_NATIVE_COMPILER_VERSION,
  aebNativeDescriptorDigest,
  compileAebNativeEvidence,
} from '../../../packages/verify/dist/aeb-native-compiler.js';

const report = runSuite();

function result(id) {
  const found = report.cases.find((entry) => entry.id === id);
  assert.ok(found, `missing result: ${id}`);
  return found;
}

test('all nine source-pinned composition cases pass', () => {
  assert.equal(report.profile, PROFILE);
  assert.deepEqual(report.summary, { total: 9, passed: 9, failed: 0 });
  assert.equal(report.implementation.independent_implementation, false);
  assert.equal(report.implementation.production_mediation, false);
  assert.equal(verifySourceLock().valid, true);
  assert.equal(report.source_pins.mapping_profile_digest, PINNED_MAPPING_PROFILE_DIGEST);
});

test('exact allow reaches AEB admission only under local atomic reservation', () => {
  const exactCase = result('allow_exact_call_admitted');
  const exact = exactCase.observed;
  assert.equal(exact.pdp_decision, 'ALLOW');
  assert.equal(exact.material_action, 'MATCH');
  assert.equal(exact.native_verification, 'VERIFIED');
  assert.equal(exact.rp_acceptance, 'ACCEPTED');
  assert.equal(exact.evidence_satisfaction, 'SATISFIED');
  assert.equal(exact.local_authorization, 'AUTHORIZED');
  assert.equal(exact.reservation, 'RESERVED');
  assert.equal(exact.aeb_decision, 'ADMIT');
  assert.equal(exact.provider_outcome, 'NOT_INVOKED');
  assert.equal(exact.execution_proven_by_authzen, false);

  const compiler = exactCase.details.native_compiler;
  assert.equal(compiler['@version'], AEB_NATIVE_COMPILER_VERSION);
  assert.equal(compiler.axes.verified.result, 'VERIFIED');
  assert.equal(compiler.axes.accepted.result, 'ACCEPTED');
  assert.equal(compiler.axes.match.result, 'MATCH');
  assert.equal(compiler.axes.satisfied.result, 'SATISFIED');
  assert.equal(compiler.axes.policy_input.result, 'ALLOW');
  assert.deepEqual(compiler.axes.local_authorization, {
    result: 'NOT_EVALUATED',
    reasons: ['compiler_does_not_evaluate_local_authorization'],
  });
  assert.equal(compiler.claims.local_authorization_established, false);
  assert.equal(compiler.semantic_loss.status, 'NONE');
  assert.equal(compiler.legs[0].native_descriptor.pinned, true);
  assert.equal(compiler.legs[0].native_descriptor.id, AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID);
  assert.equal(
    compiler.legs[0].native_descriptor.protocol.id,
    'emilia-authzen-local-pep-envelope',
  );
  assert.equal(
    compiler.legs[0].native_descriptor.verifier.implementation_id,
    'emilia:authzen-local-pep-envelope-verifier',
  );
  assert.equal(exactCase.details.local_pep_attestation.authzen_signature_claimed, false);
  assert.equal(exactCase.details.policy_input_matches_verified_observation, true);
});

test('beneficiary substitution stays allowed at the toy PDP but refuses before entry', () => {
  const changed = result('allow_changed_beneficiary_refused');
  assert.equal(changed.observed.pdp_decision, 'ALLOW');
  assert.equal(changed.observed.material_action, 'MISMATCH');
  assert.equal(changed.observed.action_match, 'MISMATCH');
  assert.equal(changed.observed.evidence_satisfaction, 'UNSATISFIED');
  assert.equal(changed.observed.reservation, 'NOT_ATTEMPTED');
  assert.equal(changed.observed.aeb_decision, 'REFUSE');
  assert.equal(changed.observed.provider_entry, 'REFUSED_BEFORE_ENTRY');
  assert.equal(changed.details.material_reason, 'caid_mismatch:beneficiary_account');
  assert.equal(changed.details.native_compiler.axes.verified.result, 'VERIFIED');
  assert.equal(changed.details.native_compiler.axes.accepted.result, 'ACCEPTED');
  assert.equal(changed.details.native_compiler.axes.match.result, 'MISMATCH');
  assert.equal(changed.details.native_compiler.axes.satisfied.result, 'UNSATISFIED');
});

test('AuthZEN deny and named-human authorization remain separate', () => {
  const denied = result('deny_does_not_admit').observed;
  assert.equal(denied.pdp_decision, 'DENY');
  assert.equal(denied.evidence_satisfaction, 'SATISFIED');
  assert.equal(denied.local_authorization, 'NOT_AUTHORIZED');
  assert.deepEqual(denied.reasons, ['local_policy_denied']);
  const deniedCompiler = result('deny_does_not_admit').details.native_compiler;
  assert.equal(deniedCompiler.axes.policy_input.result, 'DENY');
  assert.equal(deniedCompiler.axes.local_authorization.result, 'NOT_EVALUATED');

  const noHuman = result('allow_does_not_fill_named_human_role').observed;
  assert.equal(noHuman.pdp_decision, 'ALLOW');
  assert.equal(noHuman.authzen_role, 'MACHINE_POLICY_INPUT');
  assert.equal(noHuman.named_human_authorization_proven, false);
  assert.equal(noHuman.evidence_satisfaction, 'UNSATISFIED');
  assert.deepEqual(noHuman.reasons, ['required_role_unsatisfied']);

  const noHumanCompiler = result('allow_does_not_fill_named_human_role').details.native_compiler;
  assert.equal(noHumanCompiler.axes.verified.result, 'VERIFIED');
  assert.equal(noHumanCompiler.axes.match.result, 'MATCH');
  assert.equal(noHumanCompiler.axes.satisfied.result, 'UNSATISFIED');
  assert.equal(noHumanCompiler.axes.policy_input.result, 'ALLOW');
  assert.equal(noHumanCompiler.axes.local_authorization.result, 'NOT_EVALUATED');
});

test('missing or substituted native descriptor and relying-party pin fail closed', () => {
  const missing = buildAuthzenNativeCompilerFixture();
  delete missing.input.native_descriptors.registry[AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID];
  const missingReport = compileAebNativeEvidence(missing.input);
  assert.equal(missingReport.legs[0].native_descriptor.pinned, false);
  assert.equal(missingReport.axes.accepted.result, 'INDETERMINATE');
  assert.equal(missingReport.axes.match.result, 'INDETERMINATE');
  assert.equal(missingReport.axes.satisfied.result, 'INDETERMINATE');
  assert.ok(missingReport.reasons.includes(
    `native_descriptor_not_registered:${AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID}`,
  ));

  const substituted = buildAuthzenNativeCompilerFixture();
  const descriptor = substituted.input.native_descriptors
    .registry[AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID];
  descriptor.verifier.implementation_revision = 'substituted-v9';
  descriptor.descriptor_digest = aebNativeDescriptorDigest(
    AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID,
    descriptor,
  );
  const substitutedReport = compileAebNativeEvidence(substituted.input);
  assert.equal(substitutedReport.legs[0].native_descriptor.pinned, false);
  assert.equal(substitutedReport.axes.accepted.result, 'INDETERMINATE');
  assert.equal(substitutedReport.axes.match.result, 'INDETERMINATE');
  assert.equal(substitutedReport.axes.satisfied.result, 'INDETERMINATE');
  assert.ok(substitutedReport.reasons.includes(
    `native_descriptor_pin_mismatch:${AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID}`,
  ));

  const changedPin = buildAuthzenNativeCompilerFixture();
  changedPin.input.native_descriptors.pins[AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID]
    = `sha256:${'f'.repeat(64)}`;
  const changedPinReport = compileAebNativeEvidence(changedPin.input);
  assert.equal(changedPinReport.legs[0].native_descriptor.pinned, false);
  assert.equal(changedPinReport.axes.satisfied.result, 'INDETERMINATE');
  assert.ok(changedPinReport.reasons.includes(
    `native_descriptor_pin_mismatch:${AUTHZEN_PEP_NATIVE_DESCRIPTOR_ID}`,
  ));
});

test('the local PEP signature binds the observation without becoming an AuthZEN signature', () => {
  const fixture = buildAuthzenNativeCompilerFixture();
  assert.equal(fixture.attestation.protocol_id, 'authzen-local-pep-observation');
  assert.equal(fixture.attestation.signature.key_id, 'test-verifier:authzen-local-pep:v0.1');
  assert.equal(fixture.attestation.native_artifact_digest, digestAeb(fixture.observation));
  assert.equal(fixture.observation.boolean_decision, true);
  assert.match(fixture.observation.authzen_request_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(fixture.observation.full_typed_action_digest, /^sha256:[0-9a-f]{64}$/);
  const compiled = compileAebNativeEvidence(fixture.input);
  assert.equal(compiled.legs[0].artifact_digest, digestAeb(fixture.envelope));

  const tampered = buildAuthzenNativeCompilerFixture();
  const artifact = tampered.input.native_legs[0].artifact;
  const last = artifact.attestation.mapping.caid.at(-1);
  artifact.attestation.mapping.caid
    = `${artifact.attestation.mapping.caid.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`;
  const report = compileAebNativeEvidence(tampered.input);
  assert.equal(report.axes.verified.result, 'FAILED');
  assert.equal(report.axes.accepted.result, 'REJECTED');
  assert.equal(report.axes.satisfied.result, 'UNSATISFIED');
  assert.ok(report.reasons.includes('native_attestation_signature_invalid'));
});

test('observation mutation with an unchanged attestation fails before mapping', () => {
  const fixture = buildAuthzenNativeCompilerFixture();
  fixture.input.native_legs[0].artifact.observation.boolean_decision = false;
  const report = compileAebNativeEvidence(fixture.input);
  assert.equal(report.axes.verified.result, 'FAILED');
  assert.equal(report.axes.accepted.result, 'REJECTED');
  assert.equal(report.axes.match.result, 'INDETERMINATE');
  assert.equal(report.legs[0].action.native_raw_mapping, 'INDETERMINATE');
  assert.equal(report.legs[0].action.native_raw_caid, null);
  assert.equal(report.legs[0].action.native_raw_normalized_action_digest, null);
  assert.equal(report.legs[0].artifact_digest, digestAeb(fixture.input.native_legs[0].artifact));
  assert.ok(report.reasons.includes('pep_observation_digest_mismatch'));
  assert.ok(report.reasons.includes('native_verification_required'));
});

test('attestation and observation substitution fails before mapping', () => {
  const benign = buildAuthzenNativeCompilerFixture();
  const substituted = buildAuthzenNativeCompilerFixture({
    call_fixture: 'substituted_call',
  });
  benign.input.native_legs[0].artifact.attestation = substituted.attestation;
  const report = compileAebNativeEvidence(benign.input);
  assert.equal(report.axes.verified.result, 'FAILED');
  assert.equal(report.axes.accepted.result, 'REJECTED');
  assert.equal(report.axes.match.result, 'INDETERMINATE');
  assert.equal(report.legs[0].action.native_raw_mapping, 'INDETERMINATE');
  assert.ok(report.reasons.includes('pep_observation_digest_mismatch'));
  assert.ok(report.reasons.includes('pep_observation_reference_mismatch'));
});

test('validly signed reference, action, and mapping disagreements fail closed', () => {
  const wrongReference = buildAuthzenNativeCompilerFixture({
    attestation_native_artifact_ref: 'urn:emilia:authzen-local-pep:substituted',
  });
  const referenceReport = compileAebNativeEvidence(wrongReference.input);
  assert.equal(referenceReport.axes.verified.result, 'FAILED');
  assert.ok(referenceReport.reasons.includes('pep_observation_reference_mismatch'));

  const wrongAction = buildAuthzenNativeCompilerFixture({
    attestation_mapping_overrides: {
      caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`,
    },
  });
  const actionReport = compileAebNativeEvidence(wrongAction.input);
  assert.equal(actionReport.axes.verified.result, 'FAILED');
  assert.ok(actionReport.reasons.includes('pep_observation_action_mismatch'));

  const wrongMapping = buildAuthzenNativeCompilerFixture({
    attestation_mapping_overrides: { mapper_id: 'mapper:substituted' },
  });
  const mappingReport = compileAebNativeEvidence(wrongMapping.input);
  assert.equal(mappingReport.axes.verified.result, 'FAILED');
  assert.ok(mappingReport.reasons.includes('pep_observation_mapping_mismatch'));
});

test('native replay unit is stable across compiler wrapper references', () => {
  const first = buildAuthzenNativeCompilerFixture({
    artifact_ref: 'urn:emilia:wrapper:first',
  });
  const second = buildAuthzenNativeCompilerFixture({
    artifact_ref: 'urn:emilia:wrapper:second',
  });
  const firstReport = compileAebNativeEvidence(first.input);
  const secondReport = compileAebNativeEvidence(second.input);
  assert.equal(firstReport.legs[0].replay_unit, secondReport.legs[0].replay_unit);
  assert.equal(firstReport.replay_unit, secondReport.replay_unit);
  assert.notEqual(firstReport.legs[0].artifact_ref, secondReport.legs[0].artifact_ref);
});

test('compiler leaves lifecycle unestablished and the consequence kernel alone advances it', () => {
  const exact = result('allow_exact_call_admitted');
  const lifecycle = exact.details.native_compiler.lifecycle;
  assert.equal(lifecycle.reservation.result, 'NOT_EVALUATED');
  assert.equal(lifecycle.consumption.result, 'NOT_EVALUATED');
  assert.equal(lifecycle.provider_entry.result, 'NOT_ESTABLISHED');
  assert.equal(lifecycle.provider_outcome.result, 'NOT_ESTABLISHED');
  assert.equal(lifecycle.observed_effect.result, 'NOT_ESTABLISHED');
  assert.equal(lifecycle.retry.result, 'NOT_EVALUATED');
  assert.equal(lifecycle.reconciliation.result, 'NOT_EVALUATED');
  assert.equal(exact.observed.reservation, 'RESERVED');
  assert.equal(exact.observed.provider_outcome, 'NOT_INVOKED');

  const timeout = result('timeout_after_dispatch_indeterminate');
  assert.equal(timeout.details.native_compiler.lifecycle.provider_outcome.result, 'NOT_ESTABLISHED');
  assert.equal(timeout.observed.provider_outcome, 'INDETERMINATE');
  assert.equal(timeout.observed.reconciliation, 'REQUIRED');
});

test('timeout is indeterminate and blind retry is refused', () => {
  const timeout = result('timeout_after_dispatch_indeterminate').observed;
  assert.equal(timeout.custody, 'INVOKING');
  assert.equal(timeout.provider_outcome, 'INDETERMINATE');
  assert.equal(timeout.effect_relation, 'INDETERMINATE');
  assert.equal(timeout.retry, 'REFUSED');
  assert.equal(timeout.reconciliation, 'REQUIRED');
  assert.equal(timeout.aeb_decision, 'INDETERMINATE');

  const retry = result('blind_retry_refused').observed;
  assert.equal(retry.reservation, 'OPERATION_REPLAY');
  assert.equal(retry.provider_entry, 'REENTRY_REFUSED');
  assert.deepEqual(retry.reasons, ['blind_retry_refused']);
});

test('only authenticated exact provider and action bindings reconcile', () => {
  const exact = result('authenticated_exact_reconciliation_accepted').observed;
  assert.equal(exact.reconciliation, 'ACCEPTED');
  assert.equal(exact.provider_outcome, 'COMMITTED');
  assert.equal(exact.effect_relation, 'OBSERVED_AS_REQUESTED');
  assert.equal(exact.aeb_decision, 'RECONCILED');

  const mismatch = result('mismatched_provider_and_action_reconciliation_refused').observed;
  assert.equal(mismatch.reconciliation, 'REFUSED');
  assert.equal(mismatch.provider_outcome, 'INDETERMINATE');
  assert.equal(mismatch.aeb_decision, 'REFUSE');
  assert.deepEqual(mismatch.reasons, ['reconciliation_binding_mismatch']);
});

test('changed mapping pin stops before translation, PDP evaluation, and AEB', () => {
  const changed = result('mapping_profile_pin_change_refused').observed;
  assert.equal(changed.preflight, 'REFUSE_MAPPING_PROFILE_PIN_MISMATCH');
  assert.equal(changed.translation, 'NOT_ATTEMPTED');
  assert.equal(changed.pdp_decision, null);
  assert.equal(changed.aeb_decision, null);
  assert.equal(changed.provider_entry, 'REFUSED_BEFORE_ENTRY');
});

test('deterministic report matches the checked-in reference and preserves nonclaims', () => {
  const reference = JSON.parse(readFileSync(new URL('./report.reference.json', import.meta.url), 'utf8'));
  assert.deepEqual(report, reference);
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(report.claim_scope.exclusions.includes('authorization_api_replay_semantics'));
  assert.ok(report.claim_scope.exclusions.includes('openid_working_group_acceptance'));
  assert.ok(report.claim_scope.exclusions.includes('production_mediation'));
});
