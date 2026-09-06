// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  AUTHZEN_PEP_ADAPTER_ID, AUTHZEN_PEP_PROFILE_ID,
  PINNED_MAPPING_PROFILE_DIGEST, PREFLIGHT_VERSION, PROFILE,
  buildAuthzenPreflightFixture, createAuthzenPepObservationEnvelopeAdapter,
  evaluateAuthzenPreflight, runSuite, verifySourceLock,
} from './run.mjs';
import {
  AEB_EVALUATION_VERSION, adapterPinDigest, digestAeb,
} from '../../../packages/verify/dist/aeb-adapter-contract.js';

let cachedReport;
const suite = () => cachedReport ??= runSuite();
const preflight = (fixture = buildAuthzenPreflightFixture()) => evaluateAuthzenPreflight(fixture.input);
const leg = (report) => report.evaluation.record.legs[0];
function result(id) {
  const found = suite().cases.find((entry) => entry.id === id);
  assert.ok(found, `missing result: ${id}`);
  return found;
}
function refusedMapping(checked, evaluatorMapping = 'MISMATCH') {
  assert.equal(checked.evaluation.valid, false);
  assert.equal(leg(checked).native_verification, 'FAILED');
  // The published evaluator compares the null mapping with the expected
  // action and reports MISMATCH; no mapped action is invented by that label.
  assert.equal(leg(checked).mapping, evaluatorMapping);
  assert.equal(leg(checked).caid, null);
  assert.equal(leg(checked).action_digest, null);
  assert.equal(checked.policy_input, 'INDETERMINATE');
}

test('all nine source-pinned composition cases pass', () => {
  const report = suite();
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
  for (const [key, value] of Object.entries({ pdp_decision: 'ALLOW', material_action: 'MATCH',
    native_verification: 'VERIFIED', rp_acceptance: 'ACCEPTED', evidence_satisfaction: 'SATISFIED',
    local_authorization: 'AUTHORIZED', reservation: 'RESERVED', aeb_decision: 'ADMIT',
    provider_outcome: 'NOT_INVOKED', execution_proven_by_authzen: false })) assert.equal(exact[key], value, key);
  const checked = exactCase.details.local_pep_preflight;
  assert.equal(checked['@version'], PREFLIGHT_VERSION);
  assert.equal(checked.evaluation.record['@type'], AEB_EVALUATION_VERSION);
  assert.equal(leg(checked).native_verification, 'VERIFIED');
  assert.equal(leg(checked).acceptance, 'ACCEPTED');
  assert.equal(leg(checked).mapping, 'MATCH');
  assert.equal(checked.evaluation.record.verdict, 'SATISFIED');
  assert.equal(checked.policy_input, 'ALLOW');
  assert.equal(checked.local_authorization, 'NOT_EVALUATED');
  assert.equal(checked.local_authorization_established, false);
  assert.equal(leg(checked).adapter_id, AUTHZEN_PEP_ADAPTER_ID);
  assert.equal(leg(checked).profile_id, AUTHZEN_PEP_PROFILE_ID);
  assert.equal(exactCase.details.local_pep_attestation.authzen_signature_claimed, false);
  assert.equal(exactCase.details.policy_input_matches_verified_observation, true);
});
test('beneficiary substitution stays allowed at toy PDP but refuses before entry', () => {
  const changed = result('allow_changed_beneficiary_refused');
  for (const [key, value] of Object.entries({ pdp_decision: 'ALLOW', material_action: 'MISMATCH',
    action_match: 'MISMATCH', evidence_satisfaction: 'UNSATISFIED', reservation: 'NOT_ATTEMPTED',
    aeb_decision: 'REFUSE', provider_entry: 'REFUSED_BEFORE_ENTRY' })) assert.equal(changed.observed[key], value, key);
  assert.equal(changed.details.material_reason, 'caid_mismatch:beneficiary_account');
  const checked = changed.details.local_pep_preflight;
  assert.equal(leg(checked).native_verification, 'VERIFIED');
  assert.equal(leg(checked).acceptance, 'ACCEPTED');
  assert.equal(leg(checked).mapping, 'MISMATCH');
  assert.equal(checked.evaluation.record.verdict, 'UNSATISFIED');
});
test('AuthZEN deny and named-human authorization remain separate', () => {
  const denied = result('deny_does_not_admit');
  assert.equal(denied.observed.pdp_decision, 'DENY');
  assert.equal(denied.observed.evidence_satisfaction, 'SATISFIED');
  assert.equal(denied.observed.local_authorization, 'NOT_AUTHORIZED');
  assert.deepEqual(denied.observed.reasons, ['local_policy_denied']);
  assert.equal(denied.details.local_pep_preflight.policy_input, 'DENY');
  assert.equal(denied.details.local_pep_preflight.local_authorization, 'NOT_EVALUATED');
  const noHuman = result('allow_does_not_fill_named_human_role');
  assert.equal(noHuman.observed.pdp_decision, 'ALLOW');
  assert.equal(noHuman.observed.authzen_role, 'MACHINE_POLICY_INPUT');
  assert.equal(noHuman.observed.named_human_authorization_proven, false);
  assert.equal(noHuman.observed.evidence_satisfaction, 'UNSATISFIED');
  assert.deepEqual(noHuman.observed.reasons, ['required_role_unsatisfied']);
  const checked = noHuman.details.local_pep_preflight;
  assert.equal(leg(checked).native_verification, 'VERIFIED');
  assert.equal(leg(checked).mapping, 'MATCH');
  assert.equal(checked.evaluation.record.verdict, 'UNSATISFIED');
  assert.equal(checked.policy_input, 'ALLOW');
  assert.equal(checked.local_authorization, 'NOT_EVALUATED');
});

test('preflight preserves unsigned refusal even when evidence is satisfied', () => {
  const checked = preflight();
  assert.equal(checked.evaluation.record.verdict, 'SATISFIED');
  assert.equal(checked.evaluation.valid, false);
  assert.equal(checked.evaluation.record.signature, undefined);
  assert.deepEqual(checked.evaluation.reasons, ['evaluation_signature_required']);
  assert.deepEqual(checked.evaluation.record.reasons, ['evaluation_signature_required']);
  assert.equal(checked.portable_credential, false);
  assert.equal(checked.local_authorization_established, false);
});
test('preflight missing adapter and profile pins refuse before mapping', () => {
  for (const pinKind of ['adapters', 'profiles']) {
    const fixture = buildAuthzenPreflightFixture();
    delete fixture.input.config[pinKind][pinKind === 'adapters' ? AUTHZEN_PEP_ADAPTER_ID : AUTHZEN_PEP_PROFILE_ID];
    const checked = preflight(fixture);
    refusedMapping(checked, 'INDETERMINATE');
    assert.equal(checked.evaluation.record.verdict, 'UNSATISFIED');
    assert.equal(leg(checked).acceptance, 'INDETERMINATE');
    assert.ok(leg(checked).reasons.includes('adapter_or_profile_not_pinned'));
  }
});
test('preflight adapter version and mapping digest substitutions fail closed', () => {
  const adapter = buildAuthzenPreflightFixture();
  const pin = adapter.input.config.adapters[AUTHZEN_PEP_ADAPTER_ID];
  pin.version = 'substituted-v9';
  pin.config_digest = adapterPinDigest(AUTHZEN_PEP_ADAPTER_ID, pin);
  const checkedAdapter = preflight(adapter);
  refusedMapping(checkedAdapter, 'INDETERMINATE');
  assert.ok(leg(checkedAdapter).reasons.includes('adapter_version_not_registered'));
  const profile = buildAuthzenPreflightFixture();
  profile.input.config.profiles[AUTHZEN_PEP_PROFILE_ID].definition.target_action_type = 'substituted';
  const checkedProfile = preflight(profile);
  refusedMapping(checkedProfile, 'INDETERMINATE');
  assert.ok(leg(checkedProfile).reasons.includes('mapping_profile_digest_mismatch'));
});
test('preflight does not promote per-leg diagnostics under a corrupted RP pin', () => {
  const fixture = buildAuthzenPreflightFixture();
  fixture.input.config.adapters[AUTHZEN_PEP_ADAPTER_ID].config_digest = `sha256:${'f'.repeat(64)}`;
  const checked = preflight(fixture);
  assert.equal(checked.evaluation.valid, false);
  assert.equal(checked.evaluation.record.verdict, 'INDETERMINATE');
  assert.equal(checked.policy_input, 'INDETERMINATE');
  assert.ok(checked.evaluation.reasons.includes(`invalid_adapter_pin:${AUTHZEN_PEP_ADAPTER_ID}`));
  assert.ok(checked.evaluation.reasons.includes('cannot_evaluate_unpinned_requirement'));
});
test('preflight verifies and projects the same immutable observation snapshot', () => {
  const denied = buildAuthzenPreflightFixture({ token_subject: 'mallory@example.com' });
  const allowed = buildAuthzenPreflightFixture();
  let reads = 0;
  Object.defineProperty(denied.input.legs[0], 'artifact', {
    enumerable: true,
    get() { return ++reads === 1 ? denied.envelope : allowed.envelope; },
  });
  const checked = preflight(denied);
  assert.equal(reads, 1);
  assert.equal(leg(checked).native_verification, 'VERIFIED');
  assert.equal(leg(checked).evidence_digest, digestAeb(denied.envelope));
  assert.notEqual(leg(checked).evidence_digest, digestAeb(allowed.envelope));
  assert.equal(checked.policy_input, 'DENY');
  assert.equal(checked.local_authorization, 'NOT_EVALUATED');
});
test('preflight rejects non-plain outer input rather than bypassing its snapshot', () => {
  const denied = buildAuthzenPreflightFixture({ token_subject: 'mallory@example.com' });
  const allowed = buildAuthzenPreflightFixture();
  const input = Object.assign(new class Input {}, denied.input);
  let reads = 0;
  Object.defineProperty(input.legs[0], 'artifact', {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? denied.envelope : new Proxy(denied.envelope, {
        get(target, key) { return allowed.envelope[key] ?? Reflect.get(target, key); },
      });
    },
  });
  const checked = evaluateAuthzenPreflight(input);
  assert.equal(reads, 0);
  assert.equal(checked.evaluation.valid, false);
  assert.equal(checked.policy_input, 'INDETERMINATE');
  assert.deepEqual(checked.evaluation.record.legs, []);
});
test('preflight refuses unpinned signing keys and stale observations', () => {
  const unpinned = buildAuthzenPreflightFixture();
  const pin = unpinned.input.config.adapters[AUTHZEN_PEP_ADAPTER_ID];
  pin.trust_roots = [];
  pin.config_digest = adapterPinDigest(AUTHZEN_PEP_ADAPTER_ID, pin);
  const checkedKey = preflight(unpinned);
  refusedMapping(checkedKey);
  assert.ok(checkedKey.evaluation.reasons.includes('native_attestation_signature_invalid'));
  const stale = buildAuthzenPreflightFixture();
  stale.input.evaluated_at = '2026-08-31T19:20:00Z';
  const checkedTime = preflight(stale);
  refusedMapping(checkedTime);
  assert.equal(leg(checkedTime).freshness.fresh, false);
  assert.ok(checkedTime.evaluation.reasons.includes('native_attestation_outside_validity'));
});
test('preflight malformed evaluator input returns no policy claim or action', () => {
  for (const input of [null, {}, { legs: [] }]) {
    const checked = evaluateAuthzenPreflight(input);
    assert.equal(checked.evaluation.valid, false);
    assert.equal(checked.policy_input, 'INDETERMINATE');
    assert.deepEqual(checked.evaluation.record.legs, []);
    assert.equal(checked.local_authorization_established, false);
  }
});
test('preflight local PEP signature binds observation, without becoming an AuthZEN signature', () => {
  const fixture = buildAuthzenPreflightFixture();
  assert.equal(fixture.attestation.protocol_id, 'authzen-local-pep-observation');
  assert.equal(fixture.attestation.signature.key_id, 'test-verifier:authzen-local-pep:v0.1');
  assert.equal(fixture.attestation.native_artifact_digest, digestAeb(fixture.observation));
  assert.equal(fixture.observation.boolean_decision, true);
  assert.match(fixture.observation.authzen_request_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(fixture.observation.full_typed_action_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(leg(preflight(fixture)).evidence_digest, digestAeb(fixture.envelope));
  const tampered = buildAuthzenPreflightFixture();
  const artifact = tampered.input.legs[0].artifact;
  const last = artifact.attestation.mapping.caid.at(-1);
  artifact.attestation.mapping.caid = `${artifact.attestation.mapping.caid.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`;
  const checked = preflight(tampered);
  refusedMapping(checked);
  assert.equal(leg(checked).acceptance, 'REJECTED');
  assert.equal(checked.evaluation.record.verdict, 'UNSATISFIED');
  assert.ok(checked.evaluation.reasons.includes('native_attestation_signature_invalid'));
});
test('preflight observation mutation with unchanged attestation fails before mapping', () => {
  const fixture = buildAuthzenPreflightFixture();
  fixture.input.legs[0].artifact.observation.boolean_decision = false;
  const checked = preflight(fixture);
  refusedMapping(checked);
  assert.equal(leg(checked).acceptance, 'REJECTED');
  assert.equal(leg(checked).evidence_digest, digestAeb(fixture.input.legs[0].artifact));
  assert.ok(checked.evaluation.reasons.includes('pep_observation_digest_mismatch'));
});
test('preflight guarded adapter cannot map before native verification', () => {
  const fixture = buildAuthzenPreflightFixture();
  const adapter = createAuthzenPepObservationEnvelopeAdapter({ id: AUTHZEN_PEP_ADAPTER_ID, version: '1' });
  const input = {
    ...fixture.input.legs[0],
    profile: fixture.input.config.profiles[AUTHZEN_PEP_PROFILE_ID],
    native: { native_verification: 'FAILED' },
  };
  assert.deepEqual(adapter.mapAction(input), {
    mapping: 'INDETERMINATE', caid: null, action_digest: null,
    reasons: ['native_verification_required'],
  });
  input.native.native_verification = 'VERIFIED';
  input.artifact.observation.boolean_decision = false;
  const changed = adapter.mapAction(input);
  assert.equal(changed.mapping, 'INDETERMINATE');
  assert.equal(changed.caid, null);
  assert.equal(changed.action_digest, null);
  assert.ok(changed.reasons.includes('pep_observation_digest_mismatch'));
});
test('preflight malformed envelopes and extra fields cannot produce mapping or policy input', () => {
  for (const mutate of [
    (f) => { f.input.legs[0].artifact = null; },
    (f) => { f.input.legs[0].artifact.attestation = []; },
    (f) => { f.input.legs[0].artifact.extra = true; },
    (f) => { f.input.legs[0].artifact.observation.extra = true; },
    (f) => { f.input.legs[0].artifact.observation.boolean_decision = 'true'; },
    (f) => { f.input.legs[0].artifact.observation.authzen_request_digest = 'not-a-digest'; },
  ]) {
    const fixture = buildAuthzenPreflightFixture();
    mutate(fixture);
    refusedMapping(preflight(fixture));
  }
});
test('preflight attestation and observation substitution fails before mapping', () => {
  const benign = buildAuthzenPreflightFixture();
  benign.input.legs[0].artifact.attestation = buildAuthzenPreflightFixture({ call_fixture: 'substituted_call' }).attestation;
  const checked = preflight(benign);
  refusedMapping(checked);
  assert.equal(leg(checked).acceptance, 'REJECTED');
  assert.ok(checked.evaluation.reasons.includes('pep_observation_digest_mismatch'));
  assert.ok(checked.evaluation.reasons.includes('pep_observation_reference_mismatch'));
});
test('preflight validly signed reference, action, and mapping disagreements fail closed', () => {
  for (const [options, reason] of [
    [{ attestation_native_artifact_ref: 'urn:emilia:authzen-local-pep:substituted' }, 'pep_observation_reference_mismatch'],
    [{ attestation_mapping_overrides: { caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}` } }, 'pep_observation_action_mismatch'],
    [{ attestation_mapping_overrides: { normalized_action_digest: `sha256:${'a'.repeat(64)}` } }, 'pep_observation_action_mismatch'],
    [{ attestation_mapping_overrides: { mapper_id: 'mapper:substituted' } }, 'pep_observation_mapping_mismatch'],
    [{ attestation_mapping_overrides: { profile_digest: `sha256:${'a'.repeat(64)}` } }, 'pep_observation_mapping_mismatch'],
    [{ attestation_mapping_overrides: { resolver_digest: `sha256:${'a'.repeat(64)}` } }, 'pep_observation_mapping_mismatch'],
  ]) {
    const checked = preflight(buildAuthzenPreflightFixture(options));
    refusedMapping(checked);
    assert.ok(checked.evaluation.reasons.includes(reason));
  }
});
test('preflight native replay unit and RP replay key are stable across wrapper references', () => {
  const first = preflight(buildAuthzenPreflightFixture({ artifact_ref: 'urn:emilia:wrapper:first' }));
  const second = preflight(buildAuthzenPreflightFixture({ artifact_ref: 'urn:emilia:wrapper:second' }));
  assert.equal(leg(first).replay_unit, leg(second).replay_unit);
  assert.deepEqual(first.native_replay_keys, second.native_replay_keys);
  assert.match(first.native_replay_keys[0], /^aeb-native:sha256:[0-9a-f]{64}$/);
  assert.notEqual(leg(first).artifact_ref, leg(second).artifact_ref);
});

test('local preflight leaves lifecycle unestablished; consequence kernel alone advances it', () => {
  const exact = result('allow_exact_call_admitted');
  assert.deepEqual(exact.details.local_pep_preflight.lifecycle, {
    reservation: 'NOT_EVALUATED', consumption: 'NOT_EVALUATED', provider_entry: 'NOT_ESTABLISHED',
    provider_outcome: 'NOT_ESTABLISHED', observed_effect: 'NOT_ESTABLISHED', retry: 'NOT_EVALUATED',
    reconciliation: 'NOT_EVALUATED',
  });
  assert.equal(exact.observed.reservation, 'RESERVED');
  assert.equal(exact.observed.provider_outcome, 'NOT_INVOKED');
  const timeout = result('timeout_after_dispatch_indeterminate');
  assert.equal(timeout.details.local_pep_preflight.lifecycle.provider_outcome, 'NOT_ESTABLISHED');
  assert.equal(timeout.observed.provider_outcome, 'INDETERMINATE');
  assert.equal(timeout.observed.reconciliation, 'REQUIRED');
});
test('timeout is indeterminate and blind retry is refused', () => {
  const timeout = result('timeout_after_dispatch_indeterminate').observed;
  for (const [key, value] of Object.entries({ custody: 'INVOKING', provider_outcome: 'INDETERMINATE',
    effect_relation: 'INDETERMINATE', retry: 'REFUSED', reconciliation: 'REQUIRED',
    aeb_decision: 'INDETERMINATE' })) assert.equal(timeout[key], value, key);
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
test('deterministic report matches reference and preserves nonclaims', () => {
  const report = suite();
  const reference = JSON.parse(readFileSync(new URL('./report.reference.json', import.meta.url), 'utf8'));
  assert.deepEqual(report, reference);
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(report.claim_scope.exclusions.includes('authorization_api_replay_semantics'));
  assert.ok(report.claim_scope.exclusions.includes('openid_working_group_acceptance'));
  assert.ok(report.claim_scope.exclusions.includes('production_mediation'));
});
