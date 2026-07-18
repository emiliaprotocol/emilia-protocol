// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION } from '../../packages/gate/action-escrow-evidence.js';
import { DOCUMENT_ACTION_BINDING_VERSION } from '../../packages/verify/document-action-binding.js';
import { runActionEscrowScenario } from './scenario.mjs';

const scenarioPromise = runActionEscrowScenario();

test('keeps document, exact-action approvals, and external custody visibly separate', async () => {
  const scenario = await scenarioPromise;
  assert.deepEqual(scenario.view.integration_rows.map((row) => row.id), [
    'document',
    'execution',
    'agreement',
    'approvals',
    'custodian',
  ]);
  assert.equal(scenario.view.integration_rows.every((row) => row.pass), true);
  assert.equal(scenario.view.document.verification.dab.valid, true);
  assert.equal(scenario.view.document.verification.authorizes_payment, false);
  assert.equal(
    scenario.view.document.verification.document_as_payment_refusal,
    'resolution_profile_invalid',
  );
});

test('uses the shipped DAB, Action Escrow kernel, and portable evidence package', async () => {
  const scenario = await scenarioPromise;
  assert.equal(scenario.bundle.binding.profile, DOCUMENT_ACTION_BINDING_VERSION);
  assert.equal(scenario.bundle.version, ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION);
  assert.equal(scenario.bundleVerification.valid, true);
  assert.equal(scenario.bundleVerification.reason, 'verified');
  assert.equal(Object.values(scenario.bundleVerification.checks).every(Boolean), true);
  assert.equal(Object.hasOwn(scenario.bundle.document, 'content_base64'), false);
  assert.equal(scenario.bundle.agreement_acceptances.length, 2);
  assert.equal(scenario.bundle.release_approvals.length, 2);
});

test('releases exactly once and refuses every required mutation', async () => {
  const scenario = await scenarioPromise;
  assert.equal(scenario.view.release.gate.allowed, true);
  assert.equal(scenario.view.release.gate.reason, 'release_committed');
  assert.equal(scenario.view.release.gate.release_calls, 1);
  assert.equal(scenario.view.release.gate.replay_refused, true);
  assert.deepEqual(scenario.view.attacks.map((attack) => attack.id), [
    'pdf-bytes',
    'material-terms',
    'destination',
    'amount',
    'signer',
    'milestone-evidence',
    'amendment-version',
    'replay',
  ]);
  assert.equal(scenario.view.attacks.every((attack) => (
    attack.refused && attack.reason === attack.expected_reason
  )), true);
});

test('preserves approve, decline, reject, and amend as distinct signed outcomes', async () => {
  const scenario = await scenarioPromise;
  assert.deepEqual(scenario.view.outcomes.map((outcome) => outcome.outcome), [
    'approve',
    'decline',
    'reject',
    'amend',
  ]);
  assert.equal(scenario.view.outcomes.every((outcome) => outcome.signature_verified), true);
  assert.equal(
    scenario.view.outcomes.filter((outcome) => outcome.release_authorized).length,
    1,
  );
  assert.equal(
    scenario.view.outcomes.find((outcome) => outcome.outcome === 'approve')
      ?.release_authorized,
    true,
  );
});

test('labels external custody as simulated and never assigns custody to EMILIA', async () => {
  const scenario = await scenarioPromise;
  assert.equal(
    scenario.view.custodian.provider.provider_mode,
    'SIMULATED_LOCAL_PROVIDER',
  );
  assert.equal(scenario.view.custodian.provider.emilia_holds_funds, false);
  assert.equal(
    scenario.view.custodian.provider.license_reference,
    'SIMULATED-NOT-A-LICENSE',
  );
});
