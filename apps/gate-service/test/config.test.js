// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateGateServiceConfig } from '../src/config.js';
import { OBSERVED_ACTION, createDurableTestState } from './helpers.js';
import { createEg1Harness } from '../../../packages/gate/index.js';

function validConfig() {
  const state = createDurableTestState();
  const harness = createEg1Harness({ action: OBSERVED_ACTION });
  return {
    connector: {
      async getRepository() {},
      async deleteRepository() {},
    },
    consumptionStore: state.consumptionStore,
    evidenceLog: state.evidenceLog,
    actionStore: state.actionStore,
    authenticateRequest: async () => true,
    readiness: async () => ({ ok: true }),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
  };
}

test('configuration requires operator-supplied durable state and pinned trust', () => {
  assert.doesNotThrow(() => validateGateServiceConfig(validConfig()));

  const ephemeral = validConfig();
  ephemeral.consumptionStore = { ...ephemeral.consumptionStore, durable: false };
  assert.throws(
    () => validateGateServiceConfig(ephemeral),
    (error) => error.code === 'EMILIA_GATE_CONFIG_INVALID'
      && error.reasons.includes('durable_consumption_store_required'),
  );

  const weakEvidence = validConfig();
  weakEvidence.evidenceLog = { ...weakEvidence.evidenceLog, atomicAppend: false };
  assert.throws(
    () => validateGateServiceConfig(weakEvidence),
    (error) => error.reasons.includes('durable_atomic_evidence_log_required'),
  );

  const unauthenticated = validConfig();
  delete unauthenticated.authenticateRequest;
  assert.throws(
    () => validateGateServiceConfig(unauthenticated),
    (error) => error.reasons.includes('request_authenticator_required'),
  );

  const unreadable = validConfig();
  delete unreadable.readiness;
  assert.throws(
    () => validateGateServiceConfig(unreadable),
    (error) => error.reasons.includes('readiness_check_required'),
  );
});

test('configuration rejects inline receipt keys and unknown secret-bearing shortcuts', () => {
  assert.throws(
    () => validateGateServiceConfig({ ...validConfig(), allowInlineKey: true }),
    (error) => error.reasons.includes('inline_receipt_keys_forbidden'),
  );
  assert.throws(
    () => validateGateServiceConfig({ ...validConfig(), githubToken: 'do-not-accept-here' }),
    (error) => error.reasons.includes('unknown_config_key:githubToken'),
  );
});
