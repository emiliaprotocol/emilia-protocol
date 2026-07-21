// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { evaluateGateControlPlane } from '../../packages/gate/control-plane.js';
import { DEPLOYMENT_PROFILE_VERSION, deploymentProfileDigest } from '../../packages/gate/deployment-attestation.js';
import { COVERAGE_INVENTORY_VERSION, signEnforcementProbe } from '../../packages/gate/coverage.js';
import { SETTLEMENT_PROFILE_VERSION } from '../../packages/gate/settlement.js';
import {
  createMemoryWitnessSequenceStore,
  signNetworkWitnessStatement,
} from '../../packages/gate/network-witness.js';

const now = Date.parse('2026-07-16T20:00:00.000Z');
const actionDigest = `sha256:${'11'.repeat(32)}`;
const configDigest = `sha256:${'22'.repeat(32)}`;
const authDigest = `sha256:${'33'.repeat(32)}`;
const executionDigest = `sha256:${'44'.repeat(32)}`;
const outcomeDigest = `sha256:${'55'.repeat(32)}`;
const probeKeys = crypto.generateKeyPairSync('ed25519');
const witnessKeys = crypto.generateKeyPairSync('ed25519');

const deploymentProfile = {
  '@version': DEPLOYMENT_PROFILE_VERSION,
  profile_id: 'profile:grid-gate-prod',
  verifier_id: 'verifier:demo-rats',
  evidence_type: 'application/eat+cwt',
  gate_id: 'gate:grid-west',
  environment_id: 'env:prod-west',
  audience: 'rp:grid-operator',
  nonce: 'attestation-grid-west-1',
  max_age_sec: 300,
  max_future_skew_sec: 30,
  required_measurements: {
    image: `sha256:${'66'.repeat(32)}`,
    config: configDigest,
    policy: `sha256:${'77'.repeat(32)}`,
  },
};

const surface = {
  surface_id: 'surface:grid-curtailment-west',
  action_family: 'grid.curtailment',
  gate_id: deploymentProfile.gate_id,
  environment_id: deploymentProfile.environment_id,
  deployment_profile_hash: deploymentProfileDigest(deploymentProfile),
  probe_action_digest: actionDigest,
  required: true,
  witness: { witness_id: 'witness:grid-edge', capture_point_id: 'capture:grid-west-a', event: 'effect_observed', required: true },
};

const probe = signEnforcementProbe({
  probe_id: 'probe:independent-grid',
  surface_id: surface.surface_id,
  gate_id: surface.gate_id,
  environment_id: surface.environment_id,
  action_family: surface.action_family,
  action_digest: actionDigest,
  tested_at: '2026-07-16T19:59:30.000Z',
  nonce: 'canary-grid-west-1',
  result: 'blocked_without_receipt',
  response_status: 428,
}, probeKeys.privateKey);

const witness = signNetworkWitnessStatement({
  witness_id: surface.witness.witness_id,
  capture_point_id: surface.witness.capture_point_id,
  sequence: 42,
  observed_at: '2026-07-16T19:59:45.000Z',
  event: 'effect_observed',
  direction: 'egress',
  action_digest: actionDigest,
  flow_digest: `sha256:${'88'.repeat(32)}`,
  byte_count: 487,
  config_digest: configDigest,
}, witnessKeys.privateKey);

const common = {
  witnesses: [witness],
};

const coverageInventory = {
  '@version': COVERAGE_INVENTORY_VERSION,
  inventory_id: 'inventory:grid-west-v1',
  surfaces: [surface],
};

const settlementProfile = {
  '@version': SETTLEMENT_PROFILE_VERSION,
  profile_id: 'profile:grid-settlement-v1',
  require_witness: true,
  require_outcome: true,
  require_coverage: true,
  required_witness_event: 'effect_observed',
  required_witness_id: surface.witness.witness_id,
  required_capture_point_id: surface.witness.capture_point_id,
  required_coverage_state: 'gated',
  required_surface_id: surface.surface_id,
};

const settlement = {
  bundle: {
    action_digest: actionDigest,
    authorization: { artifact: 'demo-authorization' },
    execution: { artifact: 'demo-execution' },
    witness,
    outcome: { artifact: 'demo-meter-outcome' },
    coverage: { surface_id: surface.surface_id },
  },
};

const options = {
  now,
  coverageInventory,
  settlementProfile,
  attestationVerifiers: {
    'verifier:demo-rats': async () => ({
      verified: true,
      verifier_id: deploymentProfile.verifier_id,
      evidence_type: deploymentProfile.evidence_type,
      gate_id: deploymentProfile.gate_id,
      environment_id: deploymentProfile.environment_id,
      audience: deploymentProfile.audience,
      nonce: deploymentProfile.nonce,
      issued_at: '2026-07-16T19:59:20.000Z',
      expires_at: '2026-07-16T20:04:20.000Z',
      measurements: { ...deploymentProfile.required_measurements },
    }),
  },
  pinnedProbes: [{
    probe_id: probe.probe.id,
    key_id: probe.probe.key_id,
    surface_ids: [surface.surface_id],
    public_key: probeKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  }],
  expectedProbeNonces: { [surface.surface_id]: 'canary-grid-west-1' },
  pinnedWitnesses: [{
    witness_id: witness.witness.id,
    key_id: witness.witness.key_id,
    public_key: witnessKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    capture_point_ids: [witness.witness.capture_point_id],
    config_digests: [configDigest],
  }],
  verifyAuthorization: async () => ({ accepted: true, action_digest: actionDigest, decision_digest: authDigest }),
  verifyExecution: async () => ({
    accepted: true,
    action_digest: actionDigest,
    authorization_digest: authDigest,
    execution_digest: executionDigest,
    outcome: 'executed',
  }),
  verifyOutcome: async () => ({
    accepted: true,
    action_digest: actionDigest,
    execution_digest: executionDigest,
    outcome_digest: outcomeDigest,
    within_tolerance: true,
  }),
};

const usage = {
  org: 'ep:org:grid-operator',
  period: { periodStart: '2026-07-01T00:00:00.000Z', periodEnd: '2026-08-01T00:00:00.000Z' },
  entries: [{
    kind: 'decision', at: '2026-07-16T19:59:00.000Z', action: 'grid.curtailment',
    allow: true, status: 200, reason: 'allow', required_tier: 'quorum', hash: 'demo-evidence-hash',
  }],
};

async function run(label, coverage, usageInput = usage) {
  const report = await evaluateGateControlPlane(
    { coverage, settlements: [settlement], usage: usageInput },
    {
      ...options,
      witnessSequenceStore: createMemoryWitnessSequenceStore(),
      allowEphemeralWitnessStore: true,
    },
  );
  const row = report.artifacts.coverage.surfaces[0];
  const result = report.artifacts.settlements[0];
  console.log(`\n${label}`);
  console.log(`  enforcement: ${row.state} (${row.reason})`);
  console.log(`  witness:     ${row.witness_verified ? 'verified' : 'absent'}`);
  console.log(`  settlement:  ${result.verdict}`);
  console.log(`  metering:    ${report.artifacts.usage?.protected_actions ?? 0} protected action`);
  return report;
}

const complete = await run('COMPLETE THREE-PLANE VIEW', {
  ...common,
  deployments: [{ profile: deploymentProfile, evidence: { format: 'demo-eat', token: 'opaque' } }],
  probes: [probe],
});
const witnessOnly = await run('GATE REMOVED; WITNESS STILL HEALTHY', common, { ...usage, entries: [] });

if (complete.artifacts.settlements[0].eligible !== true
    || witnessOnly.artifacts.coverage.surfaces[0].state !== 'witness_only'
    || witnessOnly.artifacts.settlements[0].verdict !== 'refuse_coverage') {
  process.exitCode = 1;
}
