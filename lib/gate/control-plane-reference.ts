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
import { hashCanonical } from '../../packages/gate/execution-binding.js';

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function iso(ms) {
  return new Date(ms).toISOString();
}

function monthWindow(now) {
  const date = new Date(now);
  const start = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1);
  const end = Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1);
  return { periodStart: iso(start), periodEnd: iso(end) };
}

export async function runGateControlPlaneReference({ mode = 'complete', now = Date.now() } = {}) {
  if (!['complete', 'witness_only'].includes(mode)) throw new TypeError('unknown_control_plane_mode');
  const probeKeys = crypto.generateKeyPairSync('ed25519');
  const witnessKeys = crypto.generateKeyPairSync('ed25519');
  const action = {
    action_type: 'grid.curtailment',
    site_id: 'dc-west-04',
    target_kw: 12_500,
    duration_seconds: 900,
    action_nonce: crypto.randomUUID(),
  };
  const actionDigest = `sha256:${hashCanonical(action)}`;
  const configDigest = sha256('witness-config:grid-west:v1');
  const authDigest = sha256(`authorization:${actionDigest}`);
  const executionDigest = sha256(`execution:${authDigest}`);
  const outcomeDigest = sha256(`meter-outcome:${actionDigest}`);

  const deploymentProfile = {
    '@version': DEPLOYMENT_PROFILE_VERSION,
    profile_id: 'profile:grid-gate-prod',
    verifier_id: 'verifier:reference-rats',
    evidence_type: 'application/eat+cwt',
    gate_id: 'gate:grid-west',
    environment_id: 'env:prod-west',
    audience: 'rp:grid-operator',
    nonce: `attestation:${action.action_nonce}`,
    max_age_sec: 300,
    max_future_skew_sec: 30,
    required_measurements: {
      workload: sha256('emilia-gate-service:reference'),
      image: sha256('container:emilia-gate:reference'),
      config: sha256('gate-config:grid-west:v1'),
      policy: sha256('grid-curtailment-policy:v1'),
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
    tested_at: iso(now - 20_000),
    nonce: `canary:${action.action_nonce}`,
    result: 'blocked_without_receipt',
    response_status: 428,
  }, probeKeys.privateKey);
  const witness = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: Math.max(1, Math.floor(now / 1000)),
    observed_at: iso(now - 10_000),
    event: 'effect_observed',
    direction: 'egress',
    action_digest: actionDigest,
    flow_digest: sha256(`flow:${actionDigest}`),
    byte_count: 487,
    config_digest: configDigest,
  }, witnessKeys.privateKey);
  const complete = mode === 'complete';
  const coverageInventory = {
    '@version': COVERAGE_INVENTORY_VERSION,
    inventory_id: 'inventory:grid-west-v1',
    surfaces: [surface],
  };
  const coverage = {
    deployments: complete ? [{ profile: deploymentProfile, evidence: { format: 'reference-eat', token: 'opaque' } }] : [],
    probes: complete ? [probe] : [],
    witnesses: [witness],
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
  const bundle = {
    action_digest: actionDigest,
    authorization: { kind: 'reference_authorization' },
    execution: { kind: 'reference_execution' },
    witness,
    outcome: { kind: 'reference_meter_outcome' },
    coverage: { surface_id: surface.surface_id },
  };
  const report = await evaluateGateControlPlane({
    coverage,
    settlements: [{ bundle }],
    usage: {
      org: 'ep:org:grid-operator',
      period: monthWindow(now),
      entries: complete ? [{
        kind: 'decision', at: iso(now - 30_000), action: action.action_type,
        allow: true, status: 200, reason: 'allow', required_tier: 'quorum',
        hash: sha256(`decision:${authDigest}`),
      }] : [],
    },
  }, {
    now,
    coverageInventory,
    settlementProfile,
    attestationVerifiers: {
      'verifier:reference-rats': async () => ({
        verified: true,
        verifier_id: deploymentProfile.verifier_id,
        evidence_type: deploymentProfile.evidence_type,
        gate_id: deploymentProfile.gate_id,
        environment_id: deploymentProfile.environment_id,
        audience: deploymentProfile.audience,
        nonce: deploymentProfile.nonce,
        issued_at: iso(now - 25_000),
        expires_at: iso(now + 275_000),
        measurements: { ...deploymentProfile.required_measurements },
      }),
    },
    pinnedProbes: [{
      probe_id: probe.probe.id,
      key_id: probe.probe.key_id,
      surface_ids: [surface.surface_id],
      public_key: probeKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    expectedProbeNonces: { [surface.surface_id]: `canary:${action.action_nonce}` },
    pinnedWitnesses: [{
      witness_id: witness.witness.id,
      key_id: witness.witness.key_id,
      public_key: witnessKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      capture_point_ids: [witness.witness.capture_point_id],
      config_digests: [configDigest],
    }],
    // This endpoint is an explicitly labeled reference scenario. Deployments
    // must replace this store with the durable Postgres witness adapter.
    witnessSequenceStore: createMemoryWitnessSequenceStore(),
    allowEphemeralWitnessStore: true,
    verifyAuthorization: async () => ({ accepted: true, action_digest: actionDigest, decision_digest: authDigest }),
    verifyExecution: async () => ({
      accepted: true, action_digest: actionDigest, authorization_digest: authDigest,
      execution_digest: executionDigest, outcome: 'executed',
    }),
    verifyOutcome: async () => ({
      accepted: true, action_digest: actionDigest, execution_digest: executionDigest,
      outcome_digest: outcomeDigest, within_tolerance: true,
    }),
  });
  const row = report.artifacts.coverage.surfaces[0];
  const settlement = report.artifacts.settlements[0];
  return {
    ok: true,
    reference_only: true,
    physical_claim: false,
    mode,
    generated_at: report.generated_at,
    action,
    action_digest: actionDigest,
    planes: {
      enforcement: {
        state: row.state,
        reason: row.reason,
        deployment_attested: row.deployment_attested,
        refusal_probe_verified: row.refusal_probe_verified,
        bypass_probe_verified: row.bypass_probe_verified,
      },
      witness: {
        verified: row.witness_verified,
        witness_id: witness.witness.id,
        capture_point_id: witness.witness.capture_point_id,
        sequence: witness.observation.sequence,
        payload_captured: witness.privacy.payload_captured,
        statement_digest: (report.artifacts.settlements[0] as { evidence?: { witness_digest?: string } }).evidence?.witness_digest ?? null,
      },
      control: {
        coverage_complete: report.coverage_complete,
        coverage_bps: report.artifacts.coverage.declared_coverage_bps,
        settlement_verdict: settlement.verdict,
        settlement_eligible: settlement.eligible,
        usage_complete: report.usage_complete,
        protected_actions: report.artifacts.usage?.protected_actions ?? 0,
      },
    },
    hashes: {
      deployment_profile: deploymentProfileDigest(deploymentProfile),
      coverage_report: report.artifacts.coverage.report_hash,
      settlement_result: settlement.result_hash,
      usage_statement: report.usage_statement_hash,
      control_plane: report.control_plane_digest,
    },
    limitations: [
      ...report.limitations,
      'This reference scenario uses an in-memory witness sequence store and makes no production durability claim.',
    ],
  };
}

const gateControlPlaneReference = { runGateControlPlaneReference };

export default gateControlPlaneReference;
