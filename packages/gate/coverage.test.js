// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  COVERAGE_INVENTORY_VERSION,
  coverageInventoryDigest,
  evaluateGateCoverage,
  parseEnforcementProbeStatement,
  signEnforcementProbe,
  verifyEnforcementProbe,
} from './coverage.js';
import { DEPLOYMENT_PROFILE_VERSION, deploymentProfileDigest } from './deployment-attestation.js';
import {
  acceptNetworkWitnessStatement,
  createMemoryWitnessSequenceStore,
  signNetworkWitnessStatement,
} from './network-witness.js';

const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const ACTION = `sha256:${'11'.repeat(32)}`;
const CONFIG = `sha256:${'22'.repeat(32)}`;

const deploymentProfile = {
  '@version': DEPLOYMENT_PROFILE_VERSION,
  profile_id: 'profile:grid-gate',
  verifier_id: 'verifier:rat-eat',
  evidence_type: 'application/eat+cwt',
  gate_id: 'gate:grid-west',
  environment_id: 'env:prod-west',
  audience: 'rp:grid-operator',
  nonce: 'attestation:grid-west:1',
  max_age_sec: 300,
  max_future_skew_sec: 30,
  required_measurements: { image: `sha256:${'33'.repeat(32)}`, config: CONFIG },
};

const surface = {
  surface_id: 'surface:curtailment-west',
  action_family: 'grid.curtailment',
  gate_id: deploymentProfile.gate_id,
  environment_id: deploymentProfile.environment_id,
  deployment_profile_hash: deploymentProfileDigest(deploymentProfile),
  probe_action_digest: ACTION,
  required: true,
  witness: { witness_id: 'witness:edge-1', capture_point_id: 'capture:grid-a', event: 'request_observed', required: true },
};

const inventory = {
  '@version': COVERAGE_INVENTORY_VERSION,
  inventory_id: 'inventory:grid-west-v1',
  surfaces: [surface],
};

function claims() {
  return {
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
  };
}

function keys() {
  const probe = crypto.generateKeyPairSync('ed25519');
  const witness = crypto.generateKeyPairSync('ed25519');
  const probeStatement = (result = 'blocked_without_receipt', testedAt = '2026-07-16T19:59:30.000Z') => signEnforcementProbe({
    probe_id: 'probe:independent-1',
    surface_id: surface.surface_id,
    gate_id: surface.gate_id,
    environment_id: surface.environment_id,
    action_family: surface.action_family,
    action_digest: ACTION,
    tested_at: testedAt,
    nonce: `probe-${result}-${testedAt}`,
    result,
    response_status: result === 'blocked_without_receipt' ? 428 : (result === 'executed_without_receipt' ? 200 : 503),
  }, probe.privateKey);
  const firstProbe = probeStatement();
  const witnessStatement = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 3,
    observed_at: '2026-07-16T19:59:40.000Z',
    event: 'request_observed',
    direction: 'ingress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, witness.privateKey);
  return {
    probePrivateKey: probe.privateKey,
    witnessPrivateKey: witness.privateKey,
    probeStatement,
    firstProbe,
    witnessStatement,
    pinnedProbes: [{
      probe_id: 'probe:independent-1',
      key_id: firstProbe.probe.key_id,
      surface_ids: [surface.surface_id, 'surface:curtailment-east'],
      public_key: probe.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    pinnedWitnesses: [{
      witness_id: surface.witness.witness_id,
      key_id: witnessStatement.witness.key_id,
      public_key: witness.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      capture_point_ids: [surface.witness.capture_point_id],
      config_digests: [CONFIG],
    }],
  };
}

function options(k) {
  return {
    now: NOW,
    attestationVerifiers: { [deploymentProfile.verifier_id]: async () => claims() },
    pinnedProbes: k.pinnedProbes,
    pinnedWitnesses: k.pinnedWitnesses,
    witnessSequenceStore: createMemoryWitnessSequenceStore(),
    allowEphemeralWitnessStore: true,
    expectedProbeNonces: {
      [surface.surface_id]: 'probe-blocked_without_receipt-2026-07-16T19:59:30.000Z',
    },
  };
}

test('gated requires a fresh attested deployment plus a pinned refusal probe', async () => {
  const k = keys();
  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: { eat: 'opaque' } }],
    probes: [k.firstProbe],
    witnesses: [k.witnessStatement],
  }, options(k));
  assert.equal(report.complete, true);
  assert.equal(report.surfaces[0].state, 'gated');
  assert.equal(report.surfaces[0].witness_verified, true);
  assert.equal(report.declared_coverage_bps, 10_000);
  assert.match(report.report_hash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(report.inventory_hash, coverageInventoryDigest(inventory));
});

test('a passive observation without active enforcement proof is witness_only', async () => {
  const k = keys();
  const report = await evaluateGateCoverage({ inventory, witnesses: [k.witnessStatement] }, options(k));
  assert.equal(report.complete, false);
  assert.equal(report.surfaces[0].state, 'witness_only');
  assert.equal(report.surfaces[0].reason, 'traffic_observed_without_active_enforcement_proof');
});

test('a witness observation for another action cannot satisfy the required coverage row', async () => {
  const k = keys();
  const wrongActionWitness = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 4,
    observed_at: '2026-07-16T19:59:40.000Z',
    event: surface.witness.event,
    direction: 'ingress',
    action_digest: `sha256:${'99'.repeat(32)}`,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);
  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [wrongActionWitness],
  }, options(k));
  assert.equal(report.surfaces[0].state, 'gated');
  assert.equal(report.surfaces[0].witness_verified, false);
  assert.equal(report.surfaces[0].complete, false);
  assert.equal(report.complete, false);
});

test('a sequence-equivocating witness rejected by ingestion cannot satisfy coverage', async () => {
  const k = keys();
  const store = createMemoryWitnessSequenceStore();
  const ingestionOptions = {
    pinnedWitnesses: k.pinnedWitnesses,
    now: NOW,
    sequenceStore: store,
    allowEphemeralStore: true,
  };
  const first = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 7,
    observed_at: '2026-07-16T19:59:35.000Z',
    event: 'response_observed',
    direction: 'egress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);
  const conflicting = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 7,
    observed_at: '2026-07-16T19:59:40.000Z',
    event: surface.witness.event,
    direction: 'ingress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);

  assert.equal((await acceptNetworkWitnessStatement(first, ingestionOptions)).accepted, true);
  assert.equal(
    (await acceptNetworkWitnessStatement(conflicting, ingestionOptions)).reason,
    'sequence_equivocation',
  );

  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [conflicting],
  }, {
    ...options(k),
    witnessSequenceStore: store,
    allowEphemeralWitnessStore: true,
  });
  assert.equal(report.surfaces[0].witness_verified, false);
  assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_equivocation');
  assert.equal(report.surfaces[0].complete, false);
  assert.equal(report.complete, false);
});

test('accepted witness evidence is invalidated by a later conflict for the same evidence key', async () => {
  const k = keys();
  const conflicting = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: k.witnessStatement.observation.sequence,
    observed_at: '2026-07-16T19:59:45.000Z',
    event: surface.witness.event,
    direction: 'egress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);

  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [k.witnessStatement, conflicting],
  }, options(k));

  assert.equal(report.surfaces[0].witness_verified, false);
  assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_equivocation');
  assert.equal(report.surfaces[0].complete, false);
  assert.equal(report.complete, false);
});

test('witness conflict order cannot change coverage acceptance', async (t) => {
  const k = keys();
  const conflictingEvent = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: k.witnessStatement.observation.sequence,
    observed_at: '2026-07-16T19:59:45.000Z',
    event: 'response_observed',
    direction: 'egress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);
  const permutations = [
    ['matching observation first', [k.witnessStatement, conflictingEvent]],
    ['matching observation second', [conflictingEvent, k.witnessStatement]],
  ];

  for (const [name, witnesses] of permutations) {
    await t.test(name, async () => {
      const report = await evaluateGateCoverage({
        inventory,
        deployments: [{ profile: deploymentProfile, evidence: {} }],
        probes: [k.firstProbe],
        witnesses,
      }, options(k));

      assert.equal(report.surfaces[0].witness_verified, false);
      assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_equivocation');
      assert.equal(report.surfaces[0].complete, false);
      assert.equal(report.complete, false);
    });
  }
});

test('same-sequence equivocation invalidates the prior action even when the action digest changes', async () => {
  const k = keys();
  const conflictingAction = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: k.witnessStatement.observation.sequence,
    observed_at: '2026-07-16T19:59:45.000Z',
    event: surface.witness.event,
    direction: 'egress',
    action_digest: `sha256:${'44'.repeat(32)}`,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);

  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [k.witnessStatement, conflictingAction],
  }, options(k));

  assert.equal(report.surfaces[0].witness_verified, false);
  assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_equivocation');
  assert.equal(report.surfaces[0].complete, false);
  assert.equal(report.complete, false);
});

test('coverage can reuse a durable RP-trusted acceptance but not a presenter-supplied lookalike', async () => {
  const k = keys();
  const memory = createMemoryWitnessSequenceStore();
  const acceptance = await acceptNetworkWitnessStatement(k.witnessStatement, {
    pinnedWitnesses: k.pinnedWitnesses,
    now: NOW,
    sequenceStore: { durable: true, advance: (...args) => memory.advance(...args) },
  });
  const offlineOptions = options(k);
  delete offlineOptions.witnessSequenceStore;
  delete offlineOptions.allowEphemeralWitnessStore;
  offlineOptions.trustedWitnessAcceptances = [acceptance];
  const accepted = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
  }, offlineOptions);
  assert.equal(accepted.complete, true);
  assert.equal(accepted.surfaces[0].witness_verified, true);

  delete offlineOptions.trustedWitnessAcceptances;
  const presented = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [acceptance],
  }, offlineOptions);
  assert.equal(presented.complete, false);
  assert.equal(presented.surfaces[0].witness_verified, false);
});

test('trusted S7 coverage is invalidated by a verified conflicting S7 regardless of ingestion label', async (t) => {
  const k = keys();
  const s7a = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 7,
    observed_at: '2026-07-16T19:59:30.000Z',
    event: surface.witness.event,
    direction: 'ingress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);
  const s8a = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 8,
    observed_at: '2026-07-16T19:59:35.000Z',
    event: surface.witness.event,
    direction: 'ingress',
    action_digest: ACTION,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);
  const s7b = signNetworkWitnessStatement({
    witness_id: surface.witness.witness_id,
    capture_point_id: surface.witness.capture_point_id,
    sequence: 7,
    observed_at: '2026-07-16T19:59:40.000Z',
    event: surface.witness.event,
    direction: 'egress',
    action_digest: `sha256:${'44'.repeat(32)}`,
    config_digest: CONFIG,
  }, k.witnessPrivateKey);

  const history = async () => {
    const memory = createMemoryWitnessSequenceStore();
    const store = { durable: true, advance: (...args) => memory.advance(...args) };
    const ingestionOptions = {
      pinnedWitnesses: k.pinnedWitnesses,
      now: NOW,
      sequenceStore: store,
    };
    const acceptance = await acceptNetworkWitnessStatement(s7a, ingestionOptions);
    assert.equal(acceptance.accepted, true);
    assert.equal((await acceptNetworkWitnessStatement(s8a, ingestionOptions)).accepted, true);
    return { acceptance, ingestionOptions, store };
  };
  const evidence = {
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
  };

  await t.test('sequence_rollback', async () => {
    const { acceptance, ingestionOptions, store } = await history();
    const conflict = await acceptNetworkWitnessStatement(s7b, ingestionOptions);
    assert.equal(conflict.reason, 'sequence_rollback');
    const report = await evaluateGateCoverage(evidence, {
      ...options(k),
      witnessSequenceStore: store,
      trustedWitnessAcceptances: [acceptance, conflict],
    });
    assert.equal(report.surfaces[0].witness_verified, false);
    assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_equivocation');
    assert.equal(report.surfaces[0].complete, false);
    assert.equal(report.complete, false);
  });

  await t.test('durable_sequence_store_required', async () => {
    const { acceptance } = await history();
    const conflict = await acceptNetworkWitnessStatement(s7b, {
      pinnedWitnesses: k.pinnedWitnesses,
      now: NOW,
    });
    assert.equal(conflict.reason, 'durable_sequence_store_required');
    const offlineOptions = options(k);
    delete offlineOptions.witnessSequenceStore;
    delete offlineOptions.allowEphemeralWitnessStore;
    offlineOptions.trustedWitnessAcceptances = [acceptance, conflict];
    const report = await evaluateGateCoverage(evidence, offlineOptions);
    assert.equal(report.surfaces[0].witness_verified, false);
    assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_equivocation');
    assert.equal(report.surfaces[0].complete, false);
    assert.equal(report.complete, false);
  });
});

test('ordinary witness rollback and replay refusals never become coverage evidence', async (t) => {
  const k = keys();
  const evidence = {
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [k.witnessStatement],
  };

  await t.test('statement_replay', async () => {
    const store = createMemoryWitnessSequenceStore();
    assert.equal((await acceptNetworkWitnessStatement(k.witnessStatement, {
      pinnedWitnesses: k.pinnedWitnesses,
      now: NOW,
      sequenceStore: store,
      allowEphemeralStore: true,
    })).accepted, true);
    const report = await evaluateGateCoverage(evidence, {
      ...options(k),
      witnessSequenceStore: store,
    });
    assert.equal(report.surfaces[0].witness_verified, false);
    assert.equal(report.surfaces[0].witness_acceptance_reason, 'statement_replay');
    assert.equal(report.complete, false);
  });

  await t.test('sequence_rollback', async () => {
    const store = createMemoryWitnessSequenceStore();
    const next = signNetworkWitnessStatement({
      witness_id: surface.witness.witness_id,
      capture_point_id: surface.witness.capture_point_id,
      sequence: k.witnessStatement.observation.sequence + 1,
      observed_at: '2026-07-16T19:59:45.000Z',
      event: surface.witness.event,
      direction: 'ingress',
      action_digest: ACTION,
      config_digest: CONFIG,
    }, k.witnessPrivateKey);
    const ingestionOptions = {
      pinnedWitnesses: k.pinnedWitnesses,
      now: NOW,
      sequenceStore: store,
      allowEphemeralStore: true,
    };
    assert.equal((await acceptNetworkWitnessStatement(k.witnessStatement, ingestionOptions)).accepted, true);
    assert.equal((await acceptNetworkWitnessStatement(next, ingestionOptions)).accepted, true);
    const report = await evaluateGateCoverage(evidence, {
      ...options(k),
      witnessSequenceStore: store,
    });
    assert.equal(report.surfaces[0].witness_verified, false);
    assert.equal(report.surfaces[0].witness_acceptance_reason, 'sequence_rollback');
    assert.equal(report.complete, false);
  });
});

test('a verified bypass wins over a simultaneous block result', async () => {
  const k = keys();
  const bypass = k.probeStatement('executed_without_receipt');
  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe, bypass],
    witnesses: [k.witnessStatement],
  }, options(k));
  assert.equal(report.complete, false);
  assert.equal(report.surfaces[0].state, 'ungated');
  assert.equal(report.surfaces[0].bypass_probe_verified, true);
});

test('a replayed block result with the wrong challenge nonce cannot establish gated coverage', async () => {
  const k = keys();
  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [k.witnessStatement],
  }, { ...options(k), expectedProbeNonces: { [surface.surface_id]: 'fresh-rp-challenge' } });
  assert.equal(report.complete, false);
  assert.equal(report.surfaces[0].state, 'witness_only');
  assert.equal(report.surfaces[0].probe_nonce_verified, false);
});

test('attestation alone is unknown because running is not route mediation', async () => {
  const k = keys();
  const report = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
  }, options(k));
  assert.equal(report.surfaces[0].state, 'unknown');
  assert.equal(report.surfaces[0].deployment_attested, true);
  assert.equal(report.surfaces[0].refusal_probe_verified, false);
});

test('stale signed probes are reported stale, never silently unknown or gated', async () => {
  const k = keys();
  const stale = k.probeStatement('blocked_without_receipt', '2026-07-16T18:00:00.000Z');
  const report = await evaluateGateCoverage({ inventory, probes: [stale] }, { ...options(k), probeMaxAgeSec: 60 });
  assert.equal(report.surfaces[0].state, 'stale');
  assert.equal(report.complete, false);
});

test('untrusted probe keys, altered results, and wrong action probes cannot establish coverage', async () => {
  const k = keys();
  const untrusted = await evaluateGateCoverage({
    inventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
  }, { ...options(k), pinnedProbes: [] });
  assert.equal(untrusted.surfaces[0].state, 'unknown');
  assert.equal(verifyEnforcementProbe(k.firstProbe, {
    pinnedProbes: k.pinnedProbes.map(({ surface_ids: _surfaceIds, ...pin }) => pin),
    expectedSurface: surface,
    now: NOW,
  }).reason, 'probe_surface_unpinned');

  const altered = structuredClone(k.firstProbe);
  altered.test.result = 'executed_without_receipt';
  altered.test.response_status = 200;
  assert.equal(verifyEnforcementProbe(altered, {
    pinnedProbes: k.pinnedProbes, expectedSurface: surface, now: NOW,
  }).accepted, false);

  const wrongAction = signEnforcementProbe({
    probe_id: 'probe:independent-1', surface_id: surface.surface_id, gate_id: surface.gate_id,
    environment_id: surface.environment_id, action_family: surface.action_family,
    action_digest: `sha256:${'99'.repeat(32)}`, tested_at: '2026-07-16T19:59:30.000Z',
    nonce: 'wrong-action', result: 'blocked_without_receipt', response_status: 428,
  }, k.probePrivateKey);
  assert.equal(verifyEnforcementProbe(wrongAction, {
    pinnedProbes: k.pinnedProbes, expectedSurface: surface, now: NOW,
  }).reason, 'probe_context_mismatch');
});

test('invalid and duplicate inventories fail closed and the report names the inventory boundary', async () => {
  const invalid = await evaluateGateCoverage({ inventory: { ...inventory, surfaces: [surface, surface] } });
  assert.equal(invalid.complete, false);
  assert.equal(invalid.reason, 'surface_id_duplicate');
  const k = keys();
  const report = await evaluateGateCoverage({ inventory, witnesses: [k.witnessStatement] }, options(k));
  assert.match(report.limitations[0], /declared inventory/);
});

test('serialized probe ingress refuses duplicate keys and oversize', () => {
  const k = keys();
  assert.deepEqual(parseEnforcementProbeStatement(JSON.stringify(k.firstProbe)), k.firstProbe);
  assert.equal(parseEnforcementProbeStatement('{"test":{},"test":{}}'), null);
  assert.equal(parseEnforcementProbeStatement(JSON.stringify(k.firstProbe), { maxBytes: 10 }), null);
});

test('probe verification refuses non-canonical encodings and non-Ed25519 keys', () => {
  const k = keys();
  const badSignature = structuredClone(k.firstProbe);
  badSignature.signature.signature_b64u += '=';
  assert.equal(verifyEnforcementProbe(badSignature, {
    pinnedProbes: k.pinnedProbes, expectedSurface: surface, now: NOW,
  }).reason, 'probe_signature_invalid');
  const badKeyPins = k.pinnedProbes.map((pin) => ({ ...pin, public_key: `${pin.public_key}=` }));
  assert.equal(verifyEnforcementProbe(k.firstProbe, {
    pinnedProbes: badKeyPins, expectedSurface: surface, now: NOW,
  }).reason, 'probe_pinned_key_invalid');
  const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const wrongAlgorithmPins = k.pinnedProbes.map((pin) => ({
    ...pin,
    public_key: p256.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  }));
  assert.equal(verifyEnforcementProbe(k.firstProbe, {
    pinnedProbes: wrongAlgorithmPins, expectedSurface: surface, now: NOW,
  }).reason, 'probe_pinned_key_invalid');
});

test('partial coverage stays canonical and is represented as integer basis points', async () => {
  const k = keys();
  const second = {
    ...surface,
    surface_id: 'surface:curtailment-east',
    witness: { ...surface.witness },
  };
  const partialInventory = { ...inventory, surfaces: [surface, second] };
  const report = await evaluateGateCoverage({
    inventory: partialInventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: [k.firstProbe],
    witnesses: [k.witnessStatement],
  }, options(k));
  assert.equal(report.complete, false);
  assert.equal(report.declared_coverage_bps, 5_000);
  assert.match(report.report_hash, /^sha256:[0-9a-f]{64}$/);
});

test('evidence collection resource limits fail closed before verification work', async () => {
  const result = await evaluateGateCoverage({ inventory, probes: new Array(50_001) });
  assert.equal(result.complete, false);
  assert.equal(result.reason, 'coverage_probes_limit_exceeded');
  assert.deepEqual(result.surfaces, []);
});

test('inventory and signed evidence are snapshotted before async attestation verification', async () => {
  const k = keys();
  const mutableInventory = structuredClone(inventory);
  const mutableProbes = [structuredClone(k.firstProbe)];
  const mutableWitnesses = [structuredClone(k.witnessStatement)];
  const opts = options(k);
  opts.attestationVerifiers = {
    [deploymentProfile.verifier_id]: async () => {
      mutableInventory.surfaces[0].probe_action_digest = `sha256:${'99'.repeat(32)}`;
      mutableProbes.length = 0;
      mutableWitnesses.length = 0;
      opts.pinnedProbes.length = 0;
      opts.pinnedWitnesses.length = 0;
      opts.expectedProbeNonces[surface.surface_id] = 'mutated-after-admission';
      return claims();
    },
  };
  const report = await evaluateGateCoverage({
    inventory: mutableInventory,
    deployments: [{ profile: deploymentProfile, evidence: {} }],
    probes: mutableProbes,
    witnesses: mutableWitnesses,
  }, opts);
  assert.equal(report.complete, true);
  assert.equal(report.surfaces[0].state, 'gated');
  assert.equal(report.surfaces[0].witness_verified, true);
  assert.equal(report.inventory_hash, coverageInventoryDigest(inventory));
});
