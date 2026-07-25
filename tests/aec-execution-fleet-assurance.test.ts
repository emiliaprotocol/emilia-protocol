// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import { runAecExecutionFleetAssuranceChecks } from '../formal/check-aec-execution-fleet-assurance.mjs';
import {
  AEC_EXECUTION_FLEET_ASSURANCE_SCENARIOS,
  runAecExecutionFleetAssuranceScenario,
} from '../conformance/refinement/adapters/aec-execution-fleet-assurance.mjs';

const EXPECTED_OBLIGATIONS = [
  'ConstructorTrustInputsImmutable',
  'VerifierMethodCaptured',
  'TransactionScopedTrustRefused',
  'CanonicalActionKeyOnly',
  'ReservationOwnerFenced',
  'ReservationNeverExpires',
  'SharedHeadAppendAtomic',
  'EvidenceReadbackAcknowledgementExact',
  'ResponseLossFreezesReplay',
  'ReplicasShareConsumptionDomain',
  'RestartCannotAdoptReservation',
  'ReservationFailureCannotExecute',
  'ProviderExecutionAtMostOnce',
] as const;

describe('AEC action-keyed fleet bounded assurance checker', () => {
  it('verifies every named boundary and exposes a paired unsafe counterexample', () => {
    const result = runAecExecutionFleetAssuranceChecks();

    expect(result).toMatchObject({
      model: 'EP-AEC-EXECUTION-FLEET-ASSURANCE-BOUNDED-MODEL-v1',
      method: 'bounded_exhaustive_state_exploration',
      verified: true,
      unsafe_comparison: {
        mutations_checked: EXPECTED_OBLIGATIONS.length,
        mutations_exposed: EXPECTED_OBLIGATIONS.length,
      },
    });
    expect(Object.keys(result.obligations)).toEqual(EXPECTED_OBLIGATIONS);

    for (const name of EXPECTED_OBLIGATIONS) {
      const obligation = result.obligations[name];
      expect(obligation, name).toMatchObject({
        verified: true,
        counterexample: null,
      });
      expect(obligation.states_checked, name).toBeGreaterThan(0);
      expect(obligation.unsafe.mutation, name).toMatch(/^unsafe_/);
      expect(obligation.unsafe.states_checked, name).toBeGreaterThan(0);
      expect(obligation.unsafe.counterexample, name).not.toBeNull();
      expect(obligation.unsafe.counterexample.trace.length, name).toBeGreaterThan(0);
    }

    expect(result.limitations.join(' ')).toMatch(/does not establish .*database linearizability/i);
  });
});

describe('AEC action-keyed fleet production-entry runtime scenarios', () => {
  it('runs the complete deterministic scenario set', async () => {
    expect(AEC_EXECUTION_FLEET_ASSURANCE_SCENARIOS).toEqual([
      'aec-fleet-pinned-boundary',
      'aec-fleet-owner-reservation',
      'aec-fleet-atomic-evidence',
      'aec-fleet-reservation-failure',
      'aec-fleet-response-loss',
      'aec-fleet-replica-restart',
    ]);

    const results = await Promise.all(
      AEC_EXECUTION_FLEET_ASSURANCE_SCENARIOS.map(runAecExecutionFleetAssuranceScenario),
    );
    expect(results.map((result) => result.scenario)).toEqual(AEC_EXECUTION_FLEET_ASSURANCE_SCENARIOS);
    expect(results.every((result) => result.steps.length > 0)).toBe(true);
  });

  it('pins trust and methods and refuses transaction-scoped trust configuration', async () => {
    const result = await runAecExecutionFleetAssuranceScenario('aec-fleet-pinned-boundary');
    const steps = Object.fromEntries(result.steps.map((step) => [step.operator, step]));

    expect(steps.ExecuteWithPinnedTrust).toMatchObject({
      accepted: true,
      projection: { provider_executions: 1 },
    });
    expect(steps.MutateConstructorTrustInputs).toMatchObject({
      accepted: false,
      projection: { provider_executions: 0, trust_mutation_admitted: false },
    });
    expect(steps.ReplaceCapturedMethods).toMatchObject({
      accepted: true,
      projection: { provider_executions: 1, replacement_calls: 0 },
    });
    expect(steps.InjectTransactionTrust).toMatchObject({
      accepted: false,
      projection: { provider_executions: 0, runtime_config_refused: true },
    });
  });

  it('keeps reservations owner-fenced and non-expiring across restart', async () => {
    const result = await runAecExecutionFleetAssuranceScenario('aec-fleet-owner-reservation');
    const steps = Object.fromEntries(result.steps.map((step) => [step.operator, step]));

    expect(steps.ReserveAsOwner.accepted).toBe(true);
    expect(steps.RestartCannotAdopt).toMatchObject({
      accepted: false,
      projection: { commit_refused: true, release_refused: true },
    });
    expect(steps.ReservationDoesNotExpire).toMatchObject({
      accepted: true,
      projection: { replay_blocked: true, permanent_consumption: true },
    });
  });

  it('recovers response loss, continues one shared head, and rejects substituted readback', async () => {
    const result = await runAecExecutionFleetAssuranceScenario('aec-fleet-atomic-evidence');
    const steps = Object.fromEntries(result.steps.map((step) => [step.operator, step]));

    expect(steps.RecoverAppendAfterResponseLoss).toMatchObject({
      accepted: true,
      projection: { recovered_same_record: true },
    });
    expect(steps.ContinueSharedHeadAfterRestart).toMatchObject({
      accepted: true,
      projection: { sequence: 1, predecessor_matches: true },
    });
    expect(steps.RejectSubstitutedReadback).toMatchObject({
      accepted: false,
      projection: { exact_readback_refused: true },
    });
  });

  it('fails closed before provider entry when reservation fails', async () => {
    const result = await runAecExecutionFleetAssuranceScenario('aec-fleet-reservation-failure');
    expect(result.steps).toContainEqual({
      operator: 'RefuseProviderWhenReservationFails',
      accepted: false,
      projection: {
        provider_executions: 0,
        reservation_failure_refused: true,
      },
    });
  });

  it('freezes replay after provider response loss', async () => {
    const result = await runAecExecutionFleetAssuranceScenario('aec-fleet-response-loss');
    const steps = Object.fromEntries(result.steps.map((step) => [step.operator, step]));

    expect(steps.LoseProviderResponse).toMatchObject({
      accepted: false,
      projection: { provider_executions: 1, indeterminate_recorded: true },
    });
    expect(steps.RefuseReplayAfterResponseLoss).toMatchObject({
      accepted: false,
      projection: { provider_executions: 1, replay_refused: true },
    });
  });

  it('uses one canonical action key across replicas, decoys, and restart', async () => {
    const result = await runAecExecutionFleetAssuranceScenario('aec-fleet-replica-restart');
    const steps = Object.fromEntries(result.steps.map((step) => [step.operator, step]));

    expect(steps.ExecuteCanonicalActionOnReplicaA).toMatchObject({
      accepted: true,
      projection: { provider_executions: 1, canonical_action_key: true },
    });
    expect(steps.RefuseDecoyReplayOnReplicaB).toMatchObject({
      accepted: false,
      projection: { provider_executions: 1, replay_refused: true },
    });
    expect(steps.RefuseReplayAfterRestart).toMatchObject({
      accepted: false,
      projection: { provider_executions: 1, replay_refused: true },
    });
  });
});
