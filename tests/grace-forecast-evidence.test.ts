// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  FORECAST_EVIDENCE_VERSION,
  TIMESFM_ADAPTER_PROFILE,
  assessForecastForGrace,
  buildTimesFmForecastEvidence,
  forecastDigest,
  reconcileForecastObservation,
  validateForecastEvidence,
} from '../lib/grace/forecast-evidence.js';
import {
  executeGraceCurtailment,
  graceDigest,
  signGraceArtifact,
  signGraceArtifactV2,
  verifyGraceArtifact,
} from '../lib/grace/mobile-grid.js';
import {
  createGraceReferenceInput,
  createGraceReferenceRuntime,
} from '../lib/grace/reference-scenario.js';

const CHECKPOINT_DIGEST = `sha256:${'c'.repeat(64)}`;
const BACKTEST_CODE_DIGEST = `sha256:${'d'.repeat(64)}`;
const FORECAST_KEY_ID = 'ep:key:timesfm-reference';
const forecastKeys = crypto.generateKeyPairSync('ed25519');
const forecastPublic = forecastKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const pqKeys = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPublic = Buffer.from(pqKeys.publicKey).toString('base64url');
const pqPrivate = Buffer.from(pqKeys.secretKey).toString('base64url');
const input = createGraceReferenceInput();

const sourceObservations = Array.from({ length: 12 }, (_, index) => ({
  at: new Date(Date.parse('2026-07-15T19:05:00.000Z') + index * 5 * 60_000).toISOString(),
  available_curtailment_mw: (20 + (index % 3) * 0.1).toFixed(3),
}));

const forecastPoints = [
  { at: '2026-07-15T20:00:00.000Z', p10: '19.000', p50: '20.500', p90: '22.000' },
  { at: '2026-07-15T20:30:00.000Z', p10: '18.500', p50: '20.000', p90: '22.000' },
  { at: '2026-07-15T21:00:00.000Z', p10: '18.000', p50: '19.500', p90: '21.500' },
  { at: '2026-07-15T21:30:00.000Z', p10: '18.200', p50: '19.700', p90: '21.700' },
];

function body(overrides: any = {}) {
  const built = buildTimesFmForecastEvidence({
    forecast_id: 'forecast:grace:reference-0042',
    generated_at: '2026-07-15T20:10:00.000Z',
    action_digest: graceDigest(input.action),
    action_window: input.action.window,
    source_id: 'meter-history:facility:us-west-dc-17',
    source_observations: sourceObservations,
    source_frequency: 'PT5M',
    model_version: '2.5',
    checkpoint_id: 'google/timesfm-2.5-200m-pytorch',
    checkpoint_digest: CHECKPOINT_DIGEST,
    adapter_version: '0.1.0',
    adapter_config: { context_length: 12, horizon_length: 4, quantiles: ['0.1', '0.5', '0.9'] },
    points: forecastPoints,
    step: 'PT30M',
    backtest: {
      method: 'rolling_origin',
      window_count: 12,
      metric: 'MAE',
      value: '1.200',
      unit: 'MW',
      evaluated_through: '2026-07-15T20:00:00.000Z',
      code_digest: BACKTEST_CODE_DIGEST,
    },
  });
  return { ...built, ...overrides };
}

function signed(overrides: any = {}) {
  return signGraceArtifact(body(overrides), {
    privateKey: forecastKeys.privateKey,
    keyId: FORECAST_KEY_ID,
  });
}

const policy = {
  required: true,
  expected_model_id: 'timesfm',
  expected_model_version: '2.5',
  expected_checkpoint_digest: CHECKPOINT_DIGEST,
  expected_adapter_id: TIMESFM_ADAPTER_PROFILE,
  expected_adapter_version: '0.1.0',
  expected_adapter_config_digest: body().adapter.config_digest,
  expected_series_source_id: 'meter-history:facility:us-west-dc-17',
  max_forecast_age_sec: 15 * 60,
  max_input_age_sec: 90 * 60,
  max_interval_width_mw: '5.000',
  min_backtest_windows: 10,
  max_backtest_mae_mw: '2.000',
  require_target_at_or_below_p10: true,
};

function assess(value: any, overrides: any = {}) {
  return assessForecastForGrace(value, {
    policy: overrides.policy || policy,
    expected_action_digest: overrides.expected_action_digest || graceDigest(input.action),
    expected_action_window: overrides.expected_action_window || input.action.window,
    action_target_mw: overrides.action_target_mw || '18.000',
    now: overrides.now || '2026-07-15T20:15:00.000Z',
  });
}

async function executeComposition(forecastEvidence: any, forecastTrust: any, forecastPolicy: any = policy) {
  const state = createGraceReferenceRuntime();
  const result = await executeGraceCurtailment({
    ...input,
    forecastEvidence,
    forecastTrust,
    forecastPolicy,
    executionStore: state.executionStore,
    actuator: state.actuator,
    actuatorTrust: state.actuatorKey.trust,
    meter: state.meter,
    meterTrust: state.meterKey.trust,
    settlementStore: state.settlementStore,
    allowEphemeralState: true,
    settle: async ({ key }) => ({ settlement_id: 'settlement:forecast-reference', entitlement_key: key }),
    operator: 'operator:us-west-dc-17',
    developer: 'cosa-reference-adapter/1.0',
    capsuleSigner: state.capsuleKey,
    clock: () => '2026-07-15T20:15:00.000Z',
  });
  return { result, state };
}

describe('EP-FORECAST-EVIDENCE-v0.1 closed evidence object', () => {
  it('builds deterministic TimesFM evidence with explicit nonclaims', () => {
    const value = body();
    expect(value['@version']).toBe(FORECAST_EVIDENCE_VERSION);
    expect(value.series.input_digest).toBe(forecastDigest(sourceObservations));
    expect(value.forecast.action_window).toMatchObject({
      aggregation: 'minimum_across_action_window',
      p10: '18.000',
      p50: '19.500',
      p90: '21.500',
    });
    expect(value.claim_boundary).toEqual({
      advisory_only: true,
      never_sole_gate: true,
      physical_truth: 'NOT_ESTABLISHED',
      authority: 'NONE',
      settlement_input: false,
    });
    expect(validateForecastEvidence(value)).toMatchObject({ valid: true, reasons: [] });
  });

  it('the Ed25519 envelope binds the input digest, checkpoint, output, and action', () => {
    const artifact = signed();
    expect(verifyGraceArtifact(artifact, {
      publicKeySpkiB64u: forecastPublic,
      keyId: FORECAST_KEY_ID,
      version: FORECAST_EVIDENCE_VERSION,
    })).toBe(true);
    for (const tampered of [
      { ...artifact, action_digest: `sha256:${'0'.repeat(64)}` },
      { ...artifact, series: { ...artifact.series, input_digest: `sha256:${'1'.repeat(64)}` } },
      { ...artifact, model: { ...artifact.model, checkpoint_digest: `sha256:${'2'.repeat(64)}` } },
      { ...artifact, forecast: { ...artifact.forecast, points: artifact.forecast.points.map((p: any, i: number) => (
        i === 0 ? { ...p, p50: '99.000' } : p
      )) } },
    ]) {
      expect(verifyGraceArtifact(tampered, {
        publicKeySpkiB64u: forecastPublic,
        keyId: FORECAST_KEY_ID,
        version: FORECAST_EVIDENCE_VERSION,
      })).toBe(false);
    }
  });

  it.each([
    ['unknown member', () => ({ ...body(), surprise: true }), 'forecast_shape_invalid'],
    ['claiming authority', () => ({ ...body(), claim_boundary: { ...body().claim_boundary, authority: 'GRANTED' } }), 'forecast_authority_overclaim'],
    ['crossed quantiles', () => {
      const value = body();
      value.forecast.points[1].p10 = '23.000';
      return value;
    }, 'forecast_quantiles_crossed'],
    ['dishonest window summary', () => ({
      ...body(), forecast: {
        ...body().forecast,
        action_window: { ...body().forecast.action_window, p10: '19.000' },
      },
    }), 'forecast_action_window_summary_mismatch'],
  ])('refuses %s structurally', (_name, make, reason) => {
    expect(validateForecastEvidence(make()).reasons).toContain(reason);
  });
});

describe('forecast evidence can tighten but never authorize GRACE', () => {
  it('accepts a pinned, fresh, bounded forecast as advisory input', () => {
    expect(assess(signed())).toMatchObject({ valid: true, reasons: [], posture: 'TIGHTEN_ONLY' });
  });

  it.each([
    ['action substitution', signed(), { expected_action_digest: `sha256:${'a'.repeat(64)}` }, 'forecast_action_substitution'],
    ['stale forecast', signed(), { now: '2026-07-15T21:00:00.000Z' }, 'forecast_stale_or_from_future'],
    ['checkpoint substitution', signed(), { policy: { ...policy, expected_checkpoint_digest: `sha256:${'e'.repeat(64)}` } }, 'forecast_checkpoint_substitution'],
    ['adapter configuration substitution', signed(), { policy: { ...policy, expected_adapter_config_digest: `sha256:${'f'.repeat(64)}` } }, 'forecast_adapter_config_substitution'],
    ['excessive uncertainty', signed(), { policy: { ...policy, max_interval_width_mw: '3.000' } }, 'forecast_uncertainty_exceeds_policy'],
    ['insufficient conservative capacity', signed(), { action_target_mw: '18.001' }, 'forecast_conservative_capacity_below_action'],
    ['insufficient backtest', signed(), { policy: { ...policy, min_backtest_windows: 13 } }, 'forecast_backtest_sample_too_small'],
    ['poor backtest error', signed(), { policy: { ...policy, max_backtest_mae_mw: '1.000' } }, 'forecast_backtest_error_exceeds_policy'],
    ['action-window mismatch', signed(), { expected_action_window: { not_before: '2026-07-15T20:30:00.000Z', not_after: input.action.window.not_after } }, 'forecast_action_window_mismatch'],
  ])('refuses %s by name', (_name, value, options, reason) => {
    expect(assess(value, options).reasons).toContain(reason);
  });

  it('reconciles against separately authenticated observation without rewriting forecast evidence', () => {
    const artifact = signed();
    const before = forecastDigest(artifact);
    const within = reconcileForecastObservation(artifact, {
      observed_value_mw: '17.928',
      observation_digest: `sha256:${'9'.repeat(64)}`,
      observed_at: '2026-07-15T21:45:01.000Z',
    });
    expect(within.status).toBe('OUTSIDE_BAND');
    expect(within.reason).toBe('observed_value_outside_forecast_band');
    expect(forecastDigest(artifact)).toBe(before);
    expect(reconcileForecastObservation(artifact, {
      observed_value_mw: '19.000',
      observation_digest: `sha256:${'9'.repeat(64)}`,
      observed_at: '2026-07-15T21:45:01.000Z',
    }).status).toBe('WITHIN_BAND');
  });
});

describe('GRACE forecast-to-authority composition', () => {
  it('binds a verified forecast into dispatch, Action State, and the signed final bundle', async () => {
    const forecastEvidence = signed();
    const { result } = await executeComposition(forecastEvidence, {
        signature_profile: 'Ed25519',
        key_id: FORECAST_KEY_ID,
        public_key_spki: forecastPublic,
    });
    expect(result.ok).toBe(true);
    expect(result.forecast_assessment).toMatchObject({ valid: true, posture: 'TIGHTEN_ONLY' });
    expect(result.bundle.forecast_evidence_digest).toBe(forecastDigest(forecastEvidence));
    expect(result.bundle.forecast_reconciliation_status).toBe('OUTSIDE_BAND');
    expect(result.action_state.capsule.constraints.map((item: any) => item.id)).toEqual(expect.arrayContaining([
      'ep:grace:forecast_advisory',
      'ep:grace:forecast_reconciliation',
    ]));
    expect(result.action_state.capsule.constraints.find(
      (item: any) => item.id === 'ep:grace:forecast_reconciliation',
    )).toMatchObject({ result: 'fail', blocking: false });
    expect(result.settlement.settled).toBe(true);
  });

  it('accepts the same evidence under the real Ed25519 plus ML-DSA-65 hybrid envelope', async () => {
    const hybrid = await signGraceArtifactV2(body(), {
      privateKey: forecastKeys.privateKey,
      keyId: FORECAST_KEY_ID,
      pqPrivateKey: pqPrivate,
      pqPublicKey: pqPublic,
      pqKeyId: 'ep:key:timesfm-reference-pq',
    });
    const { result } = await executeComposition(hybrid, {
      signature_profile: 'hybrid_all',
      key_id: FORECAST_KEY_ID,
      public_key_spki: forecastPublic,
      pq_key_id: 'ep:key:timesfm-reference-pq',
      pq_public_key: pqPublic,
    });
    expect(result).toMatchObject({ ok: true, verdict: 'executed_measured_settled' });
    expect(result.forecast_assessment).toMatchObject({ valid: true, posture: 'TIGHTEN_ONLY' });
  });

  it('required forecast absence or signature tamper refuses before actuator entry', async () => {
    for (const forecastEvidence of [undefined, { ...signed(), generated_at: '2026-07-15T20:11:00.000Z' }]) {
      const { result, state } = await executeComposition(forecastEvidence, {
          signature_profile: 'Ed25519',
          key_id: FORECAST_KEY_ID,
          public_key_spki: forecastPublic,
      });
      expect(result.verdict).toBe('refuse_forecast_evidence');
      expect(state.actuator.invocationCount()).toBe(0);
    }
  });

  it('a malformed optional policy refuses instead of silently disabling the forecast gate', async () => {
    const { result, state } = await executeComposition(undefined, undefined, {
      ...policy,
      required: false,
      unexpected: true,
    });
    expect(result.verdict).toBe('refuse_forecast_policy');
    expect(state.actuator.invocationCount()).toBe(0);
  });
});
