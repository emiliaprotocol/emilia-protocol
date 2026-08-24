// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import {
  FORECAST_EVIDENCE_VERSION,
  TIMESFM_ADAPTER_PROFILE,
  assessForecastForGrace,
  buildTimesFmForecastEvidence,
  forecastDigest,
  reconcileForecastObservation,
} from '../../lib/grace/forecast-evidence.js';
import {
  graceDigest,
  signGraceArtifact,
  verifyGraceArtifact,
} from '../../lib/grace/mobile-grid.js';
import { createGraceReferenceInput } from '../../lib/grace/reference-scenario.js';

const input = createGraceReferenceInput();
const key = crypto.generateKeyPairSync('ed25519');
const keyId = 'ep:key:timesfm-reference';
const publicKey = key.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const checkpointDigest = `sha256:${'c'.repeat(64)}`;
const source = Array.from({ length: 12 }, (_, index) => ({
  at: new Date(Date.parse('2026-07-15T19:05:00.000Z') + index * 5 * 60_000).toISOString(),
  available_curtailment_mw: (20 + (index % 3) * 0.1).toFixed(3),
}));
const points = [
  { at: '2026-07-15T20:00:00.000Z', p10: '19.000', p50: '20.500', p90: '22.000' },
  { at: '2026-07-15T20:30:00.000Z', p10: '18.500', p50: '20.000', p90: '22.000' },
  { at: '2026-07-15T21:00:00.000Z', p10: '18.000', p50: '19.500', p90: '21.500' },
  { at: '2026-07-15T21:30:00.000Z', p10: '18.200', p50: '19.700', p90: '21.700' },
];
const adapterConfig = { context_length: 12, horizon_length: 4, quantiles: ['0.1', '0.5', '0.9'] };
const body = buildTimesFmForecastEvidence({
  forecast_id: 'forecast:grace:reference-0042',
  generated_at: '2026-07-15T20:10:00.000Z',
  action_digest: graceDigest(input.action),
  action_window: input.action.window,
  source_id: 'meter-history:facility:us-west-dc-17',
  source_observations: source,
  source_frequency: 'PT5M',
  model_version: '2.5',
  checkpoint_id: 'google/timesfm-2.5-200m-pytorch',
  checkpoint_digest: checkpointDigest,
  adapter_version: '0.1.0',
  adapter_config: adapterConfig,
  points,
  step: 'PT30M',
  backtest: {
    method: 'rolling_origin', window_count: 12, metric: 'MAE', value: '1.200', unit: 'MW',
    evaluated_through: '2026-07-15T20:00:00.000Z',
    code_digest: `sha256:${'d'.repeat(64)}`,
  },
});
const artifact = signGraceArtifact(body, { privateKey: key.privateKey, keyId });
const signatureValid = verifyGraceArtifact(artifact, {
  publicKeySpkiB64u: publicKey,
  keyId,
  version: FORECAST_EVIDENCE_VERSION,
});
const assessment = assessForecastForGrace(artifact, {
  policy: {
    required: true,
    expected_model_id: 'timesfm',
    expected_model_version: '2.5',
    expected_checkpoint_digest: checkpointDigest,
    expected_adapter_id: TIMESFM_ADAPTER_PROFILE,
    expected_adapter_version: '0.1.0',
    expected_adapter_config_digest: forecastDigest(adapterConfig),
    expected_series_source_id: 'meter-history:facility:us-west-dc-17',
    max_forecast_age_sec: 900,
    max_input_age_sec: 5400,
    max_interval_width_mw: '5.000',
    min_backtest_windows: 10,
    max_backtest_mae_mw: '2.000',
    require_target_at_or_below_p10: true,
  },
  expected_action_digest: graceDigest(input.action),
  expected_action_window: input.action.window,
  action_target_mw: '18.000',
  now: '2026-07-15T20:15:00.000Z',
});
const reconciliation = reconcileForecastObservation(artifact, {
  observed_value_mw: '17.928',
  observation_digest: `sha256:${'9'.repeat(64)}`,
  observed_at: '2026-07-15T21:45:01.000Z',
});

console.log(JSON.stringify({
  reference_only: true,
  model_executed: false,
  note: 'Deterministic adapter-contract fixture. It does not execute or benchmark TimesFM.',
  signature_valid: signatureValid,
  gate_posture: assessment.posture,
  gate_valid: assessment.valid,
  evidence_digest: assessment.evidence_digest,
  action_window_p10_mw: body.forecast.action_window.p10,
  action_target_mw: '18.000',
  reconciliation,
  authority_from_forecast: false,
  settlement_from_forecast: false,
}, null, 2));
