// SPDX-License-Identifier: Apache-2.0
/**
 * EP-FORECAST-EVIDENCE-v0.1.
 *
 * A signed, action-bound assertion about one model run. Forecast evidence is
 * advisory input only. It can make a GRACE policy stricter, but it never
 * authorizes dispatch, proves physical truth, replaces meter evidence, or
 * establishes settlement eligibility.
 */
import crypto from 'node:crypto';
import { canonicalizeStrictJson } from '../../packages/verify/strict-json.js';

export const FORECAST_EVIDENCE_VERSION = 'EP-FORECAST-EVIDENCE-v0.1';
export const FORECAST_RECONCILIATION_VERSION = 'EP-FORECAST-RECONCILIATION-v0.1';
export const TIMESFM_ADAPTER_PROFILE = 'emilia.timesfm.v2.5';

export const FORECAST_LIMITS = Object.freeze({
  max_points: 1000,
  max_source_points: 16_384,
  max_depth: 16,
  max_nodes: 20_000,
  max_string_bytes: 2 * 1024 * 1024,
});

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9:_.@/-]{1,256}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,6})?$/;
const STEP = /^PT([1-9][0-9]{0,5})(M|H)$/;

const BODY_KEYS = new Set([
  '@version', 'forecast_id', 'generated_at', 'action_digest', 'model', 'adapter',
  'series', 'forecast', 'backtest', 'claim_boundary',
]);
const MODEL_KEYS = new Set([
  'provider', 'model_id', 'model_version', 'checkpoint_id', 'checkpoint_digest',
]);
const ADAPTER_KEYS = new Set(['adapter_id', 'adapter_version', 'config_digest']);
const SERIES_KEYS = new Set([
  'source_id', 'input_digest', 'observed_from', 'observed_through', 'frequency',
  'point_count',
]);
const FORECAST_KEYS = new Set([
  'target', 'unit', 'horizon_start', 'horizon_end', 'step', 'points', 'action_window',
]);
const POINT_KEYS = new Set(['at', 'p10', 'p50', 'p90']);
const WINDOW_KEYS = new Set(['not_before', 'not_after', 'aggregation', 'p10', 'p50', 'p90']);
const BACKTEST_KEYS = new Set([
  'method', 'window_count', 'metric', 'value', 'unit', 'evaluated_through',
  'code_digest',
]);
const CLAIM_KEYS = new Set([
  'advisory_only', 'never_sole_gate', 'physical_truth', 'authority', 'settlement_input',
]);

type RecordValue = Record<string, any>;

export interface ForecastPolicy {
  required: boolean;
  expected_model_id: string;
  expected_model_version: string;
  expected_checkpoint_digest: string;
  expected_adapter_id: string;
  expected_adapter_version: string;
  expected_adapter_config_digest: string;
  expected_series_source_id: string;
  max_forecast_age_sec: number;
  max_input_age_sec: number;
  max_interval_width_mw: string;
  min_backtest_windows: number;
  max_backtest_mae_mw: string;
  require_target_at_or_below_p10: boolean;
}

function record(value: unknown): value is RecordValue {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value: unknown, keys: Set<string>): value is RecordValue {
  if (!record(value)) return false;
  const own = Reflect.ownKeys(value);
  return own.length === keys.size
    && own.every((key) => typeof key === 'string' && keys.has(key));
}

function id(value: unknown): value is string {
  return typeof value === 'string' && ID.test(value);
}

function instant(value: unknown): value is string {
  return typeof value === 'string' && INSTANT.test(value) && Number.isFinite(Date.parse(value));
}

function decimal(value: unknown): value is string {
  return typeof value === 'string' && DECIMAL.test(value);
}

function decimalMicros(value: string): bigint {
  const [whole, fraction = ''] = value.split('.');
  return BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, '0'));
}

function compareDecimal(a: string, b: string): -1 | 0 | 1 {
  const left = decimalMicros(a), right = decimalMicros(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

function subtractDecimal(a: string, b: string): bigint {
  return decimalMicros(a) - decimalMicros(b);
}

function stepMilliseconds(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const match = STEP.exec(value);
  if (!match) return null;
  const amount = Number(match[1]);
  const milliseconds = amount * (match[2] === 'H' ? 3_600_000 : 60_000);
  return Number.isSafeInteger(milliseconds) && milliseconds > 0 ? milliseconds : null;
}

function canonical(value: unknown): string {
  return canonicalizeStrictJson(value, {
    maxDepth: FORECAST_LIMITS.max_depth,
    maxNodes: FORECAST_LIMITS.max_nodes,
    maxStringBytes: FORECAST_LIMITS.max_string_bytes,
  });
}

export function forecastDigest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex')}`;
}

function unsignedBody(value: unknown): unknown {
  if (!record(value)) return value;
  const { signature: _signature, signer_key_id: _signer, pq_signer_key_id: _pqSigner, ...body } = value;
  return body;
}

function add(reasons: string[], condition: boolean, reason: string): void {
  if (!condition && !reasons.includes(reason)) reasons.push(reason);
}

/** Validate only the closed forecast-evidence payload. Signature trust is separate. */
export function validateForecastEvidence(value: unknown): { valid: boolean; reasons: string[]; body: RecordValue | null } {
  const reasons: string[] = [];
  const body = unsignedBody(value);
  if (!exact(body, BODY_KEYS)) return { valid: false, reasons: ['forecast_shape_invalid'], body: null };
  try { canonical(body); } catch { reasons.push('forecast_not_canonicalizable'); }

  add(reasons, body['@version'] === FORECAST_EVIDENCE_VERSION, 'forecast_version_invalid');
  add(reasons, id(body.forecast_id), 'forecast_id_invalid');
  add(reasons, instant(body.generated_at), 'forecast_generated_at_invalid');
  add(reasons, typeof body.action_digest === 'string' && DIGEST.test(body.action_digest), 'forecast_action_digest_invalid');

  add(reasons, exact(body.model, MODEL_KEYS), 'forecast_model_shape_invalid');
  if (exact(body.model, MODEL_KEYS)) {
    add(reasons, id(body.model.provider), 'forecast_model_provider_invalid');
    add(reasons, id(body.model.model_id), 'forecast_model_id_invalid');
    add(reasons, id(body.model.model_version), 'forecast_model_version_invalid');
    add(reasons, id(body.model.checkpoint_id), 'forecast_checkpoint_id_invalid');
    add(reasons, typeof body.model.checkpoint_digest === 'string' && DIGEST.test(body.model.checkpoint_digest), 'forecast_checkpoint_digest_invalid');
  }

  add(reasons, exact(body.adapter, ADAPTER_KEYS), 'forecast_adapter_shape_invalid');
  if (exact(body.adapter, ADAPTER_KEYS)) {
    add(reasons, id(body.adapter.adapter_id), 'forecast_adapter_id_invalid');
    add(reasons, id(body.adapter.adapter_version), 'forecast_adapter_version_invalid');
    add(reasons, typeof body.adapter.config_digest === 'string' && DIGEST.test(body.adapter.config_digest), 'forecast_adapter_config_digest_invalid');
  }

  add(reasons, exact(body.series, SERIES_KEYS), 'forecast_series_shape_invalid');
  if (exact(body.series, SERIES_KEYS)) {
    add(reasons, id(body.series.source_id), 'forecast_series_source_invalid');
    add(reasons, typeof body.series.input_digest === 'string' && DIGEST.test(body.series.input_digest), 'forecast_input_digest_invalid');
    add(reasons, instant(body.series.observed_from), 'forecast_observed_from_invalid');
    add(reasons, instant(body.series.observed_through), 'forecast_observed_through_invalid');
    add(reasons, typeof body.series.frequency === 'string' && stepMilliseconds(body.series.frequency) !== null, 'forecast_series_frequency_invalid');
    add(reasons, Number.isSafeInteger(body.series.point_count)
      && body.series.point_count > 0
      && body.series.point_count <= FORECAST_LIMITS.max_source_points, 'forecast_series_point_count_invalid');
    if (instant(body.series.observed_from) && instant(body.series.observed_through)) {
      add(reasons, Date.parse(body.series.observed_from) <= Date.parse(body.series.observed_through), 'forecast_series_window_invalid');
    }
  }

  add(reasons, exact(body.forecast, FORECAST_KEYS), 'forecast_output_shape_invalid');
  if (exact(body.forecast, FORECAST_KEYS)) {
    add(reasons, body.forecast.target === 'available_curtailment_mw', 'forecast_target_invalid');
    add(reasons, body.forecast.unit === 'MW', 'forecast_unit_invalid');
    add(reasons, instant(body.forecast.horizon_start), 'forecast_horizon_start_invalid');
    add(reasons, instant(body.forecast.horizon_end), 'forecast_horizon_end_invalid');
    const stepMs = stepMilliseconds(body.forecast.step);
    add(reasons, stepMs !== null, 'forecast_step_invalid');
    add(reasons, Array.isArray(body.forecast.points)
      && body.forecast.points.length > 0
      && body.forecast.points.length <= FORECAST_LIMITS.max_points, 'forecast_points_invalid');
    if (Array.isArray(body.forecast.points) && body.forecast.points.length > 0
        && body.forecast.points.length <= FORECAST_LIMITS.max_points) {
      let previous = -Infinity;
      for (const point of body.forecast.points) {
        add(reasons, exact(point, POINT_KEYS), 'forecast_point_shape_invalid');
        if (!exact(point, POINT_KEYS)) continue;
        add(reasons, instant(point.at), 'forecast_point_time_invalid');
        add(reasons, decimal(point.p10) && decimal(point.p50) && decimal(point.p90), 'forecast_point_quantile_invalid');
        if (decimal(point.p10) && decimal(point.p50) && decimal(point.p90)) {
          add(reasons, compareDecimal(point.p10, point.p50) <= 0
            && compareDecimal(point.p50, point.p90) <= 0, 'forecast_quantiles_crossed');
        }
        if (instant(point.at)) {
          const at = Date.parse(point.at);
          add(reasons, at > previous, 'forecast_points_not_strictly_ordered');
          previous = at;
        }
      }
      if (instant(body.forecast.horizon_start) && instant(body.forecast.horizon_end) && stepMs !== null) {
        const points = body.forecast.points;
        add(reasons, points[0]?.at === body.forecast.horizon_start, 'forecast_first_point_mismatch');
        const expectedEnd = Date.parse(points.at(-1)?.at || '') + stepMs;
        add(reasons, expectedEnd === Date.parse(body.forecast.horizon_end), 'forecast_last_point_mismatch');
      }
    }
    add(reasons, exact(body.forecast.action_window, WINDOW_KEYS), 'forecast_action_window_shape_invalid');
    if (exact(body.forecast.action_window, WINDOW_KEYS)) {
      const window = body.forecast.action_window;
      add(reasons, instant(window.not_before) && instant(window.not_after)
        && Date.parse(window.not_before) < Date.parse(window.not_after), 'forecast_action_window_invalid');
      add(reasons, window.aggregation === 'minimum_across_action_window', 'forecast_action_window_aggregation_invalid');
      add(reasons, decimal(window.p10) && decimal(window.p50) && decimal(window.p90), 'forecast_action_window_quantile_invalid');
      if (decimal(window.p10) && decimal(window.p50) && decimal(window.p90)) {
        add(reasons, compareDecimal(window.p10, window.p50) <= 0
          && compareDecimal(window.p50, window.p90) <= 0, 'forecast_action_window_quantiles_crossed');
      }
      if (Array.isArray(body.forecast.points) && body.forecast.points.length > 0
          && body.forecast.points.every((point: any) => exact(point, POINT_KEYS)
            && decimal(point.p10) && decimal(point.p50) && decimal(point.p90))) {
        const inWindow = body.forecast.points.filter((point: any) => instant(point.at)
          && instant(window.not_before) && instant(window.not_after)
          && stepMs !== null
          && Date.parse(point.at) < Date.parse(window.not_after)
          && Date.parse(point.at) + stepMs > Date.parse(window.not_before));
        add(reasons, inWindow.length > 0, 'forecast_action_window_has_no_points');
        if (inWindow.length > 0 && decimal(window.p10) && decimal(window.p50) && decimal(window.p90)) {
          for (const quantile of ['p10', 'p50', 'p90']) {
            const minimum = inWindow.reduce((current: string, point: any) => (
              compareDecimal(point[quantile], current) < 0 ? point[quantile] : current
            ), inWindow[0][quantile]);
            add(reasons, window[quantile] === minimum, 'forecast_action_window_summary_mismatch');
          }
        }
      }
    }
  }

  add(reasons, exact(body.backtest, BACKTEST_KEYS), 'forecast_backtest_shape_invalid');
  if (exact(body.backtest, BACKTEST_KEYS)) {
    add(reasons, body.backtest.method === 'rolling_origin', 'forecast_backtest_method_invalid');
    add(reasons, Number.isSafeInteger(body.backtest.window_count)
      && body.backtest.window_count > 0 && body.backtest.window_count <= 100_000, 'forecast_backtest_window_count_invalid');
    add(reasons, body.backtest.metric === 'MAE', 'forecast_backtest_metric_invalid');
    add(reasons, decimal(body.backtest.value), 'forecast_backtest_value_invalid');
    add(reasons, body.backtest.unit === 'MW', 'forecast_backtest_unit_invalid');
    add(reasons, instant(body.backtest.evaluated_through), 'forecast_backtest_time_invalid');
    add(reasons, typeof body.backtest.code_digest === 'string' && DIGEST.test(body.backtest.code_digest), 'forecast_backtest_code_digest_invalid');
  }

  add(reasons, exact(body.claim_boundary, CLAIM_KEYS), 'forecast_claim_boundary_shape_invalid');
  if (exact(body.claim_boundary, CLAIM_KEYS)) {
    add(reasons, body.claim_boundary.advisory_only === true, 'forecast_must_be_advisory_only');
    add(reasons, body.claim_boundary.never_sole_gate === true, 'forecast_must_never_be_sole_gate');
    add(reasons, body.claim_boundary.physical_truth === 'NOT_ESTABLISHED', 'forecast_physical_truth_overclaim');
    add(reasons, body.claim_boundary.authority === 'NONE', 'forecast_authority_overclaim');
    add(reasons, body.claim_boundary.settlement_input === false, 'forecast_settlement_input_prohibited');
  }

  if (instant(body.generated_at) && exact(body.series, SERIES_KEYS)
      && instant(body.series.observed_through)) {
    add(reasons, Date.parse(body.series.observed_through) <= Date.parse(body.generated_at), 'forecast_generated_before_input');
  }
  if (exact(body.backtest, BACKTEST_KEYS) && instant(body.backtest.evaluated_through)
      && exact(body.series, SERIES_KEYS) && instant(body.series.observed_through)) {
    add(reasons, Date.parse(body.backtest.evaluated_through) <= Date.parse(body.series.observed_through), 'forecast_backtest_after_input');
  }

  return { valid: reasons.length === 0, reasons, body };
}

export function validateForecastPolicy(policy: unknown): policy is ForecastPolicy {
  if (!record(policy)) return false;
  const keys = new Set([
    'required', 'expected_model_id', 'expected_model_version', 'expected_checkpoint_digest',
    'expected_adapter_id', 'expected_adapter_version', 'expected_adapter_config_digest',
    'expected_series_source_id', 'max_forecast_age_sec', 'max_input_age_sec',
    'max_interval_width_mw', 'min_backtest_windows', 'max_backtest_mae_mw',
    'require_target_at_or_below_p10',
  ]);
  return exact(policy, keys)
    && typeof policy.required === 'boolean'
    && id(policy.expected_model_id) && id(policy.expected_model_version)
    && DIGEST.test(policy.expected_checkpoint_digest)
    && id(policy.expected_adapter_id) && id(policy.expected_adapter_version)
    && DIGEST.test(policy.expected_adapter_config_digest)
    && id(policy.expected_series_source_id)
    && Number.isSafeInteger(policy.max_forecast_age_sec) && policy.max_forecast_age_sec > 0
    && Number.isSafeInteger(policy.max_input_age_sec) && policy.max_input_age_sec > 0
    && decimal(policy.max_interval_width_mw)
    && Number.isSafeInteger(policy.min_backtest_windows) && policy.min_backtest_windows > 0
    && decimal(policy.max_backtest_mae_mw)
    && typeof policy.require_target_at_or_below_p10 === 'boolean';
}

/**
 * Apply relying-party policy after native signature verification. The result
 * can only tighten GRACE. It never returns an authorization decision.
 */
export function assessForecastForGrace(value: unknown, {
  policy,
  expected_action_digest,
  expected_action_window,
  action_target_mw,
  now,
}: {
  policy: ForecastPolicy;
  expected_action_digest: string;
  expected_action_window: { not_before: string; not_after: string };
  action_target_mw: string;
  now: string;
}): { valid: boolean; reasons: string[]; evidence_digest: string | null; posture: 'TIGHTEN_ONLY' } {
  const checked = validateForecastEvidence(value);
  const reasons = [...checked.reasons];
  if (!validateForecastPolicy(policy)) reasons.push('forecast_policy_invalid');
  if (!checked.body || !validateForecastPolicy(policy)) {
    return { valid: false, reasons: [...new Set(reasons)], evidence_digest: null, posture: 'TIGHTEN_ONLY' };
  }
  const body = checked.body;
  const window = body.forecast.action_window;
  add(reasons, DIGEST.test(expected_action_digest) && body.action_digest === expected_action_digest, 'forecast_action_substitution');
  add(reasons, instant(now), 'forecast_gate_time_invalid');
  add(reasons, instant(expected_action_window?.not_before)
    && instant(expected_action_window?.not_after)
    && window.not_before === expected_action_window.not_before
    && window.not_after === expected_action_window.not_after, 'forecast_action_window_mismatch');
  add(reasons, body.model.model_id === policy.expected_model_id
    && body.model.model_version === policy.expected_model_version, 'forecast_model_substitution');
  add(reasons, body.model.checkpoint_digest === policy.expected_checkpoint_digest, 'forecast_checkpoint_substitution');
  add(reasons, body.adapter.adapter_id === policy.expected_adapter_id
    && body.adapter.adapter_version === policy.expected_adapter_version, 'forecast_adapter_substitution');
  add(reasons, body.adapter.config_digest === policy.expected_adapter_config_digest, 'forecast_adapter_config_substitution');
  add(reasons, body.series.source_id === policy.expected_series_source_id, 'forecast_series_source_substitution');
  if (instant(now) && instant(body.generated_at)) {
    const age = Date.parse(now) - Date.parse(body.generated_at);
    add(reasons, age >= 0 && age <= policy.max_forecast_age_sec * 1000, 'forecast_stale_or_from_future');
  }
  if (instant(now) && instant(body.series.observed_through)) {
    const age = Date.parse(now) - Date.parse(body.series.observed_through);
    add(reasons, age >= 0 && age <= policy.max_input_age_sec * 1000, 'forecast_input_stale_or_from_future');
  }
  if (instant(body.forecast.horizon_start) && instant(body.forecast.horizon_end)
      && instant(expected_action_window.not_before) && instant(expected_action_window.not_after)) {
    add(reasons, Date.parse(body.forecast.horizon_start) <= Date.parse(expected_action_window.not_before)
      && Date.parse(body.forecast.horizon_end) >= Date.parse(expected_action_window.not_after), 'forecast_horizon_does_not_cover_action');
  }
  if (decimal(policy.max_interval_width_mw) && Array.isArray(body.forecast.points)) {
    const maxWidth = decimalMicros(policy.max_interval_width_mw);
    add(reasons, body.forecast.points.every((point: any) => decimal(point.p10) && decimal(point.p90)
      && subtractDecimal(point.p90, point.p10) <= maxWidth), 'forecast_uncertainty_exceeds_policy');
  }
  add(reasons, body.backtest.window_count >= policy.min_backtest_windows, 'forecast_backtest_sample_too_small');
  if (decimal(body.backtest.value) && decimal(policy.max_backtest_mae_mw)) {
    add(reasons, compareDecimal(body.backtest.value, policy.max_backtest_mae_mw) <= 0, 'forecast_backtest_error_exceeds_policy');
  }
  if (policy.require_target_at_or_below_p10) {
    add(reasons, decimal(action_target_mw) && decimal(window.p10)
      && compareDecimal(action_target_mw, window.p10) <= 0, 'forecast_conservative_capacity_below_action');
  }
  let evidenceDigest: string | null = null;
  try { evidenceDigest = forecastDigest(value); } catch { /* structural reason already recorded */ }
  return {
    valid: reasons.length === 0,
    reasons: [...new Set(reasons)],
    evidence_digest: reasons.length === 0 ? evidenceDigest : null,
    posture: 'TIGHTEN_ONLY',
  };
}

/** Build the unsigned payload from a TimesFM adapter result. */
export function buildTimesFmForecastEvidence({
  forecast_id,
  generated_at,
  action_digest,
  action_window,
  source_id,
  source_observations,
  source_frequency,
  model_version,
  checkpoint_id,
  checkpoint_digest,
  adapter_version,
  adapter_config,
  points,
  step,
  backtest,
}: any = {}): RecordValue {
  if (!Array.isArray(source_observations) || source_observations.length === 0
      || source_observations.length > FORECAST_LIMITS.max_source_points) {
    throw new TypeError('bounded source observations are required');
  }
  const intervalMs = stepMilliseconds(step);
  const ordered = points?.filter((point: any) => instant(point?.at)
    && instant(action_window?.not_before) && instant(action_window?.not_after)
    && intervalMs !== null
    && Date.parse(point.at) < Date.parse(action_window.not_after)
    && Date.parse(point.at) + intervalMs > Date.parse(action_window.not_before));
  if (!Array.isArray(ordered) || ordered.length === 0) throw new TypeError('forecast points must cover the action window');
  const minimum = (quantile: 'p10' | 'p50' | 'p90'): string => ordered.reduce(
    (current: string, point: any) => compareDecimal(point[quantile], current) < 0 ? point[quantile] : current,
    ordered[0][quantile],
  );
  const body = {
    '@version': FORECAST_EVIDENCE_VERSION,
    forecast_id,
    generated_at,
    action_digest,
    model: {
      provider: 'google-research',
      model_id: 'timesfm',
      model_version,
      checkpoint_id,
      checkpoint_digest,
    },
    adapter: {
      adapter_id: TIMESFM_ADAPTER_PROFILE,
      adapter_version,
      config_digest: forecastDigest(adapter_config),
    },
    series: {
      source_id,
      input_digest: forecastDigest(source_observations),
      observed_from: source_observations[0]?.at,
      observed_through: source_observations.at(-1)?.at,
      frequency: source_frequency,
      point_count: source_observations.length,
    },
    forecast: {
      target: 'available_curtailment_mw',
      unit: 'MW',
      horizon_start: points?.[0]?.at,
      horizon_end: new Date(Date.parse(points?.at(-1)?.at) + (stepMilliseconds(step) || 0)).toISOString(),
      step,
      points: structuredClone(points),
      action_window: {
        not_before: action_window?.not_before,
        not_after: action_window?.not_after,
        aggregation: 'minimum_across_action_window',
        p10: minimum('p10'),
        p50: minimum('p50'),
        p90: minimum('p90'),
      },
    },
    backtest: structuredClone(backtest),
    claim_boundary: {
      advisory_only: true,
      never_sole_gate: true,
      physical_truth: 'NOT_ESTABLISHED',
      authority: 'NONE',
      settlement_input: false,
    },
  };
  const checked = validateForecastEvidence(body);
  if (!checked.valid) throw new TypeError(`invalid TimesFM forecast evidence: ${checked.reasons.join(',')}`);
  return body;
}

/**
 * Compare the forecast's declared action-window band with a separately
 * authenticated observed value. This never rewrites the original evidence.
 */
export function reconcileForecastObservation(value: unknown, {
  observed_value_mw,
  observation_digest,
  observed_at,
}: any = {}): RecordValue {
  const checked = validateForecastEvidence(value);
  if (!checked.valid || !checked.body || !decimal(observed_value_mw)
      || typeof observation_digest !== 'string' || !DIGEST.test(observation_digest)
      || !instant(observed_at)) {
    return {
      '@version': FORECAST_RECONCILIATION_VERSION,
      status: 'INDETERMINATE',
      forecast_evidence_digest: null,
      observation_digest: DIGEST.test(observation_digest || '') ? observation_digest : null,
      observed_at: instant(observed_at) ? observed_at : null,
      observed_value_mw: decimal(observed_value_mw) ? observed_value_mw : null,
      reason: checked.reasons[0] || 'observation_invalid',
    };
  }
  const window = checked.body.forecast.action_window;
  const within = compareDecimal(observed_value_mw, window.p10) >= 0
    && compareDecimal(observed_value_mw, window.p90) <= 0;
  return {
    '@version': FORECAST_RECONCILIATION_VERSION,
    status: within ? 'WITHIN_BAND' : 'OUTSIDE_BAND',
    forecast_evidence_digest: forecastDigest(value),
    observation_digest,
    observed_at,
    observed_value_mw,
    expected_band_mw: { p10: window.p10, p90: window.p90 },
    reason: within ? null : 'observed_value_outside_forecast_band',
  };
}
