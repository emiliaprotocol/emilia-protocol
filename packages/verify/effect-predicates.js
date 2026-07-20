// SPDX-License-Identifier: Apache-2.0
/**
 * EP-OUTCOME-BINDING-v1 — predicted-effects predicates + divergence evaluation.
 *
 * THE GAP THIS BOUNDS
 * -------------------
 * Every receipt in the stack proves approval of BYTES: the exact canonical
 * action a human signed. What the action then DID to the world is unproven.
 * This module bounds that residual (it does not close it):
 *
 *   1. PREDICTED EFFECTS — an array inside the receipt payload the human
 *      signs: [{effect_type, target, predicate}], where each predicate is one
 *      of a CLOSED op set (eq | lte | gte | range | set_eq | count_lte |
 *      absent). The array is canonicalized (JCS-style, byte-identical to
 *      evidence-graph.js canon()) and digested: predicted_effects_digest.
 *
 *   2. DIVERGENCE EVALUATION — a deterministic, pure comparison of the signed
 *      predictions against executor-attested observed effects, yielding a
 *      CLOSED outcome set: in_bounds | divergent | incomparable.
 *
 * FAIL-CLOSED RULES (each is load-bearing)
 * - Comparison values are STRINGS, never JSON numbers — the same
 *   canonicalization-malleability rule amounts follow everywhere in EP
 *   (a number re-serializes; a string is the byte the human signed). A
 *   numeric value anywhere makes the evaluation 'incomparable' (a refusal
 *   with a reason), NEVER a pass.
 * - Numeric ordering (lte/gte/range/count_lte) is exact decimal-string
 *   comparison — pure string math, no floats, so "9007199254740993" and
 *   "0.1" compare correctly and replay identically everywhere.
 * - A predicate with no matching observed effect (or an ambiguous /
 *   malformed one) is 'incomparable' — missing observation is a refusal,
 *   never a silent pass. The one exception is derived counts: count_lte
 *   counts matches (zero is a valid count) and absent REQUIRES zero matches.
 * - Unknown predicate ops and unknown members are malformed on both sides.
 *   Operational metadata belongs in a separately typed evidence component.
 * - Outcome precedence: divergent > incomparable > in_bounds. A proven
 *   divergence is never masked by a neighboring incomparable predicate; both
 *   classes drive the same downstream downgrade ('conflicted' at the graph
 *   layer), so precedence never converts a refusal into a pass.
 *
 * WHAT THIS DOES NOT PROVE: the observed effects are an EXECUTOR CLAIM. A
 * lying executor defeats observation; this module makes divergence
 * machine-detectable and attributable, not impossible. Tolerance bounds are
 * policy: wide bounds prove little.
 */
import crypto from 'node:crypto';

export const PREDICATE_OPS = Object.freeze([
  'eq',        // observed value is exactly the predicted string
  'lte',       // observed decimal-string value <= predicted value
  'gte',       // observed decimal-string value >= predicted value
  'range',     // predicted min <= observed value <= predicted max
  'set_eq',    // observed values (as a set) equal the predicted set
  'count_lte', // number of matching observed effects <= predicted value
  'absent',    // NO observed effect may match (effect_type, target)
]);

export const DIVERGENCE_OUTCOMES = Object.freeze([
  'in_bounds', 'divergent', 'incomparable',
]);
export const MAX_PREDICTED_EFFECTS = 64;
export const MAX_OBSERVED_EFFECTS = 256;
export const MAX_EFFECT_STRING_LENGTH = 512;

// Deterministic JCS-style canonicalization (I-JSON subset; no floats) —
// byte-identical to lib/evidence/evidence-graph.js canon().
function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
}
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const tooLong = (value) => typeof value === 'string'
  && [...value].length > MAX_EFFECT_STRING_LENGTH;

/**
 * Digest of a predicted-effects array: sha256 over its canonical bytes.
 * This is the value the receipt payload binds as predicted_effects_digest.
 */
export function predictedEffectsDigest(predictedEffects) {
  return `sha256:${sha256hex(canon(predictedEffects))}`;
}

// ── Exact decimal-string comparison (no floats, ever) ───────────────────────

// Canonical decimal: optional sign, no leading zeros on the integer part,
// optional fraction. Trailing fraction zeros are tolerated ("1.50") and
// normalized for comparison; "01" is rejected (not canonical).
function splitDecimal(s) {
  if (typeof s !== 'string') return null;
  const m = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(s);
  if (!m) return null;
  const out = { neg: m[1] === '-', int: m[2], frac: (m[3] || '').replace(/0+$/, '') };
  if (out.int === '0' && out.frac === '') out.neg = false; // -0 == 0
  return out;
}

/** Is s a decimal string this module can order exactly? */
export function isDecimalString(s) {
  return splitDecimal(s) !== null;
}

/**
 * Exact ordering of two decimal strings: -1 | 0 | 1, or null when either
 * input is not a decimal string (callers MUST treat null as incomparable,
 * never as equality — fail closed).
 */
export function compareDecimalStrings(a, b) {
  const A = splitDecimal(a);
  const B = splitDecimal(b);
  if (!A || !B) return null;
  if (A.neg !== B.neg) return A.neg ? -1 : 1;
  let mag;
  if (A.int.length !== B.int.length) mag = A.int.length < B.int.length ? -1 : 1;
  else if (A.int !== B.int) mag = A.int < B.int ? -1 : 1;
  else {
    const len = Math.max(A.frac.length, B.frac.length);
    const af = A.frac.padEnd(len, '0');
    const bf = B.frac.padEnd(len, '0');
    mag = af < bf ? -1 : af > bf ? 1 : 0;
  }
  return A.neg ? -mag : mag;
}

// ── Structural validation of the SIGNED prediction array ────────────────────

const ENTRY_KEYS = Object.freeze(['effect_type', 'target', 'predicate']);
const OBSERVED_ENTRY_KEYS = Object.freeze(['effect_type', 'target', 'value', 'values']);
const PREDICATE_KEYS = Object.freeze({
  eq: ['op', 'value'],
  lte: ['op', 'value'],
  gte: ['op', 'value'],
  range: ['op', 'min', 'max'],
  set_eq: ['op', 'values'],
  count_lte: ['op', 'value'],
  absent: ['op'],
});

/**
 * Validate a predicted_effects array structurally. Returns {ok, reasons}.
 * Strict on the SIGNED side: unknown ops, unknown members, and numeric
 * comparison values are all malformed (fail closed — never evaluate a
 * prediction whose intent this evaluator might silently misread).
 */
export function validatePredictedEffects(predicted) {
  const reasons = [];
  const bad = (why) => { reasons.push(why); };
  if (!Array.isArray(predicted) || predicted.length === 0) {
    return { ok: false, reasons: ['predicted_effects must be a non-empty array'] };
  }
  if (predicted.length > MAX_PREDICTED_EFFECTS) {
    return { ok: false, reasons: [`predicted_effects exceeds the ${MAX_PREDICTED_EFFECTS}-entry limit`] };
  }
  predicted.forEach((entry, i) => {
    const at = `predicted_effects[${i}]`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return bad(`${at} is not an object`);
    for (const k of Object.keys(entry)) {
      if (!ENTRY_KEYS.includes(k)) return bad(`${at} has unknown member "${k}"`);
    }
    if (typeof entry.effect_type !== 'string' || !entry.effect_type || tooLong(entry.effect_type)) {
      return bad(`${at}.effect_type must be a non-empty string of at most ${MAX_EFFECT_STRING_LENGTH} characters`);
    }
    if (typeof entry.target !== 'string' || !entry.target || tooLong(entry.target)) {
      return bad(`${at}.target must be a non-empty string of at most ${MAX_EFFECT_STRING_LENGTH} characters`);
    }
    if (entry.target.includes('*')) {
      return bad(`${at}.target contains "*"; EP-OUTCOME-BINDING-v1 targets are literal identifiers, not patterns`);
    }
    const p = entry.predicate;
    if (!p || typeof p !== 'object' || Array.isArray(p)) return bad(`${at}.predicate is not an object`);
    if (!PREDICATE_OPS.includes(p.op)) return bad(`${at}.predicate.op "${p.op}" is not a known op`);
    const allowed = PREDICATE_KEYS[p.op];
    for (const k of Object.keys(p)) {
      if (!allowed.includes(k)) return bad(`${at}.predicate (op ${p.op}) has unknown member "${k}"`);
    }
    if (p.op === 'eq') {
      if (typeof p.value === 'number') return bad(`${at}.predicate.value is a number; comparison values MUST be strings (canonicalization malleability)`);
      if (typeof p.value !== 'string' || tooLong(p.value)) return bad(`${at}.predicate.value must be a bounded string`);
    }
    if (p.op === 'lte' || p.op === 'gte') {
      if (typeof p.value === 'number') return bad(`${at}.predicate.value is a number; comparison values MUST be strings (canonicalization malleability)`);
      if (typeof p.value !== 'string' || tooLong(p.value) || !isDecimalString(p.value)) return bad(`${at}.predicate.value must be a bounded decimal string`);
    }
    if (p.op === 'range') {
      let broke = false;
      for (const f of ['min', 'max']) {
        if (typeof p[f] === 'number') { bad(`${at}.predicate.${f} is a number; comparison values MUST be strings (canonicalization malleability)`); broke = true; }
        else if (typeof p[f] !== 'string' || tooLong(p[f]) || !isDecimalString(p[f])) { bad(`${at}.predicate.${f} must be a bounded decimal string`); broke = true; }
      }
      if (!broke && compareDecimalStrings(p.min, p.max) === 1) bad(`${at}.predicate range has min > max`);
    }
    if (p.op === 'set_eq') {
      if (!Array.isArray(p.values) || p.values.length > MAX_OBSERVED_EFFECTS) return bad(`${at}.predicate.values must be a bounded array of strings`);
      for (const v of p.values) {
        if (typeof v === 'number') return bad(`${at}.predicate.values contains a number; comparison values MUST be strings (canonicalization malleability)`);
        if (typeof v !== 'string' || tooLong(v)) return bad(`${at}.predicate.values must contain only bounded strings`);
      }
    }
    if (p.op === 'count_lte') {
      if (typeof p.value === 'number') return bad(`${at}.predicate.value is a number; comparison values MUST be strings (canonicalization malleability)`);
      if (typeof p.value !== 'string' || tooLong(p.value) || !/^(0|[1-9][0-9]*)$/.test(p.value)) return bad(`${at}.predicate.value must be a bounded non-negative integer string`);
    }
  });
  return { ok: reasons.length === 0, reasons };
}

function validateObservedEffects(observed) {
  const reasons = [];
  const bad = (why) => { reasons.push(why); };
  if (!Array.isArray(observed)) {
    return { ok: false, reasons: ['observed_effects is missing or not an array (refusal, never a pass)'] };
  }
  if (observed.length > MAX_OBSERVED_EFFECTS) {
    return { ok: false, reasons: [`observed_effects exceeds the ${MAX_OBSERVED_EFFECTS}-entry limit`] };
  }
  observed.forEach((entry, i) => {
    const at = `observed_effects[${i}]`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      bad(`${at} is not an object`);
      return;
    }
    for (const member of Object.keys(entry)) {
      if (!OBSERVED_ENTRY_KEYS.includes(member)) bad(`${at} has unknown member "${member}"`);
    }
    if (typeof entry.effect_type !== 'string' || !entry.effect_type || tooLong(entry.effect_type)) {
      bad(`${at}.effect_type must be a non-empty bounded string`);
    }
    if (typeof entry.target !== 'string' || !entry.target || tooLong(entry.target)
        || entry.target.includes('*')) {
      bad(`${at}.target must be a bounded literal identifier`);
    }
    const hasValue = Object.hasOwn(entry, 'value');
    const hasValues = Object.hasOwn(entry, 'values');
    if (hasValue === hasValues) bad(`${at} must carry exactly one of value or values`);
    if (hasValue && typeof entry.value === 'number') {
      bad(`${at}.value is a number; observed values MUST be strings`);
    } else if (hasValue && (typeof entry.value !== 'string' || tooLong(entry.value))) {
      bad(`${at}.value must be a bounded string`);
    }
    if (hasValues && (!Array.isArray(entry.values)
        || entry.values.length > MAX_OBSERVED_EFFECTS)) {
      bad(`${at}.values must be a bounded array`);
    } else if (hasValues) {
      for (const value of entry.values) {
        if (typeof value !== 'string' || tooLong(value)) {
          bad(`${at}.values MUST be strings of bounded length`);
        }
      }
    }
  });
  return { ok: reasons.length === 0, reasons };
}

// ── Divergence evaluation ────────────────────────────────────────────────────

const key = (effectType, target) => `${effectType} on ${target}`;

// Evaluate ONE prediction entry against its matching observed entries.
// Returns { outcome, reason } with outcome in DIVERGENCE_OUTCOMES.
function evaluateEntry(entry, matches) {
  const { predicate: p } = entry;
  const at = key(entry.effect_type, entry.target);
  const inBounds = { outcome: 'in_bounds', reason: null };
  const divergent = (reason) => ({ outcome: 'divergent', reason });
  const incomparable = (reason) => ({ outcome: 'incomparable', reason });

  if (p.op === 'absent') {
    return matches.length === 0
      ? inBounds
      : divergent(`predicted absent for ${at}, observed ${matches.length} effect(s)`);
  }
  if (p.op === 'count_lte') {
    const count = String(matches.length);
    // count is always a valid non-negative integer decimal string, and
    // p.value was already structurally validated as a decimal string for
    // count_lte in validatePredictedEffects (which ran before this entry
    // was ever reached) — the comparison cannot be null here.
    const cmp = /** @type {number} */ (compareDecimalStrings(count, p.value));
    return cmp <= 0
      ? inBounds
      : divergent(`predicted count <= ${p.value} for ${at}, observed ${count}`);
  }
  // All remaining ops compare against exactly ONE observed effect.
  if (matches.length === 0) return incomparable(`no observed effect for ${at}`);
  if (matches.length > 1) return incomparable(`ambiguous: ${matches.length} observed effects match ${at}`);
  const obs = matches[0];

  if (p.op === 'set_eq') {
    if (!Array.isArray(obs.values)) return incomparable(`observed effect for ${at} has no values array`);
    for (const v of obs.values) {
      if (typeof v !== 'string') return incomparable(`observed values for ${at} contain a non-string (values MUST be strings)`);
    }
    const want = [...new Set(p.values)].sort();
    const got = [...new Set(obs.values)].sort();
    return canon(want) === canon(got)
      ? inBounds
      : divergent(`predicted set_eq [${want.join(',')}] for ${at}, observed [${got.join(',')}]`);
  }

  // eq / lte / gte / range read obs.value, which MUST be a string.
  if (typeof obs.value === 'number') return incomparable(`observed value for ${at} is a number; values MUST be strings (canonicalization malleability)`);
  if (typeof obs.value !== 'string') return incomparable(`observed effect for ${at} has no string value`);

  if (p.op === 'eq') {
    return obs.value === p.value
      ? inBounds
      : divergent(`predicted eq "${p.value}" for ${at}, observed "${obs.value}"`);
  }
  // Ordered ops: the observed value must itself be an exact decimal string.
  if (!isDecimalString(obs.value)) return incomparable(`observed value "${obs.value}" for ${at} is not a decimal string`);
  // obs.value was just confirmed a decimal string above (isDecimalString
  // check), and p.value / p.min / p.max were structurally validated as
  // decimal strings for their respective ops in validatePredictedEffects
  // (which ran before this entry was ever reached) — none of these
  // comparisons can be null here.
  if (p.op === 'lte') {
    const cmp = /** @type {number} */ (compareDecimalStrings(obs.value, p.value));
    return cmp <= 0
      ? inBounds
      : divergent(`predicted <= ${p.value} for ${at}, observed ${obs.value}`);
  }
  if (p.op === 'gte') {
    const cmp = /** @type {number} */ (compareDecimalStrings(obs.value, p.value));
    return cmp >= 0
      ? inBounds
      : divergent(`predicted >= ${p.value} for ${at}, observed ${obs.value}`);
  }
  // range
  const cmpMin = /** @type {number} */ (compareDecimalStrings(obs.value, p.min));
  if (cmpMin < 0) return divergent(`predicted range [${p.min}, ${p.max}] for ${at}, observed ${obs.value} (below min)`);
  const cmpMax = /** @type {number} */ (compareDecimalStrings(obs.value, p.max));
  if (cmpMax > 0) return divergent(`predicted range [${p.min}, ${p.max}] for ${at}, observed ${obs.value} (above max)`);
  return inBounds;
}

/**
 * Evaluate a signed predicted_effects array against executor-attested
 * observed effects. Pure and deterministic: same inputs -> same outcome,
 * same reasons, in the same order (replayable by any third party).
 *
 * @param {Array} predicted  [{effect_type, target, predicate}] — the array
 *                           the human signed (validated strictly here).
 * @param {Array} observed   [{effect_type, target, value?|values?}] —
 *                           executor-attested closed objects.
 * @returns {{ outcome: 'in_bounds'|'divergent'|'incomparable',
 *            results: Array<{effect_type,target,op,outcome,reason}>,
 *            reasons: string[] }}
 */
export function evaluatePredictedEffects(predicted, observed) {
  const structural = validatePredictedEffects(predicted);
  if (!structural.ok) {
    return {
      outcome: 'incomparable',
      results: [],
      reasons: structural.reasons.map((r) => `malformed predicted_effects: ${r}`),
    };
  }
  const observedStructural = validateObservedEffects(observed);
  if (!observedStructural.ok) {
    return {
      outcome: 'incomparable',
      results: [],
      reasons: observedStructural.reasons.map((reason) => `malformed observed_effects: ${reason}`),
    };
  }
  const results = predicted.map((entry) => {
    const matches = observed.filter(
      (o) => o && typeof o === 'object' && o.effect_type === entry.effect_type && o.target === entry.target,
    );
    const { outcome, reason } = evaluateEntry(entry, matches);
    return { effect_type: entry.effect_type, target: entry.target, op: entry.predicate.op, outcome, reason };
  });
  const reasons = results.filter((r) => r.reason).map((r) => r.reason);
  // Precedence: divergent > incomparable > in_bounds. Both non-pass classes
  // downgrade identically downstream; a proven divergence is never masked.
  const outcome = results.some((r) => r.outcome === 'divergent') ? 'divergent'
    : results.some((r) => r.outcome === 'incomparable') ? 'incomparable'
      : 'in_bounds';
  return { outcome, results, reasons };
}
