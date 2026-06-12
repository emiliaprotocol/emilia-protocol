/**
 * AML screening — sanctions/PEP matching, structuring + velocity detection.
 *
 * Pure functions over an in-memory watchlist. EP is not a transaction monitor;
 * this layer adds AML *risk signals* to the guard decision on financial actions
 * so a sanctioned counterparty fails closed and a structuring pattern escalates
 * to accountable signoff. It is the evidence layer beneath the human decision,
 * not a replacement for a bank's BSA/AML program.
 *
 * The bundled watchlist is a small SNAPSHOT for screening logic + tests. In
 * production the list is refreshed from the official feed (OFAC SDN/consolidated,
 * EU/UN lists) by an operations job; `loadWatchlist()` is the injection point.
 * The matching, structuring, and velocity logic here is the part that must be
 * correct regardless of which list is loaded.
 *
 * @license Apache-2.0
 */

import { SANCTIONS_SNAPSHOT } from './watchlist.js';

// ── Name normalization + matching ────────────────────────────────────────────

/** Normalize a name for matching: lowercase, strip punctuation, collapse space. */
export function normalizeName(name) {
  return String(name || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '') // strip diacritics
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenSet(name) {
  return new Set(normalizeName(name).split(' ').filter(Boolean));
}

/** Jaccard token overlap in [0,1] — order-independent name similarity. */
function tokenOverlap(a, b) {
  const sa = tokenSet(a);
  const sb = tokenSet(b);
  if (sa.size === 0 || sb.size === 0) return 0;
  let inter = 0;
  for (const t of sa) if (sb.has(t)) inter++;
  return inter / new Set([...sa, ...sb]).size;
}

/**
 * Screen a counterparty name (and optional country) against the watchlist.
 *
 * @param {string} name
 * @param {object} [opts]
 * @param {string} [opts.country] - ISO-3166 alpha-2; checked against embargoes
 * @param {Array} [opts.list] - watchlist override (defaults to the snapshot)
 * @param {number} [opts.threshold=0.85] - fuzzy match floor
 * @returns {{ hit: boolean, topScore: number, matches: Array, country_blocked: boolean }}
 */
export function screenSanctions(name, opts = {}) {
  const list = opts.list || SANCTIONS_SNAPSHOT;
  const threshold = opts.threshold ?? 0.85;
  const norm = normalizeName(name);

  const matches = [];
  for (const entry of list) {
    const names = [entry.name, ...(entry.aliases || [])];
    let best = 0;
    for (const candidate of names) {
      const exact = normalizeName(candidate) === norm && norm.length > 0;
      const score = exact ? 1 : tokenOverlap(name, candidate);
      if (score > best) best = score;
    }
    if (best >= threshold) {
      matches.push({ name: entry.name, program: entry.program, list: entry.list, type: entry.type, score: Number(best.toFixed(3)) });
    }
  }
  matches.sort((a, b) => b.score - a.score);

  const country = (opts.country || '').toUpperCase();
  const country_blocked = country ? EMBARGOED_COUNTRIES.has(country) : false;

  return {
    hit: matches.length > 0 || country_blocked,
    topScore: matches[0]?.score ?? 0,
    matches,
    country_blocked,
  };
}

// Comprehensive sanctions programs target these jurisdictions (illustrative
// snapshot; production loads the current embargo set with the watchlist).
const EMBARGOED_COUNTRIES = new Set(['IR', 'KP', 'SY', 'CU']);

// ── Structuring + velocity ───────────────────────────────────────────────────

const CTR_THRESHOLD_USD = 10_000; // US Currency Transaction Report threshold

/**
 * Detect structuring: amounts deliberately kept just under a reporting
 * threshold, especially repeatedly. Classic smurfing pattern.
 *
 * @param {number} amount - this transaction
 * @param {number[]} [recentAmounts] - recent amounts for the same counterparty
 * @param {number} [threshold=10000]
 * @returns {{ structuring: boolean, reason?: string, score: number }}
 */
export function detectStructuring(amount, recentAmounts = [], threshold = CTR_THRESHOLD_USD) {
  const justUnder = (x) => x >= threshold * 0.9 && x < threshold;
  const thisJustUnder = typeof amount === 'number' && justUnder(amount);
  const priorsJustUnder = (recentAmounts || []).filter(justUnder).length;

  // Repeated near-threshold transfers, or a single near-threshold transfer
  // following others, is a structuring signal.
  if (thisJustUnder && priorsJustUnder >= 1) {
    return { structuring: true, score: Math.min(1, 0.5 + priorsJustUnder * 0.2), reason: `${priorsJustUnder + 1} transfers of $${threshold * 0.9}-$${threshold} (just under the $${threshold} reporting threshold).` };
  }
  if (thisJustUnder) {
    return { structuring: false, score: 0.4, reason: `Single transfer just under the $${threshold} reporting threshold.` };
  }
  // Aggregation: several sub-threshold transfers summing over the threshold in
  // the window.
  const windowSum = (recentAmounts || []).reduce((s, x) => s + (x || 0), 0) + (amount || 0);
  if (priorsJustUnder >= 2 && windowSum >= threshold) {
    return { structuring: true, score: 0.7, reason: `${priorsJustUnder} recent near-threshold transfers aggregating to $${windowSum}.` };
  }
  return { structuring: false, score: 0 };
}

/**
 * Velocity: an unusual count of transfers in the window.
 * @param {number[]} recentAmounts
 * @param {number} [maxInWindow=10]
 */
export function detectVelocity(recentAmounts = [], maxInWindow = 10) {
  const count = (recentAmounts || []).length + 1;
  return { high_velocity: count > maxInWindow, count };
}

// ── Aggregate screening for a guard action ───────────────────────────────────

/**
 * Aggregate AML screening for a financial guard action.
 *
 * @param {object} aml - AML context attached to the guard input
 * @param {string} [aml.counterpartyName]
 * @param {string} [aml.counterpartyCountry]
 * @param {number} [aml.amount]
 * @param {number[]} [aml.recentAmounts]
 * @returns {{ recommendation:'allow'|'signoff'|'deny', risk:'none'|'elevated'|'blocked', signals:string[], detail:object }}
 */
export function screenAml(aml) {
  if (!aml || typeof aml !== 'object') {
    return { recommendation: 'allow', risk: 'none', signals: [], detail: {} };
  }
  const signals = [];
  const detail = {};

  if (aml.counterpartyName || aml.counterpartyCountry) {
    const s = screenSanctions(aml.counterpartyName || '', { country: aml.counterpartyCountry });
    detail.sanctions = s;
    if (s.matches.length) signals.push(`sanctions_match:${s.matches[0].name} (${s.matches[0].program}, score ${s.matches[0].score})`);
    if (s.country_blocked) signals.push(`embargoed_jurisdiction:${aml.counterpartyCountry}`);
    if (s.hit) {
      // A sanctions hit fails closed — no signoff path. OFAC blocking is not a
      // discretionary approval.
      return { recommendation: 'deny', risk: 'blocked', signals, detail };
    }
  }

  if (typeof aml.amount === 'number') {
    const st = detectStructuring(aml.amount, aml.recentAmounts);
    detail.structuring = st;
    if (st.structuring) signals.push(`structuring:${st.reason}`);
    const vel = detectVelocity(aml.recentAmounts);
    detail.velocity = vel;
    if (vel.high_velocity) signals.push(`high_velocity:${vel.count} transfers in window`);

    if (st.structuring || vel.high_velocity) {
      return { recommendation: 'signoff', risk: 'elevated', signals, detail };
    }
    if (st.score >= 0.4) {
      // A single near-threshold transfer is a soft signal: surface it, escalate
      // to signoff so a human owns it, but it is not a block.
      signals.push('near_threshold_amount');
      return { recommendation: 'signoff', risk: 'elevated', signals, detail };
    }
  }

  return { recommendation: 'allow', risk: 'none', signals, detail };
}
