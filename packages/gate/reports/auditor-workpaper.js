// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — auditor control-testing workpaper (ITGC / SOX-shaped).
 *
 * The artifact an external auditor's control test consumes: a pinned population
 * of guarded gate decisions over a period, a deterministic (seed-reproducible,
 * RNG-free) attribute sample, per-item attribute observations tied to named
 * evidence-log fields, and an exception list — computed from the gate's
 * tamper-evident evidence log. Pure function: same entries + same options in,
 * identical JSON out (pin `now` for a byte-stable artifact).
 *
 * HONESTY BOUNDARY (carried inside the artifact): this workpaper SUPPORTS the
 * auditor's control test. It never performs, reviews, or concludes the test —
 * the sign-off fields are ALWAYS emitted null and rendered as blanks for the
 * auditor to complete. A refusal (deny decision) is the deny-by-default control
 * operating as designed and is NOT a control exception.
 *
 * Fail closed: missing client/engagement/control reference, an invalid or
 * inverted period, a non-integer sample size, or a missing sample seed is an
 * error, not a guess. Entries that cannot be verified as log records are
 * EXCLUDED from the population and surfaced as integrity_warnings — the
 * workpaper never samples what it cannot account for. Window is half-open
 * [periodStart, periodEnd): an entry stamped exactly at periodEnd belongs to
 * the NEXT period, so adjacent workpapers never double-count.
 */

import crypto from 'node:crypto';

export const AUDIT_WORKPAPER_VERSION = 'EP-GATE-AUDIT-WORKPAPER-v1';

/**
 * Mandatory honesty header. Present verbatim in every workpaper and every
 * rendered view; a document without it is not an EP-GATE-AUDIT-WORKPAPER-v1.
 */
export const AUDIT_WORKPAPER_HONESTY_NOTICE =
  'This workpaper was prepared from the deploying organization\'s tamper-evident '
  + 'evidence log to SUPPORT control testing. It supplies the population, a '
  + 'reproducible sample, and per-item attribute observations; it does not perform '
  + 'the test. The auditor performs and concludes the test and remains responsible '
  + 'for sample evaluation and any conclusion drawn. This is not an audit opinion, '
  + 'and nothing in this document constitutes a conclusion, certification, or '
  + 'attestation by the preparer or by EMILIA Gate.';

/**
 * Refusal treatment is a structural statement of the format, not commentary:
 * a denial is the control WORKING, so it can never be a control exception.
 */
export const REFUSAL_TREATMENT =
  'A refusal (deny decision) is the deny-by-default control operating as designed: '
  + 'the gate withheld execution. Refusals are therefore NOT control exceptions. '
  + 'Attributes A1-A5 describe properties of a granted authorization and are recorded '
  + 'as not_applicable on refusals; only A6 (the refusal was durably logged in the '
  + 'tamper-evident chain) is tested on a refusal.';

/**
 * The attribute test plan. Each attribute names the evidence-log field(s) the
 * observation is read from, so the auditor can retrace every pass/fail to the
 * underlying record. Missing or malformed evidence FAILS the attribute — an
 * observation the log cannot support is never presumed to pass.
 */
export const AUDIT_ATTRIBUTES = [
  {
    id: 'A1',
    name: 'receipt_verified_against_pinned_issuer',
    evidence_field: 'signer',
    test: 'The decision records the pinned issuer key that verified the receipt signature. The gate sets `signer` only after Ed25519 verification against pinned/registry issuer keys; an allow without a recorded signer fails.',
  },
  {
    id: 'A2',
    name: 'credited_assurance_tier_meets_required',
    evidence_field: 'have_tier, required_tier',
    test: 'The cryptographically credited assurance tier meets or exceeds the tier the manifest requires for this action. An unknown or missing tier on either side fails (fail closed).',
  },
  {
    id: 'A3',
    name: 'not_a_replay',
    evidence_field: 'reason, receipt_id',
    test: 'The authorization was granted on a fresh presentation: the decision reason is `allow` and a stable issuer-generated receipt_id (the replay-defense key) is present. Without a receipt_id, replay detection is impossible for this decision.',
  },
  {
    id: 'A4',
    name: 'one_time_consumption_recorded',
    evidence_field: 'consumption_mode',
    test: 'One-time consumption of the receipt was actually recorded (`consume` or `reserve`). Mode `none` means replay defense was explicitly bypassed for this decision and fails.',
  },
  {
    id: 'A5',
    name: 'named_principal_present',
    evidence_field: 'subject',
    test: 'A named principal (the receipt subject) is recorded on the decision, attributing the authorization to a human identity as pinned by the deployer.',
  },
  {
    id: 'A6',
    name: 'decision_logged_tamper_evident',
    evidence_field: 'hash, prev_hash, seq',
    test: 'The decision is a well-formed record of the hash-chained evidence log: 64-hex record hash, non-empty prev_hash, non-negative integer seq.',
  },
];

const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };
const HEX64 = /^[0-9a-f]{64}$/;

function sha256hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function toMs(t) {
  if (t == null) return null;
  const ms = typeof t === 'number' ? t : Date.parse(t);
  return Number.isFinite(ms) ? ms : null;
}

function nonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

/* ------------------------- attribute observations ------------------------ */

function observeA1(e) {
  return { pass: nonEmptyString(e.signer), observed: nonEmptyString(e.signer) ? e.signer : 'signer absent' };
}
function observeA2(e) {
  const have = e.have_tier;
  const req = e.required_tier;
  const pass = nonEmptyString(have) && nonEmptyString(req)
    && TIER_RANK[have] !== undefined && TIER_RANK[req] !== undefined
    && TIER_RANK[have] >= TIER_RANK[req];
  return { pass, observed: `credited=${have ?? 'absent'} required=${req ?? 'absent'}` };
}
function observeA3(e) {
  const pass = e.reason === 'allow' && nonEmptyString(e.receipt_id);
  return { pass, observed: `reason=${e.reason ?? 'absent'} receipt_id=${nonEmptyString(e.receipt_id) ? e.receipt_id : 'absent'}` };
}
function observeA4(e) {
  const pass = e.consumption_mode === 'consume' || e.consumption_mode === 'reserve';
  return { pass, observed: `consumption_mode=${e.consumption_mode ?? 'absent'}` };
}
function observeA5(e) {
  return { pass: nonEmptyString(e.subject), observed: nonEmptyString(e.subject) ? e.subject : 'subject absent' };
}
function observeA6(e) {
  const pass = nonEmptyString(e.hash) && HEX64.test(e.hash)
    && nonEmptyString(e.prev_hash)
    && Number.isInteger(e.seq) && e.seq >= 0;
  return {
    pass,
    observed: `hash=${nonEmptyString(e.hash) && HEX64.test(e.hash) ? 'well-formed' : 'malformed'} prev_hash=${nonEmptyString(e.prev_hash) ? 'present' : 'absent'} seq=${Number.isInteger(e.seq) ? e.seq : 'absent'}`,
  };
}

const OBSERVERS = { A1: observeA1, A2: observeA2, A3: observeA3, A4: observeA4, A5: observeA5, A6: observeA6 };

/** Attributes tested even on a refusal (the refusal itself must be accounted for). */
const REFUSAL_TESTED = new Set(['A6']);

function testItem(e) {
  const isRefusal = e.allow === false;
  const attributes = AUDIT_ATTRIBUTES.map((a) => {
    if (isRefusal && !REFUSAL_TESTED.has(a.id)) {
      return {
        id: a.id,
        name: a.name,
        evidence_field: a.evidence_field,
        result: 'not_applicable',
        observed: `refusal (reason=${e.reason ?? 'unspecified'}) — control operated as designed; attribute describes a granted authorization`,
      };
    }
    const { pass, observed } = OBSERVERS[a.id](e);
    return { id: a.id, name: a.name, evidence_field: a.evidence_field, result: pass ? 'pass' : 'fail', observed };
  });
  return {
    hash: e.hash,
    seq: Number.isInteger(e.seq) ? e.seq : null,
    at: e.at,
    action: nonEmptyString(e.action) ? e.action : null,
    verdict: isRefusal ? 'refusal' : 'allow',
    reason: nonEmptyString(e.reason) ? e.reason : null,
    attributes,
  };
}

/* --------------------------------- build --------------------------------- */

/**
 * Build the control-testing workpaper over a slice of the evidence log.
 *
 * Population = every well-formed guarded decision entry in the half-open
 * window [periodStart, periodEnd). `population_hash` pins the population
 * itself: sha256 over the lexicographically sorted entry hashes, newline-
 * joined — the auditor can recompute it from the listed items.
 *
 * Sampling is deterministic and RNG-free: for each population entry compute
 * sha256(sampleSeed + entry_hash) as lowercase hex; order ascending (ties
 * broken by entry hash); select the first sampleSize entries. Reproducible by
 * the auditor from the same seed and the same population. sampleSize >= the
 * population size selects the full population ("100% examination").
 *
 * @param {Array<object>} entries  evidence.all() (or a durable export of it)
 * @param {object} [o]
 * @param {string} [o.client]       audit client / deploying organization (required)
 * @param {string} [o.engagement]   engagement reference (required)
 * @param {string} [o.controlRef]   control identifier under test (required)
 * @param {string|number} [o.periodStart]  inclusive window start (ISO or epoch ms)
 * @param {string|number} [o.periodEnd]    EXCLUSIVE window end (ISO or epoch ms)
 * @param {number} [o.sampleSize]   positive integer sample size (required)
 * @param {string} [o.sampleSeed]   seed pinning the sample selection (required)
 * @param {number|Function} [o.now=Date.now]  clock for generated_at (pin for determinism)
 * @returns {object} EP-GATE-AUDIT-WORKPAPER-v1 document
 */
export function buildAuditWorkpaper(entries = [], {
  client, engagement, controlRef, periodStart, periodEnd, sampleSize, sampleSeed, now = Date.now,
} = {}) {
  if (!Array.isArray(entries)) throw new Error('audit workpaper: entries must be an array (evidence.all())');
  if (!nonEmptyString(client)) throw new Error('audit workpaper: client is required');
  if (!nonEmptyString(engagement)) throw new Error('audit workpaper: engagement is required');
  if (!nonEmptyString(controlRef)) throw new Error('audit workpaper: controlRef is required');
  const startMs = toMs(periodStart);
  const endMs = toMs(periodEnd);
  if (startMs == null || endMs == null) {
    throw new Error('audit workpaper: periodStart and periodEnd must be ISO timestamps or epoch ms');
  }
  if (endMs <= startMs) throw new Error('audit workpaper: empty or inverted period (periodEnd must be after periodStart)');
  if (!Number.isInteger(sampleSize) || /** @type {number} */ (sampleSize) < 1) {
    throw new Error('audit workpaper: sampleSize must be a positive integer');
  }
  if (!nonEmptyString(sampleSeed)) {
    throw new Error('audit workpaper: sampleSeed is required — the sample must be reproducible by the auditor');
  }

  // Scope + integrity pass. Out-of-window records are out of scope; records we
  // cannot verify as log entries are warned AND excluded — never sampled over.
  const warnings = [];
  const population = []; // guarded decision entries, in supplied (log) order
  let inWindow = 0;
  let outsideWindow = 0;
  let notGuarded = 0;
  let executions = 0;
  entries.forEach((e, index) => {
    const ref = { index, seq: e && typeof e === 'object' && Number.isInteger(e.seq) ? e.seq : null };
    if (!e || typeof e !== 'object' || Array.isArray(e)) { warnings.push({ ...ref, problem: 'not_an_object' }); return; }
    // An entry whose timestamp cannot be parsed cannot be placed in ANY period;
    // it is warned, never silently assigned in or out of the window.
    const t = toMs(e.at);
    if (t == null) { warnings.push({ ...ref, problem: 'missing_or_unparseable_at' }); return; }
    if (t < startMs || t >= endMs) { outsideWindow += 1; return; }
    if (!nonEmptyString(e.hash)) { warnings.push({ ...ref, problem: 'missing_hash' }); return; }
    if (e.kind !== 'decision' && e.kind !== 'execution') { warnings.push({ ...ref, problem: 'unknown_kind', kind: e.kind ?? null }); return; }
    inWindow += 1;
    if (e.kind === 'execution') { executions += 1; return; }
    if (typeof e.allow !== 'boolean') { warnings.push({ ...ref, problem: 'decision_missing_allow' }); inWindow -= 1; return; }
    if (e.reason === 'not_guarded') { notGuarded += 1; return; } // ran OUTSIDE the control — not in the tested population
    population.push(e);
  });

  // Pin the population itself: order-independent hash over the entry hashes.
  const popHashes = population.map((e) => e.hash);
  const populationHash = sha256hex([...popHashes].sort().join('\n'));

  // Deterministic, RNG-free sampling — reproducible from (seed, population).
  const keyed = population
    .map((e) => ({ e, key: sha256hex(sampleSeed + e.hash) }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : (a.e.hash < b.e.hash ? -1 : 1)));
  const fullPopulation = /** @type {number} */ (sampleSize) >= population.length;
  const selected = fullPopulation ? keyed : keyed.slice(0, sampleSize);

  const testedItems = selected.map(({ e }) => testItem(e));

  // Exceptions = failed attributes on sampled items. Refusals cannot produce
  // A1-A5 exceptions by construction (not_applicable) — see REFUSAL_TREATMENT.
  const exceptions = [];
  for (const item of testedItems) {
    for (const a of item.attributes) {
      if (a.result === 'fail') {
        exceptions.push({
          entry_hash: item.hash,
          seq: item.seq,
          at: item.at,
          action: item.action,
          attribute: a.id,
          name: a.name,
          evidence_field: a.evidence_field,
          observed: a.observed,
        });
      }
    }
  }

  // Chain head at export time: the last supplied entry carrying a hash.
  let chainHead = null;
  for (let i = entries.length - 1; i >= 0; i -= 1) {
    const e = entries[i];
    if (e && typeof e === 'object' && nonEmptyString(e.hash)) { chainHead = e.hash; break; }
  }

  const nowMs = typeof now === 'function' ? now() : now;

  return {
    '@version': AUDIT_WORKPAPER_VERSION,
    notice: AUDIT_WORKPAPER_HONESTY_NOTICE,
    client,
    engagement,
    control: {
      ref: controlRef,
      name: 'EMILIA Gate — deny-by-default authorization of consequential machine actions',
      statement: 'Guarded actions execute only with a valid, in-scope, sufficiently-assured, fresh, one-time authorization receipt from a named principal; every decision (allow or refusal) is appended to a hash-chained, tamper-evident evidence log.',
    },
    period: { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString(), end_exclusive: true },
    generated_at: new Date(nowMs).toISOString(),
    population: {
      size: population.length,
      population_hash: populationHash,
      hash_method: 'sha256 over the lexicographically sorted entry hashes, newline-joined',
      excluded: {
        outside_window: outsideWindow,
        not_guarded_passthroughs: notGuarded,
        executions,
        integrity_warnings: warnings.length,
      },
      items: population.map((e) => ({
        hash: e.hash,
        seq: Number.isInteger(e.seq) ? e.seq : null,
        at: e.at,
        action: nonEmptyString(e.action) ? e.action : null,
        allow: e.allow,
        reason: nonEmptyString(e.reason) ? e.reason : null,
      })),
    },
    sampling: {
      method: 'Deterministic attribute sampling, no RNG: for each population entry compute sha256(seed + entry_hash) as lowercase hex; order ascending (ties broken by entry hash); select the first sample_size entries. Reproducible from the same seed and the same population.',
      seed: sampleSeed,
      requested_size: sampleSize,
      selected_size: selected.length,
      full_population: fullPopulation,
      basis: fullPopulation ? '100% examination' : 'attribute sample',
      selected: selected.map(({ e }) => e.hash),
    },
    attribute_testing: {
      plan: AUDIT_ATTRIBUTES,
      refusal_treatment: REFUSAL_TREATMENT,
      items: testedItems,
    },
    exceptions: {
      total: exceptions.length,
      refusals_are_not_exceptions: REFUSAL_TREATMENT,
      items: exceptions,
    },
    completeness: {
      entries_supplied: entries.length,
      entries_in_window: inWindow,
      population_size: population.length,
      first_population_hash: popHashes[0] ?? null,
      last_population_hash: popHashes[popHashes.length - 1] ?? null,
      chain_head: chainHead,
    },
    integrity_warnings: warnings,
    // The module NEVER concludes. These are the auditor's fields, emitted null
    // by construction and rendered as blanks to fill.
    conclusion: { tested_by: null, reviewed_by: null, conclusion: null },
  };
}

/* -------------------------------- markdown ------------------------------- */

/**
 * Table cells must not break the table; the source strings are log-derived.
 * Backslash is escaped FIRST: escaping only the pipe turns a log-derived
 * `a\|b` into `a\\|b`, where the `\\` renders as a literal backslash and
 * leaves the pipe live as a cell delimiter, letting an action or refusal
 * reason split its cell and shift every column after it.
 */
function cell(v) {
  return String(v ?? '—')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

const BLANK = '`____________________`';

function resultMark(r) {
  return r === 'pass' ? 'pass' : r === 'fail' ? 'FAIL' : 'n/a';
}

/**
 * Render the workpaper for the audit file. Refuses any document that is not a
 * verbatim EP-GATE-AUDIT-WORKPAPER-v1: wrong @version, an altered or removed
 * honesty notice, or machine-filled sign-off fields (the format defines them
 * as always-null; a filled conclusion did not come from this module and must
 * never render as an apparently machine-supported conclusion).
 */
export function renderMarkdown(pack) {
  if (!pack || typeof pack !== 'object' || pack['@version'] !== AUDIT_WORKPAPER_VERSION) {
    throw new Error(`audit workpaper: renderMarkdown requires an ${AUDIT_WORKPAPER_VERSION} document`);
  }
  if (pack.notice !== AUDIT_WORKPAPER_HONESTY_NOTICE) {
    throw new Error('audit workpaper: refusing to render a document whose honesty notice was altered or removed');
  }
  const c = pack.conclusion;
  if (!c || typeof c !== 'object' || c.tested_by !== null || c.reviewed_by !== null || c.conclusion !== null) {
    throw new Error('audit workpaper: refusing to render — sign-off fields must be null (the auditor completes them on the rendered workpaper, never in the machine artifact)');
  }

  const L = [];
  L.push('# Control-Testing Workpaper — EMILIA Gate');
  L.push('');
  L.push(`> ${pack.notice}`);
  L.push('');
  L.push(`- **Format:** ${AUDIT_WORKPAPER_VERSION}`);
  L.push(`- **Client:** ${cell(pack.client)}`);
  L.push(`- **Engagement:** ${cell(pack.engagement)}`);
  L.push(`- **Control:** ${cell(pack.control.ref)} — ${cell(pack.control.name)}`);
  L.push(`- **Period:** ${pack.period.start} — ${pack.period.end} (end exclusive)`);
  L.push(`- **Generated:** ${pack.generated_at}`);
  L.push('');
  L.push('## Control under test');
  L.push('');
  L.push(pack.control.statement);
  L.push('');

  L.push('## Population');
  L.push('');
  L.push(`- Guarded decisions in window: **${pack.population.size}**`);
  L.push(`- Population hash: \`${cell(pack.population.population_hash)}\` (${pack.population.hash_method})`);
  L.push(`- Excluded: ${pack.population.excluded.outside_window} outside window, ${pack.population.excluded.not_guarded_passthroughs} not-guarded pass-through(s), ${pack.population.excluded.executions} execution record(s), ${pack.population.excluded.integrity_warnings} integrity warning(s)`);
  if (pack.population.items.length === 0) {
    L.push('');
    L.push('_No guarded decisions in the period. A zero-activity population is a valid (boring) result, not an error._');
  } else {
    L.push('');
    L.push('| Seq | At | Action | Verdict | Reason | Entry hash |');
    L.push('| ---: | --- | --- | --- | --- | --- |');
    for (const it of pack.population.items) {
      L.push(`| ${cell(it.seq)} | ${cell(it.at)} | ${cell(it.action)} | ${it.allow ? 'allow' : 'refusal'} | ${cell(it.reason)} | \`${cell(it.hash)}\` |`);
    }
  }
  L.push('');

  L.push('## Sampling');
  L.push('');
  L.push(`- Method: ${pack.sampling.method}`);
  L.push(`- Seed: \`${cell(pack.sampling.seed)}\``);
  L.push(`- Requested: ${pack.sampling.requested_size} · Selected: ${pack.sampling.selected_size} · Basis: **${pack.sampling.basis}**`);
  if (pack.sampling.selected.length) {
    L.push('- Selected entry hashes (selection order):');
    for (const h of pack.sampling.selected) L.push(`  - \`${cell(h)}\``);
  } else {
    L.push('- Selected entry hashes: _none (empty population)_');
  }
  L.push('');

  L.push('## Attribute test plan');
  L.push('');
  L.push('| # | Attribute | Evidence field(s) | Test |');
  L.push('| --- | --- | --- | --- |');
  for (const a of pack.attribute_testing.plan) {
    L.push(`| ${a.id} | ${cell(a.name)} | ${cell(a.evidence_field)} | ${cell(a.test)} |`);
  }
  L.push('');
  L.push(`> ${pack.attribute_testing.refusal_treatment}`);
  L.push('');

  L.push('## Attribute results');
  if (pack.attribute_testing.items.length === 0) {
    L.push('');
    L.push('_No items sampled (empty population)._');
  } else {
    L.push('');
    L.push('| Item | At | Action | Verdict | A1 | A2 | A3 | A4 | A5 | A6 |');
    L.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const it of pack.attribute_testing.items) {
      const marks = it.attributes.map((a) => resultMark(a.result));
      L.push(`| \`${cell(it.hash)}\` | ${cell(it.at)} | ${cell(it.action)} | ${it.verdict} | ${marks.join(' | ')} |`);
    }
    L.push('');
    L.push('Observations (per attribute, per item):');
    L.push('');
    for (const it of pack.attribute_testing.items) {
      L.push(`- \`${cell(it.hash)}\` (${it.verdict}${it.reason ? `, reason: ${cell(it.reason)}` : ''})`);
      for (const a of it.attributes) {
        L.push(`  - ${a.id} ${cell(a.name)} [${resultMark(a.result)}] — ${cell(a.evidence_field)}: ${cell(a.observed)}`);
      }
    }
  }
  L.push('');

  L.push('## Exceptions');
  L.push('');
  L.push(`> ${pack.exceptions.refusals_are_not_exceptions}`);
  L.push('');
  if (pack.exceptions.total === 0) {
    L.push('No exceptions: no sampled item failed an applicable attribute.');
  } else {
    L.push(`${pack.exceptions.total} failed attribute observation(s):`);
    L.push('');
    L.push('| Entry hash | Seq | Attribute | Evidence field(s) | Observed |');
    L.push('| --- | ---: | --- | --- | --- |');
    for (const x of pack.exceptions.items) {
      L.push(`| \`${cell(x.entry_hash)}\` | ${cell(x.seq)} | ${x.attribute} ${cell(x.name)} | ${cell(x.evidence_field)} | ${cell(x.observed)} |`);
    }
  }
  L.push('');

  L.push('## Completeness');
  L.push('');
  L.push(`- Log entries supplied: ${pack.completeness.entries_supplied} · in window: ${pack.completeness.entries_in_window} · population: ${pack.completeness.population_size}`);
  L.push(`- First population hash: ${pack.completeness.first_population_hash ? `\`${cell(pack.completeness.first_population_hash)}\`` : '—'}`);
  L.push(`- Last population hash: ${pack.completeness.last_population_hash ? `\`${cell(pack.completeness.last_population_hash)}\`` : '—'}`);
  L.push(`- Evidence chain head at export: ${pack.completeness.chain_head ? `\`${cell(pack.completeness.chain_head)}\`` : '—'}`);
  L.push('');

  L.push('## Integrity warnings');
  if (pack.integrity_warnings.length === 0) {
    L.push('');
    L.push('None.');
  } else {
    L.push('');
    L.push(`${pack.integrity_warnings.length} supplied entr(ies) could not be verified as log records and are EXCLUDED from the population above:`);
    L.push('');
    L.push('| Index | Seq | Problem |');
    L.push('| ---: | ---: | --- |');
    for (const w of pack.integrity_warnings) {
      L.push(`| ${w.index} | ${cell(w.seq)} | ${cell(w.problem)} |`);
    }
  }
  L.push('');

  L.push('## Sign-off (auditor completes)');
  L.push('');
  L.push('_These fields are intentionally blank. The preparer of this workpaper does not perform, review, or conclude the test._');
  L.push('');
  L.push('| Field | Entry |');
  L.push('| --- | --- |');
  L.push(`| Tested by / date | ${BLANK} |`);
  L.push(`| Reviewed by / date | ${BLANK} |`);
  L.push(`| Conclusion | ${BLANK} |`);
  L.push('');
  return L.join('\n');
}

export default {
  AUDIT_WORKPAPER_VERSION,
  AUDIT_WORKPAPER_HONESTY_NOTICE,
  AUDIT_ATTRIBUTES,
  REFUSAL_TREATMENT,
  buildAuditWorkpaper,
  renderMarkdown,
};
