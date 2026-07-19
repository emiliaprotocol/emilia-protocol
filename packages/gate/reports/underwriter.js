// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — underwriter control attestation (AI-liability loss-run analogue).
 *
 * The artifact an AI-liability underwriter prices premium credit against — the
 * MFA-for-cyber analogue: evidence that a deny-by-default authorization control
 * was IN FORCE and OPERATING over the policy period, computed from the gate's
 * tamper-evident evidence log. Pure function: same entries + same options in,
 * identical JSON out (pin `now` for a byte-stable artifact).
 *
 * HONESTY BOUNDARY (carried inside the artifact): this attests CONTROL
 * OPERATION only. It does not attest the business correctness of any authorized
 * action, and it is not an insurance document until adopted by the carrier.
 * Near-miss / remediation narrative belongs to the broker — the builder emits
 * those fields as null and NEVER fabricates prose.
 *
 * Fail closed: a missing insured or an invalid period is an error, not a guess.
 * Entries that cannot be verified as log records (unparseable time, missing
 * hash, unknown kind, decision without an allow verdict) are EXCLUDED from every
 * attested count and surfaced as integrity_warnings — the attestation never
 * counts what it cannot account for. A zero-activity period is a valid (boring)
 * attestation, not an error.
 */

export const UNDERWRITER_ATTESTATION_VERSION = 'EP-GATE-UNDERWRITER-ATTESTATION-v1';

// The gate's assurance vocabulary. `software` is the single-approver baseline;
// the distribution always carries all three so an underwriter can see zeros.
const KNOWN_TIERS = ['class_a', 'quorum', 'software'];

function toMs(t) {
  if (t == null) return null;
  const ms = typeof t === 'number' ? t : Date.parse(t);
  return Number.isFinite(ms) ? ms : null;
}

/** Deterministic object from a Map: keys sorted, never insertion-ordered. */
function sortedObject(map) {
  const out = {};
  for (const k of [...map.keys()].sort()) out[k] = map.get(k);
  return out;
}

function countBy(items, keyFn) {
  const m = new Map();
  for (const it of items) {
    const k = keyFn(it);
    m.set(k, (m.get(k) || 0) + 1);
  }
  return m;
}

/** Tier histogram seeded with the known tiers so zeros are explicit. */
function tierDistribution(values) {
  const m = new Map(KNOWN_TIERS.map((t) => [t, 0]));
  for (const v of values) {
    const k = typeof v === 'string' && v.length ? v : 'unspecified';
    m.set(k, (m.get(k) || 0) + 1);
  }
  return sortedObject(m);
}

/** Action family = the namespace segment ('payment.release' -> 'payment'). */
function actionFamily(action) {
  if (typeof action !== 'string' || action.length === 0) return 'unknown';
  const dot = action.indexOf('.');
  return dot > 0 ? action.slice(0, dot) : action;
}

/**
 * Build the underwriter attestation over a slice of the evidence log.
 * @param {Array<object>} entries  evidence.all() (or a durable export of it)
 * @param {object} [o]
 * @param {string} [o.insured]           named insured (required)
 * @param {string} [o.policyRef]       carrier policy/submission reference (null until bound)
 * @param {string|number} [o.periodStart]  inclusive period start (ISO or epoch ms)
 * @param {string|number} [o.periodEnd]    inclusive period end (ISO or epoch ms)
 * @param {number|Function} [o.now]    clock for generated_at (pin for determinism)
 * @returns {object} EP-GATE-UNDERWRITER-ATTESTATION-v1 document
 */
export function buildUnderwriterAttestation(entries = [], {
  insured, policyRef = null, periodStart, periodEnd, now = Date.now,
} = {}) {
  if (!insured || typeof insured !== 'string') {
    throw new Error('underwriter attestation: insured (named insured) is required');
  }
  const startMs = toMs(periodStart);
  const endMs = toMs(periodEnd);
  if (startMs == null || endMs == null) {
    throw new Error('underwriter attestation: periodStart and periodEnd must be valid ISO strings or epoch ms');
  }
  if (startMs > endMs) {
    throw new Error('underwriter attestation: periodStart must not be after periodEnd');
  }
  if (!Array.isArray(entries)) {
    throw new Error('underwriter attestation: entries must be an array (evidence.all())');
  }

  // Scope + integrity pass. Out-of-window records are simply out of scope;
  // records we cannot verify as log entries are warned AND excluded — never
  // attested over. Exclusion is the conservative direction for premium credit.
  const warnings = [];
  const inScope = [];
  entries.forEach((e, index) => {
    const ref = { index, seq: e && typeof e === 'object' && Number.isInteger(e.seq) ? e.seq : null };
    if (!e || typeof e !== 'object') { warnings.push({ ...ref, reason: 'not_an_object' }); return; }
    const t = toMs(e.at);
    if (t == null) { warnings.push({ ...ref, reason: 'unparseable_at' }); return; }
    if (t < startMs || t > endMs) return;
    if (typeof e.hash !== 'string' || e.hash.length === 0) { warnings.push({ ...ref, reason: 'missing_hash' }); return; }
    if (e.kind !== 'decision' && e.kind !== 'execution') { warnings.push({ ...ref, reason: 'unknown_kind' }); return; }
    if (e.kind === 'decision' && typeof e.allow !== 'boolean') { warnings.push({ ...ref, reason: 'decision_missing_allow' }); return; }
    inScope.push({ entry: e, t });
  });

  const decisions = inScope.filter((x) => x.entry.kind === 'decision');
  const executions = inScope.filter((x) => x.entry.kind === 'execution').map((x) => x.entry);

  // 'not_guarded' pass-throughs ran WITHOUT the control — they are the
  // uncontrolled surface, reported separately from protected-action volume.
  const uncontrolled = decisions.filter((x) => x.entry.reason === 'not_guarded').map((x) => x.entry);
  const guarded = decisions.filter((x) => x.entry.reason !== 'not_guarded');
  const guardedAllows = guarded.filter((x) => x.entry.allow === true).map((x) => x.entry);
  const denies = guarded.filter((x) => x.entry.allow === false).map((x) => x.entry);

  const families = new Map();
  for (const { entry: d } of guarded) {
    const fam = actionFamily(d.action);
    const f = families.get(fam) || { decisions: 0, allowed: 0, denied: 0 };
    f.decisions += 1;
    if (d.allow) f.allowed += 1; else f.denied += 1;
    families.set(fam, f);
  }

  const reasons = sortedObject(countBy(denies, (d) => String(d.reason ?? 'unspecified')));
  const replayBlocked = denies.filter((d) => d.reason === 'replay_refused').length;

  // Hard actions = quorum required by the manifest, per the recorded decision.
  const hard = guarded.filter((x) => x.entry.required_tier === 'quorum');
  const hardAllowed = hard.filter((x) => x.entry.allow === true).length;

  // Replay defense bypassed = the gate authorized with consumptionMode 'none'
  // (one-time consumption explicitly skipped). An underwriter must see this.
  const replayBypassed = guardedAllows.filter((a) => a.consumption_mode === 'none').length;

  let firstAt = null; let lastAt = null;
  for (const { entry: d, t } of decisions) {
    if (firstAt === null || t < firstAt.t) firstAt = { t, at: d.at };
    if (lastAt === null || t > lastAt.t) lastAt = { t, at: d.at };
  }

  const nowMs = typeof now === 'function' ? now() : now;

  return {
    '@version': UNDERWRITER_ATTESTATION_VERSION,
    product: 'EMILIA Gate',
    generated_at: new Date(nowMs).toISOString(),
    insured,
    policy_ref: policyRef ?? null,
    period: { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString() },
    honesty: {
      attests: 'Operation of a deny-by-default authorization control (EMILIA Gate) over the stated period, computed from the gate\'s tamper-evident evidence log.',
      does_not_attest: [
        'The business correctness or wisdom of any authorized action.',
        'Identity proofing, authority enrollment, or issuer/approver key custody, which remain external trust roots.',
        'Any period, system, or enforcement point outside the supplied evidence log.',
      ],
      status: 'Not an insurance document. This attestation carries no coverage effect until adopted by the carrier.',
    },
    control_in_force: {
      control: 'EMILIA Gate — Consequence Firewall',
      mode: 'deny_by_default',
      statement: 'Guarded actions execute only with a valid, in-scope, sufficiently-assured, fresh, one-time authorization receipt; absent or insufficient proof is refused, and every decision is appended to a hash-chained evidence log.',
      guarded_decisions: guarded.length,
      first_decision_at: firstAt?.at ?? null,
      last_decision_at: lastAt?.at ?? null,
    },
    volume: {
      guarded_decisions: guarded.length,
      allowed: guardedAllows.length,
      denied: denies.length,
      by_action_family: sortedObject(families),
    },
    denials: {
      total: denies.length,
      // 0/0 is 'no guarded activity', not a 0% denial rate — represent as null.
      rate: guarded.length === 0 ? null : denies.length / guarded.length,
      reasons,
    },
    replay: { attempts_blocked: replayBlocked },
    assurance: {
      required_tier_distribution: tierDistribution(guarded.map((x) => x.entry.required_tier)),
      credited_tier_distribution_on_allow: tierDistribution(guardedAllows.map((a) => a.have_tier)),
    },
    quorum_usage: {
      hard_action_decisions: hard.length,
      allowed: hardAllowed,
      denied: hard.length - hardAllowed,
    },
    exceptions: {
      uncontrolled_passthroughs: uncontrolled.length,
      uncontrolled_actions: [...new Set(uncontrolled.map((d) => (typeof d.action === 'string' && d.action) || 'unknown'))].sort(),
      replay_defense_bypassed: replayBypassed,
    },
    executions: {
      recorded: executions.length,
      executed: executions.filter((x) => x.outcome === 'executed').length,
      failed: executions.filter((x) => x.outcome === 'failed').length,
    },
    // Broker fields. NEVER machine-generated — the builder only ever emits null.
    narrative: { near_misses: null, remediation: null, completed_by: 'broker' },
    evidence: {
      log_entries_supplied: entries.length,
      in_scope: inScope.length,
      first_hash: inScope[0]?.entry.hash ?? null,
      last_hash: inScope[inScope.length - 1]?.entry.hash ?? null,
      integrity_warnings: warnings,
    },
  };
}

/* ------------------------------- markdown ------------------------------- */

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

function pct(rate) {
  return rate == null ? 'n/a' : `${(rate * 100).toFixed(2)}%`;
}

function countTable(header, obj) {
  const keys = Object.keys(obj);
  if (keys.length === 0) return ['_None in period._'];
  return [
    `| ${header} | Count |`,
    '|---|---:|',
    ...keys.map((k) => `| ${cell(k)} | ${obj[k]} |`),
  ];
}

const BROKER_PLACEHOLDER = '_(left to the broker — not machine-generated)_';

/**
 * Render the attestation for a submission packet. Refuses any document that is
 * not an EP-GATE-UNDERWRITER-ATTESTATION-v1 — never renders what it cannot
 * vouch the shape of. Narrative fields render exactly as present in the pack
 * (the broker fills them into the JSON); null renders as a placeholder.
 */
export function renderMarkdown(pack) {
  if (!pack || typeof pack !== 'object' || pack['@version'] !== UNDERWRITER_ATTESTATION_VERSION) {
    throw new Error(`renderMarkdown requires an ${UNDERWRITER_ATTESTATION_VERSION} document`);
  }
  const fams = pack.volume.by_action_family;
  const famKeys = Object.keys(fams);
  const req = pack.assurance.required_tier_distribution;
  const cred = pack.assurance.credited_tier_distribution_on_allow;
  const tierKeys = [...new Set([...Object.keys(req), ...Object.keys(cred)])].sort();
  const warnings = pack.evidence.integrity_warnings;

  const lines = [
    '# Underwriter Control Attestation — EMILIA Gate',
    '',
    `\`${UNDERWRITER_ATTESTATION_VERSION}\` · generated ${pack.generated_at}`,
    '',
    `**Insured:** ${cell(pack.insured)} · **Policy:** ${cell(pack.policy_ref)} · **Period:** ${pack.period.start} → ${pack.period.end}`,
    '',
    `> **Attests:** ${pack.honesty.attests}`,
    `> **Does not attest:** ${pack.honesty.does_not_attest.join(' ')}`,
    `> **Status:** ${pack.honesty.status}`,
    '',
    '## Control in force',
    '',
    `- Control: ${pack.control_in_force.control} (${pack.control_in_force.mode})`,
    `- ${pack.control_in_force.statement}`,
    `- Guarded decisions in period: ${pack.control_in_force.guarded_decisions}`
      + (pack.control_in_force.first_decision_at
        ? ` (first ${pack.control_in_force.first_decision_at}, last ${pack.control_in_force.last_decision_at})`
        : ''),
    '',
    '## Protected-action volume',
    '',
    ...(famKeys.length === 0
      ? ['_No guarded decisions in the period._']
      : [
        '| Action family | Decisions | Allowed | Denied |',
        '|---|---:|---:|---:|',
        ...famKeys.map((k) => `| ${cell(k)} | ${fams[k].decisions} | ${fams[k].allowed} | ${fams[k].denied} |`),
      ]),
    '',
    '## Denials',
    '',
    `- Denials: ${pack.denials.total} of ${pack.volume.guarded_decisions} guarded decisions (${pct(pack.denials.rate)})`,
    '',
    ...countTable('Denial reason', pack.denials.reasons),
    '',
    '## Replay defense',
    '',
    `- Replay attempts blocked: ${pack.replay.attempts_blocked}`,
    '',
    '## Assurance tiers',
    '',
    '| Tier | Required (guarded) | Credited (allowed) |',
    '|---|---:|---:|',
    ...tierKeys.map((t) => `| ${cell(t)} | ${req[t] ?? 0} | ${cred[t] ?? 0} |`),
    '',
    '## Quorum usage on hard actions',
    '',
    `- Decisions requiring quorum: ${pack.quorum_usage.hard_action_decisions} (allowed ${pack.quorum_usage.allowed}, denied ${pack.quorum_usage.denied})`,
    '',
    '## Exceptions / uncontrolled actions',
    '',
    `- Uncontrolled pass-throughs (not guarded by manifest): ${pack.exceptions.uncontrolled_passthroughs}`,
    `- Uncontrolled actions: ${pack.exceptions.uncontrolled_actions.length ? pack.exceptions.uncontrolled_actions.map(cell).join(', ') : '—'}`,
    `- Replay defense bypassed (consumption mode "none"): ${pack.exceptions.replay_defense_bypassed}`,
    '',
    '## Executions',
    '',
    `- Recorded: ${pack.executions.recorded} (executed ${pack.executions.executed}, failed ${pack.executions.failed})`,
    '',
    '## Near-miss narrative (broker)',
    '',
    `- Near misses: ${pack.narrative.near_misses == null ? BROKER_PLACEHOLDER : cell(pack.narrative.near_misses)}`,
    `- Remediation: ${pack.narrative.remediation == null ? BROKER_PLACEHOLDER : cell(pack.narrative.remediation)}`,
    '',
    '## Evidence basis',
    '',
    `- Log entries supplied: ${pack.evidence.log_entries_supplied} · in scope: ${pack.evidence.in_scope}`,
    `- First hash: ${cell(pack.evidence.first_hash)} · Last hash: ${cell(pack.evidence.last_hash)}`,
    `- Integrity warnings: ${warnings.length}`,
    ...(warnings.length
      ? warnings.map((w) => `  - index ${w.index}${w.seq != null ? ` (seq ${w.seq})` : ''}: ${cell(w.reason)}`)
      : []),
    '',
  ];
  return lines.join('\n');
}

export default { UNDERWRITER_ATTESTATION_VERSION, buildUnderwriterAttestation, renderMarkdown };
