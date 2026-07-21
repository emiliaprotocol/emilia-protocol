// Generated from underwriter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate underwriter attestation tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildUnderwriterAttestation, renderMarkdown, UNDERWRITER_ATTESTATION_VERSION, } from './underwriter.js';
let n = 0;
/** A synthetic evidence-log record in the shape createEvidenceLog produces. */
function entry(over = {}) {
    n += 1;
    return {
        seq: n,
        prev_hash: `h${n - 1}`,
        kind: 'decision',
        at: '2026-01-15T00:00:00.000Z',
        action: 'payment.release',
        allow: false,
        status: 428,
        reason: 'receipt_required',
        required_tier: 'class_a',
        receipt_id: null,
        subject: null,
        hash: `h${n}`,
        ...over,
    };
}
const OPTS = {
    insured: 'Acme Robotics, Inc.',
    policyRef: 'POL-2026-001',
    periodStart: '2026-01-01T00:00:00.000Z',
    periodEnd: '2026-01-31T23:59:59.000Z',
    now: Date.parse('2026-02-01T00:00:00.000Z'),
};
/** A representative month: allows, denials, replay, quorum, exception, executions. */
function fixtureEntries() {
    return [
        entry({ allow: true, reason: 'allow', have_tier: 'class_a', consumption_mode: 'consume', receipt_id: 'rcpt_1' }),
        entry({ allow: true, reason: 'allow', required_tier: 'quorum', have_tier: 'quorum', consumption_mode: 'consume', receipt_id: 'rcpt_2' }),
        entry({ reason: 'receipt_required' }),
        entry({ reason: 'replay_refused', receipt_id: 'rcpt_1' }),
        entry({ action: 'db.drop_table', required_tier: 'quorum', reason: 'assurance_too_low', have_tier: 'software' }),
        entry({ action: 'read.balance', allow: true, reason: 'not_guarded', required_tier: 'software' }),
        entry({ action: 'email.send', allow: true, reason: 'allow', required_tier: 'software', have_tier: 'software', consumption_mode: 'none' }),
        entry({ kind: 'execution', outcome: 'executed', authorizes_decision: 'h1' }),
        entry({ kind: 'execution', outcome: 'failed', authorizes_decision: 'h2' }),
    ];
}
test('builds the attestation over a representative period', () => {
    const pack = buildUnderwriterAttestation(fixtureEntries(), OPTS);
    assert.equal(pack['@version'], UNDERWRITER_ATTESTATION_VERSION);
    assert.equal(pack.insured, 'Acme Robotics, Inc.');
    assert.equal(pack.policy_ref, 'POL-2026-001');
    assert.equal(pack.generated_at, '2026-02-01T00:00:00.000Z');
    assert.equal(pack.control_in_force.mode, 'deny_by_default');
    assert.equal(pack.control_in_force.guarded_decisions, 6);
    assert.deepEqual(pack.volume, {
        guarded_decisions: 6,
        allowed: 3,
        denied: 3,
        by_action_family: {
            db: { decisions: 1, allowed: 0, denied: 1 },
            email: { decisions: 1, allowed: 1, denied: 0 },
            payment: { decisions: 4, allowed: 2, denied: 2 },
        },
    });
    assert.equal(pack.denials.total, 3);
    assert.equal(pack.denials.rate, 0.5);
    assert.deepEqual(pack.denials.reasons, {
        assurance_too_low: 1,
        receipt_required: 1,
        replay_refused: 1,
    });
    assert.equal(pack.replay.attempts_blocked, 1);
    assert.deepEqual(pack.assurance.required_tier_distribution, { class_a: 3, quorum: 2, software: 1 });
    assert.deepEqual(pack.assurance.credited_tier_distribution_on_allow, { class_a: 1, quorum: 1, software: 1 });
    assert.deepEqual(pack.quorum_usage, { hard_action_decisions: 2, allowed: 1, denied: 1 });
    assert.deepEqual(pack.exceptions, {
        uncontrolled_passthroughs: 1,
        uncontrolled_actions: ['read.balance'],
        replay_defense_bypassed: 1,
    });
    assert.deepEqual(pack.executions, { recorded: 2, executed: 1, failed: 1 });
    assert.equal(pack.evidence.log_entries_supplied, 9);
    assert.equal(pack.evidence.in_scope, 9);
    assert.deepEqual(pack.evidence.integrity_warnings, []);
});
test('deterministic: same inputs produce byte-identical JSON', () => {
    const a = buildUnderwriterAttestation(fixtureEntries(), OPTS);
    const b = buildUnderwriterAttestation(fixtureEntries(), OPTS);
    // seq/hash counters differ across fixture calls only in receipt ids we set —
    // reset by construction: entry() is monotonic, so rebuild from a frozen copy.
    const frozen = fixtureEntries();
    const c = buildUnderwriterAttestation(frozen, OPTS);
    const d = buildUnderwriterAttestation(frozen, OPTS);
    assert.equal(JSON.stringify(c), JSON.stringify(d));
    assert.deepEqual(Object.keys(a), Object.keys(b));
});
test('window filtering: out-of-period entries are out of scope, bounds inclusive', () => {
    const inAtStart = entry({ at: '2026-01-01T00:00:00.000Z', reason: 'receipt_required' });
    const inAtEnd = entry({ at: '2026-01-31T23:59:59.000Z', reason: 'receipt_required' });
    const before = entry({ at: '2025-12-31T23:59:59.999Z', allow: true, reason: 'allow', have_tier: 'class_a' });
    const after = entry({ at: '2026-02-01T00:00:00.001Z', allow: true, reason: 'allow', have_tier: 'class_a' });
    const pack = buildUnderwriterAttestation([before, inAtStart, inAtEnd, after], OPTS);
    assert.equal(pack.evidence.log_entries_supplied, 4);
    assert.equal(pack.evidence.in_scope, 2);
    assert.equal(pack.volume.guarded_decisions, 2);
    assert.equal(pack.volume.allowed, 0);
    // Out-of-window records are not malformed — no warnings.
    assert.deepEqual(pack.evidence.integrity_warnings, []);
    assert.equal(pack.control_in_force.first_decision_at, '2026-01-01T00:00:00.000Z');
    assert.equal(pack.control_in_force.last_decision_at, '2026-01-31T23:59:59.000Z');
});
test('malformed entries are warned AND excluded from every attested count', () => {
    const good = entry({ allow: true, reason: 'allow', have_tier: 'class_a' });
    const bad = [
        null,
        entry({ at: undefined }),
        entry({ at: 'not-a-date' }),
        entry({ hash: undefined }),
        entry({ kind: 'mystery' }),
        entry({ allow: undefined }),
    ];
    const pack = buildUnderwriterAttestation([good, ...bad], OPTS);
    assert.equal(pack.evidence.in_scope, 1);
    assert.equal(pack.volume.guarded_decisions, 1);
    assert.equal(pack.volume.allowed, 1);
    const reasons = pack.evidence.integrity_warnings.map((w) => w.reason);
    assert.deepEqual(reasons, [
        'not_an_object',
        'unparseable_at',
        'unparseable_at',
        'missing_hash',
        'unknown_kind',
        'decision_missing_allow',
    ]);
    // Warnings point back at the supplied array (and seq when present).
    assert.equal(pack.evidence.integrity_warnings[0].index, 1);
    assert.equal(pack.evidence.integrity_warnings[0].seq, null);
    assert.equal(typeof pack.evidence.integrity_warnings[3].seq, 'number');
});
test('zero-activity period yields a valid, boring attestation — not an error', () => {
    const pack = buildUnderwriterAttestation([], OPTS);
    assert.equal(pack['@version'], UNDERWRITER_ATTESTATION_VERSION);
    assert.equal(pack.volume.guarded_decisions, 0);
    assert.equal(pack.denials.total, 0);
    assert.equal(pack.denials.rate, null); // 0/0 is 'no activity', never 0%
    assert.equal(pack.control_in_force.first_decision_at, null);
    assert.deepEqual(pack.assurance.required_tier_distribution, { class_a: 0, quorum: 0, software: 0 });
    assert.equal(pack.evidence.first_hash, null);
    const md = renderMarkdown(pack);
    assert.match(md, /No guarded decisions in the period/);
    assert.match(md, /n\/a/);
});
test('fails closed on a missing insured', () => {
    assert.throws(() => buildUnderwriterAttestation([], { ...OPTS, insured: undefined }), /insured/);
    assert.throws(() => buildUnderwriterAttestation([], { ...OPTS, insured: '' }), /insured/);
});
test('fails closed on a missing or inverted period', () => {
    assert.throws(() => buildUnderwriterAttestation([], { ...OPTS, periodEnd: undefined }), /periodStart and periodEnd/);
    assert.throws(() => buildUnderwriterAttestation([], { ...OPTS, periodStart: 'not-a-date' }), /periodStart and periodEnd/);
    assert.throws(() => buildUnderwriterAttestation([], { ...OPTS, periodStart: OPTS.periodEnd, periodEnd: OPTS.periodStart }), /must not be after/);
});
test('fails closed on non-array entries', () => {
    assert.throws(() => buildUnderwriterAttestation({ not: 'an array' }, OPTS), /entries must be an array/);
});
test('honesty header attests control operation only', () => {
    const pack = buildUnderwriterAttestation([], OPTS);
    assert.match(pack.honesty.attests, /deny-by-default/);
    assert.match(pack.honesty.attests, /tamper-evident evidence log/);
    assert.ok(pack.honesty.does_not_attest.some((s) => /business correctness/.test(s)));
    assert.match(pack.honesty.status, /Not an insurance document/);
});
test('narrative fields are never fabricated', () => {
    const pack = buildUnderwriterAttestation(fixtureEntries(), OPTS);
    assert.equal(pack.narrative.near_misses, null);
    assert.equal(pack.narrative.remediation, null);
    assert.equal(pack.narrative.completed_by, 'broker');
    const md = renderMarkdown(pack);
    assert.match(md, /Near misses: _\(left to the broker — not machine-generated\)_/);
    assert.match(md, /Remediation: _\(left to the broker — not machine-generated\)_/);
});
test('renderMarkdown renders the pack and broker-supplied narrative verbatim', () => {
    const pack = buildUnderwriterAttestation(fixtureEntries(), OPTS);
    const md = renderMarkdown(pack);
    assert.match(md, /Underwriter Control Attestation/);
    assert.match(md, /Acme Robotics, Inc\./);
    assert.match(md, /\| payment \| 4 \| 2 \| 2 \|/);
    assert.match(md, /\| replay_refused \| 1 \|/);
    assert.match(md, /Replay attempts blocked: 1/);
    assert.match(md, /\| quorum \| 2 \| 1 \|/);
    assert.match(md, /Uncontrolled pass-throughs \(not guarded by manifest\): 1/);
    assert.match(md, /Does not attest/);
    assert.match(md, /Not an insurance document/);
    // Broker fills the JSON; the renderer shows exactly what is there.
    const withNarrative = { ...pack, narrative: { ...pack.narrative, near_misses: 'One attempted double-release, refused.' } };
    assert.match(renderMarkdown(withNarrative), /One attempted double-release, refused\./);
});
test('renderMarkdown refuses anything that is not this attestation format', () => {
    assert.throws(() => renderMarkdown(null), /EP-GATE-UNDERWRITER-ATTESTATION-v1/);
    assert.throws(() => renderMarkdown({}), /EP-GATE-UNDERWRITER-ATTESTATION-v1/);
    assert.throws(() => renderMarkdown({ '@version': 'EP-GATE-RETENTION-EXPORT-v1' }), /EP-GATE-UNDERWRITER-ATTESTATION-v1/);
});
test('integrity warnings surface in the markdown evidence basis', () => {
    const pack = buildUnderwriterAttestation([entry({ hash: undefined })], OPTS);
    const md = renderMarkdown(pack);
    assert.match(md, /Integrity warnings: 1/);
    assert.match(md, /missing_hash/);
});
