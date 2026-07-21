// SPDX-License-Identifier: Apache-2.0
// Generated from metrics.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate metrics tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createMetrics, classifyDenialReason, METRICS_VERSION, METRICS_CONTENT_TYPE, REASON_CLASSES, } from './metrics.js';
const NOW = 1_700_000_000_000; // fixed injected clock (ms)
const fixedNow = () => NOW;
function make(opts = {}) {
    return createMetrics({ now: fixedNow, ...opts });
}
/** Extract the numeric value of a sample line, or null if the line is absent. */
function sample(text, line) {
    const hit = text.split('\n').find((l) => l.startsWith(line + ' '));
    return hit ? Number(hit.slice(line.length + 1)) : null;
}
test('version and content type constants', () => {
    assert.equal(METRICS_VERSION, 'EP-GATE-METRICS-v1');
    assert.equal(METRICS_CONTENT_TYPE, 'text/plain; version=0.0.4; charset=utf-8');
});
test('counts allow and deny decisions with outcome/action_type/tier labels', () => {
    const m = make();
    m.onDecision({ allow: true, action: 'payment.release', have_tier: 'class_a', reason: 'allow' });
    m.onDecision({ allow: true, action: 'payment.release', have_tier: 'class_a', reason: 'allow' });
    m.onDecision({ allow: false, action: 'payment.release', required_tier: 'class_a', reason: 'receipt_required' });
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="payment.release",outcome="allow",tier="class_a"}'), 2);
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="payment.release",outcome="deny",tier="class_a"}'), 1);
    assert.equal(sample(out, 'ep_gate_denials_total{reason_class="receipt_missing"}'), 1);
});
test('exact deterministic exposition for fixed inputs (format 0.0.4)', () => {
    const m = make();
    m.onDecision({ allow: true, action: 'payment.release', have_tier: 'class_a', reason: 'allow', at: '2026-01-02T03:04:05.000Z' });
    m.onDecision({ allow: false, action: 'payment.release', required_tier: 'class_a', reason: 'receipt_required' });
    const expected = [
        '# HELP ep_gate_decisions_total Gate decisions by outcome, action type, and credited assurance tier.',
        '# TYPE ep_gate_decisions_total counter',
        'ep_gate_decisions_total{action_type="payment.release",outcome="allow",tier="class_a"} 1',
        'ep_gate_decisions_total{action_type="payment.release",outcome="deny",tier="class_a"} 1',
        '# HELP ep_gate_denials_total Denied gate decisions by bounded denial reason class.',
        '# TYPE ep_gate_denials_total counter',
        'ep_gate_denials_total{reason_class="receipt_missing"} 1',
        '# HELP ep_gate_evidence_entries_total Evidence-log entries recorded for gate decisions.',
        '# TYPE ep_gate_evidence_entries_total counter',
        'ep_gate_evidence_entries_total 2',
        '# HELP ep_gate_last_decision_timestamp_seconds Unix timestamp (seconds) of the most recent gate decision.',
        '# TYPE ep_gate_last_decision_timestamp_seconds gauge',
        `ep_gate_last_decision_timestamp_seconds ${NOW / 1000}`,
        '# HELP ep_gate_metrics_malformed_total Decision entries the metrics layer could not interpret (dropped, never thrown).',
        '# TYPE ep_gate_metrics_malformed_total counter',
        'ep_gate_metrics_malformed_total 0',
        '# HELP ep_gate_replays_blocked_total Receipt replays refused by one-time consumption.',
        '# TYPE ep_gate_replays_blocked_total counter',
        'ep_gate_replays_blocked_total 0',
    ].join('\n') + '\n';
    assert.equal(m.render(), expected);
    // render() is a pure read: calling it again yields byte-identical output.
    assert.equal(m.render(), expected);
});
test('deterministic across instances and insertion orders (stable sort)', () => {
    const entries = [
        { allow: true, action: 'zeta.action', have_tier: 'software', reason: 'allow' },
        { allow: false, action: 'alpha.action', required_tier: 'quorum', reason: 'assurance_too_low' },
        { allow: false, action: 'alpha.action', required_tier: 'quorum', reason: 'replay_refused' },
    ];
    const a = make();
    const b = make();
    for (const e of entries)
        a.onDecision(e);
    for (const e of [...entries].reverse())
        b.onDecision(e);
    assert.equal(a.render(), b.render());
    // Series lines are sorted: alpha.action rows precede zeta.action rows.
    const lines = a.render().split('\n').filter((l) => l.startsWith('ep_gate_decisions_total{'));
    assert.deepEqual(lines, [...lines].sort());
});
test('HELP and TYPE lines present for every metric', () => {
    const out = make().render();
    for (const name of [
        'ep_gate_decisions_total',
        'ep_gate_denials_total',
        'ep_gate_evidence_entries_total',
        'ep_gate_last_decision_timestamp_seconds',
        'ep_gate_metrics_malformed_total',
        'ep_gate_replays_blocked_total',
    ]) {
        assert.match(out, new RegExp(`^# HELP ${name} .+$`, 'm'), `HELP for ${name}`);
        assert.match(out, new RegExp(`^# TYPE ${name} (counter|gauge)$`, 'm'), `TYPE for ${name}`);
    }
});
test('gauge emits no sample before the first decision (no fabricated 1970)', () => {
    const out = make().render();
    assert.equal(sample(out, 'ep_gate_last_decision_timestamp_seconds'), null);
    assert.match(out, /# TYPE ep_gate_last_decision_timestamp_seconds gauge/);
});
test('gauge prefers the entry timestamp over the injected clock', () => {
    const m = make();
    m.onDecision({ allow: true, action: 'a', reason: 'allow', at: '2026-01-02T03:04:05.000Z' });
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_last_decision_timestamp_seconds'), Date.parse('2026-01-02T03:04:05.000Z') / 1000);
});
test('NEGATIVE: malformed entries increment the malformed counter and never throw', () => {
    const m = make();
    const poisoned = { get allow() { throw new Error('boom'); } };
    const hostileProxy = new Proxy({}, { get() { throw new Error('trap'); } });
    const bad = [null, undefined, 42, 'deny', [], {}, { allow: 'yes' }, { outcome: 'maybe' }, poisoned, hostileProxy];
    for (const e of bad) {
        assert.doesNotThrow(() => m.onDecision(e)); // the enforcement-path guarantee
    }
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_metrics_malformed_total'), bad.length);
    // Nothing malformed leaks into the real counters.
    assert.equal(out.includes('ep_gate_decisions_total{'), false);
    assert.equal(sample(out, 'ep_gate_evidence_entries_total'), 0);
});
test('NEGATIVE: label values are escaped — quotes, newlines, backslashes', () => {
    const m = make();
    m.onDecision({ allow: true, action: 'pay"ment\\evil\nnewline', have_tier: 'tier"x', reason: 'allow' });
    const out = m.render();
    const line = out.split('\n').find((l) => l.startsWith('ep_gate_decisions_total{'));
    assert.equal(line, 'ep_gate_decisions_total{action_type="pay\\"ment\\\\evil\\nnewline",outcome="allow",tier="tier\\"x"} 1');
    // No raw newline may survive inside a sample line (it would forge extra samples).
    assert.equal(out.split('\n').every((l) => l === '' || l.startsWith('#') || /^[a-z_]+(\{.*\})? \S+$/.test(l)), true);
});
test('NEGATIVE: action_type cardinality is capped by maxSeries — overflow buckets to _other', () => {
    const m = make({ maxSeries: 2 });
    m.onDecision({ allow: true, action: 'a.one', have_tier: 'software', reason: 'allow' });
    m.onDecision({ allow: true, action: 'b.two', have_tier: 'software', reason: 'allow' });
    m.onDecision({ allow: true, action: 'c.three', have_tier: 'software', reason: 'allow' });
    m.onDecision({ allow: true, action: 'd.four', have_tier: 'software', reason: 'allow' });
    m.onDecision({ allow: true, action: 'a.one', have_tier: 'software', reason: 'allow' }); // known value still counts normally
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="a.one",outcome="allow",tier="software"}'), 2);
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="b.two",outcome="allow",tier="software"}'), 1);
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="_other",outcome="allow",tier="software"}'), 2);
    assert.equal(out.includes('c.three'), false);
    assert.equal(out.includes('d.four'), false);
});
test('replay denials increment ep_gate_replays_blocked_total and reason_class="replay"', () => {
    const m = make();
    m.onDecision({ allow: false, action: 'payment.release', required_tier: 'class_a', reason: 'replay_refused' });
    m.onDecision({ allow: false, action: 'payment.release', required_tier: 'class_a', reason: 'replay_refused' });
    m.onDecision({ allow: false, action: 'payment.release', required_tier: 'class_a', reason: 'receipt_required' });
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_replays_blocked_total'), 2);
    assert.equal(sample(out, 'ep_gate_denials_total{reason_class="replay"}'), 2);
    assert.equal(sample(out, 'ep_gate_denials_total{reason_class="receipt_missing"}'), 1);
});
test('denial reasons classify into the bounded reason_class set', () => {
    assert.equal(classifyDenialReason('replay_refused'), 'replay');
    assert.equal(classifyDenialReason('receipt_required'), 'receipt_missing');
    assert.equal(classifyDenialReason('receipt_rejected:bad_signature'), 'receipt_invalid');
    assert.equal(classifyDenialReason('receipt_rejected:missing_receipt_id'), 'receipt_invalid');
    assert.equal(classifyDenialReason('assurance_too_low'), 'assurance');
    assert.equal(classifyDenialReason('unknown_required_tier'), 'assurance');
    assert.equal(classifyDenialReason('execution_binding_failed'), 'execution_binding');
    assert.equal(classifyDenialReason('evidence_log_failed'), 'infrastructure');
    assert.equal(classifyDenialReason('consumption_store_lacks_reserve'), 'infrastructure');
    assert.equal(classifyDenialReason('something_new_entirely'), 'other');
    assert.equal(classifyDenialReason(undefined), 'other');
    assert.equal(classifyDenialReason(12), 'other');
    for (const r of ['replay_refused', 'receipt_required', 'weird']) {
        assert.equal(REASON_CLASSES.includes(classifyDenialReason(r)), true);
    }
});
test('evidence counter skips decisions whose evidence write failed (evidence: null)', () => {
    const m = make();
    m.onDecision({ allow: true, action: 'a', reason: 'allow' });
    m.onDecision({ allow: false, action: 'a', reason: 'evidence_log_failed', evidence: null });
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_evidence_entries_total'), 1);
    assert.equal(sample(out, 'ep_gate_denials_total{reason_class="infrastructure"}'), 1);
});
test('missing action/tier bucket to "unknown" — well-formed, not malformed', () => {
    const m = make();
    m.onDecision({ allow: true, reason: 'allow' });
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="unknown",outcome="allow",tier="unknown"}'), 1);
    assert.equal(sample(out, 'ep_gate_metrics_malformed_total'), 0);
});
test('a throwing injected clock skips the gauge but never throws', () => {
    const m = createMetrics({ now: () => { throw new Error('clock down'); } });
    assert.doesNotThrow(() => m.onDecision({ allow: true, action: 'a', reason: 'allow' }));
    const out = m.render();
    assert.equal(sample(out, 'ep_gate_last_decision_timestamp_seconds'), null);
    assert.equal(sample(out, 'ep_gate_decisions_total{action_type="a",outcome="allow",tier="unknown"}'), 1);
    assert.equal(sample(out, 'ep_gate_metrics_malformed_total'), 0);
});
test('handler() returns a framework-agnostic scrape response', () => {
    const m = make();
    m.onDecision({ allow: true, action: 'payment.release', have_tier: 'class_a', reason: 'allow' });
    const res = m.handler();
    assert.equal(res.status, 200);
    assert.deepEqual(res.headers, { 'content-type': METRICS_CONTENT_TYPE });
    assert.equal(res.body, m.render());
    assert.equal(res.body.endsWith('\n'), true);
});
test('invalid maxSeries is clamped to the default, never thrown', () => {
    for (const bad of [0, -1, 1.5, 'lots', NaN, Infinity]) {
        assert.doesNotThrow(() => createMetrics({ maxSeries: bad }));
        const m = createMetrics({ maxSeries: bad, now: fixedNow });
        m.onDecision({ allow: true, action: 'a', reason: 'allow' });
        assert.equal(sample(m.render(), 'ep_gate_decisions_total{action_type="a",outcome="allow",tier="unknown"}'), 1);
    }
});
