// Generated from siem.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate SIEM export tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { SIEM_EXPORT_VERSION, SIEM_OCSF_CLASS_UID, toOCSF, toCEF, createSiemForwarder } from './siem.js';
import { createEvidenceLog } from './evidence.js';
// A refused decision exactly as the gate's evidence log records it.
const DENY = {
    seq: 4,
    prev_hash: 'aaa1111111111111111111111111111111111111111111111111111111111111',
    kind: 'decision',
    at: '2026-07-04T12:00:00.000Z',
    action: 'payment.release',
    allow: false,
    status: 428,
    reason: 'replay_refused',
    selector: { protocol: 'mcp', tool: 'release_payment' },
    required_tier: 'class_a',
    receipt_id: 'rcpt_42',
    subject: 'agent:test',
    observed_action_hash: null,
    hash: 'bbb2222222222222222222222222222222222222222222222222222222222222',
};
const ALLOW = { ...DENY, seq: 5, allow: true, status: 200, reason: 'allow', hash: 'ccc3' };
const EXECUTED = {
    seq: 6, prev_hash: 'ccc3', kind: 'execution', at: '2026-07-04T12:00:01.000Z',
    action: 'payment.release', outcome: 'executed', receipt_id: 'rcpt_42',
    authorizes_decision: 'ccc3', hash: 'ddd4',
};
test('toOCSF maps a deny decision to an API Activity failure', () => {
    const e = toOCSF(DENY);
    assert.equal(e.class_uid, SIEM_OCSF_CLASS_UID);
    assert.equal(e.class_uid, 6003);
    assert.equal(e.category_uid, 6);
    assert.equal(e.activity_id, 99);
    assert.equal(e.activity_name, 'decision');
    assert.equal(e.type_uid, 600399);
    assert.equal(e.time, Date.parse(DENY.at));
    assert.equal(e.status_id, 2);
    assert.equal(e.status, 'Failure');
    assert.equal(e.status_detail, 'replay_refused');
    assert.equal(e.severity_id, 3);
    assert.equal(e.api.operation, 'payment.release');
    assert.equal(e.actor.user.uid, 'agent:test');
    assert.equal(e.metadata.uid, DENY.hash);
    assert.equal(e.metadata.correlation_uid, 'rcpt_42');
    assert.equal(e.metadata.log_name, SIEM_EXPORT_VERSION);
    assert.equal(e.unmapped.required_tier, 'class_a');
    assert.equal(e.unmapped.evidence_seq, 4);
});
test('toOCSF maps an allow decision to Success / Informational', () => {
    const e = toOCSF(ALLOW);
    assert.equal(e.status_id, 1);
    assert.equal(e.status, 'Success');
    assert.equal(e.severity_id, 1);
});
test('toOCSF maps an execution entry by its outcome', () => {
    const ok = toOCSF(EXECUTED);
    assert.equal(ok.activity_name, 'execution');
    assert.equal(ok.status_id, 1);
    const failed = toOCSF({ ...EXECUTED, outcome: 'failed' });
    assert.equal(failed.status_id, 2);
    assert.equal(failed.status_detail, 'failed');
});
test('toOCSF is deterministic for a fixed entry', () => {
    assert.deepEqual(toOCSF(DENY), toOCSF(DENY));
    assert.equal(JSON.stringify(toOCSF(DENY)), JSON.stringify(toOCSF(DENY)));
});
test('toOCSF: malformed entry -> structured error event, no throw', () => {
    for (const bad of [null, undefined, 'nope', 42, [], {}, { at: 'not-a-date', allow: true }, { at: DENY.at }]) {
        const e = toOCSF(bad);
        assert.equal(e.status, 'Failure');
        assert.equal(e.status_detail, 'malformed_evidence_entry');
        assert.equal(e.activity_id, 0);
        assert.equal(e.time, 0); // sentinel — never the wall clock
        assert.equal(e.unmapped.error, 'malformed_evidence_entry');
    }
});
test('toOCSF: circular entry still yields an error event, no throw', () => {
    const cyc = {};
    cyc.self = cyc;
    const e = toOCSF(cyc);
    assert.equal(e.status_detail, 'malformed_evidence_entry');
    assert.equal(e.unmapped.entry_preview, '[unserializable]');
});
test('toCEF emits the exact expected one-line record', () => {
    const line = toCEF(DENY);
    const expected = 'CEF:0|EmiliaProtocol|Gate|1|gate.decision.deny|payment.release refused|7|'
        + `end=${Date.parse(DENY.at)} act=deny outcome=replay_refused suser=agent:test `
        + `cs1=rcpt_42 cs1Label=receipt_id cs2=${DENY.hash} cs2Label=evidence_hash `
        + 'cs3=class_a cs3Label=required_tier '
        + `cs4=${SIEM_EXPORT_VERSION} cs4Label=export_version cn1=4 cn1Label=evidence_seq`;
    assert.equal(line, expected);
    assert.ok(!line.includes('\n'));
});
test('toCEF is deterministic and distinguishes allow from deny', () => {
    assert.equal(toCEF(DENY), toCEF(DENY));
    const allowLine = toCEF(ALLOW);
    assert.ok(allowLine.includes('|gate.decision.allow|payment.release allowed|3|'));
    assert.ok(allowLine.includes('act=allow'));
    const execLine = toCEF(EXECUTED);
    assert.ok(execLine.includes('|gate.execution.allow|payment.release executed|3|'));
});
test('toCEF escapes pipes, equals, backslashes, and newlines', () => {
    const nasty = { ...DENY, action: 'pay|ment', reason: 'a=b\\c', subject: 'agent:\nmulti' };
    const line = toCEF(nasty);
    assert.ok(line.includes('|pay\\|ment refused|')); // prefix: pipe escaped
    assert.ok(line.includes('outcome=a\\=b\\\\c')); // extension: = and \ escaped
    assert.ok(line.includes('suser=agent: multi')); // newline collapsed
    assert.ok(!line.includes('\n'));
});
test('toCEF: malformed entry -> error line, no throw', () => {
    const line = toCEF({ garbage: true });
    assert.ok(line.startsWith('CEF:0|EmiliaProtocol|Gate|1|gate.malformed|'));
    assert.ok(line.includes('outcome=malformed_evidence_entry'));
});
test('forwarder delivers ocsf events and counts them', async () => {
    const seen = [];
    const f = createSiemForwarder({ format: 'ocsf', sink: (e) => { seen.push(e); } });
    const out = await f.forward(DENY);
    assert.equal(out.delivered, true);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].class_uid, 6003);
    assert.deepEqual(f.stats(), { format: 'ocsf', forwarded: 1, dropped: 0, malformed: 0 });
});
test('forwarder delivers cef strings', async () => {
    const seen = [];
    const f = createSiemForwarder({ format: 'cef', sink: (e) => { seen.push(e); } });
    await f.forward(ALLOW);
    assert.equal(typeof seen[0], 'string');
    assert.ok(seen[0].startsWith('CEF:0|'));
});
test('forwarder: sink that throws is counted, never propagated', async () => {
    const f = createSiemForwarder({ format: 'ocsf', sink: () => { throw new Error('splunk down'); } });
    const out = await f.forward(DENY); // must NOT throw into the gate path
    assert.equal(out.delivered, false);
    assert.deepEqual(f.stats(), { format: 'ocsf', forwarded: 0, dropped: 1, malformed: 0 });
});
test('forwarder: async sink rejection is counted, never propagated', async () => {
    const f = createSiemForwarder({ format: 'cef', sink: async () => { throw new Error('conn reset'); } });
    const out = await f.forward(DENY);
    assert.equal(out.delivered, false);
    assert.equal(f.stats().dropped, 1);
});
test('forwarder: malformed entry is counted AND still shipped as an error event', async () => {
    const seen = [];
    const f = createSiemForwarder({ format: 'ocsf', sink: (e) => { seen.push(e); } });
    const out = await f.forward({ nonsense: 1 });
    assert.equal(out.delivered, true);
    assert.equal(seen[0].status_detail, 'malformed_evidence_entry');
    assert.deepEqual(f.stats(), { format: 'ocsf', forwarded: 1, dropped: 0, malformed: 1 });
});
test('forwarder: unknown format or missing sink fails closed at construction', () => {
    assert.throws(() => createSiemForwarder({ format: 'leef', sink: () => { } }), /unknown format/);
    assert.throws(() => createSiemForwarder({ format: 'ocsf' }), /sink function/);
    assert.throws(() => createSiemForwarder(), /sink function/);
});
test('consumes real evidence-log records end to end', async () => {
    const log = createEvidenceLog();
    const rec = await log.record({
        kind: 'decision', at: '2026-07-04T12:00:00.000Z', action: 'db.drop_table',
        allow: false, status: 428, reason: 'receipt_required', selector: {},
        required_tier: 'quorum', receipt_id: null, subject: null, observed_action_hash: null,
    });
    const e = toOCSF(rec);
    assert.equal(e.metadata.uid, rec.hash);
    assert.equal(e.unmapped.evidence_seq, 0);
    assert.equal(e.unmapped.prev_hash, 'genesis');
    assert.equal(e.status_id, 2);
    const line = toCEF(rec);
    assert.ok(line.includes(`cs2=${rec.hash} cs2Label=evidence_hash`));
});
