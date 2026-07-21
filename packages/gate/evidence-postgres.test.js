// SPDX-License-Identifier: Apache-2.0
// Generated from evidence-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonicalEvidenceJson, createAtomicEvidenceLog, } from './evidence.js';
import { createPostgresEvidenceBackend, EVIDENCE_APPEND_FUNCTION, EVIDENCE_HEADS_TABLE, EVIDENCE_RECORDS_TABLE, EVIDENCE_SCHEMA, EVIDENCE_SQL, PG_EVIDENCE_VERSION, } from './evidence-postgres.js';
const MIGRATION = readFileSync(new URL('./deploy/sql/001-runtime.sql', import.meta.url), 'utf8');
function ids(prefix) {
    let next = 0;
    return () => `${prefix}-${String(++next).padStart(16, '0')}`;
}
function hashRecord(body) {
    return {
        ...body,
        hash: crypto.createHash('sha256').update(canonicalEvidenceJson(body)).digest('hex'),
    };
}
function createFakePostgres() {
    const scopes = new Map();
    const locks = new Map();
    const controls = {
        appendCalls: 0,
        failNextAppendBeforeCommit: false,
        loseNextAppendResponse: false,
        failReads: false,
        health: {
            records_ready: true,
            heads_ready: true,
            append_ready: true,
            can_read_records: true,
            can_read_heads: true,
            can_write_records_directly: false,
            can_write_heads_directly: false,
            can_append: true,
        },
        lastAppend: null,
    };
    const clone = (value) => structuredClone(value);
    const scopeKey = (tenant, gate, stream) => JSON.stringify([tenant, gate, stream]);
    const stateFor = (tenant, gate, stream, create = false) => {
        const key = scopeKey(tenant, gate, stream);
        if (!scopes.has(key) && create)
            scopes.set(key, { head: null, rows: [] });
        return scopes.get(key) ?? null;
    };
    const driverRow = (row, jsonSequence = false) => ({
        seq: jsonSequence ? row.seq : String(row.seq),
        record_id: row.record_id,
        prev_hash: row.prev_hash,
        hash: row.hash,
        record: clone(row.record),
    });
    const result = (rows) => ({ rowCount: rows.length, rows });
    async function withScopeLock(key, fn) {
        const previous = locks.get(key) ?? Promise.resolve();
        let release;
        const held = new Promise((resolve) => { release = resolve; });
        const tail = previous.then(() => held);
        locks.set(key, tail);
        await previous;
        try {
            return await fn();
        }
        finally {
            release();
            if (locks.get(key) === tail)
                locks.delete(key);
        }
    }
    async function query(text, params = []) {
        await Promise.resolve();
        if (controls.failReads && text !== EVIDENCE_SQL.appendIfHead)
            throw new Error('pg_unavailable');
        if (text === EVIDENCE_SQL.health)
            return result([clone(controls.health)]);
        const [tenant, gate, stream] = params;
        const state = stateFor(tenant, gate, stream);
        if (text === EVIDENCE_SQL.readHead) {
            return result(state?.head ? [{ seq: String(state.head.seq), hash: state.head.hash }] : []);
        }
        if (text === EVIDENCE_SQL.getById) {
            const row = state?.rows.find((candidate) => candidate.record_id === params[3]);
            return result(row ? [driverRow(row)] : []);
        }
        if (text === EVIDENCE_SQL.readAll) {
            const rows = [...(state?.rows ?? [])].sort((a, b) => a.seq - b.seq).map((row) => driverRow(row));
            return result(rows);
        }
        if (text === EVIDENCE_SQL.snapshot) {
            const rows = [...(state?.rows ?? [])].sort((a, b) => a.seq - b.seq)
                .map((row) => driverRow(row, true));
            return result([{
                    record_rows: rows,
                    head: state?.head ? clone(state.head) : null,
                }]);
        }
        if (text !== EVIDENCE_SQL.appendIfHead)
            throw new Error(`fake pg: unrecognized query: ${text}`);
        controls.appendCalls += 1;
        const expectedHeadHash = params[3];
        const record = clone(params[4]);
        const canonicalBody = params[5];
        controls.lastAppend = { tenant, gate, stream, expectedHeadHash, record: clone(record), canonicalBody };
        const { hash, ...body } = record;
        if (canonicalEvidenceJson(body) !== canonicalBody
            || crypto.createHash('sha256').update(canonicalBody).digest('hex') !== hash) {
            throw new Error('database_canonical_hash_check_failed');
        }
        const key = scopeKey(tenant, gate, stream);
        return withScopeLock(key, async () => {
            const current = stateFor(tenant, gate, stream, true);
            if ((current.head?.hash ?? null) !== expectedHeadHash)
                return result([{ appended: false }]);
            const expectedSeq = current.head === null ? 0 : current.head.seq + 1;
            const expectedPrevious = current.head?.hash ?? 'genesis';
            if (record.seq !== expectedSeq || record.prev_hash !== expectedPrevious) {
                throw new Error('database_head_extension_check_failed');
            }
            if (current.rows.some((row) => row.seq === record.seq || row.record_id === record.record_id)) {
                throw new Error('database_unique_violation');
            }
            // Mutate a transaction-local copy. A forced failure before assignment
            // models Postgres rolling the whole function statement back.
            const draft = clone(current);
            draft.rows.push({
                seq: record.seq,
                record_id: record.record_id,
                prev_hash: record.prev_hash,
                hash: record.hash,
                record,
            });
            draft.head = { seq: record.seq, hash: record.hash };
            if (controls.failNextAppendBeforeCommit) {
                controls.failNextAppendBeforeCommit = false;
                throw new Error('pg_failed_before_commit');
            }
            scopes.set(key, draft);
            if (controls.loseNextAppendResponse) {
                controls.loseNextAppendResponse = false;
                throw new Error('pg_response_lost_after_commit');
            }
            return result([{ appended: true }]);
        });
    }
    return {
        controls,
        query,
        state(tenant, gate, stream) {
            return stateFor(tenant, gate, stream, true);
        },
    };
}
function backendFor(fake, tenantId = 'tenant-a', gateId = 'gate-a') {
    return createPostgresEvidenceBackend({ query: fake.query, tenantId, gateId });
}
test('postgres evidence: constructor, health, head, all, and empty verification are strict', async () => {
    assert.throws(() => createPostgresEvidenceBackend(), /query must be/);
    assert.throws(() => createPostgresEvidenceBackend({ query: async () => ({}) }), /tenantId/);
    assert.throws(() => createPostgresEvidenceBackend({ query: async () => ({}), tenantId: 'tenant', gateId: '' }), /gateId/);
    const fake = createFakePostgres();
    const backend = backendFor(fake);
    assert.equal(backend.durable, true);
    assert.equal(backend.atomicAppend, true);
    assert.equal(backend.appendOnly, true);
    assert.deepEqual(await backend.head('decisions'), null);
    assert.deepEqual(await backend.all('decisions'), []);
    assert.deepEqual(await backend.verify('decisions'), { ok: true, length: 0, head: null });
    assert.deepEqual(await backend.health(), {
        ok: true,
        version: PG_EVIDENCE_VERSION,
        scope: { tenantId: 'tenant-a', gateId: 'gate-a' },
        checks: {
            recordsReady: true,
            headsReady: true,
            appendReady: true,
            canReadRecords: true,
            canReadHeads: true,
            noDirectRecordWrites: true,
            noDirectHeadWrites: true,
            canAppend: true,
        },
    });
    fake.controls.health.can_write_records_directly = true;
    assert.equal((await backend.health()).ok, false);
    fake.controls.failReads = true;
    await assert.rejects(backend.health(), /pg_unavailable/);
    assert.deepEqual(await backend.verify('decisions'), {
        ok: false,
        reason: 'backend_read_failed_or_malformed',
    });
});
test('postgres evidence: record() persists exact evidence.js canonical bytes and readback APIs', async () => {
    const fake = createFakePostgres();
    const backend = backendFor(fake);
    const log = createAtomicEvidenceLog(backend, {
        streamId: 'decisions',
        recordIdFactory: () => 'canonical-record-0001',
    });
    const record = await log.record({
        type: 'decision',
        allow: true,
        nested: { zebra: 2, alpha: [true, null, 'value'] },
    });
    const { hash, ...body } = record;
    assert.equal(fake.controls.lastAppend.canonicalBody, canonicalEvidenceJson(body));
    assert.equal(crypto.createHash('sha256').update(fake.controls.lastAppend.canonicalBody).digest('hex'), hash);
    assert.deepEqual(await backend.head('decisions'), { seq: 0, hash });
    assert.deepEqual(await backend.getById('decisions', record.record_id), record);
    assert.deepEqual(await backend.verify('decisions'), { ok: true, length: 1, head: hash });
    assert.deepEqual(await log.verify(), { ok: true, length: 1, head: hash });
    const copy = await backend.all('decisions');
    copy[0].nested.alpha[2] = 'mutated-by-caller';
    assert.equal((await backend.all('decisions'))[0].nested.alpha[2], 'value');
    const dateBody = {
        seq: 0,
        prev_hash: 'genesis',
        record_id: 'date-record-000001',
        value: new Date('2026-07-16T00:00:00.000Z'),
    };
    const callsBefore = fake.controls.appendCalls;
    await assert.rejects(backend.appendIfHead('dates', null, hashRecord(dateBody)), /losslessly JSON-serializable/);
    assert.equal(fake.controls.appendCalls, callsBefore, 'non-lossless records never reach Postgres');
    const escaped = '\u0000'.repeat(350_000);
    assert.ok(Buffer.byteLength(JSON.stringify(escaped), 'utf8') > 2 * 1024 * 1024);
    const escapedRecord = await createAtomicEvidenceLog(backend, {
        streamId: 'escaped-canonical-body',
        recordIdFactory: () => 'escaped-record-00001',
    }).record({ type: 'decision', escaped });
    assert.equal(escapedRecord.seq, 0, 'JSON escape expansion remains compatible with evidence.js limits');
});
test('postgres evidence: two concurrent appenders produce one monotonically increasing chain', async () => {
    const fake = createFakePostgres();
    const backend = backendFor(fake);
    const first = createAtomicEvidenceLog(backend, {
        streamId: 'shared',
        maxRetries: 256,
        recordIdFactory: ids('replica-a'),
    });
    const second = createAtomicEvidenceLog(backend, {
        streamId: 'shared',
        maxRetries: 256,
        recordIdFactory: ids('replica-b'),
    });
    await Promise.all(Array.from({ length: 64 }, (_, index) => ((index % 2 === 0 ? first : second).record({ type: 'decision', index }))));
    const records = await backend.all('shared');
    assert.deepEqual(records.map((record) => record.seq), Array.from({ length: 64 }, (_, index) => index));
    assert.equal(new Set(records.map((record) => record.record_id)).size, 64);
    assert.deepEqual(await backend.verify('shared'), {
        ok: true,
        length: 64,
        head: records.at(-1).hash,
    });
});
test('postgres evidence: tenant and gate scopes isolate identical streams and record IDs', async () => {
    const fake = createFakePostgres();
    const scopes = [
        backendFor(fake, 'tenant-a', 'gate-a'),
        backendFor(fake, 'tenant-b', 'gate-a'),
        backendFor(fake, 'tenant-a', 'gate-b'),
    ];
    const labels = ['tenant-a/gate-a', 'tenant-b/gate-a', 'tenant-a/gate-b'];
    const records = await Promise.all(scopes.map((backend, index) => (createAtomicEvidenceLog(backend, {
        streamId: 'same-stream',
        recordIdFactory: () => 'same-record-id-0001',
    }).record({ type: 'decision', scope: labels[index] }))));
    for (let index = 0; index < scopes.length; index++) {
        assert.equal(records[index].seq, 0);
        assert.equal((await scopes[index].all('same-stream'))[0].scope, labels[index]);
        assert.deepEqual(await scopes[index].verify('same-stream'), {
            ok: true,
            length: 1,
            head: records[index].hash,
        });
    }
    assert.equal(fake.state('tenant-a', 'gate-a', 'same-stream').rows.length, 1);
    assert.equal(fake.state('tenant-b', 'gate-a', 'same-stream').rows.length, 1);
    assert.equal(fake.state('tenant-a', 'gate-b', 'same-stream').rows.length, 1);
});
test('postgres evidence: verify detects tampering, duplicate-sequence forks, and head rollback', async () => {
    const fake = createFakePostgres();
    const backend = backendFor(fake);
    const tamperLog = createAtomicEvidenceLog(backend, {
        streamId: 'tamper',
        recordIdFactory: ids('tamper'),
    });
    await tamperLog.record({ type: 'decision', allow: true });
    fake.state('tenant-a', 'gate-a', 'tamper').rows[0].record.allow = false;
    assert.deepEqual(await backend.verify('tamper'), {
        ok: false,
        at: 0,
        reason: 'hash_mismatch_or_malformed_record',
    });
    const forkLog = createAtomicEvidenceLog(backend, {
        streamId: 'fork',
        recordIdFactory: ids('fork'),
    });
    await forkLog.record({ type: 'decision', branch: 'one' });
    const forkState = fake.state('tenant-a', 'gate-a', 'fork');
    const duplicate = structuredClone(forkState.rows[0]);
    duplicate.record_id = 'fork-injected-00001';
    duplicate.record.record_id = duplicate.record_id;
    forkState.rows.push(duplicate);
    assert.deepEqual(await backend.verify('fork'), {
        ok: false,
        at: 0,
        reason: 'fork_detected',
    });
    const rollbackLog = createAtomicEvidenceLog(backend, {
        streamId: 'rollback',
        recordIdFactory: ids('rollback'),
    });
    const first = await rollbackLog.record({ type: 'decision', index: 0 });
    await rollbackLog.record({ type: 'decision', index: 1 });
    fake.state('tenant-a', 'gate-a', 'rollback').head = { seq: 0, hash: first.hash };
    assert.deepEqual(await backend.verify('rollback'), {
        ok: false,
        reason: 'head_rollback_or_mismatch',
    });
});
test('postgres evidence: rollback and storage failures fail closed; post-commit loss recovers', async () => {
    const fake = createFakePostgres();
    const backend = backendFor(fake);
    const log = createAtomicEvidenceLog(backend, {
        streamId: 'failures',
        recordIdFactory: () => 'stable-failure-id-01',
    });
    fake.controls.failNextAppendBeforeCommit = true;
    await assert.rejects(log.record({ type: 'decision', attempt: 1 }), /atomic_evidence_append_indeterminate/);
    assert.deepEqual(await backend.head('failures'), null);
    assert.deepEqual(await backend.all('failures'), []);
    const retried = await log.record({ type: 'decision', attempt: 1 });
    assert.equal(retried.seq, 0, 'rolled-back sequence remains available');
    assert.equal((await backend.all('failures')).length, 1);
    fake.controls.loseNextAppendResponse = true;
    const recoveredLog = createAtomicEvidenceLog(backend, {
        streamId: 'response-loss',
        recordIdFactory: () => 'stable-response-id-1',
    });
    const recovered = await recoveredLog.record({ type: 'decision', allow: false });
    assert.equal(recovered.record_id, 'stable-response-id-1');
    assert.equal((await backend.all('response-loss')).length, 1);
    fake.controls.failReads = true;
    const unavailable = createAtomicEvidenceLog(backend, {
        streamId: 'outage',
        recordIdFactory: () => 'outage-record-id-001',
    });
    await assert.rejects(unavailable.record({ type: 'decision' }), /pg_unavailable/);
    assert.equal(fake.state('tenant-a', 'gate-a', 'outage').rows.length, 0);
});
test('postgres evidence: malformed driver results never become storage verdicts', async () => {
    const malformed = createPostgresEvidenceBackend({
        tenantId: 'tenant-a',
        gateId: 'gate-a',
        query: async () => ({ rows: [] }),
    });
    await assert.rejects(malformed.readHead('stream'), /storage outcome is unproven/);
    await assert.rejects(malformed.readAll('stream'), /storage outcome is unproven/);
    await assert.rejects(malformed.health(), /storage outcome is unproven/);
    assert.deepEqual(await malformed.verify('stream'), {
        ok: false,
        reason: 'backend_read_failed_or_malformed',
    });
});
test('postgres evidence SQL: row-lock fencing, canonical checks, and DB-role immutability are explicit', () => {
    assert.equal(PG_EVIDENCE_VERSION, 'EP-GATE-PG-EVIDENCE-v1');
    assert.equal(EVIDENCE_SCHEMA, 'emilia_gate_evidence');
    assert.equal(EVIDENCE_RECORDS_TABLE, 'emilia_gate_evidence.records');
    assert.equal(EVIDENCE_HEADS_TABLE, 'emilia_gate_evidence.heads');
    assert.equal(EVIDENCE_APPEND_FUNCTION, 'emilia_gate_evidence.append_record');
    assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, gate_id, stream_id, seq\)/);
    assert.match(MIGRATION, /UNIQUE \(tenant_id, gate_id, stream_id, record_id\)/);
    assert.match(MIGRATION, /head_seq BETWEEN 0 AND 9007199254740991/);
    assert.match(MIGRATION, /octet_length\(p_canonical_body\) > 8388608/);
    assert.match(MIGRATION, /SECURITY DEFINER/);
    assert.match(MIGRATION, /SET search_path = pg_catalog, pg_temp/);
    assert.match(MIGRATION, /FOR UPDATE;/);
    assert.match(MIGRATION, /p_expected_head_hash IS DISTINCT FROM v_head_hash/);
    assert.match(MIGRATION, /public\.digest\(convert_to\(p_canonical_body, 'UTF8'\), 'sha256'\)/);
    assert.match(MIGRATION, /v_body IS DISTINCT FROM \(p_record - 'hash'\)/);
    assert.match(MIGRATION, /BEFORE UPDATE OR DELETE OR TRUNCATE/);
    assert.match(MIGRATION, /ALTER ROLE emilia_gate_evidence_runtime[\s\S]+NOLOGIN[\s\S]+NOINHERIT/);
    assert.match(MIGRATION, /ALTER TABLE emilia_gate_evidence\.records OWNER TO CURRENT_USER/);
    assert.match(MIGRATION, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER/);
    assert.match(MIGRATION, /GRANT SELECT ON emilia_gate_evidence\.records, emilia_gate_evidence\.heads/);
    assert.match(MIGRATION, /GRANT EXECUTE ON FUNCTION emilia_gate_evidence\.append_record/);
    assert.doesNotMatch(MIGRATION, /GRANT\s+(INSERT|UPDATE|DELETE|TRUNCATE)/i);
    assert.match(EVIDENCE_SQL.appendIfHead, /append_record\(\$1, \$2, \$3, \$4, \$5::jsonb, \$6\)/);
});
