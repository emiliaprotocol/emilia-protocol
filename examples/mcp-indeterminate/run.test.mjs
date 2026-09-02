// SPDX-License-Identifier: Apache-2.0
// Generated from run.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
//   node --test examples/mcp-indeterminate/run.test.mjs
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { AUTHORITY_INSTANCE_DIGEST, actionCaid, nextLegalMove, replayUnitForRun, runConformantHost, runFailedPath, runModelChosenKeyProbe, runNaiveHost, } from './client.mjs';
import { AEB_MAPPING, FIELD_GROUP_VERSION, META_OUTCOME, OUTCOME_VALUES, deriveReplayUnit, mappingFor, parseOutcomeEnvelope, } from './field-group.mjs';
import { verifyProviderStatement } from './ledger.mjs';
const here = dirname(fileURLToPath(import.meta.url));
function scratch() {
    return mkdtempSync(join(tmpdir(), 'ep-mcp-test-'));
}
test('a naive retry on today\'s MCP produces a duplicate effect', async () => {
    const dir = scratch();
    try {
        const run = await runNaiveHost(dir);
        assert.equal(run.effects, 2, 'one authorization must have produced two settled payments');
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
test('the field group turns the same crash into indeterminate then executed, once', async () => {
    const dir = scratch();
    try {
        const run = await runConformantHost(dir);
        assert.equal(run.effects, 1);
        assert.equal(run.finalOutcome, 'executed');
        const wire = run.lines.filter((l) => l.who === 'wire').map((l) => l.text).join('\n');
        assert.match(wire, /outcome=indeterminate retry=refuse reconciliation=required/);
        assert.match(wire, /outcome=executed retry=not_applicable reconciliation=applied/);
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
test('a crash before the effect reconciles to failed and requires a new admission', async () => {
    const dir = scratch();
    try {
        const run = await runFailedPath(dir);
        assert.equal(run.effects, 0, 'no effect may have landed');
        assert.equal(run.finalOutcome, 'failed');
        assert.equal(run.retry, 'requires_new_admission');
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
test('a model-chosen replay unit is refused with a stated reason and no effect', async () => {
    const dir = scratch();
    try {
        const probe = await runModelChosenKeyProbe(dir);
        assert.equal(probe.isError, true);
        assert.deepEqual(probe.refusals, ['replay_unit_not_derived_from_authority_and_action']);
        assert.equal(probe.effects, 0, 'a refused call must not have caused an effect');
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
test('nextLegalMove never offers a retry for indeterminate', () => {
    const replayUnit = replayUnitForRun();
    const parsed = parseOutcomeEnvelope({
        version: FIELD_GROUP_VERSION,
        replay_unit: replayUnit,
        outcome: 'indeterminate',
        retry: 'refuse',
        reconciliation: 'required',
        reason_codes: [],
        reconcile: { method: 'tools/call', tool: 'reconcile_effect', replay_unit: replayUnit },
    });
    assert.equal(parsed.ok, true);
    if (!parsed.ok)
        return;
    const move = nextLegalMove(parsed.envelope);
    assert.equal(move.kind, 'reconcile');
    if (move.kind !== 'reconcile')
        return;
    assert.equal(move.handle.replay_unit, replayUnit);
});
test('the parser refuses an envelope whose reconcile handle names another replay unit', () => {
    const replayUnit = replayUnitForRun();
    const parsed = parseOutcomeEnvelope({
        version: FIELD_GROUP_VERSION,
        replay_unit: replayUnit,
        outcome: 'indeterminate',
        retry: 'refuse',
        reconciliation: 'required',
        reason_codes: [],
        reconcile: {
            method: 'tools/call',
            tool: 'reconcile_effect',
            replay_unit: `sha256:${'0'.repeat(64)}`,
        },
    });
    assert.equal(parsed.ok, false);
    if (parsed.ok)
        return;
    assert.ok(parsed.refusals.includes('reconcile_handle_not_bound_to_replay_unit'));
});
test('an indeterminate envelope that invites a retry is refused', () => {
    const replayUnit = replayUnitForRun();
    const parsed = parseOutcomeEnvelope({
        version: FIELD_GROUP_VERSION,
        replay_unit: replayUnit,
        outcome: 'indeterminate',
        retry: 'not_applicable',
        reconciliation: 'not_applicable',
        reason_codes: [],
    });
    assert.equal(parsed.ok, false);
    if (parsed.ok)
        return;
    assert.ok(parsed.refusals.includes('indeterminate_must_refuse_retry'));
});
test('closed sets: an unknown outcome value is refused, not passed through', () => {
    const parsed = parseOutcomeEnvelope({
        version: FIELD_GROUP_VERSION,
        replay_unit: replayUnitForRun(),
        outcome: 'probably_fine',
        retry: 'refuse',
        reconciliation: 'required',
        reason_codes: [],
    });
    assert.equal(parsed.ok, false);
    if (parsed.ok)
        return;
    assert.ok(parsed.refusals.includes('unknown_outcome_value'));
});
test('the derivation refuses junk instead of throwing', () => {
    for (const bad of [null, 'x', 42, {}, { authority_instance_digest: 'nope', caid: 'nope' }]) {
        const out = deriveReplayUnit(bad);
        assert.equal(out.ok, false);
        if (out.ok)
            continue;
        assert.ok(out.refusals.length > 0);
    }
});
test('the replay unit is bound to the exact action', () => {
    const a = deriveReplayUnit({
        authority_instance_digest: AUTHORITY_INSTANCE_DIGEST,
        caid: actionCaid(),
    });
    const b = deriveReplayUnit({
        authority_instance_digest: `sha256:${'1'.repeat(64)}`,
        caid: actionCaid(),
    });
    assert.equal(a.ok && b.ok, true);
    if (!a.ok || !b.ok)
        return;
    assert.notEqual(a.replay_unit, b.replay_unit);
    assert.equal(a.replay_unit, replayUnitForRun());
});
test('a provider statement under an unpinned key is refused', () => {
    const out = verifyProviderStatement({ statement: { operation_id: 'x', found: null, watermark: {} }, signature: 'AA', public_key_spki_b64: 'BB' }, 'CC');
    assert.equal(out.ok, false);
    if (out.ok)
        return;
    assert.deepEqual(out.refusals, ['provider_key_not_pinned']);
});
test('every vector in the pack parses and maps to an AEB state', () => {
    const pack = JSON.parse(readFileSync(join(here, 'vectors.v1.json'), 'utf8'));
    assert.equal(pack.vectors.length, 6);
    assert.deepEqual(pack.aeb_mapping, JSON.parse(JSON.stringify(AEB_MAPPING)));
    let mapped = 0;
    for (const vector of pack.vectors) {
        const envelope = vector.result?._meta?.[META_OUTCOME];
        if (envelope === undefined)
            continue;
        const parsed = parseOutcomeEnvelope(envelope);
        assert.equal(parsed.ok, true, `${vector.id} failed to parse`);
        if (!parsed.ok)
            continue;
        const row = mappingFor(parsed.envelope.outcome, parsed.envelope.retry, parsed.envelope.reconciliation);
        assert.ok(row !== null, `${vector.id} has no AEB mapping row`);
        mapped += 1;
    }
    assert.equal(mapped, 4);
});
test('the four AEB-04 states named in the task are all covered', () => {
    const covered = new Set(AEB_MAPPING.map((r) => r.aeb_state));
    for (const state of ['EXECUTED', 'FAILED', 'INDETERMINATE', 'REQUIRES_NEW_ADMISSION']) {
        assert.ok(covered.has(state), `${state} is not in the mapping`);
    }
    assert.deepEqual([...OUTCOME_VALUES], ['executed', 'failed', 'indeterminate']);
});
