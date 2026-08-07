// SPDX-License-Identifier: Apache-2.0
// Generated from demo.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const demo = fileURLToPath(new URL('./demo.mjs', import.meta.url));
test('authority-loop demo produces all four terminal verdicts with verified certificates', () => {
    const result = spawnSync(process.execPath, [demo], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /EMILIA AUTHORITY LOOP/);
    assert.match(result.stdout, /CAID: caid:1:travel\.book\.1:jcs-sha256:/);
    assert.match(result.stdout, /ALLOW: executed, certificate verified offline \(ticketed\)/);
    assert.match(result.stdout, /Unattended envelope: 340 of 500 USD consumed/);
    assert.match(result.stdout, /ASK: refused unattended \(budget_exceeded\)/);
    assert.match(result.stdout, /APPROVED ONCE: exact-action capability \(CAID-pinned, 620 USD\) executed/);
    assert.match(result.stdout, /REPLAY REFUSED: operation_already_committed/);
    assert.match(result.stdout, /Mandate grammar refusals: unknown_action_type/);
    assert.match(result.stdout, /REFUSE: mandate_refused:unknown_action_type/);
    assert.match(result.stdout, /INDETERMINATE: effect_indeterminate/);
    assert.match(result.stdout, /Unattended envelope: 460 of 500 USD consumed/);
    assert.match(result.stdout, /BLIND RETRY REFUSED: operation_already_committed/);
    assert.match(result.stdout, /all seven certificates verified offline/);
    assert.doesNotMatch(result.stdout, /secret|private/i);
});
