// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { runActionEscrowScenario } from './scenario.mjs';
const scenario = await runActionEscrowScenario();
const { view } = scenario;
console.log('ACTION ESCROW - KITCHEN RENOVATION REFERENCE RUN');
console.log('Both sides sign. The system obeys.');
console.log('');
for (const row of view.integration_rows) {
    console.log(`${row.number}  ${row.label.padEnd(42)} ${row.status}`);
    console.log(`    ${row.boundary}`);
}
console.log('');
console.log(`RELEASE  ${view.project.release_amount} -> ${view.project.destination_id}`);
console.log(`GATE     ${view.release.gate.allowed ? 'ALLOWED' : 'REFUSED'}; custodian calls: ${view.release.gate.release_calls}`);
console.log(`REPLAY   ${view.release.gate.replay_refused ? 'REFUSED' : 'NOT REFUSED'}`);
console.log('');
for (const attack of view.attacks) {
    console.log(`ATTACK   ${attack.title.padEnd(22)} ${attack.refused ? 'REFUSED' : 'FAILED'} (${attack.reason})`);
}
console.log('');
console.log('SIMULATED CUSTODY: no provider is connected, no real funds move, and EMILIA does not hold money.');
console.log('The demo does not establish legal enforceability, identity, licensing, workmanship, or physical completion.');
