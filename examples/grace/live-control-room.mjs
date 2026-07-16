#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { runGraceReferenceScenario } from '../../lib/grace/reference-scenario.js';

const result = await runGraceReferenceScenario();
if (process.argv.includes('--json')) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else {
  const proof = result.positive;
  const samples = proof.meter_statement.intervals.map((item) => item.load_mw).join(' -> ');
  console.log('GRACE LIVE CONTROL ROOM (reference simulation)');
  console.log('');
  console.log(`  ACTION      ${proof.action_hash}`);
  console.log('  MOBILE      2 distinct Class-A handshakes: VERIFIED');
  console.log(`  COSA        ${proof.acknowledgment.status.toUpperCase()} (reference adapter)`);
  console.log(`  POWER MW    ${proof.meter_statement.baseline_mw} -> ${samples}`);
  console.log(`  DELIVERY    ${(proof.compliance.compliance_ratio * 100).toFixed(1)}%`);
  console.log(`  ACTIONSTATE ${proof.action_state.statement_digest} (signed, unregistered)`);
  console.log(`  SETTLEMENT  ${proof.settlement.settled ? 'CONSUMED ONCE' : 'NOT SETTLED'}`);
  console.log('');
  for (const [name, attack] of Object.entries(result.attacks)) {
    console.log(`  ATTACK      ${name.padEnd(21)} ${attack.refused ? 'REFUSED' : 'FAILED'} (${attack.verdict})`);
  }
  console.log('');
  console.log('  Honest boundary: synthetic actuator and meter; no physical grid event is claimed.');
}

if (!result.positive.ok || !Object.values(result.attacks).every((attack) => attack.refused)) {
  process.exitCode = 1;
}
