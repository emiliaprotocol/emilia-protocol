#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Regenerates lib/proof-stats.json from ground truth or checks it in CI.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const check = process.argv.includes('--check');
const execution = spawnSync('npx', ['vitest', 'run', '--silent', '--reporter=json'], {
  encoding: 'utf8',
  maxBuffer: 1e9,
});
if (execution.error) throw execution.error;
const j = JSON.parse(execution.stdout);
if (execution.status !== 0) {
  console.error('PROOF STATS: FAIL — the measured test run did not pass');
  for (const result of j.testResults.filter((item) => item.status === 'failed').slice(0, 20)) {
    console.error(result.name);
    for (const assertion of result.assertionResults.filter((item) => item.status === 'failed').slice(0, 10)) {
      console.error(`  ${assertion.fullName}`);
      for (const message of assertion.failureMessages.slice(0, 2)) console.error(`  ${message.split('\n')[0]}`);
    }
  }
  process.exit(1);
}
const cfg = readFileSync('formal/ep_handshake.cfg', 'utf8');
const als = readFileSync('formal/ep_relations.als', 'utf8');
const fedAls = readFileSync('formal/ep_federation.als', 'utf8');
const redTeam = readFileSync('docs/conformance/RED_TEAM_CASES.md', 'utf8');

const stats = {
  generatedAt: new Date().toISOString(),
  tests: {
    total: j.numTotalTests,
    files: j.testResults.length,
    policy: 'all platform-applicable cases must pass; platform-specific cases may skip',
  },
  tla: {
    invariants: (cfg.match(/^INVARIANT/gm) || []).length,
    checker: 'TLC 2.19',
  },
  alloy: {
    // facts: the core relational model (ep_relations); assertions: total across
    // both models (ep_relations + ep_federation) — the convention used in docs.
    facts: (als.match(/^fact/gm) || []).length,
    assertions: (als.match(/^assert/gm) || []).length + (fedAls.match(/^assert/gm) || []).length,
    version: '6.0.0 (CI)',
  },
  redTeamCases: (redTeam.match(/^### /gm) || []).length,
};

if (check) {
  const current = JSON.parse(readFileSync('lib/proof-stats.json', 'utf8'));
  const measured = { ...stats };
  const recorded = { ...current };
  delete measured.generatedAt;
  delete recorded.generatedAt;
  if (!isDeepStrictEqual(measured, recorded)) {
    console.error('PROOF STATS: FAIL — lib/proof-stats.json does not match the executed suite');
    console.error(JSON.stringify({ recorded, measured }, null, 2));
    process.exitCode = 1;
  } else {
    console.log(`PROOF STATS: PASS (${stats.tests.total} test cases, ${stats.tests.files} files, all platform-applicable cases passed; ${stats.tla.invariants} TLA+ invariants, ${stats.alloy.facts} Alloy facts, ${stats.redTeamCases} red-team cases)`);
  }
} else {
  writeFileSync('lib/proof-stats.json', `${JSON.stringify(stats, null, 2)}\n`);
  console.log(stats);
}
