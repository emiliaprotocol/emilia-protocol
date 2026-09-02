// SPDX-License-Identifier: Apache-2.0
//
//   node examples/mcp-indeterminate/run.mjs
//
// Runs both host loops against the same injected crash, in two clean stores,
// and prints the two transcripts recorded in README.md.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runConformantHost, runNaiveHost, type Line } from './client.mjs';

const WIDTH = 78;

function rule(title: string): void {
  const bar = '='.repeat(WIDTH);
  process.stdout.write(`\n${bar}\n${title}\n${bar}\n`);
}

function print(lines: Line[]): void {
  for (const line of lines) {
    process.stdout.write(`${line.who.padEnd(6)} | ${line.text}\n`);
  }
}

async function main(): Promise<number> {
  const naiveDir = mkdtempSync(join(tmpdir(), 'ep-mcp-naive-'));
  const goodDir = mkdtempSync(join(tmpdir(), 'ep-mcp-fieldgroup-'));
  let failures = 0;
  try {
    rule('TRANSCRIPT 1  naive retry on today\'s MCP  ->  duplicate effect');
    const naive = await runNaiveHost(naiveDir);
    print(naive.lines);
    if (naive.effects !== 2) {
      process.stdout.write(`\nFAIL: expected 2 provider entries, saw ${naive.effects}\n`);
      failures += 1;
    }

    rule('TRANSCRIPT 2  EP-MCP-OUTCOME-v1  ->  indeterminate, reconcile, one effect');
    const good = await runConformantHost(goodDir);
    print(good.lines);
    if (good.effects !== 1 || good.finalOutcome !== 'executed') {
      process.stdout.write(
        `\nFAIL: expected 1 provider entry and outcome executed, saw ${good.effects} `
        + `and ${good.finalOutcome}\n`,
      );
      failures += 1;
    }

    process.stdout.write(
      `\nsame crash, same action, same authority: `
      + `${naive.effects} effects without the field group, ${good.effects} with it.\n`,
    );
  } finally {
    rmSync(naiveDir, { recursive: true, force: true });
    rmSync(goodDir, { recursive: true, force: true });
  }
  return failures;
}

process.exit(await main());
