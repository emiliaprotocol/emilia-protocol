// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runSuite } from './run.mjs';
import { runExecutorSuite } from './executor-profile.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length === 1 && args[0] === '--emit'), 'Usage: node check.mjs [--emit]');
for (const [name, report] of [
  ['report.reference.json', runSuite()],
  ['executor.report.reference.json', await runExecutorSuite()],
]) {
  assert.equal(report.summary.failed, 0, `${name}: failing cases`);
  const path = resolve(here, name);
  if (args[0] === '--emit') {
    writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
  } else {
    assert.deepEqual(report, JSON.parse(readFileSync(path, 'utf8')), `${name}: reference differs`);
  }
  process.stdout.write(`${name}: ${report.summary.passed}/${report.summary.total} passed; ${args[0] === '--emit' ? 'reference regenerated' : 'reference matched'}\n`);
}
