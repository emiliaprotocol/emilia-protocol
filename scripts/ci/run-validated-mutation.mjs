// SPDX-License-Identifier: Apache-2.0
import { spawn } from 'node:child_process';
import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mutationGateExitCode, validateMutationReportFile } from './validate-mutation-report.mjs';

const campaigns = Object.freeze({
  core: ['stryker.config.js', 'reports/mutation/core.json'],
  security: ['stryker.security.config.js', 'reports/mutation/security-kernel.json'],
  aec: ['stryker.aec.config.js', 'reports/mutation/aec-kernel.json'],
  'model-to-matter': ['stryker.model-to-matter.config.js', 'reports/mutation/model-to-matter.json'],
});
const campaign = process.argv[2];
if (!Object.hasOwn(campaigns, campaign)) {
  throw new Error(`Unknown mutation campaign: ${campaign}`);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [config, report] = campaigns[campaign];
const reportPath = path.join(root, report);
// Exact, generated report only. A stale passing JSON must not mask a crash.
rmSync(reportPath, { force: true });

const child = spawn(
  process.execPath,
  [path.join(root, 'node_modules/@stryker-mutator/core/bin/stryker.js'), 'run', config],
  { cwd: root, env: { ...process.env, EP_MUTATE_SRC: '1' }, stdio: 'inherit' },
);
const strykerResult = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('close', (code, signal) => resolve({ code, signal }));
});

let validationFailed = false;
try {
  const count = validateMutationReportFile(reportPath);
  process.stdout.write(`Mutation report integrity: PASS (${count} mutants, ${campaign})\n`);
} catch (error) {
  validationFailed = true;
  process.stderr.write(`Mutation report integrity: FAIL (${campaign}): ${error.message}\n`);
}
if (strykerResult.signal) {
  process.stderr.write(`Stryker exited on signal ${strykerResult.signal}\n`);
}
process.exitCode = mutationGateExitCode(strykerResult, validationFailed);
