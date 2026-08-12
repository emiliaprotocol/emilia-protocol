// SPDX-License-Identifier: Apache-2.0
import { appendFile } from 'node:fs/promises';
import { evaluateMergeGate } from './verify.mjs';

function input(name) {
  return process.env[`INPUT_${name.toUpperCase()}`]
    ?? process.env[`INPUT_${name.toUpperCase().replaceAll('-', '_')}`]
    ?? '';
}

async function output(name, value) {
  if (!process.env.GITHUB_OUTPUT) return;
  await appendFile(process.env.GITHUB_OUTPUT, `${name}=${String(value).replaceAll('\n', '%0A')}\n`);
}

async function summary(result) {
  if (!process.env.GITHUB_STEP_SUMMARY) return;
  const lines = [
    '# EMILIA Merge Gate',
    '',
    `**Decision:** ${result.admitted ? 'ADMIT' : 'REFUSE'}`,
    '',
    `**Reason:** \`${result.reason}\``,
  ];
  if (result.admitted) {
    lines.push('', `**CAID:** \`${result.caid}\``, '', `**Changed files:** ${result.diff.changed_files}`);
  }
  lines.push('', '> This check does not merge the pull request. Prevention requires this check to be required by branch protection or a ruleset.');
  await appendFile(process.env.GITHUB_STEP_SUMMARY, `${lines.join('\n')}\n`);
}

async function main() {
  const result = await evaluateMergeGate({
    workspace: process.env.GITHUB_WORKSPACE,
    baseSha: input('BASE-SHA'),
    headSha: input('HEAD-SHA'),
    repository: input('REPOSITORY'),
    baseRef: input('BASE-REF'),
    mandatePath: input('MANDATE-PATH') || '.emilia/merge-mandate.json',
    receiptPath: input('RECEIPT-PATH'),
    issuerPublicKey: input('ISSUER-PUBLIC-KEY'),
    now: input('EVALUATION-TIME') || new Date().toISOString(),
  });
  await output('admitted', result.admitted);
  await output('reason', result.reason);
  await output('caid', result.caid ?? '');
  await output('mandate-digest', result.mandate_digest ?? '');
  await summary(result);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.admitted) process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
