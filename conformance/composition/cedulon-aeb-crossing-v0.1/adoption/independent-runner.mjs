// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../../..');
const PROFILE = 'conformance/composition/cedulon-aeb-crossing-v0.1';

export const COMMANDS = Object.freeze([
  Object.freeze(['npm', '--prefix', 'packages/verify', 'run', 'build']),
  Object.freeze(['node', '--test', `${PROFILE}/adoption/validate.node-test.mjs`]),
  Object.freeze(['node', '--test', `${PROFILE}/run.test.mjs`]),
  Object.freeze(['node', `${PROFILE}/run.mjs`]),
  Object.freeze(['node', 'packages/verify/cli.js', 'crossing-lab', 'run', `${PROFILE}/workspace`]),
]);

function sha256(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function git(...args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
}

function run(command) {
  const [file, ...args] = command;
  const result = spawnSync(file, args, {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return {
    command: command.join(' '),
    exit_code: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function parseJsonOutput(result, label) {
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`${label} did not emit one JSON document: ${error.message}`);
  }
}

export function runIndependentReproduction() {
  if (process.argv.length !== 2) throw new Error('independent runner accepts no arguments or command overrides');
  const trackedStatus = git('status', '--porcelain', '--untracked-files=no');
  if (trackedStatus !== '') throw new Error('tracked worktree must be clean before independent reproduction');

  const startedAt = new Date().toISOString();
  const results = COMMANDS.map(run);
  const failed = results.find((result) => result.exit_code !== 0);
  if (failed) {
    process.stderr.write(failed.stderr || failed.stdout);
    throw new Error(`reproduction command failed: ${failed.command}`);
  }

  const profileReport = parseJsonOutput(results[3], 'profile runner');
  const labReport = parseJsonOutput(results[4], 'Crossing Lab CLI');
  if (profileReport.profile_passed !== true || labReport.lab_passed !== true) {
    throw new Error('profile or Crossing Lab did not report a passing result');
  }
  if (profileReport.crossing_lab_report_digest !== labReport.report_digest) {
    throw new Error('profile and Crossing Lab report digests differ');
  }

  const scriptBytes = readFileSync(fileURLToPath(import.meta.url));
  const packageLockBytes = readFileSync(resolve(ROOT, 'package-lock.json'));
  const sourceLockBytes = readFileSync(resolve(ROOT, PROFILE, 'source-lock.json'));
  const reportBytes = readFileSync(resolve(ROOT, PROFILE, 'report.reference.json'));
  const npmVersion = execFileSync('npm', ['--version'], { cwd: ROOT, encoding: 'utf8' }).trim();
  const trackedStatusAfter = git('status', '--porcelain', '--untracked-files=no');
  if (trackedStatusAfter !== '') throw new Error('reproduction commands changed tracked worktree files');
  const finishedAt = new Date().toISOString();
  return {
    '@version': 'EMILIA-INDEPENDENT-CROSSING-RUN-RECORD-v0.1',
    status: 'PASS',
    claim: 'exact-commit local reproduction only',
    profile: 'cedulon-aeb-crossing-v0.1',
    repository: 'https://github.com/emiliaprotocol/emilia-protocol',
    commit: git('rev-parse', 'HEAD'),
    tracked_worktree_clean_at_start: true,
    tracked_worktree_clean_at_end: true,
    started_at: startedAt,
    finished_at: finishedAt,
    runtime: {
      node_version: process.version,
      npm_version: npmVersion,
      package_lock_sha256: sha256(packageLockBytes),
    },
    runner: {
      path: relative(ROOT, fileURLToPath(import.meta.url)),
      sha256: sha256(scriptBytes),
      commands: results.map(({ command, exit_code }) => ({ command, exit_code })),
    },
    observed: {
      source_lock_file_sha256: sha256(sourceLockBytes),
      reference_report_file_sha256: sha256(reportBytes),
      report_digest: profileReport.report_digest,
      crossing_lab_report_digest: labReport.report_digest,
    },
    claim_boundary: {
      native_author_confirmation: false,
      endorsement_or_certification: false,
      authorization: false,
      production_deployment: false,
      settlement_or_payment_finality: false,
      general_security_assurance: false,
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(runIndependentReproduction(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
