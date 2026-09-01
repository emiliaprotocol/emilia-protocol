// SPDX-License-Identifier: Apache-2.0

import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const source = readFileSync(resolve(ROOT, '.github/workflows/dco.yml'), 'utf8');
const workflow = YAML.parse(source);
const job = workflow.jobs.dco;
const checkout = job.steps.find(
  (step: { uses?: string }) => step.uses?.startsWith('actions/checkout@'),
);
const signoff = job.steps.find(
  (step: { name?: string }) => step.name === 'Check DCO sign-off',
);

function git(repository: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd: repository,
    encoding: 'utf8',
  }).trim();
}

function commit(
  repository: string,
  authorName: string,
  authorEmail: string,
  message: string,
): string {
  execFileSync('git', ['commit', '--quiet', '--allow-empty', '-m', message], {
    cwd: repository,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: authorName,
      GIT_AUTHOR_EMAIL: authorEmail,
      GIT_COMMITTER_NAME: 'DCO contract fixture',
      GIT_COMMITTER_EMAIL: 'dco-contract@example.com',
    },
  });
  return git(repository, ['rev-parse', 'HEAD']);
}

function runDco(repository: string, baseSha: string, headSha: string) {
  return spawnSync('bash', ['-euo', 'pipefail', '-c', signoff.run], {
    cwd: repository,
    encoding: 'utf8',
    env: {
      ...process.env,
      BASE_SHA: baseSha,
      HEAD_SHA: headSha,
    },
  });
}

describe('DCO workflow contract', () => {
  it('runs checkout and the required check without a PR-author exemption', () => {
    expect(job).not.toHaveProperty('if');
    expect(checkout).not.toHaveProperty('if');
    expect(signoff).not.toHaveProperty('if');
    expect(source).not.toContain('github.event.pull_request.user.login');
  });

  it('exempts only recognized Dependabot commit authors and checks every human commit', () => {
    expect(signoff.run).toContain("author_name=\"$(git show -s --format='%an' \"$commit_sha\")\"");
    expect(signoff.run).toContain("author_email=\"$(git show -s --format='%ae' \"$commit_sha\")\"");
    expect(signoff.run).toContain('49699333+dependabot[bot]@users.noreply.github.com');
    expect(signoff.run).toContain('support@github.com');
    expect(signoff.run).toContain('continue');
    expect(signoff.run).toContain('Signed-off-by: $author');

    const repository = mkdtempSync(join(tmpdir(), 'emilia-dco-contract-'));
    try {
      git(repository, ['init', '--quiet']);
      const base = commit(
        repository,
        'Pat Example',
        'pat@example.com',
        'base\n\nSigned-off-by: Pat Example <pat@example.com>',
      );
      commit(
        repository,
        'dependabot[bot]',
        '49699333+dependabot[bot]@users.noreply.github.com',
        'current Dependabot identity',
      );
      const botOnlyHead = commit(
        repository,
        'dependabot[bot]',
        'support@github.com',
        'legacy Dependabot identity',
      );

      expect(runDco(repository, base, botOnlyHead).status).toBe(0);

      const signedHumanHead = commit(
        repository,
        'Pat Example',
        'pat@example.com',
        'signed human change\n\nSigned-off-by: Pat Example <pat@example.com>',
      );
      expect(runDco(repository, base, signedHumanHead).status).toBe(0);

      const unsignedHumanHead = commit(
        repository,
        'dependabot[bot]',
        'human@example.com',
        'human identity cannot borrow the bot name',
      );
      const unsignedResult = runDco(repository, base, unsignedHumanHead);
      expect(unsignedResult.status).toBe(1);
      expect(`${unsignedResult.stdout}${unsignedResult.stderr}`).toContain(
        `Commit ${unsignedHumanHead} is missing Signed-off-by: dependabot[bot] <human@example.com>`,
      );
    } finally {
      rmSync(repository, { recursive: true, force: true });
    }
  });
});
