// SPDX-License-Identifier: Apache-2.0

import { execFileSync, spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
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

  it('exempts only Dependabot and derived-evidence-only autopilot commits, and checks every human commit', () => {
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

      // Evidence autopilot: an App bot commit with the trailer that changes
      // only derived evidence needs no sign-off; the same identity touching
      // any other path fails.
      const autopilotName = 'emilia-evidence-autopilot[bot]';
      const autopilotEmail = '123456+emilia-evidence-autopilot[bot]@users.noreply.github.com';
      const autopilotCommit = (paths: string[]) => {
        for (const file of paths) {
          mkdirSync(dirname(join(repository, file)), { recursive: true });
          appendFileSync(join(repository, file), `${file}\n`);
          git(repository, ['add', '--', file]);
        }
        execFileSync('git', ['commit', '--quiet', '-m', 'chore(evidence): regenerate\n\nEvidence-Autopilot: v1'], {
          cwd: repository,
          env: {
            ...process.env,
            GIT_AUTHOR_NAME: autopilotName,
            GIT_AUTHOR_EMAIL: autopilotEmail,
            GIT_COMMITTER_NAME: autopilotName,
            GIT_COMMITTER_EMAIL: autopilotEmail,
          },
        });
        return git(repository, ['rev-parse', 'HEAD']);
      };
      git(repository, ['checkout', '--quiet', '--detach', signedHumanHead]);
      const evidenceOnly = autopilotCommit(['lib/proof-stats.json', 'public/.well-known/emilia-context.json']);
      expect(runDco(repository, signedHumanHead, evidenceOnly).status).toBe(0);
      const smuggled = autopilotCommit(['security/security-case.json', 'lib/code.ts']);
      const smuggledResult = runDco(repository, signedHumanHead, smuggled);
      expect(smuggledResult.status).toBe(1);
      expect(`${smuggledResult.stdout}${smuggledResult.stderr}`).toContain(
        `Commit ${smuggled} claims to be an evidence autopilot commit but is a merge or changes other paths: lib/code.ts`,
      );

      // Merge groups: GitHub's unsigned queue merge commit is skipped only
      // when the workflow says the event is a merge group.
      git(repository, ['checkout', '--quiet', '--detach', signedHumanHead]);
      commit(repository, 'Pat Example', 'pat@example.com', 'side\n\nSigned-off-by: Pat Example <pat@example.com>');
      execFileSync('git', ['merge', '--quiet', '--no-ff', '-m', 'Merge pull request #2', evidenceOnly], {
        cwd: repository,
        env: { ...process.env, GIT_AUTHOR_NAME: 'Queue', GIT_AUTHOR_EMAIL: 'queue@example.com', GIT_COMMITTER_NAME: 'Queue', GIT_COMMITTER_EMAIL: 'queue@example.com' },
      });
      const groupHead = git(repository, ['rev-parse', 'HEAD']);
      const inGroup = (skip: string) => spawnSync('bash', ['-euo', 'pipefail', '-c', signoff.run], {
        cwd: repository,
        encoding: 'utf8',
        env: { ...process.env, BASE_SHA: signedHumanHead, HEAD_SHA: groupHead, DCO_SKIP_MERGE_COMMITS: skip },
      });
      expect(inGroup('true').status).toBe(0);
      expect(inGroup('false').status).toBe(1);
      expect(signoff.env.DCO_SKIP_MERGE_COMMITS).toBe("${{ github.event_name == 'merge_group' }}");
    } finally {
      rmSync(repository, { recursive: true, force: true });
    }
  });
});
