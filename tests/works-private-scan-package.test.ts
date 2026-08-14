// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import { createPrivateScanPackage } from '../scripts/prepare-works-authority-scan.mjs';

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'works-private-scan-'));
  const repo = path.join(root, 'repo');
  await mkdir(path.join(repo, '.github', 'workflows'), { recursive: true });
  execFileSync('git', ['init', '-b', 'main'], { cwd: repo });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: repo });
  execFileSync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: repo });
  execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/acme/agent.git'], { cwd: repo });
  await writeFile(path.join(repo, '.github', 'workflows', 'test.yml'), [
    'name: test',
    'on: [push]',
    'jobs:',
    '  test:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: npm test',
    '',
  ].join('\n'));
  execFileSync('git', ['add', '.'], { cwd: repo });
  execFileSync('git', ['commit', '-m', 'fixture'], { cwd: repo });
  return { root, repo };
}

describe('private Authority Record scan package', () => {
  it('pins the clean repository, watched ref, scanner profile, and private report', async () => {
    const { root, repo } = await fixture();
    try {
      const output = path.join(root, 'private-package.json');
      const result = await createPrivateScanPackage({
        workspace: repo,
        repositoryUrl: 'https://github.com/acme/agent',
        watchedRef: 'refs/heads/main',
        output,
        observedAt: '2026-08-14T08:00:00.000Z',
      });
      expect(result.package.visibility).toBe('PRIVATE_OPERATOR_ONLY');
      expect(result.package.publication_authorized).toBe(false);
      expect(result.package.source).toMatchObject({
        repository_url: 'https://github.com/acme/agent',
        watched_ref: 'refs/heads/main',
        worktree_clean: true,
      });
      expect(result.package.source.resolved_revision).toMatch(/^[0-9a-f]{40}$/);
      expect(result.package.scanner.profile_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(result.package.report_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(result.package.report.boundary.completeMediation).toBe(false);
      expect(JSON.parse(await readFile(output, 'utf8'))).toEqual(result.package);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('refuses dirty worktrees and ref or origin substitution', async () => {
    const { root, repo } = await fixture();
    try {
      await writeFile(path.join(repo, 'untracked.txt'), 'dirty\n');
      await expect(createPrivateScanPackage({
        workspace: repo,
        repositoryUrl: 'https://github.com/acme/agent',
        watchedRef: 'refs/heads/main',
        output: path.join(root, 'dirty.json'),
        observedAt: '2026-08-14T08:00:00.000Z',
      })).rejects.toThrow('worktree is not clean');

      await rm(path.join(repo, 'untracked.txt'));
      await expect(createPrivateScanPackage({
        workspace: repo,
        repositoryUrl: 'https://github.com/other/agent',
        watchedRef: 'refs/heads/main',
        output: path.join(root, 'wrong-origin.json'),
        observedAt: '2026-08-14T08:00:00.000Z',
      })).rejects.toThrow('origin does not match');
      await expect(createPrivateScanPackage({
        workspace: repo,
        repositoryUrl: 'https://github.com/acme/agent',
        watchedRef: 'refs/heads/missing',
        output: path.join(root, 'wrong-ref.json'),
        observedAt: '2026-08-14T08:00:00.000Z',
      })).rejects.toThrow('watched ref is unavailable');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
