// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CANONICAL_RELEASE_REPOSITORY,
  validateReleaseApproval,
  verifyReleaseGitState,
  verifyRemoteReleaseGitState,
  verifyUnpublishedReleaseGitState,
} from '../scripts/require-release-approval.mjs';

const queryLocalRemote = (remote) => (_repositoryUrl, references, cwd) => {
  const result = spawnSync(
    'git',
    ['ls-remote', '--exit-code', remote, ...references],
    { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
};

const valid = {
  eventName: 'workflow_dispatch',
  actor: 'FutureEnterprises',
  allowedActor: 'FutureEnterprises',
  tag: 'verify-v3.9.0',
  tagPrefix: 'verify-v',
  packageName: '@emilia-protocol/verify',
  version: '3.9.0',
  confirmation: 'PUBLISH @emilia-protocol/verify@3.9.0',
};

describe('registry release approval', () => {
  it('accepts an owner dispatch bound to the exact package version and tag', () => {
    expect(validateReleaseApproval(valid)).toEqual({
      expectedTag: 'verify-v3.9.0',
      expectedConfirmation: 'PUBLISH @emilia-protocol/verify@3.9.0',
    });
  });

  it('rejects automatic events, other actors, tag drift, and weak confirmation', () => {
    expect(() => validateReleaseApproval({ ...valid, eventName: 'push' })).toThrow(/workflow_dispatch/);
    expect(() => validateReleaseApproval({ ...valid, actor: 'another-maintainer' })).toThrow(/restricted/);
    expect(() => validateReleaseApproval({ ...valid, tag: 'verify-v3.9.1' })).toThrow(/exactly verify-v3.9.0/);
    expect(() => validateReleaseApproval({ ...valid, confirmation: 'PUBLISH' })).toThrow(/confirmation must be exactly/);
  });

  it('binds the checked-out commit to a tag contained in main', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-release-approval-'));
    const run = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
    try {
      run('init', '--initial-branch=main');
      run('config', 'user.name', 'Release Test');
      run('config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'release\n');
      run('add', 'tracked.txt');
      run('commit', '-m', 'release source');
      run('tag', 'verify-v3.9.0');
      run('checkout', '--detach', 'verify-v3.9.0');
      const head = run('rev-parse', 'HEAD').toString().trim();
      const releaseState = {
        cwd: dir,
        tag: 'verify-v3.9.0',
        mainRef: 'refs/heads/main',
        expectedCommit: head,
        expectedRef: 'refs/heads/main',
      };
      expect(verifyReleaseGitState(releaseState)).toMatchObject({
        tag: 'verify-v3.9.0',
        mainRef: 'refs/heads/main',
      });
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'tampered\n');
      expect(() => verifyReleaseGitState(releaseState)).toThrow(/modified tracked files/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses to attribute an ancestor tag commit to a newer workflow dispatch and main commit', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-release-ancestor-'));
    const run = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
    try {
      run('init', '--initial-branch=main');
      run('config', 'user.name', 'Release Test');
      run('config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'tagged release\n');
      run('add', 'tracked.txt');
      run('commit', '-m', 'tagged release');
      run('tag', 'verify-v3.9.0');
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'newer protected main\n');
      run('commit', '-am', 'newer protected main');
      const dispatchedCommit = run('rev-parse', 'HEAD').toString().trim();
      run('checkout', '--detach', 'verify-v3.9.0');

      expect(() => verifyReleaseGitState({
        cwd: dir,
        tag: 'verify-v3.9.0',
        mainRef: 'refs/heads/main',
        expectedCommit: dispatchedCommit,
        expectedRef: 'refs/heads/main',
      })).toThrow(/dispatched commit|exact protected main commit/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a branch-selected dispatch even when it resolves to the release commit', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-release-ref-'));
    const run = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
    try {
      run('init', '--initial-branch=main');
      run('config', 'user.name', 'Release Test');
      run('config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'release\n');
      run('add', 'tracked.txt');
      run('commit', '-m', 'release source');
      run('tag', 'verify-v3.9.0');
      const head = run('rev-parse', 'HEAD').toString().trim();

      expect(() => verifyReleaseGitState({
        cwd: dir,
        tag: 'verify-v3.9.0',
        mainRef: 'refs/heads/main',
        expectedCommit: head,
        expectedRef: 'refs/heads/release-bypass',
      })).toThrow(/dispatch ref.*protected main ref/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('permits tag creation only from the exact clean main commit with no existing tag', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-go-release-approval-'));
    const run = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
    try {
      run('init', '--initial-branch=main');
      run('config', 'user.name', 'Release Test');
      run('config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'release\n');
      run('add', 'tracked.txt');
      run('commit', '-m', 'release source');
      const head = run('rev-parse', 'HEAD').toString().trim();
      expect(verifyUnpublishedReleaseGitState({
        cwd: dir,
        tag: 'packages/go-verify/v2.3.1',
        mainRef: 'refs/heads/main',
        expectedCommit: head,
      })).toMatchObject({ unpublished: true, tag: 'packages/go-verify/v2.3.1' });
      expect(() => verifyUnpublishedReleaseGitState({
        cwd: dir,
        tag: 'packages/go-verify/v2.3.1',
        mainRef: 'refs/heads/main',
        expectedCommit: '0'.repeat(40),
      })).toThrow(/dispatched commit/);
      run('tag', 'packages/go-verify/v2.3.1');
      expect(() => verifyUnpublishedReleaseGitState({
        cwd: dir,
        tag: 'packages/go-verify/v2.3.1',
        mainRef: 'refs/heads/main',
      })).toThrow(/already exists/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('revalidates remote main and the exact remote tag against the dispatched commit', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-release-remote-'));
    const remote = path.join(root, 'remote.git');
    const work = path.join(root, 'work');
    const run = (cwd, ...args) => execFileSync('git', args, { cwd, stdio: 'pipe' });
    try {
      run(root, 'init', '--bare', remote);
      run(root, 'init', '--initial-branch=main', work);
      run(work, 'config', 'user.name', 'Release Test');
      run(work, 'config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(work, 'tracked.txt'), 'release\n');
      run(work, 'add', 'tracked.txt');
      run(work, 'commit', '-m', 'release source');
      run(work, 'tag', '-a', '-m', 'annotated release', 'verify-v3.9.0');
      run(work, 'remote', 'add', 'origin', remote);
      run(work, 'push', 'origin', 'main', 'refs/tags/verify-v3.9.0');
      const head = run(work, 'rev-parse', 'HEAD').toString().trim();

      expect(verifyRemoteReleaseGitState({
        cwd: work,
        tag: 'verify-v3.9.0',
        expectedCommit: head,
        referenceQuery: queryLocalRemote(remote),
      })).toMatchObject({ mainCommit: head, tagCommit: head });
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('refuses a deleted or moved remote release tag and an advanced remote main', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-release-remote-race-'));
    const remote = path.join(root, 'remote.git');
    const work = path.join(root, 'work');
    const run = (cwd, ...args) => execFileSync('git', args, { cwd, stdio: 'pipe' });
    const state = (expectedCommit) => ({
      cwd: work,
      tag: 'verify-v3.9.0',
      expectedCommit,
      referenceQuery: queryLocalRemote(remote),
    });
    try {
      run(root, 'init', '--bare', remote);
      run(root, 'init', '--initial-branch=main', work);
      run(work, 'config', 'user.name', 'Release Test');
      run(work, 'config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(work, 'tracked.txt'), 'release\n');
      run(work, 'add', 'tracked.txt');
      run(work, 'commit', '-m', 'release source');
      run(work, 'tag', 'verify-v3.9.0');
      run(work, 'remote', 'add', 'origin', remote);
      run(work, 'push', 'origin', 'main', 'refs/tags/verify-v3.9.0');
      const releaseCommit = run(work, 'rev-parse', 'HEAD').toString().trim();

      run(work, 'push', 'origin', ':refs/tags/verify-v3.9.0');
      expect(() => verifyRemoteReleaseGitState(state(releaseCommit))).toThrow(/remote release tag.*unavailable/i);

      fs.writeFileSync(path.join(work, 'tracked.txt'), 'new commit\n');
      run(work, 'commit', '-am', 'new commit');
      const newCommit = run(work, 'rev-parse', 'HEAD').toString().trim();
      run(work, 'tag', '--force', 'verify-v3.9.0', newCommit);
      run(work, 'push', '--force', 'origin', 'refs/tags/verify-v3.9.0');
      expect(() => verifyRemoteReleaseGitState(state(releaseCommit))).toThrow(/remote release tag.*moved/i);

      run(work, 'push', 'origin', 'main');
      expect(() => verifyRemoteReleaseGitState({
        cwd: work,
        tag: 'verify-v3.9.0',
        expectedCommit: newCommit,
        referenceQuery: queryLocalRemote(remote),
      })).not.toThrow();
      expect(() => verifyRemoteReleaseGitState(state(releaseCommit))).toThrow(/remote protected main.*advanced|remote protected main.*moved/i);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('ignores a rewritten origin and queries the fixed canonical repository identity', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-release-rewritten-origin-'));
    const canonical = path.join(root, 'canonical.git');
    const attacker = path.join(root, 'attacker.git');
    const work = path.join(root, 'work');
    const run = (cwd, ...args) => execFileSync('git', args, { cwd, stdio: 'pipe' });
    try {
      run(root, 'init', '--bare', canonical);
      run(root, 'init', '--bare', attacker);
      run(root, 'init', '--initial-branch=main', work);
      run(work, 'config', 'user.name', 'Release Test');
      run(work, 'config', 'user.email', 'release-test@example.invalid');
      fs.writeFileSync(path.join(work, 'tracked.txt'), 'release\n');
      run(work, 'add', 'tracked.txt');
      run(work, 'commit', '-m', 'release source');
      run(work, 'tag', 'verify-v3.9.0');
      run(work, 'remote', 'add', 'canonical', canonical);
      run(work, 'push', 'canonical', 'main', 'refs/tags/verify-v3.9.0');
      run(work, 'remote', 'add', 'origin', attacker);
      run(work, 'push', 'origin', 'main', 'refs/tags/verify-v3.9.0');
      run(work, 'remote', 'set-url', 'origin', attacker);
      const head = run(work, 'rev-parse', 'HEAD').toString().trim();

      fs.writeFileSync(path.join(work, 'tracked.txt'), 'attacker commit\n');
      run(work, 'commit', '-am', 'attacker commit');
      run(work, 'tag', '--force', 'verify-v3.9.0');
      run(work, 'push', '--force', 'origin', 'main', 'refs/tags/verify-v3.9.0');

      let queriedRepository = null;
      const referenceQuery = (repositoryUrl, references, cwd) => {
        queriedRepository = repositoryUrl;
        return queryLocalRemote(canonical)(repositoryUrl, references, cwd);
      };
      expect(verifyRemoteReleaseGitState({
        cwd: work,
        tag: 'verify-v3.9.0',
        expectedCommit: head,
        referenceQuery,
      })).toMatchObject({
        mainCommit: head,
        tagCommit: head,
        repositoryUrl: CANONICAL_RELEASE_REPOSITORY,
      });
      expect(queriedRepository).toBe(CANONICAL_RELEASE_REPOSITORY);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
