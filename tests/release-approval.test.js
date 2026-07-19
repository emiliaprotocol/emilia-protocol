// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  validateReleaseApproval,
  verifyReleaseGitState,
  verifyUnpublishedReleaseGitState,
} from '../scripts/require-release-approval.mjs';

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
      expect(verifyReleaseGitState({ cwd: dir, tag: 'verify-v3.9.0', mainRef: 'refs/heads/main' })).toMatchObject({
        tag: 'verify-v3.9.0',
        mainRef: 'refs/heads/main',
      });
      fs.writeFileSync(path.join(dir, 'tracked.txt'), 'tampered\n');
      expect(() => verifyReleaseGitState({ cwd: dir, tag: 'verify-v3.9.0', mainRef: 'refs/heads/main' })).toThrow(/modified tracked files/);
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
});
