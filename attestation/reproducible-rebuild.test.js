// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { assertPinnedSource } from './reproducible-rebuild.mjs';

const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);

function fakeGit({ head = COMMIT_A, status = '' } = {}) {
  return (args) => {
    if (args[0] === 'rev-parse') return head;
    if (args[0] === 'status') return status;
    throw new Error(`unexpected git command: ${args.join(' ')}`);
  };
}

describe('assertPinnedSource', () => {
  it('accepts only a clean worktree at the exact attested commit', () => {
    expect(assertPinnedSource({ commit: COMMIT_A }, fakeGit()))
      .toEqual({ source_commit: COMMIT_A });
  });

  it('FAIL-CLOSED: rejects a forged commit even when artifact bytes could match', () => {
    expect(() => assertPinnedSource({ commit: COMMIT_A }, fakeGit({ head: COMMIT_B })))
      .toThrow(/source_commit_mismatch/);
  });

  it('FAIL-CLOSED: rejects uncommitted or untracked source', () => {
    expect(() => assertPinnedSource(
      { commit: COMMIT_A },
      fakeGit({ status: ' M packages/verify/index.js' }),
    )).toThrow(/source_worktree_dirty/);
  });
});
