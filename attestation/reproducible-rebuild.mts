/**
 * The LIVE reproducible-build link for the attestation chain.
 *
 * Wraps the repository's existing deterministic packager
 * (scripts/verify-reproducible-package.mjs, `npm run release:verify:reproducible`)
 * as the `rebuild` function verifyBuildAttestation() expects. The packager builds
 * the artifact TWICE from a canonicalized input and refuses if the bytes differ,
 * so the sha256 it returns is a determinism-proven binary hash.
 *
 * This rebuilds the package from the CURRENT worktree and therefore verifies,
 * before packaging, that the worktree is clean and that HEAD exactly equals the
 * attested source.commit. It does not check out an arbitrary historical commit:
 * the build harness must do that first. A caller cannot silently rebuild another
 * revision and relabel its bytes as the pinned source.
 *
 * @license Apache-2.0
 */

import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyReproduciblePackage } from '../scripts/verify-reproducible-package.mjs';

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GIT_SHA = /^[0-9a-f]{40}$/;

function runGit(args) {
  return execFileSync('git', ['-C', REPOSITORY_ROOT, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

/**
 * Verify the live source state before a reproducible build.
 *
 * `git` is injectable only so the fail-closed checks can be tested without
 * mutating the repository. Production callers use the real Git executable.
 *
 * @param {{ commit: string }} source
 * @param {(args: string[]) => string} [git]
 * @returns {{ source_commit: string }}
 */
export function assertPinnedSource(source, git = runGit) {
  if (!source || typeof source.commit !== 'string' || !GIT_SHA.test(source.commit)) {
    throw new Error('source_commit_invalid: expected a 40-hex git commit');
  }

  let head;
  let status;
  try {
    head = git(['rev-parse', 'HEAD']).trim();
    status = git(['status', '--porcelain=v1', '--untracked-files=normal']);
  } catch (error) {
    throw new Error(`source_state_unverifiable: ${error?.message || error}`);
  }

  if (!GIT_SHA.test(head)) {
    throw new Error('source_state_unverifiable: git HEAD is not a 40-hex commit');
  }
  if (head !== source.commit) {
    throw new Error(`source_commit_mismatch: checked-out HEAD ${head} != attested ${source.commit}`);
  }
  if (status.trim() !== '') {
    throw new Error('source_worktree_dirty: reproducible rebuild requires a clean pinned worktree');
  }
  return { source_commit: head };
}

/**
 * A rebuild function suitable for verifyBuildAttestation({ rebuild }).
 * @param {{ commit: string, package_path: string }} source
 * @returns {{ source_commit: string, sha256: string, filename: string, bytes: number }}
 */
export function reproducibleRebuild(source) {
  const pinned = assertPinnedSource(source);
  const result = verifyReproduciblePackage(source.package_path);
  return {
    source_commit: pinned.source_commit,
    sha256: result.sha256,
    filename: result.filename,
    bytes: result.bytes,
  };
}
