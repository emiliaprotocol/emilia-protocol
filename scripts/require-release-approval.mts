#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

interface ReleaseApprovalInput {
  eventName?: string;
  actor?: string;
  allowedActor?: string | null;
  tag?: string | null;
  tagPrefix?: string | null;
  packageName?: string | null;
  version?: string | null;
  confirmation?: string | null;
}

interface ReleaseApprovalResult {
  expectedTag: string;
  expectedConfirmation: string;
}

interface GitState {
  head: string;
  tag: string;
  mainRef: string;
  unpublished?: boolean;
}

export function validateReleaseApproval({
  eventName,
  actor,
  allowedActor,
  tag,
  tagPrefix,
  packageName,
  version,
  confirmation,
}: ReleaseApprovalInput): ReleaseApprovalResult {
  if (eventName !== 'workflow_dispatch') throw new Error('registry publication requires an explicit workflow_dispatch event');
  if (!allowedActor || actor !== allowedActor) throw new Error(`registry publication is restricted to ${allowedActor || 'a configured owner'}`);
  for (const [label, value] of Object.entries({ tag, tagPrefix, packageName, version })) {
    if (typeof value !== 'string' || value.trim() !== value || value.length === 0 || /[\s\0]/.test(value)) {
      throw new Error(`${label} is missing or malformed`);
    }
  }
  const expectedTag = `${tagPrefix}${version}`;
  if (tag !== expectedTag) throw new Error(`release tag must be exactly ${expectedTag}`);
  const expectedConfirmation = `PUBLISH ${packageName}@${version}`;
  if (confirmation !== expectedConfirmation) throw new Error(`confirmation must be exactly: ${expectedConfirmation}`);
  return { expectedTag, expectedConfirmation };
}

export function verifyReleaseGitState({ cwd, tag, mainRef = 'refs/remotes/origin/main' }: { cwd: string; tag: string; mainRef?: string }): GitState {
  const head: string = git(cwd, ['rev-parse', 'HEAD^{commit}']);
  let tagCommit: string;
  try {
    tagCommit = git(cwd, ['rev-parse', '--verify', `refs/tags/${tag}^{commit}`]);
  } catch {
    throw new Error(`release tag is not present in the checkout: ${tag}`);
  }
  if (head !== tagCommit) throw new Error(`checkout HEAD ${head} does not match release tag ${tag} (${tagCommit})`);
  try {
    git(cwd, ['rev-parse', '--verify', `${mainRef}^{commit}`]);
  } catch {
    throw new Error(`protected main reference is unavailable: ${mainRef}`);
  }
  const ancestor = spawnSync('git', ['merge-base', '--is-ancestor', head, mainRef], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (ancestor.status !== 0) throw new Error(`release commit ${head} is not contained in ${mainRef}`);
  const dirty: string = git(cwd, ['status', '--porcelain', '--untracked-files=no']);
  if (dirty) throw new Error('release checkout contains modified tracked files');
  return { head, tag, mainRef };
}

export function verifyUnpublishedReleaseGitState({ cwd, tag, mainRef = 'refs/remotes/origin/main', expectedCommit = null }: { cwd: string; tag: string; mainRef?: string; expectedCommit?: string | null }): GitState {
  const head: string = git(cwd, ['rev-parse', 'HEAD^{commit}']);
  if (expectedCommit !== null) {
    if (!/^[0-9a-f]{40}$/.test(expectedCommit || '') || head !== expectedCommit) {
      throw new Error(`release checkout ${head} does not match dispatched commit ${expectedCommit}`);
    }
  }
  let mainCommit: string;
  try {
    mainCommit = git(cwd, ['rev-parse', '--verify', `${mainRef}^{commit}`]);
  } catch {
    throw new Error(`protected main reference is unavailable: ${mainRef}`);
  }
  if (head !== mainCommit) {
    throw new Error(`release commit ${head} must be the exact protected main commit ${mainCommit}`);
  }
  const existingTag = spawnSync('git', ['rev-parse', '--verify', `refs/tags/${tag}`], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (existingTag.status === 0) throw new Error(`release tag already exists: ${tag}`);
  const dirty: string = git(cwd, ['status', '--porcelain', '--untracked-files=no']);
  if (dirty) throw new Error('release checkout contains modified tracked files');
  return { head, tag, mainRef, unpublished: true };
}

function option(argv: string[], name: string): string | null {
  const index: number = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function main(argv: string[] = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env): void {
  const approval: ReleaseApprovalResult = validateReleaseApproval({
    eventName: env.GITHUB_EVENT_NAME,
    actor: env.GITHUB_ACTOR,
    allowedActor: option(argv, '--allowed-actor'),
    tag: option(argv, '--tag'),
    tagPrefix: option(argv, '--tag-prefix'),
    packageName: option(argv, '--package'),
    version: option(argv, '--version'),
    confirmation: option(argv, '--confirmation'),
  });
  const gitState: GitState = argv.includes('--unpublished-tag')
    ? verifyUnpublishedReleaseGitState({
      cwd: env.GITHUB_WORKSPACE || process.cwd(),
      tag: approval.expectedTag,
      mainRef: option(argv, '--main-ref') || 'refs/remotes/origin/main',
      expectedCommit: option(argv, '--expected-commit'),
    })
    : verifyReleaseGitState({
      cwd: env.GITHUB_WORKSPACE || process.cwd(),
      tag: approval.expectedTag,
      mainRef: option(argv, '--main-ref') || 'refs/remotes/origin/main',
    });
  console.log(`RELEASE APPROVAL: PASS (${approval.expectedConfirmation}; ${gitState.head})`);
}

const invokedPath: string | null = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try { main(); }
  catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`RELEASE APPROVAL: REFUSED (${message})`);
    process.exitCode = 1;
  }
}
