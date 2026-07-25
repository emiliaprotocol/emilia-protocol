#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
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
  expectedCommit?: string;
  expectedRef?: string;
  unpublished?: boolean;
}

interface RemoteGitState {
  mainCommit: string;
  tagCommit: string;
  remote: string;
}

function npmArtifactFilename(packageName: string, version: string): string {
  if (!/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u.test(packageName)
    || !/^[0-9A-Za-z][0-9A-Za-z.+-]*$/u.test(version)) {
    throw new Error('approved npm package identity is malformed');
  }
  return `${packageName.replace(/^@/u, '').replace(/\//gu, '-')}-${version}.tgz`;
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

export function verifyReleaseGitState({
  cwd,
  tag,
  mainRef = 'refs/remotes/origin/main',
  expectedCommit,
  expectedRef,
}: {
  cwd: string;
  tag: string;
  mainRef?: string;
  expectedCommit?: string | null;
  expectedRef?: string | null;
}): GitState {
  const head: string = git(cwd, ['rev-parse', 'HEAD^{commit}']);
  const protectedRef = 'refs/heads/main';
  if (expectedRef !== protectedRef) {
    throw new Error(`workflow dispatch ref ${expectedRef || '(missing)'} must be the protected main ref ${protectedRef}`);
  }
  if (!/^[0-9a-f]{40}$/.test(expectedCommit || '') || head !== expectedCommit) {
    throw new Error(`release checkout ${head} does not match dispatched commit ${expectedCommit || '(missing)'}`);
  }
  let tagCommit: string;
  try {
    tagCommit = git(cwd, ['rev-parse', '--verify', `refs/tags/${tag}^{commit}`]);
  } catch {
    throw new Error(`release tag is not present in the checkout: ${tag}`);
  }
  if (head !== tagCommit) throw new Error(`checkout HEAD ${head} does not match release tag ${tag} (${tagCommit})`);
  let mainCommit: string;
  try {
    mainCommit = git(cwd, ['rev-parse', '--verify', `${mainRef}^{commit}`]);
  } catch {
    throw new Error(`protected main reference is unavailable: ${mainRef}`);
  }
  if (head !== mainCommit) {
    throw new Error(`release commit ${head} must be the exact protected main commit ${mainCommit}`);
  }
  const dirty: string = git(cwd, ['status', '--porcelain', '--untracked-files=no']);
  if (dirty) throw new Error('release checkout contains modified tracked files');
  return { head, tag, mainRef, expectedCommit, expectedRef };
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

export function verifyRemoteReleaseGitState({
  cwd,
  tag,
  expectedCommit,
  remote = 'origin',
}: {
  cwd: string;
  tag: string;
  expectedCommit: string;
  remote?: string;
}): RemoteGitState {
  if (!/^[0-9a-f]{40}$/u.test(expectedCommit)) {
    throw new Error(`remote release check requires an exact commit, received ${expectedCommit || '(missing)'}`);
  }
  const mainReference = 'refs/heads/main';
  const tagReference = `refs/tags/${tag}`;
  const peeledTagReference = `${tagReference}^{}`;
  const query = spawnSync('git', [
    'ls-remote',
    '--exit-code',
    remote,
    mainReference,
    tagReference,
    peeledTagReference,
  ], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (query.status !== 0) {
    throw new Error(`remote release references are unavailable from ${remote}: ${query.stderr || query.stdout}`);
  }
  const references: Map<string, string[]> = new Map();
  for (const line of query.stdout.split('\n').filter(Boolean)) {
    const match = line.match(/^([0-9a-f]{40})\t(.+)$/u);
    if (!match) throw new Error(`remote release reference query returned malformed output: ${line}`);
    const [, commit, reference] = match;
    const commits = references.get(reference) ?? [];
    commits.push(commit);
    references.set(reference, commits);
  }
  const exactReference = (reference: string, label: string): string | null => {
    const commits = references.get(reference) ?? [];
    if (commits.length > 1) throw new Error(`${label} is ambiguous on ${remote}`);
    return commits[0] ?? null;
  };
  const mainCommit = exactReference(mainReference, 'remote protected main');
  if (!mainCommit) throw new Error(`remote protected main is unavailable from ${remote}`);
  if (mainCommit !== expectedCommit) {
    throw new Error(`remote protected main moved or advanced: ${mainCommit} != ${expectedCommit}`);
  }
  const tagObject = exactReference(tagReference, `remote release tag ${tag}`);
  if (!tagObject) throw new Error(`remote release tag ${tag} is unavailable from ${remote}`);
  const tagCommit = exactReference(peeledTagReference, `peeled remote release tag ${tag}`) ?? tagObject;
  if (tagCommit !== expectedCommit) {
    throw new Error(`remote release tag ${tag} moved: ${tagCommit} != ${expectedCommit}`);
  }
  return { mainCommit, tagCommit, remote };
}

function option(argv: string[], name: string): string | null {
  const index: number = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function main(argv: string[] = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env): void {
  const packageName: string | null = option(argv, '--package');
  const version: string | null = option(argv, '--version');
  const approval: ReleaseApprovalResult = validateReleaseApproval({
    eventName: env.GITHUB_EVENT_NAME,
    actor: env.GITHUB_ACTOR,
    allowedActor: option(argv, '--allowed-actor'),
    tag: option(argv, '--tag'),
    tagPrefix: option(argv, '--tag-prefix'),
    packageName,
    version,
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
      expectedCommit: option(argv, '--expected-commit') || env.GITHUB_SHA,
      expectedRef: option(argv, '--expected-ref') || env.GITHUB_REF,
    });
  if (argv.includes('--revalidate-remote')) {
    verifyRemoteReleaseGitState({
      cwd: env.GITHUB_WORKSPACE || process.cwd(),
      tag: approval.expectedTag,
      expectedCommit: gitState.head,
      remote: option(argv, '--remote') || 'origin',
    });
  }
  const githubOutput: string | null = option(argv, '--github-output');
  if (githubOutput) {
    fs.appendFileSync(githubOutput, [
      `package=${packageName}`,
      `version=${version}`,
      `filename=${npmArtifactFilename(packageName!, version!)}`,
      `commit=${gitState.head}`,
      '',
    ].join('\n'));
  }
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
