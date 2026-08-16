#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Produces an owner-private scan package. It deliberately does not construct a
// public Authority Record, send an invitation, or authorize publication.

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { scanWorkspace } from '../integrations/github-authority-map-action/scan.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER_PATH = path.resolve(HERE, '../integrations/github-authority-map-action/scan.mjs');
const WATCHED_REF = /^refs\/(?:heads|tags)\/[A-Za-z0-9._/-]{1,240}$/;
const REVISION = /^[0-9a-f]{40}$/;

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function git(workspace, args) {
  try {
    return execFileSync('git', ['-C', workspace, ...args], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch (cause) {
    throw new Error(`git ${args[0]} failed`, { cause });
  }
}

function canonicalRepositoryUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('repository URL is invalid');
  }
  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com'
      || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('repository URL must be canonical GitHub HTTPS');
  }
  const parts = parsed.pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  if (parts.length !== 2) throw new Error('repository URL must identify one repository');
  const [owner, rawRepository] = parts;
  const repository = rawRepository.replace(/\.git$/i, '');
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)
      || !/^[A-Za-z0-9._-]{1,100}$/.test(repository)) {
    throw new Error('repository URL is invalid');
  }
  return `https://github.com/${owner}/${repository}`;
}

function canonicalInstant(value) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error('observed time must be canonical UTC');
  }
  return value;
}

function resolveCommit(workspace, ref, failureMessage) {
  let result;
  try {
    result = git(workspace, ['rev-parse', '--verify', `${ref}^{commit}`]).toLowerCase();
  } catch {
    throw new Error(failureMessage);
  }
  if (!REVISION.test(result)) throw new Error(failureMessage);
  return result;
}

export async function createPrivateScanPackage({
  workspace,
  repositoryUrl,
  watchedRef,
  output,
  observedAt = new Date().toISOString(),
}) {
  const root = path.resolve(workspace);
  const destination = path.resolve(output);
  const sourceUrl = canonicalRepositoryUrl(repositoryUrl);
  if (!WATCHED_REF.test(watchedRef || '')) throw new Error('watched ref is invalid');

  const origin = canonicalRepositoryUrl(git(root, ['remote', 'get-url', 'origin']));
  if (origin !== sourceUrl) throw new Error('origin does not match requested repository');
  if (git(root, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
    throw new Error('worktree is not clean');
  }
  const head = resolveCommit(root, 'HEAD', 'HEAD is unavailable');
  const resolved = resolveCommit(root, watchedRef, 'watched ref is unavailable');
  if (head !== resolved) throw new Error('watched ref does not resolve to checked-out HEAD');

  const timestamp = canonicalInstant(observedAt);
  const report = await scanWorkspace(root, { generatedAt: timestamp });
  const scannerBytes = await readFile(SCANNER_PATH);
  const reportDigest = sha256(JSON.stringify(report));
  const privatePackage = {
    '@version': 'EMILIA-WORKS-PRIVATE-SCAN-PACKAGE-v1',
    visibility: 'PRIVATE_OPERATOR_ONLY',
    publication_authorized: false,
    source: {
      repository_url: sourceUrl,
      watched_ref: watchedRef,
      resolved_revision: resolved,
      observed_at: timestamp,
      worktree_clean: true,
    },
    scanner: {
      name: '@emilia-protocol/scan',
      version: '1.0.0',
      profile_digest: sha256(scannerBytes),
    },
    report_digest: reportDigest,
    boundary: {
      raw_findings_must_remain_private: true,
      human_review_required_before_projection: true,
      repository_control_required_before_publication: true,
      exact_digest_owner_approval_required_before_publication: true,
    },
    report,
  };

  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, `${JSON.stringify(privatePackage, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(destination, 0o600);
  return { output: destination, package: privatePackage };
}

function valueAfter(arguments_, index, option) {
  const value = arguments_[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${option} requires a value`);
  return value;
}

function parseArguments(arguments_) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (['--workspace', '--repository', '--watched-ref', '--output', '--observed-at'].includes(argument)) {
      options[argument.slice(2).replaceAll('-', '_')] = valueAfter(arguments_, index, argument);
      index += 1;
    } else {
      throw new Error(`unknown option: ${argument}`);
    }
  }
  for (const required of ['workspace', 'repository', 'watched_ref', 'output']) {
    if (!options[required]) throw new Error(`--${required.replaceAll('_', '-')} is required`);
  }
  return options;
}

export async function main(arguments_ = process.argv.slice(2)) {
  try {
    const options = parseArguments(arguments_);
    const result = await createPrivateScanPackage({
      workspace: options.workspace,
      repositoryUrl: options.repository,
      watchedRef: options.watched_ref,
      output: options.output,
      observedAt: options.observed_at,
    });
    console.log(`Private Authority Record scan package: ${result.output}`);
    return 0;
  } catch (error) {
    console.error(`Private Authority Record scan refused: ${error.message}`);
    return 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  process.exitCode = await main();
}
