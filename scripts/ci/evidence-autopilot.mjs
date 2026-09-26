#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Evidence autopilot bundle tool.
 *
 * .github/workflows/evidence-autopilot.yml regenerates content-addressed
 * derived evidence on a pull request branch with the repository's official
 * writers, in an unprivileged job, and `collect`s the result into a bundle.
 * .github/workflows/evidence-autopilot-publish.yml runs this file from the
 * default branch (never from the pull request), `inspect`s the bundle and
 * turns it into one GraphQL createCommitOnBranch `request` whose
 * expectedHeadOid is the exact source commit. GitHub applies that request
 * only if the branch still points at the source commit, and signs the
 * commit it creates.
 *
 * What `inspect` proves is shape and transit integrity: the bundle names
 * only DERIVED_EVIDENCE paths, each file matches the size and sha256 the
 * manifest lists, is UTF-8 (JSON parses), and the manifest claims the
 * expected source commit. It does not regenerate anything, and the manifest
 * was written by the same unprivileged job that ran the pull request's code,
 * so it cannot show the content is correct. Correctness comes from the
 * required checks that run again on the pushed commit (and those run the
 * pull request's code too).
 *
 * dco.yml exempts the published commit from sign-off only when GitHub
 * reports it verified and authored by the pinned App bot, and it changes
 * nothing but DERIVED_EVIDENCE.
 *
 * Usage:
 *   node scripts/ci/evidence-autopilot.mjs collect --source-sha <sha> --out <dir> [--github-output <file>]
 *   node scripts/ci/evidence-autopilot.mjs inspect --bundle <dir> --source-sha <sha> [--github-output <file>]
 *   node scripts/ci/evidence-autopilot.mjs request --bundle <dir> --source-sha <sha> \
 *     --repository <owner/name> --branch <name> --run-url <url> --out <file>
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, copyFileSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const BUNDLE_VERSION = 'EP-EVIDENCE-AUTOPILOT-v1';
export const COMMIT_TRAILER = 'Evidence-Autopilot: v1';
/**
 * Lets Dependabot keep rebasing its pull request over the autopilot commit
 * (Dependabot stops rebasing once another author's commit lands, unless the
 * commit message carries this marker); the autopilot then regenerates.
 */
export const DEPENDABOT_SKIP = '[dependabot skip]';

const CREATE_COMMIT_ON_BRANCH = `mutation EvidenceAutopilot($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) {
    commit { oid }
  }
}`;

/**
 * Files the official writers derive from repository content, in the order a
 * reviewer reads them. Writer map:
 *   sync:formal-traces   -> formal/results/formal-runtime-scenario-conformance.v2.json
 *   conformance:manifest -> conformance/conformance-manifest.json
 *   sync:proof-stats     -> security/security-case.json, lib/proof-stats.json
 *   sync:llm-context     -> AI_CONTEXT.md, public/llms.txt, public/llms-full.txt,
 *                           public/.well-known/emilia-context.json
 */
export const DERIVED_EVIDENCE = Object.freeze([
  'formal/results/formal-runtime-scenario-conformance.v2.json',
  'conformance/conformance-manifest.json',
  'security/security-case.json',
  'lib/proof-stats.json',
  'AI_CONTEXT.md',
  'public/llms.txt',
  'public/llms-full.txt',
  'public/.well-known/emilia-context.json',
]);

const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024;
const SHA = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const BRANCH = /^[A-Za-z0-9._/-]{1,200}$/;

/**
 * @typedef {{ path: string, sha256: string, bytes: number }} BundleFile
 * @typedef {{ '@version': string, source_sha: string, files: BundleFile[] }} Manifest
 */

/**
 * @param {Buffer} bytes
 * @returns {string}
 */
function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * @param {string[]} args
 * @param {string} cwd
 * @returns {string}
 */
function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/**
 * Derived evidence must be UTF-8 text; JSON files must parse.
 *
 * @param {string} path
 * @param {Buffer} bytes
 */
function assertEvidenceText(path, bytes) {
  if (bytes.includes(0)) throw new Error(`${path}: contains a NUL byte`);
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error(`${path}: is not valid UTF-8`);
  if (path.endsWith('.json')) JSON.parse(text);
}

/**
 * Bundles every DERIVED_EVIDENCE file that differs between `sourceSha` and
 * HEAD. Refuses a dirty tree and any other changed path.
 *
 * @param {{ repo: string, sourceSha: string, out: string }} options
 * @returns {Manifest}
 */
export function collect({ repo, sourceSha, out }) {
  if (!SHA.test(sourceSha)) throw new Error('source sha must be a 40-character lowercase hex commit');
  const dirty = git(['status', '--porcelain', '--untracked-files=no'], repo).trim();
  if (dirty) throw new Error(`the writers left uncommitted tracked changes:\n${dirty}`);
  const changed = git(['diff', '--name-only', '-z', '--no-renames', sourceSha, 'HEAD'], repo)
    .split('\0')
    .filter(Boolean);
  const allowed = new Set(DERIVED_EVIDENCE);
  const outside = changed.filter((path) => !allowed.has(path));
  if (outside.length > 0) {
    throw new Error(`the writers changed paths outside the derived-evidence allowlist:\n${outside.join('\n')}`);
  }
  /** @type {BundleFile[]} */
  const files = [];
  for (const path of DERIVED_EVIDENCE.filter((candidate) => changed.includes(candidate))) {
    const source = join(repo, path);
    const stat = lstatSync(source);
    if (!stat.isFile()) throw new Error(`${path}: is not a regular file`);
    const bytes = readFileSync(source);
    if (bytes.length > MAX_FILE_BYTES) throw new Error(`${path}: exceeds ${MAX_FILE_BYTES} bytes`);
    assertEvidenceText(path, bytes);
    const target = join(out, 'files', path);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    files.push({ path, sha256: sha256(bytes), bytes: bytes.length });
  }
  /** @type {Manifest} */
  const manifest = { '@version': BUNDLE_VERSION, source_sha: sourceSha, files };
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

/**
 * Validates the shape and transit integrity of an untrusted bundle and
 * returns its manifest and contents: allowlisted paths only, no duplicates,
 * each file's size and sha256 as the manifest lists, UTF-8 text, JSON that
 * parses, and a manifest that claims `sourceSha`. The manifest comes from
 * the unprivileged job, so this is not evidence that the content is correct.
 *
 * @param {{ bundle: string, sourceSha: string }} options
 * @returns {{ manifest: Manifest, contents: Map<string, Buffer> }}
 */
export function inspect({ bundle, sourceSha }) {
  if (!SHA.test(sourceSha)) throw new Error('source sha must be a 40-character lowercase hex commit');
  const manifestPath = join(bundle, 'manifest.json');
  const manifestStat = lstatSync(manifestPath);
  if (!manifestStat.isFile() || manifestStat.size > MAX_MANIFEST_BYTES) {
    throw new Error('manifest.json is missing, not a regular file, or too large');
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const keys = Object.keys(manifest ?? {}).sort().join(',');
  if (keys !== '@version,files,source_sha') throw new Error(`unexpected manifest fields: ${keys}`);
  if (manifest['@version'] !== BUNDLE_VERSION) throw new Error('unsupported bundle version');
  if (manifest.source_sha !== sourceSha) {
    throw new Error(`bundle was generated from ${manifest.source_sha}, expected ${sourceSha}`);
  }
  if (!Array.isArray(manifest.files) || manifest.files.length > DERIVED_EVIDENCE.length) {
    throw new Error('manifest files must be an array no longer than the allowlist');
  }
  const allowed = new Set(DERIVED_EVIDENCE);
  /** @type {Map<string, Buffer>} */
  const contents = new Map();
  for (const entry of manifest.files) {
    const entryKeys = Object.keys(entry ?? {}).sort().join(',');
    if (entryKeys !== 'bytes,path,sha256') throw new Error(`unexpected file entry fields: ${entryKeys}`);
    if (!allowed.has(entry.path)) throw new Error(`${entry.path}: not a derived-evidence path`);
    if (contents.has(entry.path)) throw new Error(`${entry.path}: listed twice`);
    if (!/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error(`${entry.path}: malformed sha256`);
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || entry.bytes > MAX_FILE_BYTES) {
      throw new Error(`${entry.path}: malformed byte count`);
    }
    const file = join(bundle, 'files', entry.path);
    const stat = lstatSync(file);
    if (!stat.isFile()) throw new Error(`${entry.path}: bundle entry is not a regular file`);
    if (stat.size !== entry.bytes) throw new Error(`${entry.path}: size differs from the manifest`);
    const bytes = readFileSync(file);
    if (sha256(bytes) !== entry.sha256) throw new Error(`${entry.path}: sha256 differs from the manifest`);
    assertEvidenceText(entry.path, bytes);
    contents.set(entry.path, bytes);
  }
  return { manifest, contents };
}

/**
 * The commit message of a published evidence commit: a headline, the
 * provenance paragraph, the Dependabot rebase marker and the trailers.
 *
 * @param {string} sourceSha
 * @param {string} runUrl
 * @returns {{ headline: string, body: string }}
 */
export function commitMessage(sourceSha, runUrl) {
  return {
    headline: `chore(evidence): regenerate derived evidence for ${sourceSha.slice(0, 12)}`,
    body: [
      `Regenerated from ${sourceSha} by the evidence autopilot with the`,
      'official writers (sync:formal-traces, conformance:manifest,',
      'sync:proof-stats, sync:llm-context). The publisher checked only the',
      "bundle's shape and transit integrity; the required checks on this",
      'commit decide whether the evidence is correct.',
      '',
      DEPENDABOT_SKIP,
      '',
      COMMIT_TRAILER,
      `Evidence-Autopilot-Run: ${runUrl}`,
      '',
    ].join('\n'),
  };
}

/**
 * Builds the GraphQL createCommitOnBranch request that publishes an
 * inspected bundle. expectedHeadOid makes it compare-and-swap: GitHub
 * refuses it unless `branch` still points at `sourceSha`, so a branch that
 * was force-pushed, rewound or deleted in the meantime is left alone.
 *
 * @param {{ bundle: string, sourceSha: string, repository: string, branch: string, runUrl: string }} options
 * @returns {{ query: string, variables: { input: Record<string, unknown> } }}
 */
export function commitRequest({ bundle, sourceSha, repository, branch, runUrl }) {
  if (!REPOSITORY.test(repository)) throw new Error(`refusing repository ${JSON.stringify(repository)}`);
  if (
    !BRANCH.test(branch) || branch === 'main' || branch.startsWith('-') || branch.startsWith('/')
    || branch.endsWith('/') || branch.endsWith('.lock') || branch.includes('..') || branch.includes('//')
  ) {
    throw new Error(`refusing branch ${JSON.stringify(branch)}`);
  }
  const runPrefix = `https://github.com/${repository}/actions/runs/`;
  if (!runUrl.startsWith(runPrefix) || !/^\d+(?:\/attempts\/\d+)?$/.test(runUrl.slice(runPrefix.length))) {
    throw new Error(`refusing run URL ${JSON.stringify(runUrl)}`);
  }
  const { contents } = inspect({ bundle, sourceSha });
  if (contents.size === 0) throw new Error('the bundle carries no files; there is nothing to publish');
  return {
    query: CREATE_COMMIT_ON_BRANCH,
    variables: {
      input: {
        branch: { repositoryNameWithOwner: repository, branchName: branch },
        expectedHeadOid: sourceSha,
        message: commitMessage(sourceSha, runUrl),
        fileChanges: {
          additions: [...contents].map(([path, bytes]) => ({ path, contents: bytes.toString('base64') })),
        },
      },
    },
  };
}

/**
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
function parseOptions(argv) {
  /** @type {Record<string, string>} */
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`expected --option value pairs, got ${JSON.stringify(argv)}`);
    }
    options[key.slice(2)] = value;
  }
  return options;
}

/**
 * @param {string[]} argv
 * @returns {number} exit code
 */
export function main(argv) {
  const [command, ...rest] = argv;
  const options = parseOptions(rest);
  const output = options['github-output'];
  if (command === 'collect') {
    const manifest = collect({ repo: options.repo ?? process.cwd(), sourceSha: options['source-sha'] ?? '', out: options.out ?? '' });
    const changed = manifest.files.length > 0;
    console.log(changed
      ? `EVIDENCE AUTOPILOT: ${manifest.files.length} derived file(s) regenerated:\n${manifest.files.map((file) => `  ${file.path}`).join('\n')}`
      : 'EVIDENCE AUTOPILOT: derived evidence is already current');
    if (output) appendFileSync(output, `changed=${changed}\n`);
    return 0;
  }
  if (command === 'inspect') {
    const { manifest } = inspect({ bundle: options.bundle ?? '', sourceSha: options['source-sha'] ?? '' });
    const changed = manifest.files.length > 0;
    console.log(`EVIDENCE AUTOPILOT: bundle for ${manifest.source_sha} carries ${manifest.files.length} file(s)`);
    if (output) appendFileSync(output, `changed=${changed}\n`);
    return 0;
  }
  if (command === 'request') {
    if (!options.out) throw new Error('request requires --out <file>');
    const request = commitRequest({
      bundle: options.bundle ?? '',
      sourceSha: options['source-sha'] ?? '',
      repository: options.repository ?? '',
      branch: options.branch ?? '',
      runUrl: options['run-url'] ?? '',
    });
    writeFileSync(options.out, JSON.stringify(request));
    const paths = request.variables.input.fileChanges.additions.map((file) => `  ${file.path}`);
    console.log(`EVIDENCE AUTOPILOT: createCommitOnBranch request for ${options.branch} at ${options['source-sha']}:\n${paths.join('\n')}`);
    return 0;
  }
  throw new Error('usage: evidence-autopilot.mjs collect|inspect|request --option value ...');
}

// import.meta.url names the resolved file, so compare against the resolved
// argv path: CI runs a copy from $RUNNER_TEMP, which may sit behind a symlink.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(`EVIDENCE AUTOPILOT: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
