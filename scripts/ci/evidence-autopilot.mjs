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
 * One rule is about content: a DERIVED_FIELDS file (a hand-authored file
 * with one machine-owned field) must be byte-for-byte its source-commit
 * version, never the bundle's own copy of it, with only that field
 * recomputed from the tree being published. `inspect` proves that before
 * anything is published, against copies the publisher fetches from GitHub
 * by commit, and dco.yml's `verify-commit` proves it again from git.
 *
 * dco.yml exempts the published commit from sign-off only when GitHub
 * reports it verified and authored by the pinned App bot, and the base
 * branch's copy of this file (`verify-commit`) finds that it changes
 * nothing but DERIVED_EVIDENCE under the DERIVED_FIELDS rule.
 *
 * Usage:
 *   node scripts/ci/evidence-autopilot.mjs collect --source-sha <sha> --out <dir> [--github-output <file>]
 *   node scripts/ci/evidence-autopilot.mjs source-files
 *   node scripts/ci/evidence-autopilot.mjs inspect --bundle <dir> --source-sha <sha> \
 *     [--source-files <dir>] [--github-output <file>]
 *   node scripts/ci/evidence-autopilot.mjs request --bundle <dir> --source-sha <sha> \
 *     --repository <owner/name> --branch <name> --run-url <url> --out <file> [--source-files <dir>]
 *   node scripts/ci/evidence-autopilot.mjs verify-commit --commit <sha> [--repo <dir>]
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
 *   sync:clean-room-pins -> conformance/clean-room/v2/bundle.v2.json,
 *                           conformance/clean-room/v3/bundle.v3.json
 *                           (source_manifest only; see DERIVED_FIELDS)
 *   sync:proof-stats     -> security/security-case.json, lib/proof-stats.json
 *   sync:llm-context     -> AI_CONTEXT.md, public/llms.txt, public/llms-full.txt,
 *                           public/.well-known/emilia-context.json
 */
export const DERIVED_EVIDENCE = Object.freeze([
  'formal/results/formal-runtime-scenario-conformance.v2.json',
  'conformance/conformance-manifest.json',
  'conformance/clean-room/v2/bundle.v2.json',
  'conformance/clean-room/v3/bundle.v3.json',
  'security/security-case.json',
  'lib/proof-stats.json',
  'AI_CONTEXT.md',
  'public/llms.txt',
  'public/llms-full.txt',
  'public/.well-known/emilia-context.json',
]);

const CONFORMANCE_MANIFEST = 'conformance/conformance-manifest.json';

/**
 * Derived evidence inside hand-authored files, keyed by path. The current
 * clean-room bundles define the vector corpus (claim scope, runner protocol,
 * suites, totals) by review; their one derived field, source_manifest, pins
 * the conformance manifest. Each entry recomputes the derived fields from a
 * tree. In an autopilot commit such a file must be exactly its source-commit
 * version with those fields recomputed from the same commit's manifest,
 * serialized as sync:clean-room-pins writes it (`rederive`): the bot cannot
 * change a claim, a suite, a count or any other digest, and the only pin it
 * can write is the digest of the manifest it publishes alongside.
 *
 * No other hand-authored file pins the manifest: the v2 verifier, its
 * documentation and the preprint read or cite the bundle instead, so a
 * packages/verify change never needs a human (or the bot) to edit them.
 *
 * @type {Readonly<Record<string, (read: (path: string) => Buffer) => Record<string, unknown>>>}
 */
export const DERIVED_FIELDS = Object.freeze({
  'conformance/clean-room/v2/bundle.v2.json': sourceManifestPin,
  'conformance/clean-room/v3/bundle.v3.json': sourceManifestPin,
});

/**
 * The source-commit files `inspect` reads to hold DERIVED_FIELDS files to
 * their source versions. The publisher fetches them from GitHub by commit,
 * never from the bundle.
 */
export const SOURCE_FILES = Object.freeze([...Object.keys(DERIVED_FIELDS), CONFORMANCE_MANIFEST]);

/**
 * Resolves the paths a bundle may carry. A caller may narrow the allowlist
 * (scripts/ci/volatile-evidence.mjs publishes five of these files) but never
 * widen it: dco.yml exempts an autopilot commit only for DERIVED_EVIDENCE.
 *
 * @param {readonly string[]} [allowlist]
 * @returns {readonly string[]}
 */
function allowedPaths(allowlist = DERIVED_EVIDENCE) {
  const derived = new Set(DERIVED_EVIDENCE);
  if (!Array.isArray(allowlist) || allowlist.length === 0 || new Set(allowlist).size !== allowlist.length) {
    throw new Error('the allowlist must be a non-empty list of distinct paths');
  }
  const outside = allowlist.filter((path) => !derived.has(path));
  if (outside.length > 0) throw new Error(`not derived-evidence paths: ${outside.join(', ')}`);
  return allowlist;
}

const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024;
const SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
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
 * @param {string} repo
 * @param {string} commit
 * @param {string} path
 * @returns {Buffer}
 */
function blobAt(repo, commit, path) {
  return execFileSync('git', ['cat-file', 'blob', `${commit}:${path}`], {
    cwd: repo,
    maxBuffer: MAX_FILE_BYTES + 1,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * sync:clean-room-pins' source_manifest: the path, byte digest and claim
 * digest of the conformance manifest in the tree `read` returns.
 *
 * @param {(path: string) => Buffer} read
 * @returns {{ source_manifest: { path: string, sha256: string, manifest_sha256: string } }}
 */
function sourceManifestPin(read) {
  const bytes = read(CONFORMANCE_MANIFEST);
  const claim = JSON.parse(bytes.toString('utf8'))?.manifest_sha256;
  if (typeof claim !== 'string' || !SHA256.test(claim)) {
    throw new Error(`${CONFORMANCE_MANIFEST}: manifest_sha256 is not a sha256 digest`);
  }
  return { source_manifest: { path: CONFORMANCE_MANIFEST, sha256: sha256(bytes), manifest_sha256: claim } };
}

/**
 * The only content a DERIVED_FIELDS file may take: `source` (its bytes at
 * the source commit) with the derived fields recomputed from `read` (the
 * tree being published), serialized as the writer serializes it.
 *
 * @param {string} path
 * @param {Buffer} source
 * @param {(path: string) => Buffer} read
 * @returns {Buffer}
 */
export function rederive(path, source, read) {
  const derive = Object.hasOwn(DERIVED_FIELDS, path) ? DERIVED_FIELDS[path] : undefined;
  if (!derive) throw new Error(`${path}: has no derived fields`);
  const value = JSON.parse(source.toString('utf8'));
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${path}: the source commit's version is not a JSON object`);
  }
  const fields = derive(read);
  for (const key of Object.keys(fields)) {
    if (!Object.hasOwn(value, key)) throw new Error(`${path}: the source commit's version has no ${key} to refresh`);
  }
  return Buffer.from(`${JSON.stringify({ ...value, ...fields }, null, 2)}\n`, 'utf8');
}

/**
 * @param {string} path
 * @param {Buffer} bytes the content to be published
 * @param {Buffer} source
 * @param {(path: string) => Buffer} read
 */
function assertOnlyDerivedFields(path, bytes, source, read) {
  if (!rederive(path, source, read).equals(bytes)) {
    throw new Error(
      `${path}: is not its source-commit version with only its derived fields recomputed from ${CONFORMANCE_MANIFEST}`,
    );
  }
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
 * Bundles every allowlisted file (DERIVED_EVIDENCE unless narrowed) that
 * differs between `sourceSha` and HEAD. Refuses a dirty tree, any other
 * changed path and a DERIVED_FIELDS file that changes more than its derived
 * fields.
 *
 * @param {{ repo: string, sourceSha: string, out: string, allowlist?: readonly string[] }} options
 * @returns {Manifest}
 */
export function collect({ repo, sourceSha, out, allowlist }) {
  const paths = allowedPaths(allowlist);
  if (!SHA.test(sourceSha)) throw new Error('source sha must be a 40-character lowercase hex commit');
  const dirty = git(['status', '--porcelain', '--untracked-files=no'], repo).trim();
  if (dirty) throw new Error(`the writers left uncommitted tracked changes:\n${dirty}`);
  const changed = git(['diff', '--name-only', '-z', '--no-renames', sourceSha, 'HEAD'], repo)
    .split('\0')
    .filter(Boolean);
  const allowed = new Set(paths);
  const outside = changed.filter((path) => !allowed.has(path));
  if (outside.length > 0) {
    throw new Error(`the writers changed paths outside the derived-evidence allowlist:\n${outside.join('\n')}`);
  }
  /** @type {BundleFile[]} */
  const files = [];
  for (const path of paths.filter((candidate) => changed.includes(candidate))) {
    const source = join(repo, path);
    const stat = lstatSync(source);
    if (!stat.isFile()) throw new Error(`${path}: is not a regular file`);
    const bytes = readFileSync(source);
    if (bytes.length > MAX_FILE_BYTES) throw new Error(`${path}: exceeds ${MAX_FILE_BYTES} bytes`);
    assertEvidenceText(path, bytes);
    if (Object.hasOwn(DERIVED_FIELDS, path)) {
      assertOnlyDerivedFields(path, bytes, blobAt(repo, sourceSha, path), (name) => readFileSync(join(repo, name)));
    }
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
 * A DERIVED_FIELDS file must also be exactly its version at `sourceSha`,
 * which `source` reads from outside the bundle (SOURCE_FILES, fetched from
 * GitHub), with only its derived fields recomputed from the manifest being
 * published (the bundle's, or the source commit's if the bundle has none).
 *
 * @param {{ bundle: string, sourceSha: string, allowlist?: readonly string[],
 *   source?: (path: string) => Buffer }} options
 * @returns {{ manifest: Manifest, contents: Map<string, Buffer> }}
 */
export function inspect({ bundle, sourceSha, allowlist, source }) {
  const paths = allowedPaths(allowlist);
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
  if (!Array.isArray(manifest.files) || manifest.files.length > paths.length) {
    throw new Error('manifest files must be an array no longer than the allowlist');
  }
  const allowed = new Set(paths);
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
  for (const [path, bytes] of contents) {
    if (!Object.hasOwn(DERIVED_FIELDS, path)) continue;
    if (!source) throw new Error(`${path}: checking its derived fields needs the source commit's files (--source-files)`);
    assertOnlyDerivedFields(path, bytes, source(path), (name) => contents.get(name) ?? source(name));
  }
  return { manifest, contents };
}

/**
 * dco.yml's content rule for an evidence autopilot commit, read from git
 * rather than from any bundle: exactly one parent; every changed path in
 * DERIVED_EVIDENCE, added or modified (never deleted) as a regular
 * non-executable file of UTF-8 text; and every DERIVED_FIELDS file exactly
 * its parent's version with only its derived fields recomputed from the
 * commit's own tree. dco.yml runs the base branch's copy of this file, so
 * the copy in a pull request does not decide what exempts that pull
 * request's commits, and exempts only on the verdict line `main` prints.
 *
 * @param {{ repo: string, commit: string }} options
 * @returns {string[]} the changed paths
 */
export function verifyCommit({ repo, commit }) {
  if (!SHA.test(commit)) throw new Error('commit must be a 40-character lowercase hex commit');
  const parents = git(['rev-list', '--parents', '-n', '1', commit], repo).trim().split(' ').slice(1);
  if (parents.length !== 1) throw new Error(`${commit} has ${parents.length} parents; an evidence commit has exactly one`);
  const [parent] = parents;
  const allowed = new Set(DERIVED_EVIDENCE);
  const raw = git(['diff-tree', '-r', '-z', '--no-renames', '--no-commit-id', parent, commit], repo).split('\0');
  /** @type {string[]} */
  const changed = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const [meta, path] = [raw[index], raw[index + 1]];
    const fields = /^:(\d{6}) (\d{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z])\d*$/.exec(meta);
    if (!fields) throw new Error(`unexpected git diff-tree record ${JSON.stringify(meta)}`);
    const [, , mode, status] = fields;
    if (!allowed.has(path)) throw new Error(`${commit} changes ${path}, which is not derived evidence`);
    if ((status !== 'M' && status !== 'A') || mode !== '100644') {
      throw new Error(`${commit} ${status === 'D' ? 'deletes' : 'changes the type or mode of'} ${path}`);
    }
    const bytes = blobAt(repo, commit, path);
    if (bytes.length > MAX_FILE_BYTES) throw new Error(`${path}: exceeds ${MAX_FILE_BYTES} bytes`);
    assertEvidenceText(path, bytes);
    if (Object.hasOwn(DERIVED_FIELDS, path)) {
      if (status !== 'M') throw new Error(`${commit} adds ${path}, which has no source version to refresh`);
      assertOnlyDerivedFields(path, bytes, blobAt(repo, parent, path), (name) => blobAt(repo, commit, name));
    }
    changed.push(path);
  }
  return changed;
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
      'sync:clean-room-pins, sync:proof-stats, sync:llm-context). The',
      "publisher checked the bundle's shape and transit integrity, and that",
      'each clean-room bundle changes only its derived source_manifest; the',
      'required checks on this commit decide whether the evidence is correct.',
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
 * inspected bundle (`source` as for `inspect`). expectedHeadOid makes it
 * compare-and-swap: GitHub refuses it unless `branch` still points at
 * `sourceSha`, so a branch that was force-pushed, rewound or deleted in the
 * meantime is left alone.
 *
 * `allowlist` narrows the publishable paths and `message` replaces the
 * default headline and body; any replacement body must still carry
 * COMMIT_TRAILER, which dco.yml requires for the exemption.
 *
 * @param {{ bundle: string, sourceSha: string, repository: string, branch: string, runUrl: string,
 *   allowlist?: readonly string[], message?: { headline: string, body: string },
 *   source?: (path: string) => Buffer }} options
 * @returns {{ query: string, variables: { input: {
 *   branch: { repositoryNameWithOwner: string, branchName: string },
 *   expectedHeadOid: string,
 *   message: { headline: string, body: string },
 *   fileChanges: { additions: Array<{ path: string, contents: string }> },
 * } } }}
 */
export function commitRequest({ bundle, sourceSha, repository, branch, runUrl, allowlist, message, source }) {
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
  const commit = message ?? commitMessage(sourceSha, runUrl);
  if (
    typeof commit?.headline !== 'string' || !commit.headline || commit.headline.includes('\n')
    || typeof commit.body !== 'string' || !commit.body.split('\n').includes(COMMIT_TRAILER)
  ) {
    throw new Error(`the commit message needs a one-line headline and a body carrying ${COMMIT_TRAILER}`);
  }
  const { contents } = inspect({ bundle, sourceSha, allowlist, source });
  if (contents.size === 0) throw new Error('the bundle carries no files; there is nothing to publish');
  return {
    query: CREATE_COMMIT_ON_BRANCH,
    variables: {
      input: {
        branch: { repositoryNameWithOwner: repository, branchName: branch },
        expectedHeadOid: sourceSha,
        message: commit,
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
 * Reads SOURCE_FILES from a directory the publisher filled from GitHub.
 *
 * @param {string | undefined} dir
 * @returns {((path: string) => Buffer) | undefined}
 */
function sourceFiles(dir) {
  if (!dir) return undefined;
  return (path) => {
    if (!SOURCE_FILES.includes(path)) throw new Error(`${path}: not a source file inspect reads`);
    const file = join(dir, path);
    let stat;
    try {
      stat = lstatSync(file);
    } catch {
      throw new Error(`${path}: the source commit has no copy of it`);
    }
    if (!stat.isFile()) throw new Error(`${path}: source copy is not a regular file`);
    return readFileSync(file);
  };
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
  if (command === 'source-files') {
    if (rest.length > 0) throw new Error('source-files takes no options');
    console.log(SOURCE_FILES.join('\n'));
    return 0;
  }
  if (command === 'inspect') {
    const { manifest } = inspect({
      bundle: options.bundle ?? '',
      sourceSha: options['source-sha'] ?? '',
      source: sourceFiles(options['source-files']),
    });
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
      source: sourceFiles(options['source-files']),
    });
    writeFileSync(options.out, JSON.stringify(request));
    const paths = request.variables.input.fileChanges.additions.map((file) => `  ${file.path}`);
    console.log(`EVIDENCE AUTOPILOT: createCommitOnBranch request for ${options.branch} at ${options['source-sha']}:\n${paths.join('\n')}`);
    return 0;
  }
  if (command === 'verify-commit') {
    const commit = options.commit ?? '';
    const changed = verifyCommit({ repo: options.repo ?? process.cwd(), commit });
    console.log(`EVIDENCE AUTOPILOT: ${commit} changes only derived evidence:\n${changed.map((path) => `  ${path}`).join('\n')}`);
    return 0;
  }
  throw new Error('usage: evidence-autopilot.mjs collect|source-files|inspect|request|verify-commit --option value ...');
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
