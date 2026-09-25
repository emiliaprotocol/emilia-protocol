#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Evidence autopilot bundle tool.
 *
 * .github/workflows/evidence-autopilot.yml regenerates content-addressed
 * derived evidence on a pull request branch with the repository's official
 * writers, in an unprivileged job, and `collect`s the result into a bundle.
 * .github/workflows/evidence-autopilot-publish.yml runs this file from the
 * default branch (never from the pull request), `inspect`s and `apply`s the
 * bundle onto the exact source commit, and pushes one commit. dco.yml exempts
 * that commit from sign-off only while it changes nothing but
 * DERIVED_EVIDENCE.
 *
 * The bundle can only ever carry DERIVED_EVIDENCE paths. Anything else the
 * writers touched stops the run: the autopilot regenerates evidence, it
 * never edits code.
 *
 * Usage:
 *   node scripts/ci/evidence-autopilot.mjs collect --source-sha <sha> --out <dir> [--github-output <file>]
 *   node scripts/ci/evidence-autopilot.mjs inspect --bundle <dir> --source-sha <sha> [--github-output <file>]
 *   node scripts/ci/evidence-autopilot.mjs apply   --bundle <dir> --source-sha <sha> --repo <dir>
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, copyFileSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const BUNDLE_VERSION = 'EP-EVIDENCE-AUTOPILOT-v1';
export const COMMIT_TRAILER = 'Evidence-Autopilot: v1';

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
 * Validates an untrusted bundle and returns its manifest. Every byte is
 * checked against the manifest, the allowlist and the expected source.
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
 * Writes an inspected bundle into a checkout that is exactly at `sourceSha`.
 *
 * @param {{ bundle: string, sourceSha: string, repo: string }} options
 * @returns {string[]} written paths
 */
export function apply({ bundle, sourceSha, repo }) {
  const { contents } = inspect({ bundle, sourceSha });
  const head = git(['rev-parse', 'HEAD'], repo).trim();
  if (head !== sourceSha) throw new Error(`checkout is at ${head}, expected ${sourceSha}`);
  const dirty = git(['status', '--porcelain', '--untracked-files=no'], repo).trim();
  if (dirty) throw new Error(`target checkout is not clean:\n${dirty}`);
  for (const [path, bytes] of contents) {
    // Never write through a symlinked directory or file in the checkout.
    const parts = path.split('/');
    for (let depth = 1; depth < parts.length; depth += 1) {
      const directory = lstatSync(join(repo, ...parts.slice(0, depth)), { throwIfNoEntry: false });
      if (directory && !directory.isDirectory()) throw new Error(`${path}: an ancestor is not a plain directory`);
    }
    const target = join(repo, path);
    const current = lstatSync(target, { throwIfNoEntry: false });
    if (current && !current.isFile()) throw new Error(`${path}: target is not a regular file`);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
  return [...contents.keys()];
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
  if (command === 'apply') {
    const written = apply({ bundle: options.bundle ?? '', sourceSha: options['source-sha'] ?? '', repo: options.repo ?? '' });
    console.log(`EVIDENCE AUTOPILOT: wrote ${written.length} file(s):\n${written.map((path) => `  ${path}`).join('\n')}`);
    return 0;
  }
  throw new Error('usage: evidence-autopilot.mjs collect|inspect|apply --option value ...');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(`EVIDENCE AUTOPILOT: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
