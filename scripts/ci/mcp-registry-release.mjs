// SPDX-License-Identifier: Apache-2.0
// Registry metadata publication only. This never publishes an npm package.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const MCP_NAME = 'io.github.emiliaprotocol/mcp-server';
export const NPM_NAME = '@emilia-protocol/mcp-server';
export const PUBLISHER_URL = 'https://github.com/modelcontextprotocol/registry/releases/download/v1.8.1/mcp-publisher_linux_amd64.tar.gz';
export const PUBLISHER_SHA256 = 'a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc';
const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}.git`;
const REGISTRY = 'https://registry.modelcontextprotocol.io';
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const SHA = /^[a-f0-9]{40}$/u;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function validateRequest(input, server, pkg) {
  if (input.eventName !== 'workflow_dispatch' || input.actor !== 'FutureEnterprises'
    || input.triggeringActor !== 'FutureEnterprises') throw new Error('Registry dispatch and rerun require the configured owner');
  if (input.repository !== REPOSITORY || input.ref !== 'refs/heads/main'
    || !SHA.test(input.sha ?? '')) throw new Error('Registry publication requires an exact protected main commit');
  if (typeof server.version !== 'string' || server.version.length > 40 || !VERSION.test(server.version)) {
    throw new Error('Registry version must be a canonical stable semantic version');
  }
  const version = server.version;
  if (server.name !== MCP_NAME || pkg.name !== NPM_NAME || pkg.mcpName !== MCP_NAME || pkg.version !== version
    || server.repository?.url !== `https://github.com/${REPOSITORY}` || server.repository?.source !== 'github'
    || !Array.isArray(server.packages) || server.packages.length !== 1) throw new Error('MCP manifest/package identity differs');
  const entry = server.packages[0];
  if (entry.registryType !== 'npm' || entry.registryBaseUrl !== 'https://registry.npmjs.org'
    || entry.identifier !== NPM_NAME || entry.version !== version || entry.transport?.type !== 'stdio') {
    throw new Error('MCP package ownership, transport or version differs');
  }
  if (input.tag !== `mcp-v${version}`) throw new Error('Registry release tag differs from the manifest version');
  if (input.confirmation !== `REGISTER ${MCP_NAME}@${version}`) throw new Error('Registry confirmation does not match the exact server version');
  return { version, tag: input.tag };
}

export function assertImmutableTagRules(rulesets) {
  const protection = Array.isArray(rulesets) && rulesets.find((entry) => entry.target === 'tag' && entry.enforcement === 'active'
    && (!Object.hasOwn(entry, 'bypass_actors') || (Array.isArray(entry.bypass_actors) && entry.bypass_actors.length === 0))
    && entry.conditions?.ref_name?.include?.includes('refs/tags/mcp-v*')
    && Array.isArray(entry.conditions?.ref_name?.exclude) && entry.conditions.ref_name.exclude.length === 0
    && entry.rules?.some((rule) => rule.type === 'update') && entry.rules?.some((rule) => rule.type === 'deletion'));
  if (!protection) {
    throw new Error('MCP release tags require active update/deletion protection without exclusions or a reported bypass');
  }
  // GitHub returns bypass_actors only to ruleset writers. Absence is not proof of no bypass.
  return { bypass_visibility: Object.hasOwn(protection, 'bypass_actors') ? 'reported-empty' : 'unobservable-under-readonly-token' };
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function regularBytes(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Release manifest must be a regular file');
  return readFileSync(path);
}

export function verifySource(cwd, input, queryRemote = () => git(cwd, ['ls-remote', '--exit-code', REPOSITORY_URL, 'refs/heads/main', `refs/tags/${input.tag}`, `refs/tags/${input.tag}^{}`])) {
  const serverBytes = regularBytes(join(cwd, 'server.json'));
  const packageBytes = regularBytes(join(cwd, 'mcp-server/package.json'));
  const server = JSON.parse(serverBytes.toString('utf8'));
  const pkg = JSON.parse(packageBytes.toString('utf8'));
  const approved = validateRequest(input, server, pkg);
  const head = git(cwd, ['rev-parse', 'HEAD^{commit}']);
  if (head !== input.sha) throw new Error('Checkout differs from dispatched main commit');
  if (git(cwd, ['status', '--porcelain', '--untracked-files=no'])) throw new Error('Release checkout contains modified tracked source');
  const tagCommit = git(cwd, ['rev-parse', '--verify', `refs/tags/${approved.tag}^{commit}`]);
  try { git(cwd, ['merge-base', '--is-ancestor', tagCommit, head]); } catch { throw new Error('MCP release tag is not an ancestor of the dispatched main commit'); }
  /** @type {Array<[string, Buffer]>} */
  const manifests = [['server.json', serverBytes], ['mcp-server/package.json', packageBytes]];
  for (const [path, actual] of manifests) {
    const tagged = execFileSync('git', ['show', `refs/tags/${approved.tag}:${path}`], { cwd, encoding: null, timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] });
    if (!tagged.equals(actual)) throw new Error(`${path} bytes differ from immutable MCP release tag`);
  }
  const refs = new Map();
  for (const line of queryRemote().trim().split('\n')) {
    const match = /^([a-f0-9]{40})\t(refs\/(?:heads|tags)\/.+)$/u.exec(line);
    if (!match || refs.has(match[2])) throw new Error('Canonical remote references are malformed or duplicated');
    refs.set(match[2], match[1]);
  }
  if (refs.get('refs/heads/main') !== head) throw new Error('Canonical protected main moved');
  const remoteTag = refs.get(`refs/tags/${approved.tag}^{}`) ?? refs.get(`refs/tags/${approved.tag}`);
  if (remoteTag !== tagCommit) throw new Error('Canonical MCP release tag changed or disappeared');
  return { ...approved, tagCommit, head, server, packageBytes, serverBytes };
}

function expectedTarball(version) {
  return `https://registry.npmjs.org/@emilia-protocol/mcp-server/-/mcp-server-${version}.tgz`;
}

export function verifyNpmArtifact(metadata, tarball, packageBytes, version) {
  if (!VERSION.test(version) || metadata?.name !== NPM_NAME || metadata.version !== version || metadata.mcpName !== MCP_NAME
    || metadata.dist?.tarball !== expectedTarball(version)) throw new Error('Published npm identity or tarball origin differs');
  const integrity = metadata.dist?.integrity;
  if (typeof integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/u.test(integrity)
    || integrity !== `sha512-${createHash('sha512').update(tarball).digest('base64')}`) throw new Error('Published npm SHA-512 integrity differs');
  const unpacked = gunzipSync(tarball, { maxOutputLength: 32 * 1024 * 1024 });
  /** @type {import('node:child_process').ExecFileSyncOptionsWithBufferEncoding} */
  const options = { input: unpacked, encoding: null, timeout: 10_000, maxBuffer: 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] };
  const list = execFileSync('tar', ['-tf', '-'], options).toString('utf8').trim().split('\n');
  if (list.filter((path) => path === 'package/package.json').length !== 1) throw new Error('Published npm manifest path is missing or duplicated');
  const embedded = execFileSync('tar', ['-xOf', '-', 'package/package.json'], options);
  if (!embedded.equals(packageBytes)) throw new Error('Published npm package manifest bytes differ from immutable source');
  return { sha256: sha256(tarball), bytes: tarball.length, integrity };
}

export function verifyNpmProvenance(tarball, tagCommit, runnerTemp, verify = (command, args) => execFileSync(command, args,
  { encoding: 'utf8', timeout: 120_000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] })) {
  if (!SHA.test(tagCommit ?? '')) throw new Error('Provenance requires the immutable MCP tag commit');
  if (typeof runnerTemp !== 'string' || !isAbsolute(runnerTemp)) throw new Error('Provenance requires a runner-owned temporary directory');
  const directory = mkdtempSync(join(realpathSync(runnerTemp), 'emilia-mcp-registry-npm-'));
  const artifact = join(directory, 'mcp-server.tgz');
  try {
    writeFileSync(artifact, tarball, { flag: 'wx', mode: 0o600 });
    // gh checks the Sigstore signature and artifact digest before this identity policy.
    // Both digests belong to the npm publishing tag, not the newer Registry workflow.
    const results = JSON.parse(verify('gh', ['attestation', 'verify', artifact, '--repo', REPOSITORY,
      '--signer-workflow', `${REPOSITORY}/.github/workflows/_publish-npm-package.yml`,
      '--signer-digest', tagCommit, '--source-digest', tagCommit, '--source-ref', 'refs/heads/main',
      '--deny-self-hosted-runners', '--limit', '5', '--format', 'json']));
    const digest = sha256(tarball);
    const accepted = Array.isArray(results) && results.some((entry) => {
      const checked = entry?.verificationResult;
      const certificate = checked?.signature?.certificate;
      return checked?.statement?.predicateType === 'https://slsa.dev/provenance/v1'
        && checked.statement.subject?.some((subject) => subject.digest?.sha256 === digest)
        && certificate?.issuer === 'https://token.actions.githubusercontent.com'
        && certificate.sourceRepositoryURI === `https://github.com/${REPOSITORY}`
        && certificate.sourceRepositoryDigest === tagCommit && certificate.sourceRepositoryRef === 'refs/heads/main'
        && certificate.buildSignerURI === `https://github.com/${REPOSITORY}/.github/workflows/_publish-npm-package.yml@refs/heads/main`
        && certificate.buildSignerDigest === tagCommit && certificate.runnerEnvironment === 'github-hosted';
    });
    if (!accepted) throw new Error('Published npm provenance does not bind these bytes to the immutable source and trusted builder');
    return { sha256: digest, source_commit: tagCommit, signer_commit: tagCommit };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

export function assertRegistryAbsent(status) {
  if (status === 404) return;
  if (status === 200) throw new Error('Registry version already exists; refusing to overwrite or republish');
  throw new Error(`Cannot establish Registry version absence: HTTP ${status}`);
}

function normalizedServer(server) {
  const copy = structuredClone(server);
  for (const pkg of copy.packages ?? []) {
    for (const entry of pkg.environmentVariables ?? []) {
      if (!Object.hasOwn(entry, 'isRequired')) entry.isRequired = false;
      if (!Object.hasOwn(entry, 'isSecret')) entry.isSecret = false;
    }
  }
  return copy;
}

export function verifyRegistryRecord(record, expected) {
  const official = record?._meta?.['io.modelcontextprotocol.registry/official'];
  if (official?.status !== 'active' || official?.isLatest !== true) throw new Error('Registry version is not active/latest');
  assert.deepStrictEqual(normalizedServer(record.server), normalizedServer(expected), 'Registry manifest differs from the verified source');
}

export function setupAuthCache({ runnerTemp, configRoot = join(homedir(), '.config') }) {
  if (typeof runnerTemp !== 'string' || !isAbsolute(runnerTemp)) throw new Error('A runner-owned absolute temporary directory is required');
  const target = join(realpathSync(runnerTemp), 'emilia-mcp-registry-auth');
  const link = join(configRoot, 'mcp-publisher');
  if (existsSync(target) || existsSync(link)) throw new Error('Refusing an existing publisher auth cache or config');
  // lstat catches an existing dangling symlink, which existsSync intentionally ignores.
  try { lstatSync(link); throw new Error('Refusing existing publisher config'); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  mkdirSync(target, { mode: 0o700 });
  mkdirSync(configRoot, { recursive: true, mode: 0o700 });
  symlinkSync(target, link, 'dir');
  return target;
}

async function fetchBytes(url, { headers = {}, maxBytes = 1024 * 1024 } = {}) {
  const response = await fetch(url, { headers, redirect: 'error', signal: AbortSignal.timeout(30_000) });
  const advertised = Number(response.headers.get('content-length'));
  if (Number.isFinite(advertised) && advertised > maxBytes) throw new Error('Registry response exceeds its bounded size');
  if (!response.body) throw new Error('Registry response has no body');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) throw new Error('Registry response exceeds its bounded size');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return { status: response.status, bytes: Buffer.concat(chunks) };
}

async function immutableRules(token) {
  if (!token) throw new Error('Read-only GitHub workflow token is required to inspect immutable rules');
  const headers = { accept: 'application/vnd.github+json', authorization: `Bearer ${token}`, 'x-github-api-version': '2022-11-28' };
  const base = `https://api.github.com/repos/${REPOSITORY}/rulesets`;
  const list = await fetchBytes(`${base}?per_page=100`, { headers });
  if (list.status !== 200) throw new Error(`Cannot inspect GitHub rulesets: HTTP ${list.status}`);
  const summaries = JSON.parse(list.bytes.toString('utf8'));
  if (!Array.isArray(summaries) || summaries.length >= 100) throw new Error('GitHub ruleset inventory is invalid or truncated');
  const details = [];
  for (const item of summaries) {
    if (item.target !== 'tag' || item.enforcement !== 'active') continue;
    if (!Number.isSafeInteger(item.id) || item.id <= 0) throw new Error('Malformed GitHub ruleset identifier');
    const detail = await fetchBytes(`${base}/${item.id}`, { headers });
    if (detail.status !== 200) throw new Error(`Cannot inspect immutable tag rules: HTTP ${detail.status}`);
    details.push(JSON.parse(detail.bytes.toString('utf8')));
  }
  return assertImmutableTagRules(details);
}

function requestFromEnvironment(env) {
  return { eventName: env.GITHUB_EVENT_NAME, actor: env.GITHUB_ACTOR, triggeringActor: env.GITHUB_TRIGGERING_ACTOR,
    repository: env.GITHUB_REPOSITORY, ref: env.GITHUB_REF, sha: env.GITHUB_SHA,
    tag: env.RELEASE_TAG, confirmation: env.RELEASE_CONFIRMATION };
}

const recordUrl = (version) => `${REGISTRY}/v0.1/servers/${encodeURIComponent(MCP_NAME)}/versions/${version}`;

export async function main(command, env = process.env, cwd = process.cwd()) {
  if (command === 'auth-cache') { setupAuthCache({ runnerTemp: env.RUNNER_TEMP }); return; }
  if (!['preflight', 'verify'].includes(command)) throw new Error('Expected preflight, auth-cache or verify');
  const source = verifySource(cwd, requestFromEnvironment(env));
  const protection = await immutableRules(env.GH_TOKEN);
  if (command === 'preflight') {
    const metadataResponse = await fetchBytes(`https://registry.npmjs.org/${encodeURIComponent(NPM_NAME)}/${source.version}`);
    if (metadataResponse.status !== 200) throw new Error(`Exact npm release is unavailable: HTTP ${metadataResponse.status}`);
    const metadata = JSON.parse(metadataResponse.bytes.toString('utf8'));
    // Validate the fixed origin before fetching bytes. The artifact verifier repeats it.
    if (metadata.dist?.tarball !== expectedTarball(source.version)) throw new Error('Published npm tarball origin differs');
    const artifact = await fetchBytes(metadata.dist.tarball, { maxBytes: 8 * 1024 * 1024 });
    if (artifact.status !== 200) throw new Error(`Published npm artifact is unavailable: HTTP ${artifact.status}`);
    const verified = verifyNpmArtifact(metadata, artifact.bytes, source.packageBytes, source.version);
    verifyNpmProvenance(artifact.bytes, source.tagCommit, env.RUNNER_TEMP);
    const existing = await fetchBytes(recordUrl(source.version));
    assertRegistryAbsent(existing.status);
    const result = { version: source.version, tag: source.tag, tag_commit: source.tagCommit, source_commit: source.head,
      server_json_sha256: sha256(source.serverBytes), npm_tarball_sha256: verified.sha256, npm_tarball_bytes: verified.bytes,
      tag_bypass_visibility: protection.bypass_visibility };
    if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, Object.entries(result).map(([key, value]) => `${key}=${value}\n`).join(''));
    console.log(JSON.stringify(result));
    return result;
  }
  const actual = await fetchBytes(recordUrl(source.version));
  if (actual.status !== 200) throw new Error(`Published Registry version is unavailable: HTTP ${actual.status}`);
  const record = JSON.parse(actual.bytes.toString('utf8'));
  verifyRegistryRecord(record, source.server);
  const latestResponse = await fetchBytes(recordUrl('latest'));
  if (latestResponse.status !== 200) throw new Error(`Registry latest is unavailable: HTTP ${latestResponse.status}`);
  verifyRegistryRecord(JSON.parse(latestResponse.bytes.toString('utf8')), source.server);
  const receipt = { verified_at: new Date().toISOString(), source_commit: source.head, release_tag: source.tag,
    release_tag_commit: source.tagCommit, server_json_sha256: sha256(source.serverBytes), record };
  if (env.RUNNER_TEMP) writeFileSync(join(realpathSync(env.RUNNER_TEMP), 'emilia-mcp-registry-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`Registry ${MCP_NAME}@${source.version} is active/latest and matches the immutable release manifest.`);
  return receipt;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
