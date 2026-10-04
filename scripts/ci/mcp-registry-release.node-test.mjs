// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import YAML from 'yaml';
import {
  MCP_NAME, NPM_NAME, PUBLISHER_SHA256, PUBLISHER_URL,
  assertImmutableTagRules, assertRegistryAbsent, setupAuthCache,
  validateRequest, verifyNpmArtifact, verifyNpmProvenance, verifyRegistryRecord, verifySource,
} from './mcp-registry-release.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SHA = 'a'.repeat(40);
const packageText = JSON.stringify({ name: '@emilia-protocol/mcp-server', version: '2.1.4', mcpName: 'io.github.emiliaprotocol/mcp-server' });
const manifest = {
  name: 'io.github.emiliaprotocol/mcp-server', version: '2.1.4',
  description: 'Exact-action approvals.', repository: { url: 'https://github.com/emiliaprotocol/emilia-protocol', source: 'github' },
  packages: [{ registryType: 'npm', registryBaseUrl: 'https://registry.npmjs.org', identifier: '@emilia-protocol/mcp-server', version: '2.1.4', transport: { type: 'stdio' }, environmentVariables: [{ name: 'KEY', isRequired: false, isSecret: true }] }],
};
const request = () => ({ eventName: 'workflow_dispatch', actor: 'FutureEnterprises', triggeringActor: 'FutureEnterprises', repository: 'emiliaprotocol/emilia-protocol', ref: 'refs/heads/main', sha: SHA, tag: 'mcp-v2.1.4', confirmation: 'REGISTER io.github.emiliaprotocol/mcp-server@2.1.4' });
const rules = () => ({ target: 'tag', enforcement: 'active', bypass_actors: [], conditions: { ref_name: { include: ['refs/tags/mcp-v*'], exclude: [] } }, rules: [{ type: 'update' }, { type: 'deletion' }] });

test('request binds owner, protected main, repository, exact version/tag and distinct Registry confirmation', () => {
  assert.equal(validateRequest(request(), manifest, JSON.parse(packageText)).version, '2.1.4');
  for (const [key, value] of Object.entries({ eventName: 'push', actor: 'other', triggeringActor: 'other', repository: 'other/fork', ref: 'refs/heads/other', sha: 'main', tag: 'mcp-v2.1.4; touch x', confirmation: 'PUBLISH @emilia-protocol/mcp-server@2.1.4' })) {
    assert.throws(() => validateRequest({ ...request(), [key]: value }, manifest, JSON.parse(packageText)), undefined, key);
  }
  for (const version of ['02.1.4', '2.1.4-beta', '2.1.4\n', '../../x', null]) {
    assert.throws(() => validateRequest(request(), { ...manifest, version }, JSON.parse(packageText)));
  }
  for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
    const version = `2.1.4${suffix}`;
    const server = { ...manifest, version, packages: [{ ...manifest.packages[0], version }] };
    const input = { ...request(), tag: `mcp-v${version}`, confirmation: `REGISTER ${MCP_NAME}@${version}` };
    assert.throws(() => validateRequest(input, server, { ...JSON.parse(packageText), version }), /canonical stable/);
    assert.throws(() => validateRequest({ ...request(), sha: `${SHA}${suffix}` }, manifest, JSON.parse(packageText)), /protected main/);
  }
});

test('manifest and package ownership/version cannot drift or add a second package', () => {
  for (const bad of [
    { ...manifest, name: 'io.github.other/mcp-server' },
    { ...manifest, packages: [...manifest.packages, manifest.packages[0]] },
    { ...manifest, packages: [{ ...manifest.packages[0], version: '2.1.3' }] },
    { ...manifest, packages: [{ ...manifest.packages[0], transport: { type: 'http' } }] },
  ]) assert.throws(() => validateRequest(request(), bad, JSON.parse(packageText)));
  assert.throws(() => validateRequest(request(), manifest, { ...JSON.parse(packageText), mcpName: 'io.github.other/mcp-server' }));
});

test('the MCP tag namespace requires visible active protection; unreadable bypass settings are not claimed absent', () => {
  assert.equal(assertImmutableTagRules([rules()]).bypass_visibility, 'reported-empty');
  const readonly = rules(); delete readonly.bypass_actors;
  assert.equal(assertImmutableTagRules([readonly]).bypass_visibility, 'unobservable-under-readonly-token');
  for (const bad of [
    { ...rules(), enforcement: 'evaluate' }, { ...rules(), target: 'branch' },
    { ...rules(), bypass_actors: [{ actor_id: 1 }] }, { ...rules(), bypass_actors: null }, { ...rules(), rules: [{ type: 'update' }] },
    { ...rules(), conditions: { ref_name: { include: ['refs/tags/other*'], exclude: [] } } },
    { ...rules(), conditions: { ref_name: { include: ['refs/tags/mcp-v*'], exclude: ['refs/tags/mcp-v2*'] } } },
  ]) assert.throws(() => assertImmutableTagRules([bad]));
});

function scratch(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-mcp-registry-test-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('source accepts an ancestor release tag only when both manifest byte strings remain exact and remote refs match', () => scratch((dir) => {
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-b', 'main');
  mkdirSync(join(dir, 'mcp-server'));
  writeFileSync(join(dir, 'server.json'), JSON.stringify(manifest));
  writeFileSync(join(dir, 'mcp-server/package.json'), packageText);
  const commit = () => { git('add', '.'); git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture'); return git('rev-parse', 'HEAD'); };
  const tagged = commit(); git('tag', 'mcp-v2.1.4');
  writeFileSync(join(dir, 'unrelated.txt'), 'new source');
  const head = commit();
  const input = { ...request(), sha: head };
  const remote = () => `${head}\trefs/heads/main\n${tagged}\trefs/tags/mcp-v2.1.4\n`;
  assert.equal(verifySource(dir, input, remote).tagCommit, tagged);
  assert.throws(() => verifySource(dir, input, () => `${SHA}\trefs/heads/main\n${tagged}\trefs/tags/mcp-v2.1.4\n`), /main/);
  assert.throws(() => verifySource(dir, input, () => `${head}\trefs/heads/main\n${SHA}\trefs/tags/mcp-v2.1.4\n`), /tag/);
  writeFileSync(join(dir, 'server.json'), JSON.stringify({ ...manifest, description: 'changed' }));
  const changed = commit();
  assert.throws(() => verifySource(dir, { ...input, sha: changed }, () => `${changed}\trefs/heads/main\n${tagged}\trefs/tags/mcp-v2.1.4\n`), /bytes/);
}));

test('source rejects a non-ancestor tag even if the release manifests have identical bytes', () => scratch((dir) => {
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-b', 'main'); mkdirSync(join(dir, 'mcp-server'));
  writeFileSync(join(dir, 'server.json'), JSON.stringify(manifest)); writeFileSync(join(dir, 'mcp-server/package.json'), packageText);
  git('add', '.'); git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'first');
  const head = git('rev-parse', 'HEAD');
  git('checkout', '--orphan', 'other'); git('add', '.'); git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'other');
  const tagged = git('rev-parse', 'HEAD'); git('tag', 'mcp-v2.1.4'); git('checkout', 'main');
  assert.throws(() => verifySource(dir, { ...request(), sha: head }, () => `${head}\trefs/heads/main\n${tagged}\trefs/tags/mcp-v2.1.4\n`), /ancestor/);
}));

test('npm bytes must satisfy exact identity, SHA-512 SRI and the tagged embedded package manifest', () => scratch((dir) => {
  mkdirSync(join(dir, 'package')); writeFileSync(join(dir, 'package/package.json'), packageText);
  const tarball = gzipSync(execFileSync('tar', ['-cf', '-', 'package/package.json'], { cwd: dir }));
  const metadata = { ...JSON.parse(packageText), dist: { integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}`, tarball: 'https://registry.npmjs.org/@emilia-protocol/mcp-server/-/mcp-server-2.1.4.tgz' } };
  assert.equal(verifyNpmArtifact(metadata, tarball, Buffer.from(packageText), '2.1.4').sha256, createHash('sha256').update(tarball).digest('hex'));
  for (const bad of [{ ...metadata, version: '2.1.3' }, { ...metadata, mcpName: 'other' }, { ...metadata, dist: { ...metadata.dist, tarball: 'https://attacker.invalid/x' } }, { ...metadata, dist: { ...metadata.dist, integrity: 'sha1-AAAA' } }]) {
    assert.throws(() => verifyNpmArtifact(bad, tarball, Buffer.from(packageText), '2.1.4'));
  }
  assert.throws(() => verifyNpmArtifact(metadata, Buffer.concat([tarball, Buffer.from('x')]), Buffer.from(packageText), '2.1.4'), /integrity/);
  assert.throws(() => verifyNpmArtifact(metadata, tarball, Buffer.from(`${packageText}\n`), '2.1.4'), /manifest/);
}));

function attestation(tarball, commit = SHA) {
  return [{ verificationResult: {
    signature: { certificate: {
      issuer: 'https://token.actions.githubusercontent.com',
      sourceRepositoryURI: 'https://github.com/emiliaprotocol/emilia-protocol',
      sourceRepositoryDigest: commit, sourceRepositoryRef: 'refs/heads/main',
      buildSignerURI: 'https://github.com/emiliaprotocol/emilia-protocol/.github/workflows/_publish-npm-package.yml@refs/heads/main',
      buildSignerDigest: commit, runnerEnvironment: 'github-hosted',
    } },
    statement: { predicateType: 'https://slsa.dev/provenance/v1', subject: [{ digest: { sha256: createHash('sha256').update(tarball).digest('hex') } }] },
  } }];
}

test('provenance verifies the complete artifact, immutable source/builder and GitHub-hosted signer before accepting it', () => scratch((dir) => {
  const tarball = Buffer.from('fixture artifact');
  const verifier = (command, args) => {
    assert.equal(command, 'gh');
    assert.deepEqual(args.slice(0, 2), ['attestation', 'verify']);
    assert.deepEqual(args.slice(3), ['--repo', 'emiliaprotocol/emilia-protocol', '--signer-workflow',
      'emiliaprotocol/emilia-protocol/.github/workflows/_publish-npm-package.yml', '--signer-digest', SHA,
      '--source-digest', SHA, '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners', '--limit', '5', '--format', 'json']);
    assert.deepEqual(readFileSync(args[2]), tarball);
    return JSON.stringify(attestation(tarball));
  };
  assert.equal(verifyNpmProvenance(tarball, SHA, dir, verifier).sha256, createHash('sha256').update(tarball).digest('hex'));
  for (const field of ['issuer', 'sourceRepositoryURI', 'sourceRepositoryDigest', 'sourceRepositoryRef', 'buildSignerURI', 'buildSignerDigest', 'runnerEnvironment']) {
    const bad = attestation(tarball); bad[0].verificationResult.signature.certificate[field] = 'wrong';
    assert.throws(() => verifyNpmProvenance(tarball, SHA, dir, () => JSON.stringify(bad)), /provenance/);
  }
  assert.throws(() => verifyNpmProvenance(tarball, SHA, dir, () => { throw new Error('invalid cryptographic signature'); }), /signature/);
  assert.throws(() => verifyNpmProvenance(tarball, '../bad', dir, verifier), /commit/);
}));

test('altered runtime with unchanged manifest and recomputed npm SRI is refused at the provenance boundary', () => scratch((dir) => {
  mkdirSync(join(dir, 'package')); writeFileSync(join(dir, 'package/package.json'), packageText);
  writeFileSync(join(dir, 'package/index.js'), 'export const approved = true;');
  const original = gzipSync(execFileSync('tar', ['-cf', '-', 'package'], { cwd: dir }));
  writeFileSync(join(dir, 'package/index.js'), 'export const approved = false;');
  const altered = gzipSync(execFileSync('tar', ['-cf', '-', 'package'], { cwd: dir }));
  const metadata = { ...JSON.parse(packageText), dist: { integrity: `sha512-${createHash('sha512').update(altered).digest('base64')}`, tarball: 'https://registry.npmjs.org/@emilia-protocol/mcp-server/-/mcp-server-2.1.4.tgz' } };
  assert.doesNotThrow(() => verifyNpmArtifact(metadata, altered, Buffer.from(packageText), '2.1.4'));
  assert.throws(() => verifyNpmProvenance(altered, SHA, dir, () => JSON.stringify(attestation(original))), /provenance/);
}));

test('existing Registry versions never silently overwrite, and network errors are not absence', () => {
  assert.doesNotThrow(() => assertRegistryAbsent(404));
  for (const status of [200, 401, 403, 500]) assert.throws(() => assertRegistryAbsent(status));
});

test('Registry completion requires full matching manifest, active status and latest marker', () => {
  const record = { server: structuredClone(manifest), _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', isLatest: true } } };
  delete record.server.packages[0].environmentVariables[0].isRequired;
  assert.doesNotThrow(() => verifyRegistryRecord(record, manifest));
  for (const mutate of [
    (r) => { r.server.version = '2.1.3'; },
    (r) => { r.server.packages[0].version = '2.1.3'; },
    (r) => { r.server.packages[0].environmentVariables[0].isSecret = false; },
    (r) => { r.server.packages[0].environmentVariables[0].isRequired = null; },
    (r) => { r.server.unexpected = 'not a schema default'; },
    (r) => { r._meta['io.modelcontextprotocol.registry/official'].status = 'deprecated'; },
    (r) => { r._meta['io.modelcontextprotocol.registry/official'].isLatest = false; },
  ]) { const bad = structuredClone(record); mutate(bad); assert.throws(() => verifyRegistryRecord(bad, manifest)); }
});

test('CLI token cache is confined to a fresh runner temp directory without overwriting any existing config', () => scratch((dir) => {
  const configRoot = join(dir, 'config');
  const location = setupAuthCache({ runnerTemp: dir, configRoot });
  assert.equal(readlinkSync(join(configRoot, 'mcp-publisher')), location);
  assert.equal(location, join(realpathSync(dir), 'emilia-mcp-registry-auth'));
  assert.ok(existsSync(location));
  assert.throws(() => setupAuthCache({ runnerTemp: dir, configRoot }), /existing/);
}));

test('workflow is manual, main-only, protected OIDC only, with pinned tools and no secret/token fallback', () => {
  const text = readFileSync(join(ROOT, '.github/workflows/publish-mcp-registry.yml'), 'utf8');
  const workflow = YAML.parse(text);
  assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch']);
  assert.deepEqual(workflow.permissions, { contents: 'read' });
  assert.deepEqual(Object.keys(workflow.jobs), ['preflight', 'publisher']);
  assert.deepEqual(workflow.jobs.preflight.permissions, { contents: 'read' });
  assert.equal(workflow.jobs.preflight.environment, undefined);
  assert.equal(workflow.jobs.publisher.environment, 'registry-publishing-approval');
  assert.deepEqual(workflow.jobs.publisher.permissions, { contents: 'read', 'id-token': 'write' });
  assert.equal(workflow.jobs.publisher.needs, 'preflight');
  for (const job of Object.values(workflow.jobs)) {
    assert.match(job.if, /github.ref == 'refs\/heads\/main'/);
    const checkout = job.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
    assert.match(checkout.uses, /@[a-f0-9]{40}$/);
    assert.equal(checkout.with.ref, '${{ github.sha }}');
    assert.equal(checkout.with['persist-credentials'], false);
    const verify = job.steps.find((step) => step.name === 'Recheck owner, immutable tag, source bytes and public npm artifact');
    assert.ok(verify, 'each job validates independently');
    assert.equal(verify.env.RELEASE_TAG, '${{ inputs.release_tag }}');
    assert.equal(verify.env.RELEASE_CONFIRMATION, '${{ inputs.confirmation }}');
    assert.equal(verify.run, 'node scripts/ci/mcp-registry-release.mjs preflight');
    for (const step of job.steps) if (step.run) assert.ok(!step.run.includes('${{ inputs.'), 'inputs never interpolate shell code');
  }
  assert.match(text, /login github-oidc/);
  assert.ok(!/secrets\.|gh auth token|MCP_GITHUB_TOKEN|npm (publish|install|ci|run)|HOME:/u.test(text));
  assert.ok(text.includes(PUBLISHER_URL)); assert.ok(text.includes(PUBLISHER_SHA256));
  assert.equal(MCP_NAME, 'io.github.emiliaprotocol/mcp-server'); assert.equal(NPM_NAME, '@emilia-protocol/mcp-server');
});
