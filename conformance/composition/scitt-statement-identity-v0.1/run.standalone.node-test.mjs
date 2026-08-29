// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { builtinModules } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = resolve(HERE, 'run.standalone.mjs');
const SOURCE_ENTRY = resolve(HERE, 'run.mjs');
const SUPPORT_FILES = [
  'vectors.reference.json',
  'report.reference.json',
  'source-lock.json',
  'THIRD_PARTY_NOTICES.txt',
  'standalone.manifest.json',
];

function run(entry, cwd) {
  return spawnSync(process.execPath, [entry, '--check'], {
    cwd,
    encoding: 'utf8',
  });
}

test('raw handoff vector pins both exact envelopes and their shared signing input', () => {
  const vector = JSON.parse(readFileSync(resolve(HERE, 'vectors.reference.json'), 'utf8'));
  assert.equal(vector['@version'], 'EP-SCITT-STATEMENT-IDENTITY-VECTORS-v1');
  assert.equal(vector.fixture.public_jwk.kty, 'EC');
  assert.equal(vector.fixture.public_jwk.crv, 'P-256');
  assert.equal(Buffer.from(vector.fixture.cose_sign1_a_base64url, 'base64url')[0], 0xd2);
  assert.equal(Buffer.from(vector.fixture.cose_sign1_b_base64url, 'base64url')[0], 0xd2);
  assert.notEqual(vector.fixture.cose_sign1_a_base64url, vector.fixture.cose_sign1_b_base64url);
  assert.ok(Buffer.from(vector.fixture.sig_structure_base64url, 'base64url').length > 0);
  assert.match(vector.expected.statement_entry_digest_a, /^sha256:[0-9a-f]{64}$/);
  assert.match(vector.expected.statement_entry_digest_b, /^sha256:[0-9a-f]{64}$/);
  assert.match(vector.expected.signing_input_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(vector.expected.classification, 'same_signing_input_different_envelope');
});

test('standalone runner imports only Node built-ins', () => {
  assert.equal(existsSync(ENTRY), true, 'standalone entrypoint is missing');
  const source = readFileSync(ENTRY, 'utf8');
  const imports = source.split('\n')
    .map((line) => line.match(/^import .* from ["']([^"']+)["'];?$/)?.[1])
    .filter(Boolean);
  const builtins = new Set([
    ...builtinModules,
    ...builtinModules.map((name) => `node:${name}`),
  ]);
  assert.ok(imports.length > 0, 'expected explicit Node imports');
  assert.deepEqual(
    imports.filter((specifier) => !builtins.has(specifier)),
    [],
    `unexpected non-Node imports: ${imports.join(', ')}`,
  );
});

test('source and standalone runners produce the exact same pinned report', () => {
  const source = run(SOURCE_ENTRY, HERE);
  assert.equal(source.status, 0, `${source.stderr}\n${source.stdout}`);
  const standalone = run(ENTRY, HERE);
  assert.equal(standalone.status, 0, `${standalone.stderr}\n${standalone.stdout}`);
  assert.deepEqual(JSON.parse(standalone.stdout), JSON.parse(source.stdout));
});

test('standalone handoff passes all twelve cases outside the repository', () => {
  const isolated = mkdtempSync(resolve(tmpdir(), 'scitt-identity-standalone-'));
  try {
    copyFileSync(ENTRY, resolve(isolated, basename(ENTRY)));
    for (const filename of SUPPORT_FILES) {
      copyFileSync(resolve(HERE, filename), resolve(isolated, filename));
    }

    assert.equal(existsSync(resolve(isolated, 'node_modules')), false);
    const result = run(resolve(isolated, basename(ENTRY)), isolated);
    assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);

    const report = JSON.parse(result.stdout);
    assert.equal(report.passed, true);
    assert.equal(report.cases.length, 12);
    assert.equal(report.cases.every((entry) => entry.passed), true);
    assert.equal(
      report.cases.find((entry) => entry.id === 'FALSE-TAMPERING-REASON-REFUSED')
        ?.observed.classification,
      'same_signing_input_different_envelope',
    );
  } finally {
    rmSync(isolated, { recursive: true, force: true });
  }
});
