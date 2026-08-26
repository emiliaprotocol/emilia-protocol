#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Offline provenance check for the exact CCS 1.1.20 upstream reference vector. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = resolve(
  HERE,
  'fixtures/ccs-verifier-pypi-1.1.20-upstream-reference-signed-001.json',
);
const VECTOR_SHA256 = 'f4ba98ba9eb8f2a74a7b9065ed7919541ae7a58e2b4811dd0f1967408c4cd975';
const WHEEL_SHA256 = 'fd718d885a04383a0a520f9bf06de258d6ff9b4f049cddc358b58c3b2a33db9d';
const SDIST_SHA256 = '551c60eb416dac34567009b3b75fd1f501d4874bebeed68de21ceab1a7e0463f';

function fileSha256(path) {
  return crypto.createHash('sha256').update(readFileSync(path)).digest('hex');
}

const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
assert.equal(fileSha256(VECTOR_PATH), VECTOR_SHA256);
assert.equal(vector.package_version, '1.1.20');
assert.equal(vector.spec_version, '1.1');
assert.equal(vector.issuer, 'ccs-verifier/reference');
assert.equal(vector.receipt.receipt_version, '1.1');
assert.equal(vector.receipt.rule_version, '1.1.20');
assert.equal(vector.receipt.issuer, vector.issuer);
assert.equal(vector.receipt.public_key, vector.public_key_raw_b64);
assert.equal(
  vector.receipt.public_key_fingerprint,
  vector.public_key_fingerprint_sha256_16,
);

if (process.env.CCS_VERIFIER_1_1_20_WHEEL) {
  assert.equal(fileSha256(process.env.CCS_VERIFIER_1_1_20_WHEEL), WHEEL_SHA256);
}
if (process.env.CCS_VERIFIER_1_1_20_SDIST) {
  assert.equal(fileSha256(process.env.CCS_VERIFIER_1_1_20_SDIST), SDIST_SHA256);
}

console.log(
  'CCS 1.1.20 FIXTURE REPRODUCTION: PASS '
  + '(exact upstream reference vector and release-bound fields pinned)',
);
