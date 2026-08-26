#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Offline provenance and deterministic-reproduction check for CCS 1.1.19. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CCS_119_SOURCE,
  UPSTREAM_STALE_VECTOR_SHA256,
  generateEmiliaDerivedFixture,
  renderEmiliaDerivedFixture,
  verifyGeneratedReceipt,
  verifyPinnedWheel,
} from './generate_l1_119_emilia_derived_fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const STALE_PATH = resolve(
  HERE,
  'fixtures/ccs-verifier-pypi-1.1.19-upstream-stale-1.1.14-reference-signed-001.json',
);
const DERIVED_PATH = resolve(
  HERE,
  'fixtures/ccs-verifier-pypi-1.1.19-emilia-derived-reference-signed-001.json',
);

function fileSha256(path) {
  return crypto.createHash('sha256').update(readFileSync(path)).digest('hex');
}

const stale = JSON.parse(readFileSync(STALE_PATH, 'utf8'));
assert.equal(fileSha256(STALE_PATH), UPSTREAM_STALE_VECTOR_SHA256);
assert.equal(stale.package_version, '1.1.14');
assert.equal(stale.receipt.rule_version, '1.1.14');

const rendered = renderEmiliaDerivedFixture();
assert.equal(readFileSync(DERIVED_PATH, 'utf8'), rendered);
const derived = generateEmiliaDerivedFixture();
assert.equal(derived.provenance, 'EMILIA-derived');
assert.equal(derived.package_version, '1.1.19');
assert.equal(derived.receipt.rule_version, '1.1.19');
assert.deepEqual(
  {
    repository: derived.source.repository,
    tag: derived.source.tag,
    tag_object_sha: derived.source.tag_object_sha,
    commit_sha: derived.source.commit_sha,
    pypi_sdist_sha256: derived.source.pypi_sdist_sha256,
    pypi_wheel_sha256: derived.source.pypi_wheel_sha256,
  },
  CCS_119_SOURCE,
);
assert.equal(derived.source.upstream_stale_vector_sha256, UPSTREAM_STALE_VECTOR_SHA256);
assert.equal(verifyGeneratedReceipt(derived.receipt), true);

if (process.env.CCS_VERIFIER_1_1_19_WHEEL) {
  verifyPinnedWheel(process.env.CCS_VERIFIER_1_1_19_WHEEL);
}

console.log(
  'CCS 1.1.19 FIXTURE REPRODUCTION: PASS '
  + '(exact upstream-stale bytes preserved; EMILIA-derived receipt regenerated and verified)',
);
