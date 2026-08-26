#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministically regenerate EMILIA's corrected CCS 1.1.19 L1 fixture.
 *
 * The upstream 1.1.19 sdist carries a stale vector signed with rule_version
 * 1.1.14. This generator preserves the upstream field recipe and public seed,
 * changes only the release-bound rule_version to 1.1.19, and pins the exact
 * PyPI and GitHub coordinates used for the derivation.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const CCS_119_SOURCE = Object.freeze({
  repository: 'https://github.com/DSHCorrectover/ccs-verifier',
  tag: 'v1.1.19',
  tag_object_sha: 'bdd79fa8257b764cffa5bceb458330ce01bc41ce',
  commit_sha: '4c5e6c7a9670be0a417414f8b8f41ff4d5df0aa6',
  pypi_sdist_sha256: 'b540635098ccea4b9e5ccdfc016ad144a4efe4a7d21a0f351fca5b48c00b08c7',
  pypi_wheel_sha256: '762b99b3968be8c138da037ef6db15473cf6911616088d42d7b9997f16a2c3e4',
});
export const UPSTREAM_STALE_VECTOR_SHA256 =
  '5260e619c010d36729c57c5e8814613215e65e09abfba8a6a1d93f07e919762f';
export const REFERENCE_SEED_LABEL = 'ccs-verifier/reference-issuer/v1';
export const REFERENCE_SEED_HEX =
  '61f8411a9852fc0175451deb6731d5bb9b5b002e20bfcca4c2f883129cb10fa8';
export const REFERENCE_PUBLIC_KEY_RAW_BASE64 =
  'v63J4PdpUTeDVUuGMgpayNc5ex/ufTmrW+9oKyybbCw=';
export const REFERENCE_PUBLIC_KEY_SHA256 =
  '889d3f5bd86f5ff201022db9b6dbef582ba2cd84d687f63b05141bd004b1d183';

function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new TypeError('fixture contains a number outside the RFC 8785 JSON domain');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value !== 'object') throw new TypeError('fixture contains a non-JSON value');
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonical(value[key])}`
  )).join(',')}}`;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashJson(value) {
  return sha256(Buffer.from(canonical(value), 'utf8'));
}

function referenceKeyPair() {
  const seed = crypto.createHash('sha256').update(REFERENCE_SEED_LABEL, 'utf8').digest();
  assert.equal(seed.toString('hex'), REFERENCE_SEED_HEX);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  const publicRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  assert.equal(publicRaw.toString('base64'), REFERENCE_PUBLIC_KEY_RAW_BASE64);
  assert.equal(sha256(publicRaw), REFERENCE_PUBLIC_KEY_SHA256);
  return { privateKey, publicKey, publicRaw };
}

export function generateEmiliaDerivedFixture() {
  const { privateKey, publicRaw } = referenceKeyPair();
  const publicKeyBase64 = publicRaw.toString('base64');
  const fingerprint = sha256(publicRaw).slice(0, 16);
  const fixedTime = 1_893_456_000;
  const receipt = {
    trace_id: 'ref-vector-001',
    receipt_version: '1.1',
    verdict: 'allow',
    timestamp: fixedTime,
    tool: 'shell',
    tool_call_id: '',
    params_hash: 'refvec001',
    args_digest: hashJson({ command: 'echo reference' }),
    rule_summary: 'reference_vector',
    rule_version: '1.1.19',
    request_hash: hashJson({ ref: 1 }),
    response_hash: hashJson({ ok: true }),
    runtime_context_hash: hashJson({ dist: 'reference' }),
    config_hash: hashJson({ mode: 'reference' }),
    verifier_source_class: 'VerifierServer',
    deployment_mode: 'in-process',
    issuer: 'ccs-verifier/reference',
    audience: 'public',
    nonce: 'reference-nonce-001',
    sequence: 0,
    issued_at: fixedTime,
    expires_at: fixedTime + 300,
    max_clock_skew: 0,
    action: 'shell.execute',
    signature: '',
    signing_algorithm: 'Ed25519',
    public_key_fingerprint: fingerprint,
    public_key: publicKeyBase64,
    verified_at: fixedTime,
    latency_us: 0,
  };
  const { signature: _signature, ...signingPayload } = receipt;
  receipt.signature = crypto.sign(
    null,
    Buffer.from(canonical(signingPayload), 'utf8'),
    privateKey,
  ).toString('base64');
  return {
    description: 'EMILIA-derived CCS 1.1.19 L1 reference receipt. Regenerated from the exact 1.1.19 source lock and the upstream public deterministic reference seed because the 1.1.19 sdist ships a stale 1.1.14 vector. This is NOT an upstream vector or production trust anchor.',
    provenance: 'EMILIA-derived',
    issuer: 'ccs-verifier/reference',
    package_version: '1.1.19',
    public_key_fingerprint_sha256_16: fingerprint,
    public_key_raw_b64: publicKeyBase64,
    public_key_sha256_full: sha256(publicRaw),
    receipt,
    source: {
      ...CCS_119_SOURCE,
      upstream_stale_vector_sha256: UPSTREAM_STALE_VECTOR_SHA256,
      generator: 'interop/ccs-aeb/generate_l1_119_emilia_derived_fixture.mjs',
    },
    spec_version: '1.1',
    vector_id: 'emilia-derived-reference-signed-001',
  };
}

export function renderEmiliaDerivedFixture() {
  return `${JSON.stringify(generateEmiliaDerivedFixture(), null, 2)}\n`;
}

export function verifyGeneratedReceipt(receipt) {
  const publicRaw = Buffer.from(receipt.public_key, 'base64');
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      publicRaw,
    ]),
    format: 'der',
    type: 'spki',
  });
  const { signature, ...signingPayload } = receipt;
  return crypto.verify(
    null,
    Buffer.from(canonical(signingPayload), 'utf8'),
    publicKey,
    Buffer.from(signature, 'base64'),
  );
}

export function verifyPinnedWheel(path) {
  const digest = sha256(readFileSync(path));
  assert.equal(digest, CCS_119_SOURCE.pypi_wheel_sha256, 'ccs-verifier 1.1.19 wheel hash mismatch');
  return digest;
}

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return null;
  if (!process.argv[index + 1]) throw new Error(`${name} requires a path`);
  return process.argv[index + 1];
}

function main() {
  const wheel = argumentValue('--wheel');
  const check = argumentValue('--check');
  const write = argumentValue('--write');
  if (wheel) verifyPinnedWheel(wheel);
  const rendered = renderEmiliaDerivedFixture();
  if (check) {
    assert.equal(readFileSync(check, 'utf8'), rendered, 'EMILIA-derived CCS fixture is stale');
  } else if (write) {
    writeFileSync(write, rendered, 'utf8');
  } else {
    process.stdout.write(rendered);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
