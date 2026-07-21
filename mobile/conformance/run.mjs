#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { canonicalize, isCanonicalizable } from '../../packages/verify/index.js';
import { buildMobileActionIdentity } from '../../packages/mobile/action-identity.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, 'mobile/conformance/mobile-core.v1.json'), 'utf8'));
if (vectors['@version'] !== 'EP-MOBILE-CONFORMANCE-v1') throw new Error('unsupported mobile vector version');
if (!Array.isArray(vectors.presentation_mapping) || vectors.presentation_mapping.length === 0) {
  throw new Error('mobile presentation mapping vectors are required');
}
if (!Array.isArray(vectors.action_identity) || vectors.action_identity.length === 0) {
  throw new Error('mobile CAID Action Lock vectors are required');
}

const supportedPorts = new Set(['javascript', 'swift', 'kotlin']);
const selectedPorts = (process.env.MOBILE_CONFORMANCE_PORTS || 'javascript,swift,kotlin')
  .split(',')
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);
if (selectedPorts.length === 0 || new Set(selectedPorts).size !== selectedPorts.length
    || selectedPorts.some((port) => !supportedPorts.has(port))) {
  throw new Error('MOBILE_CONFORMANCE_PORTS must be a unique comma-separated subset of javascript,swift,kotlin');
}
const selected = new Set(selectedPorts);

const env = { ...process.env, ANDROID_HOME: process.env.ANDROID_HOME || path.join(/** @type {string} */ (process.env.HOME), 'Library/Android/sdk') };
if (selected.has('javascript')) {
  for (const vector of vectors.canonicalization) {
    if (!isCanonicalizable(vector.value)) throw new Error(`${vector.id}: value is outside EP canonicalization`);
    const encoded = canonicalize(vector.value);
    const digest = crypto.createHash('sha256').update(encoded, 'utf8').digest('hex');
    if (encoded !== vector.canonical || digest !== vector.sha256) throw new Error(`${vector.id}: JavaScript byte mismatch`);
  }
  for (const vector of vectors.action_identity) {
    const identity = buildMobileActionIdentity({
      actionReference: vector.action_reference,
      action: vector.action,
    });
    if (JSON.stringify(identity) !== JSON.stringify(vector.expect)) {
      throw new Error(`${vector.id}: JavaScript CAID Action Lock mismatch`);
    }
  }
  execFileSync(process.execPath, [
    '--test',
    'packages/mobile/attestation.test.js',
    'packages/mobile/enrollment.test.js',
    'packages/mobile/government.test.js',
    'packages/mobile/http.test.js',
    'packages/mobile/index.test.js',
    'packages/mobile/presentation.test.js',
    'packages/mobile/strict-json.test.js',
  ], { cwd: ROOT, env, stdio: 'inherit' });
}
if (selected.has('swift')) {
  execFileSync('swift', ['test'], { cwd: path.join(ROOT, 'sdks/swift-mobile'), env, stdio: 'inherit' });
}
if (selected.has('kotlin')) {
  execFileSync(path.join(ROOT, 'sdks/kotlin-mobile/gradlew'), ['testDebugUnitTest'], {
    cwd: path.join(ROOT, 'sdks/kotlin-mobile'), env, stdio: 'inherit',
  });
}

console.log(`EP MOBILE CONFORMANCE: PASS (${vectors.canonicalization.length} byte vectors; ${vectors.action_identity.length} Action Lock vectors; ${vectors.presentation_mapping.length} presentation vectors; ${vectors.hostile_contract.length} hostile contracts; ${selectedPorts.join(' + ')})`);
