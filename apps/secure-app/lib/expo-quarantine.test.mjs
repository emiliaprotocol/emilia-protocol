// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { verifyExpoQuarantine } from '../scripts/check-expo-quarantine.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, name), 'utf8'));

const inputs = () => ({
  packageJson: read('package.json'),
  lockfile: read('package-lock.json'),
  exceptions: read('expo-quarantine-exceptions.json'),
});

test('the committed Expo graph accepts only the current seven-day quarantine entries', () => {
  assert.deepEqual(
    verifyExpoQuarantine({ ...inputs(), now: new Date('2026-08-29T16:00:00Z') }),
    ['expo', 'expo-asset', 'expo-secure-store'],
  );
});

test('the Expo quarantine fails as soon as a held patch becomes eligible', () => {
  const candidate = inputs();
  candidate.packageJson.expo.install.exclude = ['expo'];
  candidate.packageJson.dependencies.expo = '~57.0.13';
  candidate.lockfile.packages[''].dependencies.expo = '~57.0.13';
  candidate.lockfile.packages['node_modules/expo'].version = '57.0.13';
  candidate.exceptions.entries = [{
    package: 'expo',
    accepted_spec: '~57.0.13',
    accepted_version: '57.0.13',
    doctor_required_version: '57.0.15',
    required_version_published_at: '2026-08-20T10:50:11.540Z',
    eligible_at: '2026-08-27T10:50:11.540Z',
  }];
  assert.throws(
    () => verifyExpoQuarantine({ ...candidate, now: new Date('2026-08-27T10:50:12Z') }),
    /quarantine expired/u,
  );
});

test('an unreviewed Expo Doctor exclusion cannot hide behind the quarantine', () => {
  const candidate = inputs();
  candidate.packageJson.expo.install.exclude.push('expo-local-authentication');
  assert.throws(
    () => verifyExpoQuarantine({ ...candidate, now: new Date('2026-08-29T16:00:00Z') }),
    /exclusions and quarantine exceptions differ/u,
  );
});
