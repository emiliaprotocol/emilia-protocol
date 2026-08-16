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

test('the time-bounded Expo quarantine accepts only the pinned eligible fallback versions', () => {
  assert.deepEqual(
    verifyExpoQuarantine({ ...inputs(), now: new Date('2026-08-15T16:00:00Z') }),
    ['expo', 'expo-asset', 'expo-screen-capture'],
  );
});

test('the Expo quarantine fails as soon as a held patch becomes eligible', () => {
  assert.throws(
    () => verifyExpoQuarantine({ ...inputs(), now: new Date('2026-08-21T14:26:28Z') }),
    /quarantine expired/u,
  );
});

test('an unreviewed Expo Doctor exclusion cannot hide behind the quarantine', () => {
  const candidate = inputs();
  candidate.packageJson.expo.install.exclude.push('expo-secure-store');
  assert.throws(
    () => verifyExpoQuarantine({ ...candidate, now: new Date('2026-08-15T16:00:00Z') }),
    /exclusions and quarantine exceptions differ/u,
  );
});
