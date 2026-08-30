// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DAY_MS = 24 * 60 * 60 * 1000;

export function verifyExpoQuarantine({ packageJson, lockfile, exceptions, now = new Date() }) {
  if (exceptions?.schema_version !== 'ep_expo_quarantine_exceptions_v1' || !Array.isArray(exceptions.entries)) {
    throw new Error('invalid Expo quarantine exception document');
  }

  const excluded = packageJson?.expo?.install?.exclude;
  if (!Array.isArray(excluded)) throw new Error('package.json has no Expo install exclusion list');

  const expectedExclusions = exceptions.entries.map((entry) => entry.package).sort();
  const actualExclusions = [...excluded].sort();
  if (JSON.stringify(actualExclusions) !== JSON.stringify(expectedExclusions)) {
    throw new Error('Expo install exclusions and quarantine exceptions differ');
  }

  for (const entry of exceptions.entries) {
    const publishedAt = new Date(entry.required_version_published_at);
    const eligibleAt = new Date(entry.eligible_at);
    if (!Number.isFinite(publishedAt.getTime()) || !Number.isFinite(eligibleAt.getTime())) {
      throw new Error(`${entry.package}: invalid quarantine timestamps`);
    }
    if (eligibleAt.getTime() - publishedAt.getTime() !== 7 * DAY_MS) {
      throw new Error(`${entry.package}: eligibility must be exactly seven days after publication`);
    }
    if (now.getTime() >= eligibleAt.getTime()) {
      throw new Error(`${entry.package}: quarantine expired; install ${entry.doctor_required_version}`);
    }

    if (packageJson.dependencies?.[entry.package] !== entry.accepted_spec) {
      throw new Error(`${entry.package}: package.json no longer pins the accepted spec`);
    }
    if (lockfile.packages?.['']?.dependencies?.[entry.package] !== entry.accepted_spec) {
      throw new Error(`${entry.package}: lockfile root spec differs from the exception`);
    }
    if (lockfile.packages?.[`node_modules/${entry.package}`]?.version !== entry.accepted_version) {
      throw new Error(`${entry.package}: resolved version differs from the exception`);
    }
  }

  return expectedExclusions;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const read = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, name), 'utf8'));
  const now = process.env.EMILIA_EXPO_QUARANTINE_NOW
    ? new Date(process.env.EMILIA_EXPO_QUARANTINE_NOW)
    : new Date();
  const packages = verifyExpoQuarantine({
    packageJson: read('package.json'),
    lockfile: read('package-lock.json'),
    exceptions: read('expo-quarantine-exceptions.json'),
    now,
  });
  console.log(packages.length > 0
    ? `Expo quarantine active for ${packages.join(', ')}`
    : 'No Expo quarantine exceptions active.');
}
