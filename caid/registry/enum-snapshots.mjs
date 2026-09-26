// SPDX-License-Identifier: Apache-2.0
// Loads the external enum value-set snapshots pinned by action-types.json.
//
// The registry names every governed snapshot in `enum_snapshot_files`. This
// loader reads exactly those local files, requires each file's values_ref,
// values_snapshot and values_sha256 to equal the registry entry, and returns
// frozen snapshots for the `enumSnapshots` option of computeCaid, verifyCaid,
// mapAction and compareMappedActions. It never fetches anything and has no
// fallback: a missing, escaping or mismatched file throws. computeCaid still
// recomputes values_sha256 over the values array before accepting a value, so
// this loader is a convenience, not the trust boundary.

import { readFileSync } from 'node:fs';

const REGISTRY_URL = new URL('./action-types.json', import.meta.url);
const SNAPSHOT_PATH = /^value-sets\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;

/**
 * The returned array and snapshots are frozen at runtime. The declared type is
 * a plain array so it can be passed to the CAID `enumSnapshots` options, which
 * are typed `any[]`.
 *
 * @param {any} [registry] parsed action-types.json; defaults to the checked-in registry
 * @returns {Array<Record<string, any>>}
 */
export function loadRegistryEnumSnapshots(
  registry = JSON.parse(readFileSync(REGISTRY_URL, 'utf8')),
) {
  const entries = registry?.enum_snapshot_files;
  if (!Array.isArray(entries)) {
    throw new Error('CAID registry declares no enum_snapshot_files array');
  }
  const snapshots = entries.map((entry, index) => {
    if (typeof entry?.path !== 'string' || !SNAPSHOT_PATH.test(entry.path)) {
      throw new Error(`CAID registry enum_snapshot_files[${index}].path is not a local value-set file`);
    }
    const snapshot = JSON.parse(readFileSync(new URL(entry.path, REGISTRY_URL), 'utf8'));
    for (const key of ['values_ref', 'values_snapshot', 'values_sha256']) {
      if (typeof entry[key] !== 'string' || snapshot?.[key] !== entry[key]) {
        throw new Error(`CAID enum snapshot ${entry.path} ${key} does not match the registry pin`);
      }
    }
    if (!Array.isArray(snapshot.values)) {
      throw new Error(`CAID enum snapshot ${entry.path} carries no values array`);
    }
    return Object.freeze({ ...snapshot, values: Object.freeze([...snapshot.values]) });
  });
  return /** @type {Array<Record<string, any>>} */ (Object.freeze(snapshots));
}

/** Snapshots pinned by the checked-in registry, loaded once. */
export const REGISTRY_ENUM_SNAPSHOTS = loadRegistryEnumSnapshots();
