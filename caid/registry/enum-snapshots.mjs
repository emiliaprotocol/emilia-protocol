// SPDX-License-Identifier: Apache-2.0
// Loads the external enum value-set snapshots pinned by action-types.json.
//
// The registry names every governed snapshot in `enum_snapshot_files`. This
// loader reads exactly those local files and requires, for each one:
//
// - values_ref, values_snapshot and values_sha256 to equal the registry entry;
// - values_sha256 to be the SHA-256 of the RFC 8785 canonical JSON of the
//   file's values array; and
// - snapshot_sha256 in the registry entry to be the SHA-256 of the RFC 8785
//   canonical JSON of the whole file, so the provenance members (source URL,
//   source digest, publication and retrieval dates, hash_input, @version)
//   cannot change without a registry change.
//
// It returns frozen snapshots for the `enumSnapshots` option of computeCaid,
// verifyCaid, mapAction and compareMappedActions. It never fetches anything
// and has no fallback: a missing, escaping or mismatched file throws.
// computeCaid still recomputes values_sha256 over the values array before
// accepting a value, so this loader is a convenience, not the trust boundary.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from '../impl/js/caid.mjs';

const REGISTRY_URL = new URL('./action-types.json', import.meta.url);
const SNAPSHOT_PATH = /^value-sets\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** @param {string} relativePath */
function readRegistrySnapshot(relativePath) {
  return JSON.parse(readFileSync(new URL(relativePath, REGISTRY_URL), 'utf8'));
}

/**
 * SHA-256 over the RFC 8785 canonical JSON of a value, as "sha256:<hex>".
 *
 * @param {unknown} value
 * @returns {string | null}
 */
export function jcsSha256(value) {
  const canonical = canonicalize(value);
  if (!canonical.ok) return null;
  return 'sha256:' + createHash('sha256')
    .update(/** @type {{ok: true, canonical: string}} */ (canonical).canonical, 'utf8')
    .digest('hex');
}

/**
 * The returned array and snapshots are frozen at runtime. The declared type is
 * a plain array so it can be passed to the CAID `enumSnapshots` options, which
 * are typed `any[]`.
 *
 * @param {any} [registry] parsed action-types.json; defaults to the checked-in registry
 * @param {{ readSnapshot?: (path: string) => any }} [options] test seam for the file reader
 * @returns {Array<Record<string, any>>}
 */
export function loadRegistryEnumSnapshots(
  registry = JSON.parse(readFileSync(REGISTRY_URL, 'utf8')),
  { readSnapshot = readRegistrySnapshot } = {},
) {
  const entries = registry?.enum_snapshot_files;
  if (!Array.isArray(entries)) {
    throw new Error('CAID registry declares no enum_snapshot_files array');
  }
  const snapshots = entries.map((entry, index) => {
    if (typeof entry?.path !== 'string' || !SNAPSHOT_PATH.test(entry.path)) {
      throw new Error(`CAID registry enum_snapshot_files[${index}].path is not a local value-set file`);
    }
    if (typeof entry.snapshot_sha256 !== 'string' || !DIGEST.test(entry.snapshot_sha256)) {
      throw new Error(`CAID registry enum_snapshot_files[${index}] does not pin snapshot_sha256`);
    }
    const snapshot = readSnapshot(entry.path);
    for (const key of ['values_ref', 'values_snapshot', 'values_sha256']) {
      if (typeof entry[key] !== 'string' || snapshot?.[key] !== entry[key]) {
        throw new Error(`CAID enum snapshot ${entry.path} ${key} does not match the registry pin`);
      }
    }
    if (!Array.isArray(snapshot.values)) {
      throw new Error(`CAID enum snapshot ${entry.path} carries no values array`);
    }
    if (jcsSha256(snapshot.values) !== entry.values_sha256) {
      throw new Error(`CAID enum snapshot ${entry.path} values do not match values_sha256`);
    }
    if (jcsSha256(snapshot) !== entry.snapshot_sha256) {
      throw new Error(`CAID enum snapshot ${entry.path} does not match the registry snapshot_sha256`);
    }
    return Object.freeze({ ...snapshot, values: Object.freeze([...snapshot.values]) });
  });
  return /** @type {Array<Record<string, any>>} */ (Object.freeze(snapshots));
}

/** Snapshots pinned by the checked-in registry, loaded once. */
export const REGISTRY_ENUM_SNAPSHOTS = loadRegistryEnumSnapshots();
