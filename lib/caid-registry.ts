// SPDX-License-Identifier: Apache-2.0
//
// The CAID action-type registry and the external enum value-set snapshots it
// pins, for server code that derives CAIDs from registry definitions.
//
// Registry v4 closes an external enum reference (for example currency against
// ISO 4217 alpha-3) only when the caller supplies the exact pinned value-set
// snapshot. computeCaid refuses a present field whose snapshot is missing,
// digest-mismatched, or does not contain the value. Server code obtains the
// snapshots here, through static JSON imports the application bundler can
// trace, instead of hardcoding value-set paths at each call site.
//
// The module refuses to load when the imported snapshots differ from the
// registry's enum_snapshot_files pins: the same labels in the same order, a
// values array matching values_sha256, and a whole-file RFC 8785 digest
// matching snapshot_sha256. tests/caid-registry-snapshots.test.ts also proves
// this list equals the Node loader's, so a registry pin change cannot leave
// the server silently refusing every currency-bearing action or accepting a
// value set the registry does not pin.

import crypto from 'node:crypto';

import { canonicalize } from '@/caid/impl/js/caid.mjs';
import caidActionTypeRegistry from '@/caid/registry/action-types.json';
import iso4217Alpha3Snapshot from '@/caid/registry/value-sets/iso-4217-alpha-3.2026-09-17.json';

function jcsSha256(value: unknown): string | null {
  const canonical = canonicalize(value);
  if (!canonical.ok) return null;
  return `sha256:${crypto.createHash('sha256').update(canonical.canonical, 'utf8').digest('hex')}`;
}

/**
 * Throws unless `snapshots` are exactly the value sets `registry` pins, in
 * registry order. Exported for tests; the module applies it at load.
 */
export function assertRegistryPinnedSnapshots(registry: any, snapshots: readonly any[]): void {
  const entries = registry?.enum_snapshot_files;
  if (!Array.isArray(entries) || entries.length !== snapshots.length) {
    throw new Error('CAID registry snapshots differ from enum_snapshot_files');
  }
  entries.forEach((entry: any, index: number) => {
    const snapshot = snapshots[index];
    for (const key of ['values_ref', 'values_snapshot', 'values_sha256']) {
      if (typeof entry?.[key] !== 'string' || snapshot?.[key] !== entry[key]) {
        throw new Error(`CAID enum snapshot ${index} ${key} does not match the registry pin`);
      }
    }
    if (jcsSha256(snapshot.values) !== entry.values_sha256) {
      throw new Error(`CAID enum snapshot ${index} values do not match values_sha256`);
    }
    if (typeof entry.snapshot_sha256 !== 'string' || jcsSha256(snapshot) !== entry.snapshot_sha256) {
      throw new Error(`CAID enum snapshot ${index} does not match the registry snapshot_sha256`);
    }
  });
}

export const CAID_ACTION_TYPE_REGISTRY = caidActionTypeRegistry;

export const CAID_REGISTRY_ENUM_SNAPSHOTS = Object.freeze([iso4217Alpha3Snapshot]);

assertRegistryPinnedSnapshots(CAID_ACTION_TYPE_REGISTRY, CAID_REGISTRY_ENUM_SNAPSHOTS);

/** The single active registry definition for an action type, or undefined. */
export function activeCaidDefinition(actionType: string) {
  return caidActionTypeRegistry.types.find(
    (definition) => definition.action_type === actionType && definition.status === 'active',
  );
}
