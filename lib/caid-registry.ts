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
// tests/caid-registry-snapshots.test.ts proves this list covers exactly the
// registry's enum_snapshot_files, so a registry pin change cannot leave the
// server silently refusing every currency-bearing action.

import caidActionTypeRegistry from '@/caid/registry/action-types.json';
import iso4217Alpha3Snapshot from '@/caid/registry/value-sets/iso-4217-alpha-3.2026-09-17.json';

export const CAID_ACTION_TYPE_REGISTRY = caidActionTypeRegistry;

export const CAID_REGISTRY_ENUM_SNAPSHOTS = Object.freeze([iso4217Alpha3Snapshot]);

/** The single active registry definition for an action type, or undefined. */
export function activeCaidDefinition(actionType: string) {
  return caidActionTypeRegistry.types.find(
    (definition) => definition.action_type === actionType && definition.status === 'active',
  );
}
