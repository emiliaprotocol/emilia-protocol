// SPDX-License-Identifier: Apache-2.0
//
// The CAID action-type registry and the external enum value-set snapshots it
// pins, for server code that derives CAIDs from registry definitions.
//
// The registry closes an external enum reference (for example currency against
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
// One import per enum_snapshot_files entry, in registry order. A registry
// version that adds a value set adds its import here in the same change;
// the load-time assertion below refuses a mismatch.
import iso4217Alpha3Snapshot from '@/caid/registry/value-sets/iso-4217-alpha-3.2026-09-17.json';
import ianaDnsRrTypesSnapshot from '@/caid/registry/value-sets/iana-dns-rr-types.2026-08-28.json';
import ianaJoseAlgorithmsSnapshot from '@/caid/registry/value-sets/iana-jose-algorithms.2026-05-22.json';
import ianaJoseEllipticCurvesSnapshot from '@/caid/registry/value-sets/iana-jose-elliptic-curves.2026-05-22.json';
import iso3166Alpha2Snapshot from '@/caid/registry/value-sets/iso-3166-1-alpha-2.2026-09-17.json';

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

export const CAID_REGISTRY_ENUM_SNAPSHOTS = Object.freeze([
  iso4217Alpha3Snapshot,
  ianaDnsRrTypesSnapshot,
  ianaJoseAlgorithmsSnapshot,
  ianaJoseEllipticCurvesSnapshot,
  iso3166Alpha2Snapshot,
]);

assertRegistryPinnedSnapshots(CAID_ACTION_TYPE_REGISTRY, CAID_REGISTRY_ENUM_SNAPSHOTS);

/**
 * The registry definition for an action type, whatever its status, or
 * undefined. Status never affects computation or verification: a deprecated
 * type still resolves, computes and verifies (draft-schrock-canonical-action-
 * identifier-04, Section 4). Verifiers and replay tooling use this resolver.
 */
export function registryDefinition(actionType: string) {
  return caidActionTypeRegistry.types.find((definition) => definition.action_type === actionType);
}

/**
 * The registry definition for an action type only while it is active, or
 * undefined. For issuers choosing which type to mint; never a gate on
 * verifying an existing CAID (use registryDefinition).
 */
export function activeCaidDefinition(actionType: string) {
  const definition = registryDefinition(actionType);
  return definition?.status === 'active' ? definition : undefined;
}
