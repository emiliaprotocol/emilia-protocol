// SPDX-License-Identifier: Apache-2.0
//
// The server (lib/caid-registry.ts) and Node tooling
// (caid/registry/enum-snapshots.mjs) must supply exactly the external enum
// snapshots the CAID registry pins. A registry pin change that either loader
// misses would make every currency-bearing CAID refuse in production.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { computeCaid } from '../caid/impl/js/caid.mjs';
import {
  loadRegistryEnumSnapshots,
  REGISTRY_ENUM_SNAPSHOTS,
} from '../caid/registry/enum-snapshots.mjs';
import {
  activeCaidDefinition,
  CAID_ACTION_TYPE_REGISTRY,
  CAID_REGISTRY_ENUM_SNAPSHOTS,
} from '../lib/caid-registry';
import { buildPaymentReleaseActionIdentity } from '../lib/approval-acquisition/contract';

const registry = JSON.parse(
  readFileSync(new URL('../caid/registry/action-types.json', import.meta.url), 'utf8'),
);
const pin = (snapshot: any) => ({
  values_ref: snapshot.values_ref,
  values_snapshot: snapshot.values_snapshot,
  values_sha256: snapshot.values_sha256,
});

describe('CAID registry enum snapshots', () => {
  it('server and Node loaders supply exactly the registry-pinned snapshots', () => {
    const pinned = registry.enum_snapshot_files.map(pin);
    expect(pinned.length).toBeGreaterThan(0);
    expect(CAID_REGISTRY_ENUM_SNAPSHOTS.map(pin)).toEqual(pinned);
    expect(REGISTRY_ENUM_SNAPSHOTS.map(pin)).toEqual(pinned);
    expect(REGISTRY_ENUM_SNAPSHOTS.map((s: any) => s.values))
      .toEqual(CAID_REGISTRY_ENUM_SNAPSHOTS.map((s: any) => s.values));
    expect(CAID_ACTION_TYPE_REGISTRY.meta.registry_version).toBe(registry.meta.registry_version);
  });

  it('every registry field pinned to an external value set resolves to a supplied snapshot', () => {
    const supplied = new Set(CAID_REGISTRY_ENUM_SNAPSHOTS.map((s: any) => JSON.stringify(pin(s))));
    for (const type of registry.types) {
      for (const field of [...(type.required_fields ?? []), ...(type.optional_fields ?? [])]) {
        if (field.type !== 'enum' || typeof field.values_sha256 !== 'string') continue;
        expect(supplied.has(JSON.stringify(pin(field))), `${type.action_type}.${field.name}`).toBe(true);
      }
    }
  });

  it('the loader refuses a registry entry whose file does not match its pin or escapes value-sets', () => {
    const entry = registry.enum_snapshot_files[0];
    expect(() => loadRegistryEnumSnapshots({
      enum_snapshot_files: [{ ...entry, values_sha256: `sha256:${'0'.repeat(64)}` }],
    })).toThrow(/values_sha256 does not match the registry pin/);
    expect(() => loadRegistryEnumSnapshots({
      enum_snapshot_files: [{ ...entry, path: '../action-types.json' }],
    })).toThrow(/not a local value-set file/);
    expect(() => loadRegistryEnumSnapshots({})).toThrow(/no enum_snapshot_files/);
  });

  it('payment.release.1 accepts a listed currency and refuses unlisted or unpinned ones with a reason', () => {
    const definition = activeCaidDefinition('payment.release.1');
    const action = {
      action_type: 'payment.release.1',
      amount: '184.00',
      currency: 'USD',
      beneficiary_account: `sha256:${'a'.repeat(64)}`,
      payment_instruction_id: 'pi-registry-snapshot-1',
    };
    const accepted = computeCaid(action, {
      suite: 'jcs-sha256', definitions: [definition], enumSnapshots: CAID_REGISTRY_ENUM_SNAPSHOTS,
    });
    expect(accepted.caid).toMatch(/^caid:1:payment\.release\.1:jcs-sha256:/);

    const unpinned = computeCaid(action, { suite: 'jcs-sha256', definitions: [definition] });
    expect(unpinned).toEqual({ refusals: ['mistyped_field:currency'] });

    const unlisted = computeCaid({ ...action, currency: 'ZZZ' }, {
      suite: 'jcs-sha256', definitions: [definition], enumSnapshots: CAID_REGISTRY_ENUM_SNAPSHOTS,
    });
    expect(unlisted).toEqual({ refusals: ['mistyped_field:currency'] });
  });

  it('the approval contract derives the payment CAID only for a pinned-set currency', () => {
    const material = {
      amount_usd: 184,
      currency: 'USD',
      beneficiary_account_hash: `sha256:${'b'.repeat(64)}`,
      payment_instruction_id: 'pi-registry-snapshot-2',
    };
    expect(buildPaymentReleaseActionIdentity(material)).toMatchObject({ ok: true });
    expect(buildPaymentReleaseActionIdentity({ ...material, currency: 'ZZZ' })).toEqual({
      ok: false,
      detail: 'payment material cannot form a CAID (mistyped_field:currency)',
    });
  });
});
