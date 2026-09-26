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
  jcsSha256,
  loadRegistryEnumSnapshots,
  REGISTRY_ENUM_SNAPSHOTS,
} from '../caid/registry/enum-snapshots.mjs';
import {
  activeCaidDefinition,
  assertRegistryPinnedSnapshots,
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

  it('both loaders refuse a value-set file whose provenance or values changed under an unchanged registry', () => {
    const entry = registry.enum_snapshot_files[0];
    const original = JSON.parse(
      readFileSync(new URL(`../caid/registry/${entry.path}`, import.meta.url), 'utf8'),
    );
    expect(jcsSha256(original)).toBe(entry.snapshot_sha256);
    const provenanceTampers = [
      { ...original, source: { ...original.source, url: 'https://example.invalid/list-one.xml' } },
      { ...original, source: { ...original.source, source_sha256: `sha256:${'1'.repeat(64)}` } },
      { ...original, hash_input: 'values joined by commas' },
      (({ source, ...rest }) => rest)(original),
    ];
    for (const tampered of provenanceTampers) {
      expect(() => loadRegistryEnumSnapshots(registry, { readSnapshot: () => tampered }))
        .toThrow(/does not match the registry snapshot_sha256/);
      expect(() => assertRegistryPinnedSnapshots(registry, [tampered]))
        .toThrow(/does not match the registry snapshot_sha256/);
    }
    // An extra code with a recomputed values_sha256 no longer matches the pin
    // the registry carries, so no consumer can adopt the file's own digest.
    const widenedValues = [...original.values, 'ZZZ'];
    const widened = { ...original, values: widenedValues, values_sha256: jcsSha256(widenedValues) };
    expect(() => loadRegistryEnumSnapshots(registry, { readSnapshot: () => widened }))
      .toThrow(/values_sha256 does not match the registry pin/);
    expect(() => assertRegistryPinnedSnapshots(registry, [widened]))
      .toThrow(/values_sha256 does not match the registry pin/);
    // Same labels, different values: the values digest check catches it.
    const swapped = { ...original, values: [...original.values.slice(1), 'ZZZ'] };
    expect(() => loadRegistryEnumSnapshots(registry, { readSnapshot: () => swapped }))
      .toThrow(/values do not match values_sha256/);
    expect(() => loadRegistryEnumSnapshots({
      enum_snapshot_files: [(({ snapshot_sha256, ...rest }) => rest)(entry)],
    })).toThrow(/does not pin snapshot_sha256/);
  });

  it('lists exactly the active enum fields that cannot resolve under this registry version', () => {
    const listed = new Set(
      registry.unresolved_external_enums.map((item: any) => `${item.action_type}.${item.field}`),
    );
    const snapshotFor = (field: any) => REGISTRY_ENUM_SNAPSHOTS.find((snapshot: any) =>
      snapshot.values_ref === field.values_ref
      && snapshot.values_snapshot === field.values_snapshot
      && snapshot.values_sha256 === field.values_sha256);
    const candidate = (field: any) => {
      if (Array.isArray(field.values)) return field.values[0];
      if (typeof field.values_ref === 'string' && field.values_ref.startsWith('inline:')) {
        return field.values_ref.slice('inline:'.length).split('|')[0].trim();
      }
      return snapshotFor(field)?.values[0] ?? 'UNRESOLVED';
    };
    const unresolvedTypes = new Set<string>();
    let checked = 0;
    for (const type of registry.types.filter((entry: any) => entry.status === 'active')) {
      for (const [required, fields] of [[true, type.required_fields ?? []], [false, type.optional_fields ?? []]]) {
        for (const field of fields as any[]) {
          if (field.type !== 'enum') continue;
          checked += 1;
          const result = computeCaid(
            { action_type: type.action_type, [field.name]: candidate(field) },
            { suite: 'jcs-sha256', definitions: registry.types, enumSnapshots: REGISTRY_ENUM_SNAPSHOTS },
          );
          const refused = (result.refusals ?? []).includes(`mistyped_field:${field.name}`);
          const key = `${type.action_type}.${field.name}`;
          expect(refused, key).toBe(listed.has(key));
          if (refused && required) unresolvedTypes.add(type.action_type);
        }
      }
    }
    expect(checked).toBeGreaterThan(listed.size);
    for (const item of registry.unresolved_external_enums) {
      const type = registry.types.find((entry: any) => entry.action_type === item.action_type);
      expect(type?.status, item.action_type).toBe('active');
      expect(type.required_fields.some((field: any) => field.name === item.field)).toBe(item.required);
    }
    // These types cannot produce or verify any CAID under registry v4.
    expect([...unresolvedTypes].sort()).toEqual([
      'ach.debit.originate.1', 'dns.record.delete.1', 'firewall.rule.open.1', 'key.create.1',
      'key.rotate.1', 'payment.refund.1', 'phi.disclose.1', 'pii.export.1',
      'prior.auth.approve.1', 'rx.dispense.1', 'vendor.onboard.1',
    ]);
    const active = registry.types.filter((entry: any) => entry.status === 'active').length;
    expect(active - unresolvedTypes.size).toBe(41);
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
