// SPDX-License-Identifier: Apache-2.0
//
// The server (lib/caid-registry.ts) and Node tooling
// (caid/registry/enum-snapshots.mjs) must supply exactly the external enum
// snapshots the CAID registry pins. A registry pin change that either loader
// misses would make every currency-bearing CAID refuse in production.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { computeCaid, verifyCaid } from '../caid/impl/js/caid.mjs';
import {
  activeRegistryDefinition,
  jcsSha256,
  loadRegistryEnumSnapshots,
  registryDefinition,
  REGISTRY_ENUM_SNAPSHOTS,
} from '../caid/registry/enum-snapshots.mjs';
import { buildSpec } from '../caid/spec/gen.mjs';
import { createReference } from '../caid/spec/reference.mjs';
import {
  activeCaidDefinition,
  assertRegistryPinnedSnapshots,
  CAID_ACTION_TYPE_REGISTRY,
  CAID_REGISTRY_ENUM_SNAPSHOTS,
  registryDefinition as serverRegistryDefinition,
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
    expect(() => assertRegistryPinnedSnapshots(registry, CAID_REGISTRY_ENUM_SNAPSHOTS.slice(1)))
      .toThrow(/differ from enum_snapshot_files/);
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
      expect(() => assertRegistryPinnedSnapshots(registry, [tampered, ...CAID_REGISTRY_ENUM_SNAPSHOTS.slice(1)]))
        .toThrow(/does not match the registry snapshot_sha256/);
    }
    // An extra code with a recomputed values_sha256 no longer matches the pin
    // the registry carries, so no consumer can adopt the file's own digest.
    const widenedValues = [...original.values, 'ZZZ'];
    const widened = { ...original, values: widenedValues, values_sha256: jcsSha256(widenedValues) };
    expect(() => loadRegistryEnumSnapshots(registry, { readSnapshot: () => widened }))
      .toThrow(/values_sha256 does not match the registry pin/);
    expect(() => assertRegistryPinnedSnapshots(registry, [widened, ...CAID_REGISTRY_ENUM_SNAPSHOTS.slice(1)]))
      .toThrow(/values_sha256 does not match the registry pin/);
    // Same labels, different values: the values digest check catches it.
    const swapped = { ...original, values: [...original.values.slice(1), 'ZZZ'] };
    expect(() => loadRegistryEnumSnapshots(registry, { readSnapshot: () => swapped }))
      .toThrow(/values do not match values_sha256/);
    expect(() => loadRegistryEnumSnapshots({
      enum_snapshot_files: [(({ snapshot_sha256, ...rest }) => rest)(entry)],
    })).toThrow(/does not pin snapshot_sha256/);
  });

  it('lists exactly the enum fields that cannot resolve, all on deprecated types', () => {
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
    let checked = 0;
    for (const type of registry.types) {
      for (const field of [...(type.required_fields ?? []), ...(type.optional_fields ?? [])]) {
        if (field.type !== 'enum') continue;
        checked += 1;
        const result = computeCaid(
          { action_type: type.action_type, [field.name]: candidate(field) },
          { suite: 'jcs-sha256', definitions: registry.types, enumSnapshots: REGISTRY_ENUM_SNAPSHOTS },
        );
        const refused = (result.refusals ?? []).includes(`mistyped_field:${field.name}`);
        expect(refused, `${type.action_type}.${field.name}`).toBe(listed.has(`${type.action_type}.${field.name}`));
      }
    }
    expect(checked).toBeGreaterThan(listed.size);
    for (const item of registry.unresolved_external_enums) {
      const type = registry.types.find((entry: any) => entry.action_type === item.action_type);
      expect(item.status, item.action_type).toBe('deprecated');
      expect(type?.status, item.action_type).toBe('deprecated');
      expect(type.required_fields.some((field: any) => field.name === item.field)).toBe(item.required);
    }
    // Registry v5 resolves every enum of every active type.
    expect(registry.meta.registry_version).toBe(5);
    expect([...new Set(registry.unresolved_external_enums.map((item: any) => item.action_type))].sort()).toEqual([
      'ach.debit.originate.1', 'firewall.rule.open.1', 'key.create.1', 'key.rotate.1',
      'payment.refund.1', 'phi.disclose.1', 'pii.export.1', 'prior.auth.approve.1', 'rx.dispense.1',
    ]);
  });

  it('every active type computes under the -04 reference validator', () => {
    const root = new URL('..', import.meta.url).pathname;
    const reference = createReference(buildSpec(root));
    const sample: Record<string, (field: any) => unknown> = {
      string: () => 'x',
      'amount-string': () => '1.00',
      digest: () => `sha256:${'0'.repeat(64)}`,
      timestamp: () => '2026-02-28T00:00:00Z',
      integer: () => 1,
      boolean: () => true,
      object: () => ({}),
      array: () => [],
    };
    const codeSample: Record<string, string> = {
      'iso20022-external-code': 'AC04', 'nacha-sec': 'PPD', 'ndc-11': '00000000000', hcpcs: 'A0000', 'icd-10-cm': 'A00.0',
    };
    const value = (field: any) => {
      if (field.type === 'code') return codeSample[field.format];
      if (field.type !== 'enum') return sample[field.type](field);
      if (Array.isArray(field.values)) return field.values[0];
      if (field.values_ref.startsWith('inline:')) return field.values_ref.slice('inline:'.length).split('|')[0].trim();
      return REGISTRY_ENUM_SNAPSHOTS.find((s: any) => s.values_sha256 === field.values_sha256)?.values[0];
    };
    const active = registry.types.filter((type: any) => type.status === 'active');
    expect(active).toHaveLength(53);
    for (const type of active) {
      const object: Record<string, unknown> = { action_type: type.action_type };
      for (const field of [...type.required_fields, ...(type.optional_fields ?? [])]) object[field.name] = value(field);
      const result = reference.compute(object, {
        suite: 'jcs-sha256', definitions: registry.types, enumSnapshots: REGISTRY_ENUM_SNAPSHOTS,
      });
      expect(result.caid, `${type.action_type}: ${JSON.stringify(result.refusals)}`).toMatch(/^caid:1:/);
      expect(result.definition_sha256).toBe(reference.definitionSha256(type));
    }
  });

  it('status never gates resolution: deprecated types resolve, compute and verify', () => {
    const deprecated = registry.types.filter((type: any) => type.status === 'deprecated');
    expect(deprecated).toHaveLength(9);
    for (const type of deprecated) {
      expect(registryDefinition(type.action_type)).toEqual(type);
      expect(serverRegistryDefinition(type.action_type)).toEqual(type);
      expect(activeCaidDefinition(type.action_type)).toBeUndefined();
      expect(() => activeRegistryDefinition(type.action_type)).toThrow(`use ${type.superseded_by}`);
      expect(registryDefinition(type.superseded_by).supersedes).toBe(type.action_type);
    }
    expect(() => registryDefinition('no.such.type.1')).toThrow(/has no no\.such\.type\.1/);
    expect(serverRegistryDefinition('no.such.type.1')).toBeUndefined();
    // A deprecated type resolves (never unknown_action_type): it refuses only
    // the field whose external set it never pinned.
    const refund = registryDefinition('payment.refund.1');
    const action = {
      action_type: 'payment.refund.1',
      original_payment_id: 'pay-1',
      amount: '10.00',
      currency: 'USD',
      destination_account: `sha256:${'c'.repeat(64)}`,
    };
    const opts = { suite: 'jcs-sha256', definitions: [refund], enumSnapshots: REGISTRY_ENUM_SNAPSHOTS };
    expect(computeCaid({ ...action, reason_code: 'AC04' }, opts)).toEqual({ refusals: ['mistyped_field:reason_code'] });
    const computed = computeCaid(action, opts);
    expect(computed).toEqual({ refusals: ['missing_material_field:reason_code'] });
    // dns.record.delete.1 and vendor.onboard.1 received their first pins and compute.
    for (const [actionType, extra] of [
      ['dns.record.delete.1', { zone: 'example.com', record_name: 'www.example.com', record_type: 'AAAA', rdata: '2001:db8::1' }],
      ['vendor.onboard.1', { vendor_legal_name: 'Acme', jurisdiction: 'DE', tax_id_digest: `sha256:${'d'.repeat(64)}`, bank_account_digest: `sha256:${'e'.repeat(64)}` }],
    ] as const) {
      const object = { action_type: actionType, ...extra };
      const result = computeCaid(object, {
        suite: 'jcs-sha256', definitions: [registryDefinition(actionType)], enumSnapshots: REGISTRY_ENUM_SNAPSHOTS,
      });
      expect(result.caid, actionType).toMatch(new RegExp(`^caid:1:${actionType.replaceAll('.', '\\.')}:jcs-sha256:`));
      expect(verifyCaid(object, result.caid, {
        definitions: [registryDefinition(actionType)], enumSnapshots: REGISTRY_ENUM_SNAPSHOTS,
      })).toMatchObject({ valid: true, reasons: [] });
    }
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
