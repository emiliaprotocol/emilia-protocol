// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { contract } from '../scripts/db-contract.manifest.mjs';
import { evaluateContract } from '../scripts/db-contract-audit.mjs';

function cleanSnapshot() {
  const tables = new Set(contract.requiredTables);
  const columns = [];
  for (const [table, names] of Object.entries(contract.requiredColumns)) {
    for (const column of names) columns.push({ t: table, c: column });
  }
  for (const table of contract.rlsRequired) tables.add(table);

  const policies = (contract.serviceRolePoliciesRequired || []).map((table) => ({
    t: table,
    name: 'service_role_all',
    cmd: 'ALL',
    roles: ['service_role'],
    using: 'true',
    check: 'true',
  }));
  const functions = [...new Set([
    ...contract.definerRpcsServiceRoleOnly,
    ...contract.requiredRpcs,
  ])].map((name) => ({
    name,
    args: '',
    secdef: contract.definerRpcsServiceRoleOnly.includes(name),
    acl: 'service_role=X/postgres',
  }));
  for (const signature of contract.requiredDefinerRpcSignatures || []) {
    const [, name, args] = signature.match(/^public\.([^(]+)\((.*)\)$/);
    const current = functions.find((entry) => entry.name === name);
    if (current) {
      current.args = args;
      current.secdef = true;
    } else {
      functions.push({
        name,
        args,
        secdef: true,
        acl: 'service_role=X/postgres',
      });
    }
  }

  return {
    tables: [...tables],
    reconcile_tables: [...contract.requiredQualifiedTables],
    reconcile_functions: [...new Set([
      ...contract.requiredQualifiedRpcs,
      ...contract.requiredReconcileAssertions,
    ])],
    columns,
    rls: contract.rlsRequired.map((t) => ({
      t,
      enabled: true,
      forced: (contract.forceRlsRequired || []).includes(t),
    })),
    policies,
    functions,
    indexes: Object.entries(contract.requiredIndexes || {}).flatMap(
      ([t, names]) => names.map((name) => ({ t, name })),
    ),
    table_grants: [],
    column_grants: [],
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

describe('live schema-security contract evaluator', () => {
  it('accepts a clean catalog-shaped snapshot', () => {
    const result = evaluateContract(cleanSnapshot());

    expect(result.failures).toEqual([]);
    expect(result.passCount).toBeGreaterThan(100);
  });

  it('governs the private rollout-attempt store and exact RPC signature', () => {
    expect(contract.requiredQualifiedTables).toEqual(expect.arrayContaining([
      'rollout_attempt_private.claims',
      'rollout_attempt_private.terminals',
    ]));
    expect(contract.requiredQualifiedRpcs).toContain(
      'rollout_attempt_private.apply_operation(text,text)',
    );
  });

  it('governs every Open Exposure table and exact custody RPC signature', () => {
    expect(contract.requiredQualifiedTables).toEqual(expect.arrayContaining([
      'open_exposure_private.tenant_principals',
      'open_exposure_private.ceilings',
      'open_exposure_private.exposures',
      'open_exposure_private.history',
      'open_exposure_private.reconciliation_tokens',
    ]));
    expect(contract.requiredQualifiedRpcs).toEqual(expect.arrayContaining([
      'open_exposure_private.register_ceiling(jsonb)',
      'open_exposure_private.reserve(jsonb)',
      'open_exposure_private.begin_invocation(jsonb)',
      'open_exposure_private.mark_indeterminate(jsonb)',
      'open_exposure_private.reconcile(jsonb)',
      'open_exposure_private.read_exposure(jsonb)',
      'open_exposure_private.read_history(jsonb)',
      'open_exposure_private.sum_open(jsonb)',
      'open_exposure_private.list_aging(jsonb)',
      'open_exposure_private.list_deadlines(jsonb)',
    ]));
  });

  it('rejects a missing qualified private table', () => {
    const snapshot = cleanSnapshot();
    snapshot.reconcile_tables = snapshot.reconcile_tables.filter(
      (name) => name !== 'consequence_actuator_private.provider_records',
    );

    const result = evaluateContract(snapshot);

    expect(result.failures).toContain(
      'QUALIFIED TABLE missing: consequence_actuator_private.provider_records',
    );
  });

  it('rejects a missing safety index', () => {
    const snapshot = cleanSnapshot();
    snapshot.indexes = snapshot.indexes.filter(
      ({ name }) => name !== 'idx_receipts_single_child_per_parent',
    );

    const result = evaluateContract(snapshot);

    expect(result.failures).toContain(
      'INDEX missing: receipts.idx_receipts_single_child_per_parent',
    );
  });

  it('rejects a missing private posture or exact-index assertion token', () => {
    for (const assertion of [
      'contract:table:consequence_actuator_private.provider_records:owner-force-rls-owner-only-acl',
      'contract:roles:consequence-actuator:least-privilege-membership-disjoint',
      'contract:index:public.idx_receipts_single_child_per_parent:exact-unique-btree',
    ]) {
      const snapshot = cleanSnapshot();
      snapshot.reconcile_functions = snapshot.reconcile_functions.filter(
        (value) => value !== assertion,
      );

      expect(evaluateContract(snapshot).failures).toContain(
        `RECONCILIATION SECURITY ASSERTION failed: ${assertion}`,
      );
    }
  });

  it('requires every exact consequence-control append-only trigger assertion', () => {
    const triggerAssertions = contract.requiredReconcileAssertions.filter(
      (value) => value.startsWith('contract:trigger:consequence_actuator_private.')
        || value.startsWith('contract:trigger:rollout_attempt_private.'),
    );
    expect(triggerAssertions).toHaveLength(8);

    for (const assertion of triggerAssertions) {
      const snapshot = cleanSnapshot();
      snapshot.reconcile_functions = snapshot.reconcile_functions.filter(
        (value) => value !== assertion,
      );

      expect(evaluateContract(snapshot).failures).toContain(
        `RECONCILIATION SECURITY ASSERTION failed: ${assertion}`,
      );
    }
  });

  it('requires every Open Exposure live trigger, role, and index assertion', () => {
    const openExposureAssertions = contract.requiredReconcileAssertions.filter(
      (value) => value.includes(':open_exposure_private.')
        || value === 'contract:roles:open-exposure:least-privilege-membership-disjoint',
    );
    expect(openExposureAssertions).toHaveLength(26);

    for (const assertion of openExposureAssertions) {
      const snapshot = cleanSnapshot();
      snapshot.reconcile_functions = snapshot.reconcile_functions.filter(
        (value) => value !== assertion,
      );

      expect(evaluateContract(snapshot).failures).toContain(
        `RECONCILIATION SECURITY ASSERTION failed: ${assertion}`,
      );
    }
  });

  it('accepts the exact qualified private RPC identity signature', () => {
    const snapshot = cleanSnapshot();
    const exactSignature = 'rollout_attempt_private.apply_operation(text,text)';

    expect(snapshot.reconcile_functions).toContain(exactSignature);
    expect(evaluateContract(snapshot).failures).not.toContain(
      `QUALIFIED RPC missing: ${exactSignature}`,
    );
  });

  it('rejects a bare name and wrong overload for an exact qualified private RPC', () => {
    const snapshot = cleanSnapshot();
    const exactSignature = 'rollout_attempt_private.apply_operation(text,text)';
    snapshot.reconcile_functions = snapshot.reconcile_functions.filter(
      (name) => name !== exactSignature,
    );
    snapshot.reconcile_functions.push(
      'rollout_attempt_private.apply_operation',
      'rollout_attempt_private.apply_operation(text)',
    );

    const result = evaluateContract(snapshot);

    expect(result.failures).toContain(
      `QUALIFIED RPC missing: ${exactSignature}`,
    );
  });

  it('pins exact public mutation RPC signatures, definer mode, and service execution', () => {
    const signature = 'public.consume_gate_ref_atomic(text,text,text,text,text)';
    expect(contract.requiredDefinerRpcSignatures).toContain(signature);

    for (const mutation of [
      (fn) => { fn.args = 'integer'; },
      (fn) => { fn.secdef = false; },
      (fn) => { fn.acl = 'postgres=X/postgres'; },
      (fn) => { fn.acl = '=X/postgres,service_role=X/postgres'; },
    ]) {
      const snapshot = cleanSnapshot();
      const fn = snapshot.functions.find(
        (entry) => entry.name === 'consume_gate_ref_atomic',
      );
      mutation(fn);
      expect(
        evaluateContract(snapshot).failures.some(
          (failure) => failure.includes(signature),
        ),
      ).toBe(true);
    }
  });

  it('rejects a public table grant even when RLS and policies are otherwise clean', () => {
    const snapshot = cleanSnapshot();
    snapshot.table_grants.push({ t: 'release_locks', grantee: 'anon', privilege: 'SELECT' });

    const result = evaluateContract(snapshot);

    expect(result.failures.some((failure) => failure.includes('PUBLIC TABLE GRANT on release_locks'))).toBe(true);
  });

  it('rejects direct service-role writes on an RPC-only mutation table', () => {
    const snapshot = cleanSnapshot();
    snapshot.table_grants.push({
      t: 'policy_rollouts',
      grantee: 'service_role',
      privilege: 'UPDATE',
    });

    const result = evaluateContract(snapshot);

    expect(result.failures.some(
      (failure) => failure.includes('DIRECT SERVICE-ROLE WRITE GRANT on policy_rollouts'),
    )).toBe(true);
  });

  it('rejects a public grant on a sensitive column', () => {
    const snapshot = cleanSnapshot();
    snapshot.column_grants.push({
      t: 'entities', c: 'private_key_encrypted', grantee: 'authenticated', privilege: 'SELECT',
    });

    const result = evaluateContract(snapshot);

    expect(result.failures.some((failure) => failure.includes('PUBLIC COLUMN GRANT on entities.private_key_encrypted'))).toBe(true);
  });

  it('rejects a widened policy on a secret table', () => {
    const snapshot = cleanSnapshot();
    snapshot.policies.push({
      t: 'release_locks', name: 'bad_read', cmd: 'SELECT', roles: ['authenticated'],
    });

    const result = evaluateContract(snapshot);

    expect(result.failures.some((failure) => failure.includes('ANON-READ exposure on release_locks'))).toBe(true);
  });

  it('fails closed when the live introspection RPC is stale and omits ACL fields', () => {
    const snapshot = clone(cleanSnapshot());
    delete snapshot.table_grants;

    const result = evaluateContract(snapshot);

    expect(result.failures.some((failure) => failure.includes('SNAPSHOT field missing or invalid: table_grants'))).toBe(true);
  });

  it('fails closed when reconciliation metadata is absent', () => {
    const snapshot = clone(cleanSnapshot());
    delete snapshot.reconcile_functions;

    const result = evaluateContract(snapshot);

    expect(result.failures).toContain(
      'SNAPSHOT field missing or invalid: reconcile_functions (apply the introspection migration before running the gate)',
    );
  });
});
