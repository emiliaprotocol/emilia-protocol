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
  ])].map((name) => ({ name, acl: 'service_role=X/postgres' }));

  return {
    tables: [...tables],
    columns,
    rls: contract.rlsRequired.map((t) => ({
      t,
      enabled: true,
      forced: (contract.forceRlsRequired || []).includes(t),
    })),
    policies,
    functions,
    indexes: [],
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

  it('rejects a public table grant even when RLS and policies are otherwise clean', () => {
    const snapshot = cleanSnapshot();
    snapshot.table_grants.push({ t: 'release_locks', grantee: 'anon', privilege: 'SELECT' });

    const result = evaluateContract(snapshot);

    expect(result.failures.some((failure) => failure.includes('PUBLIC TABLE GRANT on release_locks'))).toBe(true);
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
});
