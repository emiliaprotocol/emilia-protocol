// SPDX-License-Identifier: Apache-2.0
//
// Pure evaluator for the live schema-security contract. Keeping the evaluator
// free of I/O makes the ACL/policy checks testable with catalog-shaped fixtures
// while db-contract.mjs remains the production CLI and introspection boundary.

import { contract as defaultContract } from './db-contract.manifest.mjs';

const UNTRUSTED = new Set(['anon', 'authenticated', 'public']);
const WRITE_CMDS = new Set(['INSERT', 'UPDATE', 'DELETE', 'ALL']);
const READ_CMDS = new Set(['SELECT', 'ALL']);
const TABLE_PRIVILEGES = new Set([
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'ALL',
]);

// Postgres grants EXECUTE to PUBLIC by default (empty grantee in aclitem). An
// empty acl string therefore means PUBLIC can execute.
const aclAnon = (acl) => /(^|[,{])anon=[A-Za-z]*X/.test(acl);
const aclAuth = (acl) => /(^|[,{])authenticated=[A-Za-z]*X/.test(acl);
const aclPublic = (acl) => acl === '' || /(^|[,{])=[A-Za-z]*X/.test(acl);
const aclUntrusted = (acl) => aclAnon(acl) || aclAuth(acl) || aclPublic(acl);

const roleName = (role) => String(role || '').toLowerCase();
const hasUntrustedRole = (roles) => (roles || []).some((role) => UNTRUSTED.has(roleName(role)));
const truthExpression = (value) => {
  const normalized = String(value || '').replace(/\s+/g, '').toLowerCase();
  return normalized === 'true' || normalized === '(true)';
};

export function evaluateContract(snap, schemaContract = defaultContract) {
  const failures = [];
  const gaps = [];
  let passCount = 0;
  const pass = () => { passCount += 1; };
  const fail = (message) => failures.push(message);
  const list = (value) => (Array.isArray(value) ? value : []);

  const requiredSnapshotFields = [
    'tables', 'columns', 'rls', 'policies', 'functions', 'table_grants', 'column_grants',
  ];
  for (const field of requiredSnapshotFields) {
    if (Array.isArray(snap?.[field])) pass();
    else fail(`SNAPSHOT field missing or invalid: ${field} (apply the introspection migration before running the gate)`);
  }

  const tables = new Set(list(snap?.tables));
  const cols = new Map();
  for (const column of list(snap?.columns)) {
    if (!cols.has(column.t)) cols.set(column.t, new Set());
    cols.get(column.t).add(column.c);
  }
  const rls = new Map(list(snap?.rls).map((row) => [row.t, row]));
  const policiesByTable = new Map();
  for (const policy of list(snap?.policies)) {
    if (!policiesByTable.has(policy.t)) policiesByTable.set(policy.t, []);
    policiesByTable.get(policy.t).push(policy);
  }
  const fnsByName = new Map();
  for (const fn of list(snap?.functions)) {
    if (!fnsByName.has(fn.name)) fnsByName.set(fn.name, []);
    fnsByName.get(fn.name).push(fn);
  }

  // 1. Required tables
  for (const table of schemaContract.requiredTables) {
    if (tables.has(table)) pass(); else fail(`TABLE missing: ${table}`);
  }

  // 2. Known-gap tables (non-fatal, but tracked + must be reported)
  for (const gapEntry of schemaContract.knownGapTables) {
    // knownGapTables is currently [] in the manifest, so TS infers `never[]`;
    // populated entries are always { name, why } (see db-contract.manifest.mjs).
    const gap = /** @type {{name: string, why: string}} */ (gapEntry);
    if (tables.has(gap.name)) {
      gaps.push(`KNOWN GAP NOW PRESENT (promote to requiredTables): ${gap.name}`);
    } else {
      gaps.push(`KNOWN GAP (tracked, not fixed): ${gap.name} — ${gap.why}`);
    }
  }

  // 3. Required columns
  for (const [table, wanted] of Object.entries(schemaContract.requiredColumns)) {
    const have = cols.get(table) || new Set();
    for (const column of wanted) {
      if (have.has(column)) pass(); else fail(`COLUMN missing: ${table}.${column}`);
    }
  }

  // 4. RLS enabled / forced
  for (const table of schemaContract.rlsRequired) {
    if (!tables.has(table)) { fail(`RLS-required table missing: ${table}`); continue; }
    if (rls.get(table)?.enabled === true) pass(); else fail(`RLS NOT enabled: ${table}`);
  }
  for (const table of schemaContract.forceRlsRequired || []) {
    if (!tables.has(table)) { fail(`FORCE-RLS-required table missing: ${table}`); continue; }
    if (rls.get(table)?.forced === true) pass(); else fail(`RLS NOT forced: ${table}`);
  }

  // 5. No anon/authenticated/PUBLIC READ policy on sensitive tables
  for (const table of schemaContract.noAnonRead) {
    const bad = (policiesByTable.get(table) || []).filter(
      (policy) => READ_CMDS.has(policy.cmd) && hasUntrustedRole(policy.roles),
    );
    if (bad.length === 0) pass();
    else fail(`ANON-READ exposure on ${table}: ${bad.map((p) => `${p.name}[${p.cmd}→${(p.roles || []).join(',')}]`).join('; ')}`);
  }

  // 6. No anon/authenticated/PUBLIC WRITE policy on sensitive tables
  for (const table of schemaContract.noAnonWrite) {
    const bad = (policiesByTable.get(table) || []).filter(
      (policy) => WRITE_CMDS.has(policy.cmd) && hasUntrustedRole(policy.roles),
    );
    if (bad.length === 0) pass();
    else fail(`ANON-WRITE exposure on ${table}: ${bad.map((p) => `${p.name}[${p.cmd}→${(p.roles || []).join(',')}]`).join('; ')}`);
  }

  // 7. Table ACLs are independent of RLS. No public role may hold any direct
  // privilege on a service-only table; Release Lock additionally has no direct
  // service_role privilege because its RPCs are the intended boundary.
  const tableGrants = list(snap?.table_grants);
  for (const table of schemaContract.tableGrantsNoPublic || []) {
    const bad = tableGrants.filter(
      (grant) => grant.t === table
        && hasUntrustedRole([grant.grantee])
        && TABLE_PRIVILEGES.has(String(grant.privilege || '').toUpperCase()),
    );
    if (bad.length === 0) pass();
    else fail(`PUBLIC TABLE GRANT on ${table}: ${bad.map((g) => `${g.grantee}.${g.privilege}`).join(', ')}`);
  }
  for (const table of schemaContract.tableGrantsNoServiceRoleDirect || []) {
    const bad = tableGrants.filter(
      (grant) => grant.t === table
        && roleName(grant.grantee) === 'service_role'
        && TABLE_PRIVILEGES.has(String(grant.privilege || '').toUpperCase()),
    );
    if (bad.length === 0) pass();
    else fail(`DIRECT SERVICE-ROLE TABLE GRANT on ${table}: ${bad.map((g) => g.privilege).join(', ')}`);
  }

  // 8. Column ACLs close the independent column-level disclosure/write path.
  const sensitiveColumns = Object.entries(schemaContract.sensitiveColumnsNoPublicGrant || {})
    .flatMap(([table, columns]) => columns.map((column) => ({ table, column })));
  const columnGrants = list(snap?.column_grants);
  for (const { table, column } of sensitiveColumns) {
    const bad = columnGrants.filter(
      (grant) => grant.t === table && grant.c === column && hasUntrustedRole([grant.grantee]),
    );
    if (bad.length === 0) pass();
    else fail(`PUBLIC COLUMN GRANT on ${table}.${column}: ${bad.map((g) => `${g.grantee}.${g.privilege}`).join(', ')}`);
  }

  // 9. Four replay/revocation tables intentionally retain an explicit
  // service_role policy. Check the role scope and both policy expressions.
  for (const table of schemaContract.serviceRolePoliciesRequired || []) {
    const good = (policiesByTable.get(table) || []).some((policy) => {
      const roles = (policy.roles || []).map(roleName);
      return policy.cmd === 'ALL'
        && roles.length === 1
        && roles[0] === 'service_role'
        && truthExpression(policy.using)
        && truthExpression(policy.check);
    });
    if (good) pass(); else fail(`SERVICE-ROLE POLICY missing or widened: ${table}`);
  }

  // 10. SECURITY DEFINER RPCs exist + not anon/auth/PUBLIC-executable (all overloads)
  for (const name of schemaContract.definerRpcsServiceRoleOnly) {
    const overloads = fnsByName.get(name) || [];
    if (overloads.length === 0) { fail(`RPC missing: ${name}()`); continue; }
    const exposed = overloads.filter((fn) => aclUntrusted(fn.acl || ''));
    if (exposed.length === 0) pass();
    else fail(`RPC executable by untrusted role: ${name} (${exposed.length}/${overloads.length} overloads acl=${exposed.map((fn) => fn.acl).join(' | ')})`);
  }

  // 11. Required RPCs exist
  for (const name of schemaContract.requiredRpcs) {
    if (fnsByName.has(name)) pass(); else fail(`RPC missing: ${name}()`);
  }

  return { passCount, gaps, failures };
}
