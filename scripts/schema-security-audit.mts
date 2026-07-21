#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Static migration/security audit.
//
// This complements the live db-contract gate. It proves only what can be
// established from the checked-in migration source: required RLS/force-RLS
// statements, final direct policy role scope for the audited tables, explicit
// public ACL revocations, and sensitive-column revocations. It deliberately
// labels itself as source evidence; it does not claim that production has
// applied the migrations.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { contract } from './db-contract.manifest.mjs';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIG_DIR: string = path.join(ROOT, 'supabase', 'migrations');
const PUBLIC_ROLES: Set<string> = new Set(['public', 'anon', 'authenticated']);
const READ_CMDS: Set<string> = new Set(['SELECT', 'ALL']);
const WRITE_CMDS: Set<string> = new Set(['INSERT', 'UPDATE', 'DELETE', 'ALL']);

interface Policy {
  key: string;
  table: string;
  name: string;
  command: string;
  roles: string[];
  using: string | null;
  check: string | null;
}

interface MigrationFile {
  file: string;
  sql: string;
}

interface AuditCheck {
  name: string;
  ok: boolean;
}

interface AuditFailure {
  name: string;
  detail: string | boolean;
}

interface AuditResult {
  '@version': string;
  status: string;
  source: string;
  source_sha256: string;
  migration_files: string[];
  checks: AuditCheck[];
  failures: AuditFailure[];
  limitations: string[];
}

function stripComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/--[^\n]*/g, '');
}

function statementsFor(sql: string): string[] {
  return stripComments(sql)
    .split(';')
    .map((statement: string) => statement.trim().replace(/\s+/g, ' '))
    .filter(Boolean);
}

function identifier(name: string): string {
  return name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasTableReference(statement: string, table: string): boolean {
  return new RegExp(`\\b(?:TABLE\\s+|ON\\s+(?:TABLE\\s+)?)(?:public\\.)?${identifier(table)}\\b`, 'i').test(statement);
}

function roleClause(statement: string, direction: string): string {
  const match = statement.match(new RegExp(`\\b${direction}\\b([\\s\\S]*)$`, 'i'));
  return match ? match[1] : '';
}

function containsRoles(statement: string, direction: string, wanted: string[]): boolean {
  const clause: string = roleClause(statement, direction);
  return wanted.every((role: string) => new RegExp(`\\b${identifier(role)}\\b`, 'i').test(clause));
}

function directTableRevoke(statements: string[], table: string, roles: string[]): boolean {
  return statements.some((statement: string) => /^REVOKE\b/i.test(statement)
    && /\bON\s+(?:TABLE\s+)?/i.test(statement)
    && hasTableReference(statement, table)
    && /^REVOKE\s+ALL\b/i.test(statement)
    && containsRoles(statement, 'FROM', roles));
}

function directTableWriteRevoke(statements: string[], table: string, roles: string[]): boolean {
  return statements.some((statement: string) => /^REVOKE\b/i.test(statement)
    && /\bON\s+(?:TABLE\s+)?/i.test(statement)
    && hasTableReference(statement, table)
    && ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']
      .every((privilege: string) => new RegExp(`\\b${privilege}\\b`, 'i').test(statement))
    && containsRoles(statement, 'FROM', roles));
}

function directSensitiveColumnRevoke(statements: string[], table: string, column: string): boolean {
  return statements.some((statement: string) => /^REVOKE\b/i.test(statement)
    && hasTableReference(statement, table)
    && new RegExp(`\\([^)]*\\b${identifier(column)}\\b[^)]*\\)\\s+ON\\b`, 'i').test(statement)
    && containsRoles(statement, 'FROM', ['PUBLIC', 'anon', 'authenticated']));
}

function policyFromCreate(statement: string): Policy | null {
  const match = statement.match(/^CREATE\s+POLICY\s+(?:"([^"]+)"|([a-z_][a-z0-9_]*))\s+ON\s+(?:public\.)?([a-z_][a-z0-9_]*)\b([\s\S]*)$/i);
  if (!match) return null;
  const [, quotedName, bareName, table, rest] = match;
  const command: string = rest.match(/\bFOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)\b/i)?.[1]?.toUpperCase() || 'ALL';
  const to = rest.match(/\bTO\s+(.+?)(?=\s+USING\b|\s+WITH\s+CHECK\b|\s*$)/i);
  const roles: string[] = to ? to[1].split(',').map((role: string) => role.trim().replace(/^"|"$/g, '')) : ['PUBLIC'];
  return {
    key: `${table.toLowerCase()}\0${quotedName || bareName}`,
    table: table.toLowerCase(),
    name: quotedName || bareName,
    command,
    roles,
    using: rest.match(/\bUSING\s+(\([^)]*\)|\S+)/i)?.[1] || null,
    check: rest.match(/\bWITH\s+CHECK\s+(\([^)]*\)|\S+)/i)?.[1] || null,
  };
}

function applyPolicyStatements(statements: string[]): Policy[] {
  const policies: Map<string, Policy> = new Map();
  for (const statement of statements) {
    const created = policyFromCreate(statement);
    if (created) {
      policies.set(created.key, created);
      continue;
    }
    const dropped = statement.match(/^DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?(?:"([^"]+)"|([a-z_][a-z0-9_]*))\s+ON\s+(?:public\.)?([a-z_][a-z0-9_]*)\b/i);
    if (dropped) {
      policies.delete(`${dropped[3].toLowerCase()}\0${dropped[1] || dropped[2]}`);
      continue;
    }
    const altered = statement.match(/^ALTER\s+POLICY\s+(?:"([^"]+)"|([a-z_][a-z0-9_]*))\s+ON\s+(?:public\.)?([a-z_][a-z0-9_]*)\s+TO\s+(.+?)(?=\s+USING\b|\s+WITH\s+CHECK\b|\s*$)/i);
    if (altered) {
      const key = `${altered[3].toLowerCase()}\0${altered[1] || altered[2]}`;
      const current: Policy = (policies.get(key) || {
        key,
        table: altered[3].toLowerCase(),
        name: altered[1] || altered[2],
        command: 'ALL',
        roles: [],
        using: null,
        check: null,
      }) as Policy;
      current.roles = altered[4].split(',').map((role) => role.trim().replace(/^"|"$/g, ''));
      policies.set(key, current);
    }
  }
  return [...policies.values()];
}

function isPublicRole(role: any): boolean {
  return PUBLIC_ROLES.has(String(role || '').toLowerCase());
}

function policyIsServiceOnly(policy: Policy): boolean {
  return policy.command === 'ALL'
    && policy.roles.length === 1
    && policy.roles[0].toLowerCase() === 'service_role'
    && ['true', '(true)'].includes(String(policy.using || '').replace(/\s+/g, '').toLowerCase())
    && ['true', '(true)'].includes(String(policy.check || '').replace(/\s+/g, '').toLowerCase());
}

export function readMigrationBundle(root: string = ROOT): MigrationFile[] {
  const migrationDir: string = path.join(root, 'supabase', 'migrations');
  const files: MigrationFile[] = fs.readdirSync(migrationDir)
    .filter((file: string) => file.endsWith('.sql'))
    .sort()
    .map((file: string) => ({
      file,
      sql: fs.readFileSync(path.join(migrationDir, file), 'utf8'),
    }));
  return files;
}

export function auditMigrationBundle(migrationFiles: MigrationFile[], schemaContract: any = contract): AuditResult {
  const files: MigrationFile[] = migrationFiles.map((entry: MigrationFile) => ({ file: entry.file, sql: entry.sql }));
  const statements: string[] = files.flatMap((entry: MigrationFile) => statementsFor(entry.sql));
  // Fortress reassertions are forward-only: a service-only table added AFTER the
  // first fortress migration reasserts its ACL/RLS in a LATER fortress file.
  // Union the statements across ALL fortress files so a new one counts, while
  // the invariant strength is unchanged — every table's revoke must still appear
  // in some fortress migration in the checked-in source.
  const invariantFiles: MigrationFile[] = files.filter((entry: MigrationFile) => entry.file.endsWith('_fortress_db_security_invariants.sql'));
  const invariantStatements: string[] = invariantFiles.flatMap((entry: MigrationFile) => statementsFor(entry.sql));
  const failures: AuditFailure[] = [];
  const checks: AuditCheck[] = [];
  const source: string = files.map((entry: MigrationFile) => `${entry.file}\n${entry.sql}`).join('\n');
  const sourceSha256: string = createHash('sha256').update(source).digest('hex');
  const check = (name: string, fn: () => boolean | string): void => {
    const detail: boolean | string = fn();
    if (detail === true) checks.push({ name, ok: true });
    else failures.push({ name, detail: detail || 'invariant failed' });
  };

  check('fortress reconciliation migration present', () => invariantFiles.length > 0);

  for (const table of schemaContract.rlsRequired) {
    check(`RLS enabled: ${table}`, () => statements.some((statement) =>
      /^ALTER\s+TABLE\b/i.test(statement)
      && hasTableReference(statement, table)
      && /\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b/i.test(statement)));
  }
  for (const table of schemaContract.forceRlsRequired || []) {
    check(`RLS forced: ${table}`, () => statements.some((statement) =>
      /^ALTER\s+TABLE\b/i.test(statement)
      && hasTableReference(statement, table)
      && /\bFORCE\s+ROW\s+LEVEL\s+SECURITY\b/i.test(statement)));
  }

  for (const table of schemaContract.tableGrantsNoPublic || []) {
    check(`public table ACL revoked: ${table}`, () => directTableRevoke(
      invariantStatements, table, ['PUBLIC', 'anon', 'authenticated'],
    ));
    const directPublicGrant = statements.find((statement) => /^GRANT\b/i.test(statement)
      && hasTableReference(statement, table)
      && !/\([^)]*\)\s+ON\b/i.test(statement)
      && ['anon', 'authenticated', 'PUBLIC'].some((role) => containsRoles(statement, 'TO', [role])));
    if (directPublicGrant) failures.push({
      name: `no direct public table GRANT: ${table}`,
      detail: directPublicGrant,
    });
  }
  for (const table of schemaContract.tableGrantsNoServiceRoleDirect || []) {
    check(`direct service_role table ACL revoked: ${table}`, () => directTableRevoke(
      invariantStatements, table, ['service_role'],
    ));
  }
  for (const table of schemaContract.tableWriteGrantsNoServiceRole || []) {
    check(`direct service_role table writes revoked: ${table}`, () => directTableWriteRevoke(
      // RPC-only mutation boundaries may be introduced by a feature migration
      // before the next fortress reconciliation. The revocation is still an
      // auditable invariant even when it lives in that defining migration.
      statements, table, ['service_role'],
    ));
  }

  for (const [table, columns] of Object.entries(schemaContract.sensitiveColumnsNoPublicGrant || {})) {
    for (const column of (columns as string[])) {
      check(`public column ACL revoked: ${table}.${column}`, () => directSensitiveColumnRevoke(
        invariantStatements, table, column,
      ));
    }
  }

  const finalPolicies: Policy[] = applyPolicyStatements(statements);
  for (const table of schemaContract.noAnonRead || []) {
    const bad: Policy[] = finalPolicies.filter((policy: Policy) => policy.table === table
      && READ_CMDS.has(policy.command)
      && policy.roles.some(isPublicRole));
    check(`no public read policy: ${table}`, () => bad.length === 0 || `policy ${bad.map((p: Policy) => p.name).join(', ')}`);
  }
  for (const table of schemaContract.noAnonWrite || []) {
    const bad: Policy[] = finalPolicies.filter((policy: Policy) => policy.table === table
      && WRITE_CMDS.has(policy.command)
      && policy.roles.some(isPublicRole));
    check(`no public write policy: ${table}`, () => bad.length === 0 || `policy ${bad.map((p: Policy) => p.name).join(', ')}`);
  }
  for (const table of schemaContract.serviceRolePoliciesRequired || []) {
    const good: boolean = finalPolicies.some((policy: Policy) => policy.table === table && policyIsServiceOnly(policy));
    check(`service_role policy: ${table}`, () => good);
  }

  return {
    '@version': 'EP-DB-SECURITY-AUDIT-v1',
    status: failures.length === 0 ? 'passed' : 'failed',
    source: 'checked-in supabase/migrations SQL',
    source_sha256: sourceSha256,
    migration_files: files.map((entry) => entry.file),
    checks,
    failures,
    limitations: [
      'This is static migration-source evidence, not proof that production applied every migration.',
      'Pair with scripts/db-contract.mjs for live catalog ACL/RLS/policy state and scripts/migration-reconcile.mjs for object existence.',
      'The audit does not inspect application routes, escrow behavior, key custody, or cryptographic algorithm negotiation.',
    ],
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result: AuditResult = auditMigrationBundle(readMigrationBundle());
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`EP migration security audit — ${result.status}`);
    console.log(`Source SHA-256: ${result.source_sha256}`);
    console.log(`Checked ${result.migration_files.length} migration files; ${result.checks.length} invariants passed.`);
    for (const failure of result.failures) console.log(`✗ ${failure.name}: ${failure.detail}`);
    console.log(`Evidence scope: ${result.source}`);
    console.log(`Limitations: ${result.limitations[0]}`);
  }
  process.exit(result.status === 'passed' ? 0 : 1);
}
