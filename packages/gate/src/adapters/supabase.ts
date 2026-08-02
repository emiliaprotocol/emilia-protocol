// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Supabase / Postgres System-of-Record adapter.
 *
 * "Install this before your agent can run destructive SQL." Wraps the dangerous
 * database operations — destructive SQL (DELETE/DROP/TRUNCATE/UPDATE), bulk
 * export, and RLS-policy change — so they never execute without a valid,
 * sufficiently-assured, non-replayed receipt bound to THIS statement/table. The
 * exact statement is bound by hash, so an approval for one DELETE cannot be
 * swapped for a DROP.
 *
 *   import { createGate } from '@emilia-protocol/gate';
 *   import { createSupabaseManifest, guardSupabaseMutation, isDestructiveSql } from '@emilia-protocol/gate/adapters/supabase';
 *
 *   const gate = createGate({ manifest: createSupabaseManifest(), trustedKeys: [ISSUER], store: sharedConsumptionStore });
 *   // client: anything with .query(sql) (node-postgres / a Supabase RPC wrapper).
 *   await guardSupabaseMutation(gate, client, {
 *     op: 'sql.destructive', params: { sql: 'DELETE FROM payments WHERE id=1', table: 'payments' }, receipt,
 *   });
 */
import {
  canonicalActuatorObject,
  createAdapter,
  manifestFromPack,
  hashCanonical,
} from './_kit.js';
import { executeWithGateAllowance } from '../allowance.js';

export const RLS_DEFINITION_BINDING_VERSION = 'EP-SUPABASE-RLS-DEFINITION-v1';
const SUPABASE_RLS_ALLOWANCE_UNIT = 'RLSCHANGE';

const DESTRUCTIVE = /\b(delete|drop|truncate|alter\s+table)\b/i;
const UPDATE_NO_WHERE = /\bupdate\b(?:(?!\bwhere\b).)*$/is;

/** Heuristic: is this SQL destructive (DELETE/DROP/TRUNCATE/ALTER, or UPDATE without WHERE)? */
export function isDestructiveSql(sql) {
  const s = String(sql || '');
  return DESTRUCTIVE.test(s) || UPDATE_NO_WHERE.test(s.trim());
}

/** Canonical hash of a SQL statement, whitespace-collapsed and lowercased. */
export function statementHash(sql) {
  return hashCanonical(String(sql || '').replace(/\s+/g, ' ').trim().toLowerCase());
}

/** Digest the exact canonical RLS definition without placing it in evidence. */
export function rlsDefinitionDigest(definition) {
  return hashCanonical({
    version: RLS_DEFINITION_BINDING_VERSION,
    definition,
  });
}

export const SUPABASE_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'supabase.sql.destructive', label: 'Destructive SQL', action_type: 'supabase.sql.destructive',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'supabase', tool: 'execute_sql' },
    why: 'DELETE/DROP/TRUNCATE/ALTER destroys or rewrites system-of-record state. Bind the exact statement.',
    execution_binding: { required_fields: ['action_type', 'statement_hash'] },
  }),
  Object.freeze({
    id: 'supabase.data.export', label: 'Bulk data export', action_type: 'supabase.data.export',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'supabase', tool: 'export_table' },
    why: 'Moves data out of its system of record. Bind table + recipient to the approval.',
    execution_binding: { required_fields: ['action_type', 'table', 'recipient'] },
  }),
  Object.freeze({
    id: 'supabase.rls.change', label: 'RLS policy change', action_type: 'supabase.rls.change',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'supabase', tool: 'alter_policy' },
    why: 'Changes who can read/write rows. Row-Level-Security changes deserve the two-person rule.',
    execution_binding: {
      required_fields: [
        'action_type', 'table', 'policy', 'rls_definition_digest', 'rls_definition_version',
      ],
    },
  }),
]);

const OPS = {
  'sql.destructive': {
    selector: { protocol: 'supabase', tool: 'execute_sql' },
    observed: (p) => ({ action_type: 'supabase.sql.destructive', statement_hash: statementHash(p.sql) }),
    actuator: (p, observed) => ({ ...observed, sql: p.sql }),
    perform: (client, p) => client.query(p.sql),
  },
  'data.export': {
    selector: { protocol: 'supabase', tool: 'export_table' },
    observed: (p) => ({ action_type: 'supabase.data.export', table: p.table, recipient: p.recipient }),
    perform: (client, p) => client.export(p.table, p.recipient),
  },
  'rls.change': {
    selector: { protocol: 'supabase', tool: 'alter_policy' },
    observed: (p) => ({
      action_type: 'supabase.rls.change',
      table: p.table,
      policy: p.policy,
      rls_definition_digest: rlsDefinitionDigest(p.definition),
      rls_definition_version: RLS_DEFINITION_BINDING_VERSION,
    }),
    actuator: (p, observed) => ({ ...observed, definition: p.definition }),
    perform: (client, p) => client.alterPolicy(p.table, p.policy, p.definition),
  },
};

const adapter = createAdapter({ system: 'supabase', ops: OPS });
export const SUPABASE_OPS = adapter.OPS;
const supabaseAllowanceConnectors = new WeakMap<object, {
  client: any;
  connectorInstanceId: string;
}>();

export function createSupabaseManifest(extraActions = []) {
  return manifestFromPack(SUPABASE_ACTION_PACK, extraActions);
}

/**
 * Guard a destructive Supabase/Postgres mutation behind the gate.
 * @param {object} gate    a gate built with createSupabaseManifest()
 * @param {object} client  a client exposing { query(sql), export(table,recipient), alterPolicy(table,policy,def) }
 * @param {object} args    { op:'sql.destructive'|'data.export'|'rls.change', params, receipt }
 * @throws Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the statement never executes
 */
export function guardSupabaseMutation(gate, client, args) {
  return adapter.guard(gate, client, args);
}

/** Bind a typed RLS client to the project identity returned by a trusted provider probe. */
export async function createSupabaseAllowanceConnector({
  client,
}: {
  client?: any;
} = {}) {
  if (!client || typeof client.alterPolicy !== 'function') {
    throw new TypeError('createSupabaseAllowanceConnector requires a typed RLS client');
  }
  let projectRef;
  try {
    const url = new URL(client.supabaseUrl);
    const match = /^([a-z0-9-]{1,63})\.supabase\.co$/i.exec(url.hostname);
    projectRef = match?.[1];
  } catch {
    projectRef = undefined;
  }
  if (!projectRef) {
    throw new TypeError('Supabase client does not expose a valid project URL');
  }
  const connectorInstanceId = `supabase:project:${projectRef}`;
  const connector = Object.freeze({});
  supabaseAllowanceConnectors.set(connector, { client, connectorInstanceId });
  return connector;
}

/**
 * Replace one specifically bound RLS policy under a signed Gate allowance.
 *
 * Arbitrary SQL is intentionally excluded: the wrapper binds table, policy,
 * canonical definition digest, definition version, and operation identifier,
 * then invokes only the typed alterPolicy actuator.
 */
export function guardSupabaseAllowanceMutation({
  connector,
  params,
  operationId,
  ...allowanceOptions
}) {
  const configured = supabaseAllowanceConnectors.get(connector);
  if (!configured) throw new TypeError('guardSupabaseAllowanceMutation requires a configured Supabase allowance connector');
  const { client, connectorInstanceId } = configured;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new TypeError('guardSupabaseAllowanceMutation requires RLS policy params');
  }
  for (const field of ['table', 'policy', 'definition']) {
    if (typeof params[field] !== 'string' || params[field].length === 0) {
      throw new TypeError(`guardSupabaseAllowanceMutation requires params.${field}`);
    }
  }
  const input = canonicalActuatorObject({
    table: params.table,
    policy: params.policy,
    definition: params.definition,
  });
  const action = {
    action_type: 'supabase.rls.change',
    table: input.table,
    policy: input.policy,
    rls_definition_digest: rlsDefinitionDigest(input.definition),
    rls_definition_version: RLS_DEFINITION_BINDING_VERSION,
    rls_definition: input.definition,
    amount: 1,
    currency: SUPABASE_RLS_ALLOWANCE_UNIT,
    operation_id: operationId,
  };
  return executeWithGateAllowance({
    ...allowanceOptions,
    expected: {
      ...(allowanceOptions.expected || {}),
      connector_id: connectorInstanceId,
    },
    action,
    operationId,
    executeAction: (verifiedAction) => client.alterPolicy(
      verifiedAction.table,
      verifiedAction.policy,
      verifiedAction.rls_definition,
    ),
  });
}

export default {
  SUPABASE_ACTION_PACK, SUPABASE_OPS, createSupabaseManifest, guardSupabaseMutation,
  guardSupabaseAllowanceMutation,
  createSupabaseAllowanceConnector,
  isDestructiveSql, statementHash, rlsDefinitionDigest, RLS_DEFINITION_BINDING_VERSION,
};
