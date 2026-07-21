/**
 * Write-Guarded Supabase Client
 *
 * Runtime enforcement of write-path discipline. Routes and non-canonical
 * code get a client that BLOCKS inserts/updates/deletes on trust-bearing
 * tables. Only protocolWrite(), narrowly scoped security-definer RPCs, and the
 * canonical layer may mutate them through the unrestricted service client.
 *
 * This is ENFORCEMENT, not convention.
 *
 * IMPORTANT: This module creates a lightweight proxy — it does NOT mutate
 * the original client. This is critical because getServiceClient() may
 * return the same object reference, and protocol-write.js needs the
 * unrestricted client for event persistence.
 *
 * @license Apache-2.0
 */

import type { SupabaseClient } from '@supabase/supabase-js';
import { getServiceClient } from './supabase.js';

// Tables that MUST go through protocolWrite()
const TRUST_TABLES: readonly string[] = Object.freeze([
  'receipts',
  'commits',
  'disputes',
  'trust_reports',
  'protocol_events',
  'security_events',
  'authorities',
  'handshakes',
  'handshake_parties',
  'handshake_presentations',
  'handshake_bindings',
  'handshake_results',
  'handshake_policies',
  'handshake_events',
  'handshake_consumptions',
  'policy_rollouts',
  'signoff_challenges',
  'signoff_attestations',
  'signoff_consumptions',
  'signoff_events',
  'eye_observations',
  'eye_advisories',
  'eye_suppressions',
  'zk_proofs',
  'mobile_kv_state',
  'mobile_pairings',
  'mobile_sessions',
  'mobile_enrollments',
  'mobile_counters',
  'mobile_audit_records',
  'mobile_evidence_records',
  'mobile_actions',
  'mobile_action_challenges',
  'mobile_action_groups',
  'mobile_action_revisions',
  'mobile_action_events',
  'mobile_action_operations',
  'mobile_executor_keys',
  'mobile_action_alignments',
]);

/**
 * Normalize a table identifier before matching it against TRUST_TABLES, so the
 * guard can't be slipped with a schema prefix, quoting, casing, or whitespace
 * (e.g. "public.receipts", '"Receipts"', " receipts "). Defense-in-depth. (NASTY-6)
 */
function normalizeTableName(table: unknown): string {
  if (typeof table !== 'string') return '';
  let t = table.trim().toLowerCase();
  if (t.includes('.')) t = t.split('.').pop() as string; // drop schema prefix
  return t.replace(/["'`]/g, '').trim();
}

/**
 * Returns a write-guarded Supabase client.
 * Can read any table, but mutations on TRUST_TABLES throw immediately.
 * Use this in route handlers instead of getServiceClient().
 */
export function getGuardedClient(): SupabaseClient {
  const client = getServiceClient();
  return createWriteGuard(client);
}

function createWriteGuard(client: SupabaseClient): SupabaseClient {
  // Gracefully handle test mocks or misconfigured clients without .from()
  if (!client || typeof client.from !== 'function') {
    return client;
  }

  const originalFrom = client.from.bind(client);
  // Re-wrap any schema-scoped builder so `.schema('public').from('receipts')`
  // cannot bypass the guard the way a bare `.from()` interception would miss it.
  const originalSchema = typeof client.schema === 'function' ? client.schema.bind(client) : null;

  // Return a proxy object that intercepts .from() calls WITHOUT
  // mutating the original client. This prevents the guard from
  // bleeding into getServiceClient() calls in protocol-write.js.
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === 'schema' && originalSchema) {
        // schema() returns a PostgrestClient, not a SupabaseClient — but it is
        // duck-type compatible with everything createWriteGuard touches
        // (.from(), optionally .schema()), which is what the guard actually
        // relies on at runtime.
        return (schemaName: string) => createWriteGuard(originalSchema(schemaName) as unknown as SupabaseClient);
      }
      if (prop === 'from') {
        return (table: string) => {
          const query: any = originalFrom(table as any);

          if (TRUST_TABLES.includes(normalizeTableName(table))) {
            // Return a proxy that blocks mutating operations
            const blockedOps = new Set(['insert', 'update', 'upsert', 'delete']);
            return new Proxy(query, {
              get(qTarget: any, qProp: string | symbol, qReceiver: any) {
                if (blockedOps.has(qProp as string)) {
                  return (...args: unknown[]) => {
                    throw new Error(
                      `WRITE_DISCIPLINE_VIOLATION: Direct ${String(qProp)}() on trust table "${table}" is forbidden. ` +
                      `All trust-bearing writes MUST go through protocolWrite() or an approved security-definer RPC. ` +
                      `This is a runtime enforcement — not a convention.`
                    );
                  };
                }
                return Reflect.get(qTarget, qProp, qReceiver);
              },
            });
          }

          return query;
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/** Guard that the exported TRUST_TABLES list is complete */
export const _internals = { TRUST_TABLES };
