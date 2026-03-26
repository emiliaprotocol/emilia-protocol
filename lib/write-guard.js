/**
 * Write-Guarded Supabase Client
 *
 * Runtime enforcement of write-path discipline. Routes and non-canonical
 * code get a client that BLOCKS inserts/updates/deletes on trust-bearing
 * tables. Only protocolWrite() and the canonical layer use the unrestricted
 * service client.
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

import { getServiceClient } from './supabase.js';

// Tables that MUST go through protocolWrite()
const TRUST_TABLES = Object.freeze([
  'receipts',
  'commits',
  'disputes',
  'trust_reports',
  'protocol_events',
  'handshakes',
  'handshake_parties',
  'handshake_presentations',
  'handshake_bindings',
  'handshake_results',
  'handshake_policies',
  'handshake_events',
  'handshake_consumptions',
  'signoff_challenges',
  'signoff_attestations',
  'signoff_consumptions',
  'signoff_events',
  'eye_observations',
  'eye_advisories',
  'eye_suppressions',
]);

/**
 * Returns a write-guarded Supabase client.
 * Can read any table, but mutations on TRUST_TABLES throw immediately.
 * Use this in route handlers instead of getServiceClient().
 */
export function getGuardedClient() {
  const client = getServiceClient();
  return createWriteGuard(client);
}

function createWriteGuard(client) {
  // Gracefully handle test mocks or misconfigured clients without .from()
  if (!client || typeof client.from !== 'function') {
    return client;
  }

  const originalFrom = client.from.bind(client);

  // Return a proxy object that intercepts .from() calls WITHOUT
  // mutating the original client. This prevents the guard from
  // bleeding into getServiceClient() calls in protocol-write.js.
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === 'from') {
        return (table) => {
          const query = originalFrom(table);

          if (TRUST_TABLES.includes(table)) {
            // Return a proxy that blocks mutating operations
            const blockedOps = new Set(['insert', 'update', 'upsert', 'delete']);
            return new Proxy(query, {
              get(qTarget, qProp, qReceiver) {
                if (blockedOps.has(qProp)) {
                  return (...args) => {
                    throw new Error(
                      `WRITE_DISCIPLINE_VIOLATION: Direct ${qProp}() on trust table "${table}" is forbidden. ` +
                      `All trust-bearing writes MUST go through protocolWrite(). ` +
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
