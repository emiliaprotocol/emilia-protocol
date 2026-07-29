// SPDX-License-Identifier: Apache-2.0
/** Durable, tenant-scoped replay protection for action-refusal acceptance. */

import type { ActionRefusalReplayStore } from './action-refusal-statement.js';

export const ACTION_REFUSAL_REPLAY_FUNCTION =
  'emilia_gate_evidence.consume_action_refusal';

export const ACTION_REFUSAL_POSTGRES_SQL = Object.freeze({
  consume: `SELECT accepted, reason
FROM ${ACTION_REFUSAL_REPLAY_FUNCTION}($1, $2, $3, $4, $5)`,
});

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CLOSED_REASONS = new Set(['statement_replay', 'nonce_equivocation']);

function scoped(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`${label} must be a non-empty control-free string of at most 256 characters`);
  }
  return value;
}

function outcome(result: any): { accepted: boolean; reason: string | null } {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows)
      || result.rows.length !== 1 || typeof result.rows[0]?.accepted !== 'boolean') {
    throw new Error('action refusal replay outcome is unproven');
  }
  const { accepted, reason } = result.rows[0];
  if (accepted) {
    if (reason !== null && reason !== undefined && reason !== '') {
      throw new Error('accepted action refusal replay outcome carried a reason');
    }
    return { accepted: true, reason: null };
  }
  if (!CLOSED_REASONS.has(reason)) {
    throw new Error('action refusal replay outcome returned an unknown reason');
  }
  return { accepted: false, reason };
}

/**
 * The query credential is the authorization boundary. The migration grants it
 * EXECUTE on one SECURITY DEFINER function and no direct table writes.
 */
export function createPostgresActionRefusalReplayStore({
  query,
  tenantId,
  gateId,
}: {
  query?: (sql: string, params?: any[]) => Promise<any>;
  tenantId?: string;
  gateId?: string;
} = {}): ActionRefusalReplayStore & {
  scope: Readonly<{ tenantId: string; gateId: string }>;
} {
  if (typeof query !== 'function') {
    throw new TypeError('createPostgresActionRefusalReplayStore requires a pg-style query function');
  }
  const tenant = scoped(tenantId, 'tenantId');
  const gate = scoped(gateId, 'gateId');
  return Object.freeze({
    durable: true as const,
    scope: Object.freeze({ tenantId: tenant, gateId: gate }),
    async consume(relyingPartyId: string, nonce: string, refusalDigest: string) {
      const rp = scoped(relyingPartyId, 'relyingPartyId');
      const replayNonce = scoped(nonce, 'nonce');
      if (!DIGEST.test(refusalDigest)) throw new TypeError('refusalDigest is invalid');
      return outcome(await query(ACTION_REFUSAL_POSTGRES_SQL.consume, [
        tenant,
        gate,
        rp,
        replayNonce,
        refusalDigest,
      ]));
    },
  });
}

export default {
  ACTION_REFUSAL_REPLAY_FUNCTION,
  ACTION_REFUSAL_POSTGRES_SQL,
  createPostgresActionRefusalReplayStore,
};
