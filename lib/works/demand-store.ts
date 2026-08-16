// SPDX-License-Identifier: Apache-2.0

import type { SupabaseClient } from '@supabase/supabase-js';

import { getServiceClient } from '../supabase.js';
import type { AuthorityDemandStore } from './demand-service.js';

type RpcClient = Pick<SupabaseClient, 'rpc'>;

function failure(code = 'store_unavailable') {
  return { ok: false as const, code, detail: 'Authority demand storage is unavailable.' };
}

function isObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

async function call(client: RpcClient, name: string, args: Record<string, unknown>) {
  try {
    const result = await client.rpc(name, args);
    if (result?.error) {
      const code = result.error.code === 'AR004' ? 'token_unavailable'
        : result.error.code === 'AR005' ? 'record_unavailable'
          : 'store_unavailable';
      return failure(code);
    }
    return { ok: true as const, data: result?.data };
  } catch {
    return failure();
  }
}

function exactCounts(value: unknown) {
  if (!isObject(value)
      || !Number.isInteger(value.verified_requesters)
      || !Number.isInteger(value.verified_organizations)
      || (value.verified_requesters as number) < 0
      || (value.verified_organizations as number) < 0) return null;
  return {
    verified_requesters: value.verified_requesters as number,
    verified_organizations: value.verified_organizations as number,
  };
}

export function createSupabaseAuthorityDemandStore(
  client: RpcClient = getServiceClient(),
): AuthorityDemandStore {
  return {
    async createRequest(input) {
      const result = await call(client, 'create_works_authority_demand_request', {
        p_record_id: input.record_id,
        p_requester_digest: input.requester_digest,
        p_organization_domain: input.organization_domain,
        p_verification_token_digest: input.verification_token_digest,
        p_verification_expires_at: input.verification_expires_at,
        p_created_at: input.created_at,
      });
      if (!result.ok) return result;
      if (!isObject(result.data)
          || !['PENDING', 'ALREADY_VERIFIED'].includes(String(result.data.status))) {
        return failure('store_invalid');
      }
      return {
        ok: true,
        status: result.data.status as 'PENDING' | 'ALREADY_VERIFIED',
      };
    },

    async verifyRequest(input) {
      const result = await call(client, 'verify_works_authority_demand_request', {
        p_verification_token_digest: input.verification_token_digest,
        p_verified_at: input.verified_at,
      });
      if (!result.ok) return result;
      const counts = exactCounts(result.data);
      if (!counts || !isObject(result.data) || typeof result.data.record_id !== 'string') {
        return failure('store_invalid');
      }
      return { ok: true, result: { record_id: result.data.record_id, ...counts } };
    },

    async readCounts(recordId) {
      const result = await call(client, 'read_works_authority_demand_counts', {
        p_record_id: recordId,
      });
      if (!result.ok) return result;
      if (result.data === null) return failure('record_unavailable');
      const counts = exactCounts(result.data);
      return counts ? { ok: true, counts } : failure('store_invalid');
    },
  };
}
