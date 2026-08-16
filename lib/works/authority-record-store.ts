// SPDX-License-Identifier: Apache-2.0

import type { SupabaseClient } from '@supabase/supabase-js';

import { getServiceClient } from '../supabase.js';
import type {
  AuthorityRecordStore,
  StoredAuthorityInvitation,
  StoredAuthorityOwnerState,
  StoredPublicAuthorityRecord,
} from './authority-record-service.js';

type RpcClient = Pick<SupabaseClient, 'rpc'>;
type Failure = { ok: false; code: string; detail: string };

function failure(code = 'store_unavailable'): Failure {
  return {
    ok: false,
    code,
    detail: code === 'store_invalid'
      ? 'Authority Record storage returned invalid data.'
      : 'Authority Record storage is unavailable.',
  };
}

function isObject(value: unknown): value is Record<string, any> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

async function rpc(client: RpcClient, name: string, args: Record<string, unknown>) {
  try {
    const result = await client.rpc(name, args);
    if (result?.error) {
      const code = result.error.code === '23505' || result.error.code === '55000'
        ? 'already_exists'
        : result.error.code === 'P0002'
          ? 'not_found'
          : result.error.code === 'AR001'
            ? 'invitation_unavailable'
            : result.error.code === 'AR002'
              ? 'owner_credential_invalid'
              : result.error.code === 'AR003'
                ? 'record_digest_mismatch'
                : 'store_unavailable';
      return failure(code);
    }
    return { ok: true as const, data: result?.data };
  } catch {
    return failure();
  }
}

function invitation(value: unknown): StoredAuthorityInvitation | null {
  if (!isObject(value)
      || typeof value.record_id !== 'string'
      || typeof value.record_digest !== 'string'
      || !isObject(value.projection)
      || typeof value.repository_url !== 'string'
      || typeof value.contact_route !== 'string'
      || typeof value.claim_challenge !== 'string'
      || typeof value.invitation_expires_at !== 'string'
      || (value.claimed_at !== null && typeof value.claimed_at !== 'string')) return null;
  return {
    record_id: value.record_id,
    record_digest: value.record_digest,
    projection: value.projection as any,
    repository_url: value.repository_url,
    contact_route: value.contact_route,
    claim_challenge: value.claim_challenge,
    invitation_expires_at: value.invitation_expires_at,
    claimed_at: value.claimed_at,
  };
}

function ownerState(value: unknown): StoredAuthorityOwnerState | null {
  if (!isObject(value)
      || typeof value.record_id !== 'string'
      || !Number.isInteger(value.current_version)
      || typeof value.current_digest !== 'string'
      || !isObject(value.current_projection)
      || typeof value.repository_url !== 'string'
      || !['CLAIMED_PRIVATE', 'PUBLISHED', 'WITHDRAWN'].includes(value.status)
      || (value.approved_at !== null && typeof value.approved_at !== 'string')
      || (value.withdrawn_at !== null && typeof value.withdrawn_at !== 'string')) return null;
  return {
    record_id: value.record_id,
    current_version: value.current_version,
    current_digest: value.current_digest,
    current_projection: value.current_projection as any,
    repository_url: value.repository_url,
    status: value.status,
    approved_at: value.approved_at,
    withdrawn_at: value.withdrawn_at,
  };
}

function publicRecord(value: unknown): StoredPublicAuthorityRecord | null {
  if (!isObject(value)
      || typeof value.record_id !== 'string'
      || !Number.isInteger(value.version)
      || typeof value.record_digest !== 'string'
      || typeof value.approved_at !== 'string'
      || !isObject(value.projection)) return null;
  return {
    record_id: value.record_id,
    version: value.version,
    record_digest: value.record_digest,
    approved_at: value.approved_at,
    projection: value.projection as any,
  };
}

export function createSupabaseAuthorityRecordStore(
  client: RpcClient = getServiceClient(),
): AuthorityRecordStore {
  return {
    async createDraft(input) {
      const result = await rpc(client, 'create_works_authority_record_draft', {
        p_record_id: input.record_id,
        p_record_digest: input.record_digest,
        p_projection: input.projection,
        p_repository_url: input.repository_url,
        p_contact_route: input.contact_route,
        p_created_by_entity_id: input.created_by_entity_id,
        p_invitation_token_digest: input.invitation_token_digest,
        p_claim_challenge: input.claim_challenge,
        p_invitation_expires_at: input.invitation_expires_at,
      });
      if (!result.ok) return result;
      if (!isObject(result.data) || result.data.record_id !== input.record_id) return failure('store_invalid');
      return { ok: true };
    },

    async inspectInvitation(tokenDigest) {
      const result = await rpc(client, 'inspect_works_authority_record_invitation', {
        p_invitation_token_digest: tokenDigest,
      });
      if (!result.ok) return result;
      if (result.data === null) return { ok: true, invitation: null };
      const normalized = invitation(result.data);
      return normalized ? { ok: true, invitation: normalized } : failure('store_invalid');
    },

    async claimInvitation(input) {
      const result = await rpc(client, 'claim_works_authority_record', {
        p_invitation_token_digest: input.invitation_token_digest,
        p_owner_token_digest: input.owner_token_digest,
        p_proof_url: input.proof_url,
        p_proof_revision: input.proof_revision,
        p_proof_digest: input.proof_digest,
        p_claimed_at: input.claimed_at,
      });
      if (!result.ok) return result;
      const state = ownerState(result.data);
      return state ? { ok: true, state } : failure('store_invalid');
    },

    async readOwnerState(recordId, tokenDigest) {
      const result = await rpc(client, 'read_works_authority_record_owner', {
        p_record_id: recordId,
        p_owner_token_digest: tokenDigest,
      });
      if (!result.ok) return result;
      if (result.data === null) return { ok: true, state: null };
      const state = ownerState(result.data);
      return state ? { ok: true, state } : failure('store_invalid');
    },

    async appendOwnerVersion(input) {
      const result = await rpc(client, 'append_works_authority_record_version', {
        p_record_id: input.record_id,
        p_owner_token_digest: input.owner_token_digest,
        p_record_digest: input.record_digest,
        p_projection: input.projection,
        p_created_at: input.created_at,
      });
      if (!result.ok) return result;
      const state = ownerState(result.data);
      return state ? { ok: true, state } : failure('store_invalid');
    },

    async approveOwnerVersion(input) {
      const result = await rpc(client, 'approve_works_authority_record_version', {
        p_record_id: input.record_id,
        p_owner_token_digest: input.owner_token_digest,
        p_record_digest: input.record_digest,
        p_approved_at: input.approved_at,
      });
      if (!result.ok) return result;
      const state = ownerState(result.data);
      return state ? { ok: true, state } : failure('store_invalid');
    },

    async withdrawOwnerRecord(input) {
      const result = await rpc(client, 'withdraw_works_authority_record', {
        p_record_id: input.record_id,
        p_owner_token_digest: input.owner_token_digest,
        p_withdrawn_at: input.withdrawn_at,
      });
      if (!result.ok) return result;
      const state = ownerState(result.data);
      return state ? { ok: true, state } : failure('store_invalid');
    },

    async readPublicRecord(recordId) {
      const result = await rpc(client, 'read_works_authority_record_public', {
        p_record_id: recordId,
      });
      if (!result.ok) return result;
      if (result.data === null) return { ok: true, record: null };
      const record = publicRecord(result.data);
      return record ? { ok: true, record } : failure('store_invalid');
    },

    async listPublicRecords() {
      const result = await rpc(client, 'list_works_authority_records_public', {});
      if (!result.ok) return result;
      if (!Array.isArray(result.data)) return failure('store_invalid');
      const records = result.data.map(publicRecord);
      return records.every((record) => record !== null)
        ? { ok: true, records: records as StoredPublicAuthorityRecord[] }
        : failure('store_invalid');
    },
  };
}
