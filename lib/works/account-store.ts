// SPDX-License-Identifier: Apache-2.0

import type { SupabaseClient } from '@supabase/supabase-js';

import { getServiceClient } from '../supabase.js';
import type {
  AccountStoreResult,
  WorksAccountStore,
  WorksSessionActor,
} from './account-service.js';

type RpcClient = Pick<SupabaseClient, 'rpc'>;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function failure(code = 'store_unavailable'): AccountStoreResult<never> {
  return { ok: false, code };
}

function actor(value: unknown): WorksSessionActor | null {
  if (!isObject(value)
    || typeof value.account_id !== 'string'
    || typeof value.owner_entity_id !== 'string'
    || typeof value.display_name !== 'string'
    || typeof value.email_notifications !== 'boolean') return null;
  return {
    accountId: value.account_id,
    ownerEntityId: value.owner_entity_id,
    displayName: value.display_name,
    emailVerified: true,
    emailNotifications: value.email_notifications,
    claimsVerified: false,
    authMethod: 'email_code',
  };
}

async function rpc(client: RpcClient, name: string, args: Record<string, unknown>) {
  try {
    const result = await client.rpc(name, args);
    if (result?.error) {
      return failure(result.error.code === 'WA001' ? 'request_limited' : 'store_unavailable');
    }
    return { ok: true as const, data: result?.data };
  } catch {
    return failure();
  }
}

export function createSupabaseWorksAccountStore(
  client: RpcClient = getServiceClient(),
): WorksAccountStore {
  return {
    async beginChallenge(input) {
      const result = await rpc(client, 'begin_works_account_email_challenge', {
        p_challenge_id: input.challengeId,
        p_email_digest: input.emailDigest,
        p_client_digest: input.clientDigest,
        p_code_digest: input.codeDigest,
        p_mode: input.mode,
        p_display_name: input.displayName,
        p_consent: input.consent,
        p_email_notifications: input.emailNotifications,
      });
      if (!result.ok) return result;
      return isObject(result.data) && result.data.challenge_id === input.challengeId
        ? { ok: true, challengeId: input.challengeId }
        : failure('store_invalid');
    },
    async markDelivery(input) {
      const result = await rpc(client, 'mark_works_account_email_delivery', {
        p_challenge_id: input.challengeId,
        p_code_digest: input.codeDigest,
        p_delivered: input.delivered,
      });
      if (!result.ok) return result;
      return result.data === true ? { ok: true } : failure('challenge_unavailable');
    },
    async exchangeChallenge(input) {
      const result = await rpc(client, 'exchange_works_account_email_challenge', {
        p_challenge_id: input.challengeId,
        p_email_digest: input.emailDigest,
        p_code_digest: input.codeDigest,
        p_session_token_digest: input.sessionDigest,
        p_session_expires_at: input.sessionExpiresAt,
      });
      if (!result.ok) return result;
      if (!isObject(result.data) || result.data.status !== 'AUTHENTICATED') {
        return failure('challenge_unavailable');
      }
      const parsed = actor(result.data);
      return parsed ? { ok: true, actor: parsed } : failure('store_invalid');
    },
    async readSession(sessionDigest) {
      const result = await rpc(client, 'read_works_account_session', {
        p_session_token_digest: sessionDigest,
      });
      if (!result.ok) return result;
      if (result.data === null) return { ok: true, actor: null };
      const parsed = actor(result.data);
      return parsed ? { ok: true, actor: parsed } : failure('store_invalid');
    },
    async revokeSession(sessionDigest) {
      const result = await rpc(client, 'revoke_works_account_session', {
        p_session_token_digest: sessionDigest,
      });
      if (!result.ok) return result;
      return typeof result.data === 'boolean'
        ? { ok: true, revoked: result.data }
        : failure('store_invalid');
    },
  };
}
