// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import type { SupabaseClient } from '@supabase/supabase-js';

const ARENA_TOKEN = /^ep_arena_[0-9a-f]{64}$/;
const ARENA_SESSION = /^arena_session_[0-9a-f]{32}$/;

export type ArenaSessionRow = Record<string, any> & {
  id: string;
  tenant_id: string;
  session_id: string;
  status: string;
  expires_at: string;
  agent_name: string;
  challenge_id: string;
  challenge_version: number;
  allowance_profile: Record<string, unknown>;
  issuer_id: string;
  key_id: string;
  public_key: string;
  private_key_encrypted: string;
};

type ArenaAuthResult =
  | { ok: true; session: ArenaSessionRow; token_hash: string }
  | { ok: false; status: number; reason: string };

export async function authenticateArenaRequest(
  request: Pick<Request, 'headers'>,
  sessionId: string,
  {
    client,
    now = Date.now(),
  }: { client?: SupabaseClient; now?: number } = {},
): Promise<ArenaAuthResult> {
  const header = request.headers.get('authorization');
  const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
  if (!ARENA_TOKEN.test(token) || !ARENA_SESSION.test(sessionId)) {
    return { ok: false, status: 401, reason: 'arena_credential_invalid' };
  }
  const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
  let store = client;
  if (!store) {
    try {
      const { getServiceClient } = await import('@/lib/supabase');
      store = getServiceClient();
    } catch {
      return { ok: false, status: 503, reason: 'arena_auth_unavailable' };
    }
  }
  let result: { data: any; error: any };
  try {
    result = await store
      .from('arena_sessions')
      .select('*')
      .eq('token_hash', tokenHash)
      .eq('session_id', sessionId)
      .maybeSingle();
  } catch {
    return { ok: false, status: 503, reason: 'arena_auth_unavailable' };
  }
  if (result.error) return { ok: false, status: 503, reason: 'arena_auth_unavailable' };
  if (!result.data) return { ok: false, status: 404, reason: 'arena_session_not_found' };
  if (result.data.status !== 'active') {
    return { ok: false, status: 403, reason: 'arena_session_inactive' };
  }
  const expiresAt = Date.parse(result.data.expires_at);
  if (!Number.isSafeInteger(now) || !Number.isFinite(expiresAt) || now >= expiresAt) {
    return { ok: false, status: 403, reason: 'arena_session_expired' };
  }
  return { ok: true, session: result.data as ArenaSessionRow, token_hash: tokenHash };
}

export function arenaTokenFromRequest(request: Pick<Request, 'headers'>): string | null {
  const header = request.headers.get('authorization');
  const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
  return ARENA_TOKEN.test(token) ? token : null;
}
