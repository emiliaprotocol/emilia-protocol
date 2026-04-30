// SPDX-License-Identifier: Apache-2.0
//
// GET /api/handshake-policies — list active handshake policies.
//
// Read-only listing of rows from the handshake_policies table. Returns the
// policy_id (UUID FK target for POST /api/handshake), the human-readable
// policy_key, version, name, and mode. Filters to status='active' so callers
// don't accidentally start a handshake against a deprecated policy.
//
// Auth-gated to a valid EP API key. The result is operator metadata — not
// secret, but exposing it to unauthenticated callers reveals the operator's
// policy lineup, which is unnecessary for the public surface.
//
// Used by tests/k6/baseline.js to resolve a real policy_id at startup; also
// useful for any client that needs to find the UUID for a known policy_key.

import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { EP_ERROR_CODES } from '@/lib/errors/taxonomy';
import { epError } from '@/lib/errors/response';
import { logger } from '@/lib/logger.js';

export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epError(EP_ERROR_CODES.UNAUTHORIZED);

    const supabase = getGuardedClient();
    const { searchParams } = new URL(request.url);
    const policyKey = searchParams.get('policy_key');

    let query = supabase
      .from('handshake_policies')
      .select('policy_id, policy_key, version, name, mode, status')
      .eq('status', 'active')
      .order('policy_key', { ascending: true })
      .order('version', { ascending: false });

    if (policyKey) {
      query = query.eq('policy_key', policyKey);
    }

    const { data, error } = await query;
    if (error) {
      logger.error('handshake-policies list error:', error);
      return epError(EP_ERROR_CODES.INTERNAL, error.message);
    }

    return NextResponse.json({
      protocol_version: 'EP/1.1',
      policies: data || [],
      _note: 'Use policy_id as the policy_id field in POST /api/handshake.',
    });
  } catch (err) {
    logger.error('handshake-policies error:', err);
    return epError(EP_ERROR_CODES.INTERNAL);
  }
}
