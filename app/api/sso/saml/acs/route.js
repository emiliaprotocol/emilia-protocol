// SPDX-License-Identifier: Apache-2.0
// POST /api/sso/saml/acs — Assertion Consumer Service.
// Validates the signed SAML Response against the tenant's configured IdP cert,
// then resolves the asserted identity against the SCIM-provisioned directory.
// The signature/conditions/audience checks are done by node-saml (xml-crypto).

export const runtime = 'nodejs';

import crypto from 'node:crypto';
import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { buildSamlSp, validateSamlResponse } from '@/lib/sso/saml';
import { loadConnection, spOrigin } from '@/lib/sso/config';
import { mintSession, SESSION_COOKIE, SESSION_COOKIE_OPTIONS } from '@/lib/sso/session';
import { normalizeUserName } from '@/lib/scim/core';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

// T4-B: assertion replay window. node-saml already rejects assertions whose
// Conditions/NotOnOrAfter have passed, so the cache only needs to span a typical
// assertion lifetime + clock skew. 30 min is comfortably beyond both.
const REPLAY_TTL_MS = 30 * 60 * 1000;

/**
 * Record a consumed SAML Response and detect replays. Returns:
 *   'fresh'     — first time seen, recorded
 *   'replayed'  — this exact response was already consumed (reject!)
 *   'unavailable' — replay table unavailable (not yet migrated / transient DB
 *                   error); caller must fail closed.
 */
async function consumeSamlResponse(tenant, replayKey) {
  try {
    const supabase = getGuardedClient();
    const { error } = await supabase
      .from('saml_consumed_assertions')
      .insert({
        replay_key: replayKey,
        tenant_id: tenant,
        expires_at: new Date(Date.now() + REPLAY_TTL_MS).toISOString(),
      });
    if (!error) return 'fresh';
    if (error.code === '23505') return 'replayed';          // unique PK violation
    if (error.code === '42P01') {                            // relation does not exist
      logger.warn('[sso/saml/acs] replay table missing — apply migration 103; failing closed');
      return 'unavailable';
    }
    logger.warn('[sso/saml/acs] replay-cache insert failed; failing closed:', error.message);
    return 'unavailable';
  } catch (e) {
    logger.warn('[sso/saml/acs] replay-cache threw; failing closed:', e?.message);
    return 'unavailable';
  }
}

export async function POST(request) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return epProblem(400, 'invalid_acs_post', 'Expected an application/x-www-form-urlencoded SAML POST');
  }
  const samlResponse = form.get('SAMLResponse');
  const tenant = form.get('RelayState') || new URL(request.url).searchParams.get('tenant');
  if (!samlResponse) return epProblem(400, 'missing_saml_response', 'SAMLResponse is required');
  if (!tenant) return epProblem(400, 'missing_tenant', 'RelayState (tenant) is required');

  const { connection, error } = await loadConnection(tenant, 'saml');
  // Unified response for BOTH "unknown tenant" and "tenant without SAML" so this
  // unauthenticated endpoint can't be used as an oracle to enumerate the tenant
  // namespace. Same status + same generic body in both cases. (T4-A)
  if (error || !connection?.saml_idp_cert) {
    return epProblem(404, 'sso_not_configured', 'No SAML connection configured');
  }

  const origin = spOrigin(request);
  const sp = buildSamlSp({
    idpEntryPoint: connection.saml_idp_entry_point,
    idpCert: connection.saml_idp_cert,
    spEntityId: `${origin}/api/sso/saml/metadata`,
    acsUrl: `${origin}/api/sso/saml/acs`,
    audience: connection.saml_audience || `${origin}/api/sso/saml/metadata`,
    // Require a signed Response envelope by default (closes assertion-wrapping);
    // a tenant may opt out per-connection for unsigned IdP-initiated envelopes.
    wantAuthnResponseSigned: connection.saml_want_response_signed !== false,
  });

  const result = await validateSamlResponse(sp, String(samlResponse));
  if (!result.valid) {
    // A failed signature/conditions/audience check MUST NOT authenticate.
    logger.warn('[sso/saml/acs] rejected:', result.error);
    return epProblem(401, 'saml_validation_failed', result.error || 'SAML assertion did not validate');
  }

  // T4-B: one-time consumption. The response is cryptographically valid and
  // in-window; ensure it can't be replayed (esp. IdP-initiated responses, which
  // have no InResponseTo for node-saml to dedup on). Key off the exact validated
  // response bytes — any change would have already failed the signature check.
  const replayKey = crypto.createHash('sha256').update(String(samlResponse)).digest('hex');
  const consumption = await consumeSamlResponse(tenant, replayKey);
  if (consumption === 'replayed') {
    logger.warn('[sso/saml/acs] replay rejected', { tenant });
    return epProblem(401, 'saml_replay', 'This SAML response has already been consumed');
  }
  if (consumption !== 'fresh') {
    logger.warn('[sso/saml/acs] replay cache unavailable; refusing authentication', { tenant });
    return epProblem(503, 'saml_replay_cache_unavailable', 'SAML replay protection is unavailable');
  }

  const directory = await resolveDirectory(tenant, result.profile);

  // Mint the EP session — this is what "logged in" means. The session asserts
  // the verified identity; signing authority still requires the enrolled
  // passkey ceremony per action.
  const token = await mintSession({
    tenant,
    subject: result.profile.nameID,
    email: result.profile.email,
    protocol: 'saml',
    directory,
  });
  const res = NextResponse.json({
    authenticated: true,
    protocol: 'saml',
    tenant,
    identity: { nameID: result.profile.nameID, email: result.profile.email },
    directory,
    session: 'set',
  });
  res.cookies.set(SESSION_COOKIE, token, SESSION_COOKIE_OPTIONS);
  return res;
}

// Link the asserted identity to the SCIM-provisioned directory: is this a known,
// currently-active approver? (No JIT write — a deactivated/absent user is
// surfaced, not silently created.)
async function resolveDirectory(tenant, profile) {
  try {
    const supabase = getGuardedClient();
    const { data } = await supabase
      .from('scim_users')
      .select('id, active, display_name')
      .eq('tenant_id', tenant)
      .eq('user_name', normalizeUserName(profile.email || profile.nameID))
      .maybeSingle();
    if (!data) return { matched: false, active: false };
    return { matched: true, active: data.active !== false, user_id: data.id };
  } catch {
    return { matched: false, active: false, error: 'directory_lookup_failed' };
  }
}
