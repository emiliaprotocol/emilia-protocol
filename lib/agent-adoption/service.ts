// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import type { SupabaseClient } from '@supabase/supabase-js';

import { canonicalize } from '@/lib/canonical-json';
import { open, seal } from '@/lib/crypto/secret-box';
import { getWebAuthnConfig } from '@/lib/env';
import { getServiceClient } from '@/lib/supabase';
import { createOperatingBond, AgentAdoptionInputError } from './core';
import {
  AgentAdoptionTrialError,
  provisionBoundAgentTrial,
  submitBoundAgentTrial,
  type AgentAdoptionAuthorization,
} from './trial';
import {
  AgentAdoptionWebAuthnError,
  AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
  buildAgentAdoptionAssertionContext,
  buildAgentAdoptionRegistrationContext,
  createAgentAdoptionAssertionOptions,
  createAgentAdoptionRegistrationOptions,
  verifyAgentAdoptionAssertion,
  verifyAgentAdoptionRegistration,
  type AgentAdoptionAssertionCeremony,
  type AgentAdoptionCredentialMaterial,
  type AgentAdoptionRegistrationCeremony,
} from './webauthn';

const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_TOKEN = /^eaa1_[0-9a-f]{64}$/;
const SHARE_ID = /^agent_share_[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,1024}$/;
const CEREMONY_TOKEN = /^epenc:v1:[A-Za-z0-9_-]{40,131072}$/;
const CEREMONY_ENVELOPE_VERSION = 'EP-AGENT-ADOPTION-CEREMONY-ENVELOPE-v1';

type RpcClient = Pick<SupabaseClient, 'rpc'>;
type RpcError = Readonly<{ code?: string; message?: string; details?: string }>;
type CeremonyPurpose = 'registration' | 'assertion';

type CeremonyEnvelope = Readonly<{
  '@version': typeof CEREMONY_ENVELOPE_VERSION;
  purpose: CeremonyPurpose;
  challenge_token: string;
  ceremony: AgentAdoptionRegistrationCeremony | AgentAdoptionAssertionCeremony;
  credential?: AgentAdoptionCredentialMaterial;
}>;

export class AgentAdoptionServiceError extends Error {
  constructor(public status: number, public code: string, message = code, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentAdoptionServiceError';
  }
}

function fail(status: number, code: string, message = code, cause?: unknown): never {
  throw new AgentAdoptionServiceError(
    status,
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function isRecord(value: unknown): value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, any> {
  return isRecord(value)
    && Reflect.ownKeys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function contentDigest(domain: string, value: unknown): string {
  try {
    return `sha256:${crypto.createHash('sha256')
      .update(domain, 'utf8')
      .update('\0', 'utf8')
      .update(canonicalize(value), 'utf8')
      .digest('hex')}`;
  } catch (cause) {
    fail(400, 'agent_adoption_response_invalid', 'The passkey response is malformed.', cause);
  }
}

function rpcStatus(error: RpcError | null | undefined): number {
  if (error?.code === '22023') return 400;
  if (error?.code === 'P0002') return 404;
  if (error?.code === '55000' || error?.code === '23505') return 409;
  return 503;
}

async function callRpc(
  client: RpcClient,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, any>> {
  let result: any;
  try {
    result = await client.rpc(name, args);
  } catch (cause) {
    fail(503, 'agent_adoption_store_unavailable', 'Agent Adoption storage is unavailable.', cause);
  }
  if (result?.error) {
    const status = rpcStatus(result.error);
    fail(
      status,
      status === 404 ? 'agent_adoption_not_found'
        : status === 409 ? 'agent_adoption_conflict'
          : status === 400 ? 'agent_adoption_invalid'
            : 'agent_adoption_store_unavailable',
      status === 404 ? 'Agent Adoption session not found.'
        : status === 409 ? 'Agent Adoption state no longer permits this operation.'
          : status === 400 ? 'Agent Adoption input is invalid.'
            : 'Agent Adoption storage is unavailable.',
      result.error,
    );
  }
  if (!isRecord(result?.data)) {
    fail(503, 'agent_adoption_store_invalid', 'Agent Adoption storage returned an invalid result.');
  }
  return result.data;
}

function configuredRp(): { rpId: string; origin: string } {
  const config = getWebAuthnConfig();
  if (config.rpId && config.origin) return { rpId: config.rpId, origin: config.origin };
  if (config.isDevelopment) return { rpId: 'localhost', origin: 'http://localhost:3000' };
  fail(503, 'agent_adoption_webauthn_unconfigured', 'Agent Adoption passkeys are not configured.');
}

function sealCeremony(envelope: CeremonyEnvelope): string {
  const encoded = seal(canonicalize(envelope));
  if (typeof encoded !== 'string' || !CEREMONY_TOKEN.test(encoded)) {
    fail(503, 'agent_adoption_ceremony_unavailable', 'The passkey ceremony could not be created.');
  }
  return encoded;
}

function openCeremony(
  value: unknown,
  purpose: CeremonyPurpose,
  authorization: AgentAdoptionAuthorization,
): CeremonyEnvelope {
  if (typeof value !== 'string' || !CEREMONY_TOKEN.test(value)) {
    fail(400, 'agent_adoption_ceremony_invalid', 'The passkey ceremony is invalid.');
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(open(value));
  } catch (cause) {
    fail(400, 'agent_adoption_ceremony_invalid', 'The passkey ceremony is invalid.', cause);
  }
  const expectedKeys = purpose === 'assertion'
    ? ['@version', 'purpose', 'challenge_token', 'ceremony', 'credential']
    : ['@version', 'purpose', 'challenge_token', 'ceremony'];
  if (!exactObject(decoded, expectedKeys)
      || decoded['@version'] !== CEREMONY_ENVELOPE_VERSION
      || decoded.purpose !== purpose
      || typeof decoded.challenge_token !== 'string'
      || !isRecord(decoded.ceremony)
      || decoded.ceremony.context?.adoption_id !== authorization.sessionId
      || decoded.ceremony.context?.tenant_id !== authorization.session?.tenant_id
      || decoded.ceremony.context?.candidate_digest !== authorization.session?.candidate_digest
      || decoded.ceremony.context?.bond_digest !== authorization.session?.bond_digest) {
    fail(400, 'agent_adoption_ceremony_invalid', 'The passkey ceremony does not match this adoption.');
  }
  return decoded as CeremonyEnvelope;
}

function challengeContext(
  stored: Record<string, any>,
  authorization: AgentAdoptionAuthorization,
) {
  if (stored.tenant_id !== authorization.session?.tenant_id
      || stored.adoption_id !== authorization.sessionId
      || stored.candidate_digest !== authorization.session?.candidate_digest
      || stored.bond_digest !== authorization.session?.bond_digest
      || stored.bond_purpose !== 'synthetic_agent_adoption_operating_bond_v1'
      || typeof stored.challenge_token !== 'string'
      || typeof stored.issued_at !== 'string'
      || typeof stored.expires_at !== 'string') {
    fail(503, 'agent_adoption_store_invalid', 'Stored passkey context is inconsistent.');
  }
  const rp = configuredRp();
  return {
    tenantId: stored.tenant_id,
    adoptionId: stored.adoption_id,
    candidateDigest: stored.candidate_digest,
    bondDigest: stored.bond_digest,
    bondPurpose: stored.bond_purpose,
    nonce: stored.challenge_token,
    issuedAt: stored.issued_at,
    expiresAt: stored.expires_at,
    rpId: rp.rpId,
    origin: rp.origin,
  };
}

function normalizeCredential(value: unknown): AgentAdoptionCredentialMaterial {
  if (!isRecord(value)) {
    fail(503, 'agent_adoption_store_invalid', 'Stored passkey material is unavailable.');
  }
  const credential = {
    claim_boundary: value.claim_boundary,
    algorithm: value.algorithm,
    curve: value.curve,
    credential_id: value.credential_id,
    public_key_cose: value.public_key_cose,
    public_key_spki: value.public_key_spki,
    transports: value.transports ?? null,
    device_type: value.device_type,
    backed_up: value.backed_up,
    sign_count: value.sign_count,
    counter_supported: value.counter_supported,
    rp_id: value.rp_id,
    origin: value.origin,
  } as AgentAdoptionCredentialMaterial;
  if (credential.claim_boundary !== AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY
      || !CREDENTIAL_ID.test(credential.credential_id ?? '')) {
    fail(503, 'agent_adoption_store_invalid', 'Stored passkey material is inconsistent.');
  }
  return credential;
}

export async function createAgentAdoptionSession({
  input,
  client = getServiceClient(),
}: {
  input: unknown;
  client?: RpcClient;
}) {
  let built: ReturnType<typeof createOperatingBond>;
  try {
    built = createOperatingBond(input);
  } catch (cause) {
    if (cause instanceof AgentAdoptionInputError) {
      fail(400, cause.code, cause.message, cause);
    }
    throw cause;
  }
  const stored = await callRpc(client, 'create_agent_adoption_session', {
    p_agent_label: built.candidate.label,
    p_candidate_digest: built.candidate_digest,
    p_bond_digest: built.bond_digest,
    p_operating_bond: built.bond,
    p_public_projection: built.public_projection,
  });
  if (!SESSION_ID.test(stored.session_id ?? '')
      || !SESSION_TOKEN.test(stored.session_token ?? '')
      || typeof stored.created_at !== 'string'
      || typeof stored.expires_at !== 'string'
      || !Number.isFinite(Date.parse(stored.created_at))
      || !Number.isFinite(Date.parse(stored.expires_at))
      || Date.parse(stored.expires_at) <= Date.now()
      || Date.parse(stored.expires_at) - Date.parse(stored.created_at) > 30 * 24 * 60 * 60 * 1000
      || stored.candidate_digest !== built.candidate_digest
      || stored.bond_digest !== built.bond_digest
      || !sameCanonical(stored.operating_bond, built.bond)
      || !sameCanonical(stored.public_projection, built.public_projection)) {
    fail(503, 'agent_adoption_store_invalid', 'Stored Agent Adoption state is inconsistent.');
  }
  return Object.freeze({
    session_id: stored.session_id,
    session_token: stored.session_token,
    authority_state: 'draft' as const,
    passkey_asserted: false,
    bond_digest: built.bond_digest,
    expires_at: stored.expires_at,
  });
}

export async function authorizeAgentAdoptionSession({
  request,
  sessionId,
  client = getServiceClient(),
}: {
  request: Pick<Request, 'headers'>;
  sessionId: string;
  client?: RpcClient;
}): Promise<AgentAdoptionAuthorization> {
  const header = request.headers.get('authorization');
  const sessionToken = header?.startsWith('Bearer ') ? header.slice(7) : '';
  if (!SESSION_ID.test(sessionId) || !SESSION_TOKEN.test(sessionToken)) {
    fail(401, 'agent_adoption_unauthorized', 'Agent Adoption session credential is missing or invalid.');
  }
  let session: Record<string, any>;
  try {
    session = await callRpc(client, 'read_agent_adoption_session', {
      p_adoption_id: sessionId,
      p_session_token: sessionToken,
    });
  } catch (cause) {
    if (cause instanceof AgentAdoptionServiceError && cause.status === 404) {
      fail(401, 'agent_adoption_unauthorized', 'Agent Adoption session credential is missing or invalid.');
    }
    throw cause;
  }
  if (session.adoption_id !== sessionId
      || !SESSION_ID.test(session.tenant_id ?? '')
      || !DIGEST.test(session.candidate_digest ?? '')
      || !DIGEST.test(session.bond_digest ?? '')
      || typeof session.expires_at !== 'string'
      || !Number.isFinite(Date.parse(session.expires_at))) {
    fail(503, 'agent_adoption_store_invalid', 'Stored Agent Adoption state is inconsistent.');
  }
  if (Date.parse(session.expires_at) <= Date.now()) {
    fail(401, 'agent_adoption_unauthorized', 'Agent Adoption session credential is missing or invalid.');
  }
  if (session.status === 'revoked') {
    fail(410, 'agent_adoption_revoked', 'This Agent Adoption session was revoked.');
  }
  if (session.status !== 'active') {
    fail(409, 'agent_adoption_state_invalid', 'This Agent Adoption session is not active.');
  }
  return Object.freeze({ sessionId, sessionToken, session });
}

export async function createAgentAdoptionRegistrationCeremony({
  authorization,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  client?: RpcClient;
}) {
  const stored = await callRpc(client, 'create_agent_adoption_registration_challenge', {
    p_adoption_id: authorization.sessionId,
    p_session_token: authorization.sessionToken,
  });
  const context = buildAgentAdoptionRegistrationContext(challengeContext(stored, authorization));
  const ceremony = await createAgentAdoptionRegistrationOptions({ context });
  return Object.freeze({
    ceremony_token: sealCeremony({
      '@version': CEREMONY_ENVELOPE_VERSION,
      purpose: 'registration',
      challenge_token: stored.challenge_token,
      ceremony,
    }),
    options: ceremony.options,
    expires_at: ceremony.expires_at,
  });
}

export async function completeAgentAdoptionRegistration({
  authorization,
  input,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: RpcClient;
}) {
  if (!exactObject(input, ['ceremony_token', 'attestation'])) {
    fail(400, 'agent_adoption_registration_invalid', 'The passkey registration response is malformed.');
  }
  const envelope = openCeremony(input.ceremony_token, 'registration', authorization);
  let credential: AgentAdoptionCredentialMaterial;
  try {
    credential = await verifyAgentAdoptionRegistration({
      ceremony: envelope.ceremony as AgentAdoptionRegistrationCeremony,
      attestation: input.attestation,
    });
  } catch (cause) {
    if (cause instanceof AgentAdoptionWebAuthnError) {
      fail(400, cause.code, cause.message, cause);
    }
    throw cause;
  }
  const registrationDigest = contentDigest('EP-AGENT-ADOPTION-REGISTRATION-v1', {
    context: envelope.ceremony.context,
    attestation: input.attestation,
    credential,
  });
  const stored = await callRpc(client, 'complete_agent_adoption_registration', {
    p_adoption_id: authorization.sessionId,
    p_session_token: authorization.sessionToken,
    p_challenge_token: envelope.challenge_token,
    p_credential_id: credential.credential_id,
    p_public_key_cose: credential.public_key_cose,
    p_public_key_spki: credential.public_key_spki,
    p_algorithm: credential.algorithm,
    p_curve: credential.curve,
    p_transports: credential.transports,
    p_device_type: credential.device_type,
    p_backed_up: credential.backed_up,
    p_sign_count: credential.sign_count,
    p_counter_supported: credential.counter_supported,
    p_rp_id: credential.rp_id,
    p_origin: credential.origin,
    p_registration_digest: registrationDigest,
  });
  if (stored.credential_id !== credential.credential_id
      || stored.registration_digest !== registrationDigest) {
    fail(503, 'agent_adoption_store_invalid', 'Stored passkey registration is inconsistent.');
  }
  return Object.freeze({ credential_id: credential.credential_id, registered: true });
}

export async function createAgentAdoptionAssertionCeremony({
  authorization,
  input,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: RpcClient;
}) {
  if (!exactObject(input, ['credential_id']) || !CREDENTIAL_ID.test(input.credential_id)) {
    fail(400, 'agent_adoption_assertion_invalid', 'The passkey assertion request is malformed.');
  }
  const stored = await callRpc(client, 'create_agent_adoption_assertion_challenge', {
    p_adoption_id: authorization.sessionId,
    p_session_token: authorization.sessionToken,
    p_credential_id: input.credential_id,
  });
  const credential = normalizeCredential(stored.credential);
  if (credential.credential_id !== input.credential_id) {
    fail(503, 'agent_adoption_store_invalid', 'Stored passkey material is inconsistent.');
  }
  const context = buildAgentAdoptionAssertionContext(challengeContext(stored, authorization));
  const ceremony = await createAgentAdoptionAssertionOptions({ context, credential });
  return Object.freeze({
    ceremony_token: sealCeremony({
      '@version': CEREMONY_ENVELOPE_VERSION,
      purpose: 'assertion',
      challenge_token: stored.challenge_token,
      ceremony,
      credential,
    }),
    options: ceremony.options,
    expires_at: ceremony.expires_at,
  });
}

export async function completeAgentAdoptionAssertion({
  authorization,
  input,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: RpcClient;
}) {
  if (!exactObject(input, ['ceremony_token', 'assertion'])) {
    fail(400, 'agent_adoption_assertion_invalid', 'The passkey assertion response is malformed.');
  }
  const envelope = openCeremony(input.ceremony_token, 'assertion', authorization);
  const credential = normalizeCredential(envelope.credential);
  let verification: Awaited<ReturnType<typeof verifyAgentAdoptionAssertion>>;
  try {
    verification = await verifyAgentAdoptionAssertion({
      ceremony: envelope.ceremony as AgentAdoptionAssertionCeremony,
      assertion: input.assertion,
      credential,
    });
  } catch (cause) {
    if (cause instanceof AgentAdoptionWebAuthnError) {
      fail(400, cause.code, cause.message, cause);
    }
    throw cause;
  }
  const assertionDigest = contentDigest('EP-AGENT-ADOPTION-ASSERTION-v1', {
    context: envelope.ceremony.context,
    assertion: input.assertion,
    verification,
  });
  const stored = await callRpc(client, 'complete_agent_adoption_assertion', {
    p_adoption_id: authorization.sessionId,
    p_session_token: authorization.sessionToken,
    p_challenge_token: envelope.challenge_token,
    p_credential_id: verification.credential_id,
    p_new_counter: verification.sign_count,
    p_counter_supported: verification.counter_supported,
    p_device_type: verification.device_type,
    p_backed_up: verification.backed_up,
    p_assertion_digest: assertionDigest,
  });
  if (!SESSION_ID.test(stored.bond_id ?? '')
      || stored.adoption_id !== authorization.sessionId
      || stored.bond_digest !== authorization.session?.bond_digest
      || stored.assertion_observation?.assertion_digest !== assertionDigest
      || !sameCanonical(stored.operating_bond, authorization.session?.operating_bond)) {
    fail(503, 'agent_adoption_store_invalid', 'Stored Operating Bond is inconsistent.');
  }
  return Object.freeze({
    session_id: authorization.sessionId,
    session_token: authorization.sessionToken,
    authority_state: 'asserted' as const,
    passkey_asserted: true,
    bond_id: stored.bond_id,
    bond_digest: stored.bond_digest,
  });
}

export async function provisionAgentAdoptionTrial({
  authorization,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  client?: SupabaseClient;
}) {
  try {
    const result = await provisionBoundAgentTrial({ authorization, client });
    return Object.freeze({ ...result, session_token: authorization.sessionToken });
  } catch (cause) {
    if (cause instanceof AgentAdoptionTrialError) {
      fail(cause.status, cause.code, cause.message, cause);
    }
    throw cause;
  }
}

export async function attemptAgentAdoptionTrial({
  authorization,
  input,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: SupabaseClient;
}) {
  try {
    return await submitBoundAgentTrial({ authorization, input, client });
  } catch (cause) {
    if (cause instanceof AgentAdoptionTrialError) {
      fail(cause.status, cause.code, cause.message, cause);
    }
    throw cause;
  }
}

export async function publishAgentAdoptionBond({
  authorization,
  input,
  client = getServiceClient(),
  now = Date.now(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: RpcClient;
  now?: number;
}) {
  if (!exactObject(input, ['bond_id'])
      || !SESSION_ID.test(input.bond_id)
      || input.bond_id !== authorization.session?.latest_bond_id) {
    fail(400, 'agent_adoption_share_invalid', 'The Operating Bond publication request is invalid.');
  }
  const stored = await callRpc(client, 'publish_agent_adoption_share', {
    p_adoption_id: authorization.sessionId,
    p_session_token: authorization.sessionToken,
    p_bond_id: input.bond_id,
  });
  if (!SHARE_ID.test(stored.share_id ?? '')
      || stored.projection?.bond_digest !== authorization.session?.bond_digest) {
    fail(503, 'agent_adoption_store_invalid', 'Stored public Operating Bond is inconsistent.');
  }
  return Object.freeze({
    share_id: stored.share_id,
    share_url: `/adopt/r/${stored.share_id}`,
    published_at: new Date(now).toISOString(),
  });
}

export async function revokeAgentAdoption({
  authorization,
  client = getServiceClient(),
}: {
  authorization: AgentAdoptionAuthorization;
  client?: RpcClient;
}) {
  const stored = await callRpc(client, 'revoke_agent_adoption', {
    p_adoption_id: authorization.sessionId,
    p_session_token: authorization.sessionToken,
    p_reason: 'user_revoked_agent_adoption',
    p_revocation_nonce: `earv1_${crypto.randomBytes(32).toString('hex')}`,
  });
  if (stored.status !== 'revoked' || stored.adoption_id !== authorization.sessionId) {
    fail(503, 'agent_adoption_store_invalid', 'Stored Agent Adoption revocation is inconsistent.');
  }
  return Object.freeze({ authority_state: 'revoked' as const, revoked_at: stored.revoked_at });
}

export async function loadPublicAgentAdoptionBond({
  shareId,
  client = getServiceClient(),
}: {
  shareId: string;
  client?: RpcClient;
}) {
  if (!SHARE_ID.test(shareId)) return null;
  let stored: Record<string, any>;
  try {
    stored = await callRpc(client, 'read_agent_adoption_share', { p_share_id: shareId });
  } catch (cause) {
    if (cause instanceof AgentAdoptionServiceError && cause.status === 404) return null;
    throw cause;
  }
  if (stored.share_id !== shareId || stored.revoked === true || stored.projection === null) return null;
  if (stored.revoked !== false
      || stored.projection?.['@version'] !== 'EP-OPERATING-BOND-PUBLIC-v1'
      || stored.projection?.share_id !== shareId
      || !DIGEST.test(stored.projection?.bond_digest ?? '')) {
    fail(503, 'agent_adoption_store_invalid', 'Stored public Operating Bond is inconsistent.');
  }
  return Object.freeze({
    share_id: shareId,
    revoked: false,
    created_at: stored.created_at,
    projection: stored.projection,
  });
}
