// SPDX-License-Identifier: Apache-2.0
// Adoption-only WebAuthn ceremonies. These helpers produce public evidence for
// the synthetic, no-egress Agent Adoption MVP. They do not enroll Class-A
// approvers, touch provider credentials, or authorize/execute an external act.

import { createHash, timingSafeEqual } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { canonicalize } from '../canonical-json.js';
import { coseToSpkiP256 } from '../webauthn.js';

export const AGENT_ADOPTION_WEBAUTHN_VERSION = 'EP-AGENT-ADOPTION-WEBAUTHN-v1';
export const AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE =
  'ep.agent-adoption.webauthn.registration.v1';
export const AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE =
  'ep.agent-adoption.webauthn.assertion.v1';
export const AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY =
  'public_no_egress_agent_adoption_evidence_only_not_real_money_not_provider_credentials_not_civil_identity_not_certification_not_marketplace_not_production_execution';
export const AGENT_ADOPTION_WEBAUTHN_CONTEXT_TTL_MS = 5 * 60 * 1000;

const CHALLENGE_DOMAIN = 'EMILIA_AGENT_ADOPTION_WEBAUTHN_CHALLENGE_V1\0';
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.-]{2,127}$/;
const PURPOSE_PATTERN = /^synthetic_[a-z0-9][a-z0-9:_.-]{2,117}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const RP_ID_PATTERN = /^(?:localhost|(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/;
const CONTEXT_KEYS = new Set([
  '@version',
  'context_type',
  'claim_boundary',
  'tenant_id',
  'adoption_id',
  'candidate_digest',
  'bond_digest',
  'bond_purpose',
  'nonce',
  'issued_at',
  'expires_at',
  'rp_id',
  'origin',
]);
const TRANSPORTS = new Set<AuthenticatorTransportFuture>([
  'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb',
]);
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_CLIENT_DATA_BYTES = 8 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 16 * 1024;
const MAX_COSE_KEY_B64URL_CHARS = 1_368;
const MAX_SPKI_B64URL_CHARS = 512;
const MAX_CREDENTIAL_ID_CHARS = 1_024;
const MAX_JSON_DEPTH = 12;
const MAX_JSON_NODES = 512;

type ContextType =
  | typeof AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE
  | typeof AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE;

export interface AgentAdoptionWebAuthnContextInput {
  tenantId: string;
  adoptionId: string;
  candidateDigest: string;
  bondDigest: string;
  bondPurpose: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  rpId: string;
  origin: string;
}

interface AgentAdoptionWebAuthnContextBase {
  '@version': typeof AGENT_ADOPTION_WEBAUTHN_VERSION;
  context_type: ContextType;
  claim_boundary: typeof AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY;
  tenant_id: string;
  adoption_id: string;
  candidate_digest: string;
  bond_digest: string;
  bond_purpose: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  rp_id: string;
  origin: string;
}

export interface AgentAdoptionRegistrationContext extends AgentAdoptionWebAuthnContextBase {
  context_type: typeof AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE;
}

export interface AgentAdoptionAssertionContext extends AgentAdoptionWebAuthnContextBase {
  context_type: typeof AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE;
}

export type AgentAdoptionWebAuthnContext =
  | AgentAdoptionRegistrationContext
  | AgentAdoptionAssertionContext;

export interface AgentAdoptionCredentialMaterial {
  claim_boundary: typeof AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY;
  algorithm: 'ES256';
  curve: 'P-256';
  credential_id: string;
  public_key_cose: string;
  public_key_spki: string;
  transports: AuthenticatorTransportFuture[] | null;
  device_type: 'singleDevice' | 'multiDevice';
  backed_up: boolean;
  sign_count: number;
  counter_supported: boolean;
  rp_id: string;
  origin: string;
}

export interface AgentAdoptionRegistrationCeremony {
  context: AgentAdoptionRegistrationContext;
  challenge: string;
  rp_id: string;
  origin: string;
  expires_at: string;
  options: Record<string, unknown>;
}

export interface AgentAdoptionAssertionCeremony {
  context: AgentAdoptionAssertionContext;
  challenge: string;
  rp_id: string;
  origin: string;
  expires_at: string;
  credential_id: string;
  options: Record<string, unknown>;
}

export interface AgentAdoptionAssertionVerification {
  claim_boundary: typeof AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY;
  credential_id: string;
  transports: AuthenticatorTransportFuture[] | null;
  device_type: 'singleDevice' | 'multiDevice';
  backed_up: boolean;
  sign_count: number;
  counter_supported: boolean;
  rp_id: string;
  origin: string;
}

export class AgentAdoptionWebAuthnError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentAdoptionWebAuthnError';
    this.code = code;
  }
}

function refusal(code: string, message: string, cause?: unknown): AgentAdoptionWebAuthnError {
  return new AgentAdoptionWebAuthnError(code, message, cause === undefined ? undefined : { cause });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, keys: Set<string>): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function validInstant(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 32) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function validRpOrigin(rpId: unknown, origin: unknown): boolean {
  if (typeof rpId !== 'string' || !RP_ID_PATTERN.test(rpId)
      || typeof origin !== 'string' || origin.length > 512) return false;
  try {
    const parsed = new URL(origin);
    const localDevelopment = rpId === 'localhost'
      && parsed.hostname === 'localhost'
      && parsed.protocol === 'http:';
    if (parsed.protocol !== 'https:' && !localDevelopment) return false;
    if (parsed.username || parsed.password || parsed.origin !== origin) return false;
    if (parsed.hostname !== rpId && !parsed.hostname.endsWith(`.${rpId}`)) return false;
    return true;
  } catch {
    return false;
  }
}

function validateContext(
  value: unknown,
  expectedType?: ContextType,
): asserts value is AgentAdoptionWebAuthnContext {
  if (!isRecord(value) || !exactKeys(value, CONTEXT_KEYS)
      || value['@version'] !== AGENT_ADOPTION_WEBAUTHN_VERSION
      || value.claim_boundary !== AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY
      || ![AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE,
        AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE].includes(value.context_type as ContextType)
      || (expectedType !== undefined && value.context_type !== expectedType)) {
    throw refusal('context_invalid', 'Agent Adoption WebAuthn context is malformed.');
  }
  if (typeof value.tenant_id !== 'string' || !ID_PATTERN.test(value.tenant_id)) {
    throw refusal('context_invalid', 'Agent Adoption tenant identifier is invalid.');
  }
  if (typeof value.adoption_id !== 'string' || !ID_PATTERN.test(value.adoption_id)) {
    throw refusal('context_invalid', 'Agent adoption identifier is invalid.');
  }
  if (typeof value.candidate_digest !== 'string' || !DIGEST_PATTERN.test(value.candidate_digest)) {
    throw refusal('context_invalid', 'Agent adoption candidate digest is invalid.');
  }
  if (typeof value.bond_digest !== 'string' || !DIGEST_PATTERN.test(value.bond_digest)) {
    throw refusal('context_invalid', 'Agent adoption bond digest is invalid.');
  }
  if (typeof value.bond_purpose !== 'string' || !PURPOSE_PATTERN.test(value.bond_purpose)) {
    throw refusal('context_invalid', 'Agent adoption bond purpose is invalid.');
  }
  if (typeof value.nonce !== 'string' || !NONCE_PATTERN.test(value.nonce)) {
    throw refusal('context_invalid', 'Agent adoption nonce is invalid.');
  }
  if (!validInstant(value.issued_at)) {
    throw refusal('context_invalid', 'Agent adoption issued time is invalid.');
  }
  if (!validInstant(value.expires_at)) {
    throw refusal('context_invalid', 'Agent adoption expiry is invalid.');
  }
  const issued = Date.parse(value.issued_at);
  const expires = Date.parse(value.expires_at);
  if (expires <= issued || expires - issued > AGENT_ADOPTION_WEBAUTHN_CONTEXT_TTL_MS) {
    throw refusal('context_invalid', 'Agent adoption expiry must be after issuance and within five minutes.');
  }
  if (!validRpOrigin(value.rp_id, value.origin)) {
    throw refusal('context_invalid', 'Agent adoption RP ID or origin is invalid.');
  }
}

function buildContext(
  type: ContextType,
  input: AgentAdoptionWebAuthnContextInput,
): AgentAdoptionWebAuthnContext {
  if (!isRecord(input)) {
    throw refusal('context_invalid', 'Agent Adoption WebAuthn context input is malformed.');
  }
  const context = {
    '@version': AGENT_ADOPTION_WEBAUTHN_VERSION,
    context_type: type,
    claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
    tenant_id: input.tenantId,
    adoption_id: input.adoptionId,
    candidate_digest: input.candidateDigest,
    bond_digest: input.bondDigest,
    bond_purpose: input.bondPurpose,
    nonce: input.nonce,
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
    rp_id: input.rpId,
    origin: input.origin,
  };
  validateContext(context, type);
  return Object.freeze(context) as AgentAdoptionWebAuthnContext;
}

export function buildAgentAdoptionRegistrationContext(
  input: AgentAdoptionWebAuthnContextInput,
): AgentAdoptionRegistrationContext {
  return buildContext(
    AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE,
    input,
  ) as AgentAdoptionRegistrationContext;
}

export function buildAgentAdoptionAssertionContext(
  input: AgentAdoptionWebAuthnContextInput,
): AgentAdoptionAssertionContext {
  return buildContext(
    AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE,
    input,
  ) as AgentAdoptionAssertionContext;
}

export function agentAdoptionWebAuthnChallenge(context: AgentAdoptionWebAuthnContext): string {
  validateContext(context);
  return createHash('sha256')
    .update(CHALLENGE_DOMAIN, 'utf8')
    .update(canonicalize(context), 'utf8')
    .digest('base64url');
}

type NowInput = number | Date | (() => number | Date);

function nowMillis(now: NowInput | undefined): number {
  const candidate = typeof now === 'function' ? now() : (now ?? Date.now());
  const value = candidate instanceof Date ? candidate.getTime() : candidate;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw refusal('time_invalid', 'Verification time is invalid.');
  }
  return value;
}

function requireActiveContext(context: AgentAdoptionWebAuthnContext, now?: NowInput): void {
  const current = nowMillis(now);
  if (current < Date.parse(context.issued_at)) {
    throw refusal('context_not_yet_valid', 'Agent Adoption WebAuthn context is not yet valid.');
  }
  if (current >= Date.parse(context.expires_at)) {
    throw refusal('context_expired', 'Agent Adoption WebAuthn context has expired.');
  }
}

function validBase64url(value: unknown, maxChars: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxChars
      || !BASE64URL_PATTERN.test(value)) return false;
  try {
    return Buffer.from(value, 'base64url').toString('base64url') === value;
  } catch {
    return false;
  }
}

function credentialId(value: unknown): value is string {
  return validBase64url(value, MAX_CREDENTIAL_ID_CHARS);
}

function transports(value: unknown): AuthenticatorTransportFuture[] | null {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.length > TRANSPORTS.size) {
    throw refusal('credential_invalid', 'Credential transports are invalid.');
  }
  const result: AuthenticatorTransportFuture[] = [];
  for (const transport of value) {
    if (typeof transport !== 'string'
        || !TRANSPORTS.has(transport as AuthenticatorTransportFuture)
        || result.includes(transport as AuthenticatorTransportFuture)) {
      throw refusal('credential_invalid', 'Credential transports are invalid.');
    }
    result.push(transport as AuthenticatorTransportFuture);
  }
  return result;
}

function deviceType(value: unknown): 'singleDevice' | 'multiDevice' {
  if (value !== 'singleDevice' && value !== 'multiDevice') {
    throw refusal('credential_invalid', 'Credential device type is invalid.');
  }
  return value;
}

function signCount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 0xffff_ffff) {
    throw refusal('credential_invalid', 'Credential sign count is invalid.');
  }
  return value as number;
}

function validateCredentialShape(
  value: unknown,
  context: AgentAdoptionWebAuthnContext,
): asserts value is AgentAdoptionCredentialMaterial {
  if (!isRecord(value)
      || value.claim_boundary !== AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY
      || value.algorithm !== 'ES256'
      || value.curve !== 'P-256'
      || !credentialId(value.credential_id)
      || !validBase64url(value.public_key_cose, MAX_COSE_KEY_B64URL_CHARS)
      || !validBase64url(value.public_key_spki, MAX_SPKI_B64URL_CHARS)
      || typeof value.backed_up !== 'boolean'
      || typeof value.counter_supported !== 'boolean'
      || value.rp_id !== context.rp_id
      || value.origin !== context.origin) {
    throw refusal('credential_invalid', 'Agent Adoption credential material is invalid.');
  }
  transports(value.transports);
  deviceType(value.device_type);
  const counter = signCount(value.sign_count);
  if (value.counter_supported !== (counter > 0)) {
    throw refusal('credential_invalid', 'Credential counter support metadata is inconsistent.');
  }
}

function validateP256Material(
  credential: AgentAdoptionCredentialMaterial,
): Uint8Array<ArrayBuffer> {
  let derived: Buffer;
  try {
    derived = coseToSpkiP256(Buffer.from(credential.public_key_cose, 'base64url'));
  } catch (cause) {
    throw refusal('credential_key_unsupported', 'Credential is not ES256 P-256.', cause);
  }
  const expected = Buffer.from(credential.public_key_spki, 'base64url');
  if (derived.length !== expected.length || !timingSafeEqual(derived, expected)) {
    throw refusal('credential_key_mismatch', 'Credential public material is inconsistent.');
  }
  return new Uint8Array(Buffer.from(credential.public_key_cose, 'base64url'));
}

function assertBoundedJson(value: unknown, prefix: 'registration' | 'assertion'): void {
  let bytes = 0;
  let nodes = 0;
  const seen = new WeakSet<object>();
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const entry = stack.pop() as { value: unknown; depth: number };
    nodes += 1;
    if (nodes > MAX_JSON_NODES || entry.depth > MAX_JSON_DEPTH) {
      throw refusal(`${prefix}_response_too_large`, 'WebAuthn response exceeds structural limits.');
    }
    if (entry.value === null || typeof entry.value === 'boolean') {
      bytes += 4;
    } else if (typeof entry.value === 'number') {
      if (!Number.isFinite(entry.value)) {
        throw refusal(`${prefix}_response_invalid`, 'WebAuthn response is malformed.');
      }
      bytes += 16;
    } else if (typeof entry.value === 'string') {
      bytes += Buffer.byteLength(entry.value, 'utf8') + 2;
    } else if (Array.isArray(entry.value)) {
      if (seen.has(entry.value)) {
        throw refusal(`${prefix}_response_invalid`, 'WebAuthn response is cyclic.');
      }
      seen.add(entry.value);
      bytes += 2;
      for (const child of entry.value) stack.push({ value: child, depth: entry.depth + 1 });
    } else if (isRecord(entry.value)) {
      if (seen.has(entry.value)) {
        throw refusal(`${prefix}_response_invalid`, 'WebAuthn response is cyclic.');
      }
      seen.add(entry.value);
      const entries = Object.entries(entry.value);
      if (entries.length > 64) {
        throw refusal(`${prefix}_response_too_large`, 'WebAuthn response has too many members.');
      }
      bytes += 2;
      for (const [key, child] of entries) {
        bytes += Buffer.byteLength(key, 'utf8') + 2;
        stack.push({ value: child, depth: entry.depth + 1 });
      }
    } else {
      throw refusal(`${prefix}_response_invalid`, 'WebAuthn response is malformed.');
    }
    if (bytes > MAX_RESPONSE_BYTES) {
      throw refusal(`${prefix}_response_too_large`, 'WebAuthn response exceeds 256 KiB.');
    }
  }
}

function verifyClientData(
  encoded: unknown,
  expectedType: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string,
  prefix: 'registration' | 'assertion',
): void {
  if (!validBase64url(encoded, Math.ceil(MAX_CLIENT_DATA_BYTES * 4 / 3))) {
    throw refusal(`${prefix}_client_data_invalid`, 'WebAuthn client data is malformed.');
  }
  let parsed: unknown;
  try {
    const bytes = Buffer.from(encoded, 'base64url');
    if (bytes.length > MAX_CLIENT_DATA_BYTES) throw new Error('client data too large');
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch (cause) {
    throw refusal(`${prefix}_client_data_invalid`, 'WebAuthn client data is malformed.', cause);
  }
  if (!isRecord(parsed)
      || parsed.type !== expectedType
      || parsed.challenge !== challenge
      || parsed.origin !== origin
      || parsed.crossOrigin === true) {
    throw refusal(
      `${prefix}_client_data_invalid`,
      'WebAuthn client data does not match the exact ceremony.',
    );
  }
}

function validateCeremony(
  value: unknown,
  type: ContextType,
  expectedCredentialId?: string,
): asserts value is AgentAdoptionRegistrationCeremony | AgentAdoptionAssertionCeremony {
  if (!isRecord(value)) {
    throw refusal('ceremony_context_mismatch', 'WebAuthn ceremony is malformed.');
  }
  try {
    validateContext(value.context, type);
  } catch (cause) {
    throw refusal('ceremony_context_mismatch', 'WebAuthn ceremony context is invalid.', cause);
  }
  const context = value.context as AgentAdoptionWebAuthnContext;
  const challenge = agentAdoptionWebAuthnChallenge(context);
  if (value.challenge !== challenge
      || value.rp_id !== context.rp_id
      || value.origin !== context.origin
      || value.expires_at !== context.expires_at
      || (expectedCredentialId !== undefined && value.credential_id !== expectedCredentialId)) {
    throw refusal('ceremony_context_mismatch', 'WebAuthn ceremony does not match its context.');
  }
}

function preflightRegistrationResponse(
  attestation: unknown,
  ceremony: AgentAdoptionRegistrationCeremony,
): asserts attestation is Record<string, unknown> {
  assertBoundedJson(attestation, 'registration');
  if (!isRecord(attestation) || !credentialId(attestation.id)
      || attestation.rawId !== attestation.id || attestation.type !== 'public-key'
      || !isRecord(attestation.response)
      || !validBase64url(attestation.response.attestationObject, MAX_RESPONSE_BYTES * 2)) {
    throw refusal('registration_response_invalid', 'WebAuthn registration response is malformed.');
  }
  verifyClientData(
    attestation.response.clientDataJSON,
    'webauthn.create',
    ceremony.challenge,
    ceremony.origin,
    'registration',
  );
}

function preflightAssertionResponse(
  assertion: unknown,
  ceremony: AgentAdoptionAssertionCeremony,
  credential: AgentAdoptionCredentialMaterial,
): { counter: number } {
  assertBoundedJson(assertion, 'assertion');
  if (!isRecord(assertion) || assertion.id !== credential.credential_id
      || assertion.rawId !== credential.credential_id || assertion.type !== 'public-key'
      || !isRecord(assertion.response)
      || !validBase64url(assertion.response.authenticatorData,
        Math.ceil(MAX_AUTHENTICATOR_DATA_BYTES * 4 / 3))
      || !validBase64url(assertion.response.signature, MAX_RESPONSE_BYTES)) {
    throw refusal('assertion_credential_invalid', 'WebAuthn assertion credential is invalid.');
  }
  verifyClientData(
    assertion.response.clientDataJSON,
    'webauthn.get',
    ceremony.challenge,
    ceremony.origin,
    'assertion',
  );
  const authData = Buffer.from(assertion.response.authenticatorData, 'base64url');
  if (authData.length < 37 || authData.length > MAX_AUTHENTICATOR_DATA_BYTES) {
    throw refusal('assertion_authenticator_data_invalid', 'Authenticator data is malformed.');
  }
  const expectedRpHash = createHash('sha256').update(ceremony.rp_id, 'utf8').digest();
  if (!timingSafeEqual(authData.subarray(0, 32), expectedRpHash)) {
    throw refusal('assertion_rp_invalid', 'Authenticator data is for a different RP ID.');
  }
  const flags = authData[32];
  if ((flags & 0x01) === 0) {
    throw refusal('assertion_user_presence_required', 'User presence is required.');
  }
  if ((flags & 0x04) === 0) {
    throw refusal('assertion_user_verification_required', 'User verification is required.');
  }
  const counter = authData.readUInt32BE(33);
  if (!(counter === 0 && credential.sign_count === 0) && counter <= credential.sign_count) {
    throw refusal('assertion_counter_not_monotonic', 'Credential sign count did not increase.');
  }
  return { counter };
}

function freezeCeremony<T extends Record<string, unknown>>(ceremony: T): T {
  return Object.freeze({ ...ceremony, context: Object.freeze({ ...ceremony.context as object }) });
}

export async function createAgentAdoptionRegistrationOptions({
  context,
  rpName = 'EMILIA Agent Adoption',
  existingCredentials = [],
  now,
}: {
  context: AgentAdoptionRegistrationContext;
  rpName?: string;
  existingCredentials?: Array<{
    credential_id: string;
    transports?: AuthenticatorTransportFuture[] | null;
  }>;
  now?: NowInput;
}): Promise<AgentAdoptionRegistrationCeremony> {
  validateContext(context, AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE);
  requireActiveContext(context, now);
  if (typeof rpName !== 'string' || rpName.length === 0 || rpName.length > 128
      || rpName.trim() !== rpName || !Array.isArray(existingCredentials)
      || existingCredentials.length > 64) {
    throw refusal('registration_options_invalid', 'Registration option input is invalid.');
  }
  const excluded = existingCredentials.map((credential) => {
    if (!isRecord(credential) || !credentialId(credential.credential_id)) {
      throw refusal('registration_options_invalid', 'Excluded credential is invalid.');
    }
    return {
      id: credential.credential_id,
      transports: transports(credential.transports) ?? undefined,
    };
  });
  const challenge = agentAdoptionWebAuthnChallenge(context);
  let options: any;
  try {
    options = await generateRegistrationOptions({
      rpName,
      rpID: context.rp_id,
      userID: Buffer.from(context.candidate_digest.slice('sha256:'.length), 'hex'),
      userName: context.adoption_id,
      userDisplayName: context.adoption_id,
      challenge,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7],
      excludeCredentials: excluded,
    });
  } catch (cause) {
    throw refusal('registration_options_failed', 'Registration options could not be generated.', cause);
  }
  if (!isRecord(options) || options.challenge !== challenge
      || !isRecord(options.rp) || options.rp.id !== context.rp_id) {
    throw refusal('registration_options_failed', 'Generated registration options widened the ceremony.');
  }
  return freezeCeremony({
    context,
    challenge,
    rp_id: context.rp_id,
    origin: context.origin,
    expires_at: context.expires_at,
    options,
  }) as AgentAdoptionRegistrationCeremony;
}

export async function verifyAgentAdoptionRegistration({
  ceremony,
  attestation,
  now,
}: {
  ceremony: AgentAdoptionRegistrationCeremony;
  attestation: unknown;
  now?: NowInput;
}): Promise<AgentAdoptionCredentialMaterial> {
  validateCeremony(ceremony, AGENT_ADOPTION_WEBAUTHN_REGISTRATION_CONTEXT_TYPE);
  requireActiveContext(ceremony.context, now);
  preflightRegistrationResponse(attestation, ceremony);
  let verification: any;
  try {
    verification = await verifyRegistrationResponse({
      response: attestation as any,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: ceremony.origin,
      expectedRPID: ceremony.rp_id,
      expectedType: 'webauthn.create',
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7],
    });
  } catch (cause) {
    throw refusal('registration_verification_failed', 'WebAuthn registration did not verify.', cause);
  }
  if (!verification?.verified || !isRecord(verification.registrationInfo)) {
    throw refusal('registration_verification_failed', 'WebAuthn registration did not verify.');
  }
  const info = verification.registrationInfo;
  if (info.userVerified !== true) {
    throw refusal(
      'registration_user_verification_required',
      'WebAuthn registration did not prove user verification.',
    );
  }
  if (info.origin !== ceremony.origin || info.rpID !== ceremony.rp_id) {
    throw refusal('registration_scope_invalid', 'WebAuthn registration scope does not match.');
  }
  if (typeof info.credentialBackedUp !== 'boolean') {
    throw refusal('registration_metadata_invalid', 'Registration backup metadata is missing.');
  }
  if (!isRecord(info.credential) || info.credential.id !== attestation.id
      || !(info.credential.publicKey instanceof Uint8Array)
      || info.credential.publicKey.byteLength === 0
      || info.credential.publicKey.byteLength > 1_024) {
    throw refusal('registration_credential_invalid', 'Registered credential is malformed.');
  }
  let spki: Buffer;
  try {
    spki = coseToSpkiP256(info.credential.publicKey);
  } catch (cause) {
    throw refusal('registration_key_unsupported', 'Registration requires ES256 P-256.', cause);
  }
  const counter = signCount(info.credential.counter ?? 0);
  const result: AgentAdoptionCredentialMaterial = {
    claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
    algorithm: 'ES256',
    curve: 'P-256',
    credential_id: info.credential.id,
    public_key_cose: Buffer.from(info.credential.publicKey).toString('base64url'),
    public_key_spki: spki.toString('base64url'),
    transports: transports(info.credential.transports),
    device_type: deviceType(info.credentialDeviceType),
    backed_up: info.credentialBackedUp === true,
    sign_count: counter,
    counter_supported: counter > 0,
    rp_id: ceremony.rp_id,
    origin: ceremony.origin,
  };
  return Object.freeze({
    ...result,
    transports: result.transports === null ? null : Object.freeze([...result.transports]),
  }) as AgentAdoptionCredentialMaterial;
}

export async function createAgentAdoptionAssertionOptions({
  context,
  credential,
  now,
}: {
  context: AgentAdoptionAssertionContext;
  credential: AgentAdoptionCredentialMaterial;
  now?: NowInput;
}): Promise<AgentAdoptionAssertionCeremony> {
  validateContext(context, AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE);
  requireActiveContext(context, now);
  validateCredentialShape(credential, context);
  const challenge = agentAdoptionWebAuthnChallenge(context);
  const credentialTransports = transports(credential.transports) ?? undefined;
  let options: any;
  try {
    options = await generateAuthenticationOptions({
      rpID: context.rp_id,
      challenge,
      allowCredentials: [{
        id: credential.credential_id,
        transports: credentialTransports,
      }],
      userVerification: 'required',
    });
  } catch (cause) {
    throw refusal('assertion_options_failed', 'Assertion options could not be generated.', cause);
  }
  if (!isRecord(options) || options.challenge !== challenge || options.rpId !== context.rp_id
      || !Array.isArray(options.allowCredentials)
      || options.allowCredentials.length !== 1
      || !isRecord(options.allowCredentials[0])
      || options.allowCredentials[0].id !== credential.credential_id) {
    throw refusal('assertion_options_failed', 'Generated assertion options widened the ceremony.');
  }
  return freezeCeremony({
    context,
    challenge,
    rp_id: context.rp_id,
    origin: context.origin,
    expires_at: context.expires_at,
    credential_id: credential.credential_id,
    options,
  }) as AgentAdoptionAssertionCeremony;
}

export async function verifyAgentAdoptionAssertion({
  ceremony,
  assertion,
  credential,
  now,
}: {
  ceremony: AgentAdoptionAssertionCeremony;
  assertion: unknown;
  credential: AgentAdoptionCredentialMaterial;
  now?: NowInput;
}): Promise<AgentAdoptionAssertionVerification> {
  validateCeremony(
    ceremony,
    AGENT_ADOPTION_WEBAUTHN_ASSERTION_CONTEXT_TYPE,
    credential?.credential_id,
  );
  requireActiveContext(ceremony.context, now);
  validateCredentialShape(credential, ceremony.context);
  const publicKey = validateP256Material(credential);
  const preflight = preflightAssertionResponse(assertion, ceremony, credential);
  let verification: any;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion as any,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: ceremony.origin,
      expectedRPID: ceremony.rp_id,
      expectedType: 'webauthn.get',
      credential: {
        id: credential.credential_id,
        publicKey,
        counter: credential.sign_count,
        transports: transports(credential.transports) ?? undefined,
      },
      requireUserVerification: true,
    });
  } catch (cause) {
    throw refusal('assertion_verification_failed', 'WebAuthn assertion did not verify.', cause);
  }
  if (!verification?.verified || !isRecord(verification.authenticationInfo)) {
    throw refusal('assertion_verification_failed', 'WebAuthn assertion did not verify.');
  }
  const info = verification.authenticationInfo;
  if (info.credentialID !== credential.credential_id) {
    throw refusal('assertion_credential_invalid', 'Verified assertion used a different credential.');
  }
  if (info.userVerified !== true) {
    throw refusal('assertion_user_verification_required', 'Verified assertion did not prove UV.');
  }
  if (info.origin !== ceremony.origin || info.rpID !== ceremony.rp_id) {
    throw refusal('assertion_scope_invalid', 'Verified assertion scope does not match.');
  }
  if (typeof info.credentialBackedUp !== 'boolean') {
    throw refusal('assertion_metadata_invalid', 'Assertion backup metadata is missing.');
  }
  const counter = signCount(info.newCounter);
  if (counter !== preflight.counter
      || (!(counter === 0 && credential.sign_count === 0) && counter <= credential.sign_count)) {
    throw refusal('assertion_counter_not_monotonic', 'Credential sign count did not increase.');
  }
  return Object.freeze({
    claim_boundary: AGENT_ADOPTION_WEBAUTHN_CLAIM_BOUNDARY,
    credential_id: credential.credential_id,
    transports: credential.transports === null
      ? null
      : Object.freeze([...credential.transports]),
    device_type: deviceType(info.credentialDeviceType),
    backed_up: info.credentialBackedUp === true,
    sign_count: counter,
    counter_supported: counter > 0,
    rp_id: ceremony.rp_id,
    origin: ceremony.origin,
  }) as AgentAdoptionAssertionVerification;
}
