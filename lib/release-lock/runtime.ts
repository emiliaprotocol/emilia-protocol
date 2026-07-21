// SPDX-License-Identifier: Apache-2.0

import { getServiceClient } from '../supabase.js';
import { createAcrobatSignAdapter } from '../integrations/action-escrow/acrobat-sign.js';
import { createEscrowComAdapter } from '../integrations/action-escrow/escrow-com.js';
import { createReleaseLockAdapterBoundary } from './adapters.js';
import { createReleaseLockCrypto } from './crypto.js';
import { createResendReleaseLockInvitationAdapter } from './invitation-delivery.js';
import { createReleaseLockService } from './service.js';

/**
 * Resolver functions are pluggable per adapter kind (document / custodian /
 * invitation), each dispatching on a differently-shaped `request` descriptor
 * (see runtime.test.js) and returning a differently-shaped external adapter
 * object. `any` here matches that genuinely dynamic internal routing
 * contract, mirroring the same looseness `configuredAdapter()` in
 * adapters.ts already uses for the same values.
 */
type AdapterResolver = (request: any) => any;

let environmentInvitationAdapter: any = null;

function environmentText(name: string, max: number = 8192): string | null {
  const value = process.env[name]?.trim();
  return value && value.length <= max ? value : null;
}

function environmentJsonObject(name: string): Record<string, any> | null {
  const value = environmentText(name, 8192);
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    const prototype = parsed === null ? null : Object.getPrototypeOf(parsed);
    return parsed !== null
      && !Array.isArray(parsed)
      && (prototype === Object.prototype || prototype === null)
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function resolveEnvironmentDocumentAdapter(request: any): any {
  if (request?.provider !== 'acrobat_sign') return null;
  const apiOrigin = environmentText('RELEASE_LOCK_ACROBAT_SIGN_API_ORIGIN', 512);
  const oauthAccessToken = environmentText(
    'RELEASE_LOCK_ACROBAT_SIGN_OAUTH_ACCESS_TOKEN',
  );
  if (!apiOrigin || !oauthAccessToken) return null;
  try {
    return createAcrobatSignAdapter({
      apiOrigin,
      oauthAccessToken,
      fetch: globalThis.fetch,
    } as any);
  } catch {
    return null;
  }
}

/**
 * Mirrors the (non-exported) options type of createEscrowComAdapter in
 * lib/integrations/action-escrow/escrow-com.ts. Declared locally because
 * that adapter's option interface is private to its module; this shape must
 * be kept in sync with it by hand.
 */
interface EscrowComCustodianOptions {
  environment: 'sandbox' | 'production';
  email: string;
  apiKey: string;
  fetch: typeof fetch;
  customerDiligence: Record<string, any>;
  claimEffectBinding: (binding: object) => Promise<boolean>;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

function resolveEnvironmentCustodianAdapter(request: any): any {
  if (request?.provider !== 'escrow.com') return null;
  const environment = environmentText('RELEASE_LOCK_ESCROW_COM_ENVIRONMENT', 16);
  const email = environmentText('RELEASE_LOCK_ESCROW_COM_EMAIL', 320);
  const apiKey = environmentText('RELEASE_LOCK_ESCROW_COM_API_KEY', 4096);
  const customerDiligence = environmentJsonObject(
    'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
  );
  if (environment !== request.environment
      || !email
      || !apiKey
      || !customerDiligence
      || typeof request.claimEffectBinding !== 'function') {
    return null;
  }
  try {
    const custodianOptions: EscrowComCustodianOptions = {
      // createEscrowComAdapter validates this against ESCROW_ORIGINS at
      // runtime and throws on anything else, so the narrowing here just
      // matches its actual accepted domain, not a new guarantee.
      environment: environment as 'sandbox' | 'production',
      email,
      apiKey,
      fetch: globalThis.fetch,
      customerDiligence,
      claimEffectBinding: request.claimEffectBinding,
    };
    return createEscrowComAdapter(custodianOptions);
  } catch {
    return null;
  }
}

function resolveEnvironmentInvitationAdapter(request: any): any {
  if (request?.channel !== 'email') return null;
  const apiKey = environmentText('RESEND_API_KEY');
  const from = environmentText('RELEASE_LOCK_INVITATION_FROM', 320);
  const publicAppOrigin = environmentText('RELEASE_LOCK_PUBLIC_ORIGIN', 512);
  if (!apiKey || !from || !publicAppOrigin) return null;
  if (!environmentInvitationAdapter) {
    try {
      environmentInvitationAdapter = createResendReleaseLockInvitationAdapter({
        apiKey,
        from,
        publicAppOrigin,
        fetch: globalThis.fetch,
      } as any);
    } catch {
      return null;
    }
  }
  return environmentInvitationAdapter;
}

let configuredResolvers: {
  resolveDocumentAdapter: AdapterResolver;
  resolveCustodianAdapter: AdapterResolver;
  resolveInvitationAdapter: AdapterResolver;
} = Object.freeze({
  resolveDocumentAdapter: resolveEnvironmentDocumentAdapter,
  resolveCustodianAdapter: resolveEnvironmentCustodianAdapter,
  resolveInvitationAdapter: resolveEnvironmentInvitationAdapter,
});
let singleton: ReturnType<typeof createReleaseLockService> | null = null;

export interface ConfigureReleaseLockAdaptersOptions {
  resolveDocumentAdapter?: AdapterResolver;
  resolveCustodianAdapter?: AdapterResolver;
  resolveInvitationAdapter?: AdapterResolver;
}

export function configureReleaseLockAdapters({
  resolveDocumentAdapter,
  resolveCustodianAdapter,
  resolveInvitationAdapter,
}: ConfigureReleaseLockAdaptersOptions = {}): void {
  if (singleton) throw new Error('Release Lock runtime is already initialized');
  if (resolveDocumentAdapter !== undefined && typeof resolveDocumentAdapter !== 'function') {
    throw new TypeError('resolveDocumentAdapter must be a function');
  }
  if (resolveCustodianAdapter !== undefined && typeof resolveCustodianAdapter !== 'function') {
    throw new TypeError('resolveCustodianAdapter must be a function');
  }
  if (resolveInvitationAdapter !== undefined
      && typeof resolveInvitationAdapter !== 'function') {
    throw new TypeError('resolveInvitationAdapter must be a function');
  }
  configuredResolvers = Object.freeze({
    resolveDocumentAdapter: resolveDocumentAdapter || resolveEnvironmentDocumentAdapter,
    resolveCustodianAdapter: resolveCustodianAdapter || resolveEnvironmentCustodianAdapter,
    resolveInvitationAdapter: resolveInvitationAdapter || resolveEnvironmentInvitationAdapter,
  });
}

export function getReleaseLockService(): ReturnType<typeof createReleaseLockService> {
  if (!singleton) {
    const supabase = getServiceClient();
    singleton = createReleaseLockService({
      rpc: (name: string, args: unknown) => supabase.rpc(name, args as object),
      cryptoSuite: createReleaseLockCrypto(),
      adapters: createReleaseLockAdapterBoundary(configuredResolvers as any),
    } as any);
  }
  return singleton;
}

export const releaseLockRuntimeInternals = Object.freeze({
  environmentJsonObject,
  environmentText,
  resolveEnvironmentCustodianAdapter,
  resolveEnvironmentDocumentAdapter,
  resolveEnvironmentInvitationAdapter,
});
