// SPDX-License-Identifier: Apache-2.0

import { getServiceClient } from '../supabase.js';
import { createAcrobatSignAdapter } from '../integrations/action-escrow/acrobat-sign.js';
import { createEscrowComAdapter } from '../integrations/action-escrow/escrow-com.js';
import { createReleaseLockAdapterBoundary } from './adapters.js';
import { createReleaseLockCrypto } from './crypto.js';
import { createResendReleaseLockInvitationAdapter } from './invitation-delivery.js';
import { createReleaseLockService } from './service.js';

let environmentInvitationAdapter = null;

function environmentText(name, max = 8192) {
  const value = process.env[name]?.trim();
  return value && value.length <= max ? value : null;
}

function environmentJsonObject(name) {
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

function resolveEnvironmentDocumentAdapter(request) {
  if (request?.provider !== 'acrobat_sign') return null;
  const apiOrigin = environmentText('RELEASE_LOCK_ACROBAT_SIGN_API_ORIGIN', 512);
  const oauthAccessToken = environmentText(
    'RELEASE_LOCK_ACROBAT_SIGN_OAUTH_ACCESS_TOKEN',
  );
  if (!apiOrigin || !oauthAccessToken) return null;
  try {
    return createAcrobatSignAdapter(/** @type {*} */ ({
      apiOrigin,
      oauthAccessToken,
      fetch: globalThis.fetch,
    }));
  } catch {
    return null;
  }
}

function resolveEnvironmentCustodianAdapter(request) {
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
    return createEscrowComAdapter({
      environment: /** @type {string} */ (environment),
      email,
      apiKey,
      fetch: globalThis.fetch,
      customerDiligence,
      claimEffectBinding: request.claimEffectBinding,
    });
  } catch {
    return null;
  }
}

function resolveEnvironmentInvitationAdapter(request) {
  if (request?.channel !== 'email') return null;
  const apiKey = environmentText('RESEND_API_KEY');
  const from = environmentText('RELEASE_LOCK_INVITATION_FROM', 320);
  const publicAppOrigin = environmentText('RELEASE_LOCK_PUBLIC_ORIGIN', 512);
  if (!apiKey || !from || !publicAppOrigin) return null;
  if (!environmentInvitationAdapter) {
    try {
      environmentInvitationAdapter = createResendReleaseLockInvitationAdapter(/** @type {*} */ ({
        apiKey,
        from,
        publicAppOrigin,
        fetch: globalThis.fetch,
      }));
    } catch {
      return null;
    }
  }
  return environmentInvitationAdapter;
}

let configuredResolvers = Object.freeze({
  resolveDocumentAdapter: resolveEnvironmentDocumentAdapter,
  resolveCustodianAdapter: resolveEnvironmentCustodianAdapter,
  resolveInvitationAdapter: resolveEnvironmentInvitationAdapter,
});
let singleton = null;

/**
 * @param {object} [opts]
 * @param {(request: object) => object|null} [opts.resolveDocumentAdapter]
 * @param {(request: object) => object|null} [opts.resolveCustodianAdapter]
 * @param {(request: object) => object|null} [opts.resolveInvitationAdapter]
 */
export function configureReleaseLockAdapters({
  resolveDocumentAdapter,
  resolveCustodianAdapter,
  resolveInvitationAdapter,
} = {}) {
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

export function getReleaseLockService() {
  if (!singleton) {
    const supabase = getServiceClient();
    singleton = createReleaseLockService(/** @type {*} */ ({
      rpc: (name, args) => supabase.rpc(name, args),
      cryptoSuite: createReleaseLockCrypto(),
      adapters: createReleaseLockAdapterBoundary(/** @type {*} */ (configuredResolvers)),
    }));
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
