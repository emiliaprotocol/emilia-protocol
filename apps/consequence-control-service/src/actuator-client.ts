// SPDX-License-Identifier: Apache-2.0
import { GoogleAuth } from 'google-auth-library';

import {
  CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION,
  CONSEQUENCE_ACTUATOR_RESPONSE_VERSION,
  consequenceActuatorTargetDigest,
  createConsequenceActuatorClient as createApplicationAuthenticatedActuatorClient,
} from './github-app.js';

export {
  CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION,
  CONSEQUENCE_ACTUATOR_RESPONSE_VERSION,
  consequenceActuatorTargetDigest,
};

export interface ConsequenceActuatorEnvelopeBinding {
  action_digest: string;
  attempt_id: string;
  caid: string;
  expires_at: string;
  idempotency_key: string;
  nonce: string;
  operation: string;
  provider_account_id: string;
  target_digest: string;
  tenant_id: string;
}

export interface ConsequenceActuatorIdentityTokenProvider {
  fetchIdToken(audience: string): Promise<string>;
}

interface GoogleIdTokenClientLike {
  idTokenProvider: {
    fetchIdToken(audience: string): Promise<string>;
  };
}

interface GoogleAuthLike {
  getIdTokenClient(audience: string): Promise<GoogleIdTokenClientLike>;
}

function normalizeIdentityAudience(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048
      || value.includes('\0')) {
    throw new TypeError('actuator_identity_audience_invalid');
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError('actuator_identity_audience_invalid');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password
      || parsed.search || parsed.hash
      || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new TypeError('actuator_identity_audience_invalid');
  }
  return parsed.origin;
}

function assertIdentityEndpointRelation(
  endpoint: unknown,
  audience: string,
  allowInsecureLoopback: boolean,
): void {
  let endpointUrl: URL;
  const audienceUrl = new URL(audience);
  try {
    endpointUrl = new URL(String(endpoint));
  } catch {
    throw new TypeError('actuator_identity_endpoint_mismatch');
  }

  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(
    endpointUrl.hostname,
  );
  if (allowInsecureLoopback && loopback && endpointUrl.protocol === 'http:') {
    return;
  }
  if (endpointUrl.protocol !== 'https:' || endpointUrl.port
      || endpointUrl.username || endpointUrl.password
      || audienceUrl.protocol !== 'https:' || audienceUrl.port
      || !audienceUrl.hostname.endsWith('.run.app')) {
    throw new TypeError('actuator_identity_endpoint_mismatch');
  }
  if (endpointUrl.origin === audienceUrl.origin) return;

  const tagSuffix = `---${audienceUrl.hostname}`;
  if (!endpointUrl.hostname.endsWith(tagSuffix)) {
    throw new TypeError('actuator_identity_endpoint_mismatch');
  }
  const tag = endpointUrl.hostname.slice(0, -tagSuffix.length);
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(tag)) {
    throw new TypeError('actuator_identity_endpoint_mismatch');
  }
}

function normalizeIdentityToken(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16_384
      || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('actuator_identity_token_invalid');
  }
  return value;
}

export function createGoogleCloudIdentityTokenProvider({
  audience,
  auth,
}: {
  audience: string;
  auth?: GoogleAuthLike;
}) {
  const pinnedAudience = normalizeIdentityAudience(audience);
  const googleAuth: GoogleAuthLike = auth ?? new GoogleAuth();
  if (!googleAuth || typeof googleAuth.getIdTokenClient !== 'function') {
    throw new TypeError('actuator_google_auth_invalid');
  }
  let client: GoogleIdTokenClientLike | null = null;

  return Object.freeze({
    async fetchIdToken(requestedAudience: string): Promise<string> {
      if (normalizeIdentityAudience(requestedAudience) !== pinnedAudience) {
        throw new Error('actuator_identity_audience_mismatch');
      }
      if (!client) {
        const candidate = await googleAuth.getIdTokenClient(pinnedAudience);
        if (!candidate?.idTokenProvider
            || typeof candidate.idTokenProvider.fetchIdToken !== 'function') {
          throw new Error('actuator_identity_provider_unavailable');
        }
        client = candidate;
      }
      return normalizeIdentityToken(
        await client.idTokenProvider.fetchIdToken(pinnedAudience),
      );
    },
  });
}

/**
 * Adds Cloud Run workload identity without displacing the actuator's
 * application bearer. Token acquisition is mandatory for every request:
 * failures never fall back to an application-only call.
 */
export function createConsequenceActuatorClient({
  identityTokenAudience,
  identityTokenProvider,
  fetchImpl = globalThis.fetch,
  ...options
}: any = {}) {
  const pinnedAudience = normalizeIdentityAudience(identityTokenAudience);
  assertIdentityEndpointRelation(
    options.endpoint,
    pinnedAudience,
    options.allowInsecureLoopback === true,
  );
  if (!identityTokenProvider
      || typeof identityTokenProvider.fetchIdToken !== 'function'
      || typeof fetchImpl !== 'function') {
    throw new TypeError('actuator_identity_provider_required');
  }

  const identityAuthenticatedFetch = async (
    input: RequestInfo | URL,
    init: RequestInit = {},
  ) => {
    const headers = new Headers(init.headers);
    const applicationAuthorization = headers.get('authorization');
    if (!applicationAuthorization?.startsWith('Bearer ')
        || headers.has('x-serverless-authorization')) {
      throw new Error('actuator_dual_auth_contract_invalid');
    }

    let identityToken: string;
    try {
      identityToken = normalizeIdentityToken(
        await identityTokenProvider.fetchIdToken(pinnedAudience),
      );
    } catch {
      throw new Error('actuator_identity_token_unavailable');
    }
    headers.set(
      'x-serverless-authorization',
      `Bearer ${identityToken}`,
    );
    return fetchImpl(input, { ...init, headers });
  };

  return createApplicationAuthenticatedActuatorClient({
    ...options,
    fetchImpl: identityAuthenticatedFetch,
  });
}
