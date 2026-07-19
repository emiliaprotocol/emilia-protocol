// SPDX-License-Identifier: Apache-2.0
// Remote adapter for a future self-hosted risk classifier.
//
// The remote model is advisory. The deterministic guard policy is evaluated
// first and remains the floor: remote output can require human signoff, but it
// can never turn an engine signoff/deny into allow and can never deny alone.
// Remote failures fail closed to human signoff instead of silently falling back
// to a bare allow.

import {
  evaluateGuardPolicy,
  GUARD_DECISIONS,
} from '../../../lib/guard-policies.js';

const DEFAULT_TIMEOUT_MS = 2_000;
const MAX_TIMEOUT_MS = 60_000;
const VALID_TIERS = new Set(Object.values(GUARD_DECISIONS));

class RemoteModelError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RemoteModelError';
    this.code = code;
  }
}

function configuredEndpoint(value) {
  if (!value) {
    throw new Error(
      'EP_RISK_MODEL_URL is required for the remote classifier; '
      + 'use `npm run ml:eval` for the deterministic heuristic gate.',
    );
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('EP_RISK_MODEL_URL must be a valid http(s) URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('EP_RISK_MODEL_URL must use http or https.');
  }
  return url.toString();
}

function configuredTimeout(value) {
  const timeout = value === undefined ? DEFAULT_TIMEOUT_MS : Number(value);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) {
    throw new Error(`EP_RISK_MODEL_TIMEOUT_MS must be an integer from 1 to ${MAX_TIMEOUT_MS}.`);
  }
  return timeout;
}

function validateRemoteOutput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new RemoteModelError('malformed_response', 'response body must be a JSON object');
  }
  if (!VALID_TIERS.has(value.tier)) {
    throw new RemoteModelError('malformed_response', 'response tier is missing or invalid');
  }
  if (typeof value.injection_suspected !== 'boolean') {
    throw new RemoteModelError(
      'malformed_response',
      'response injection_suspected must be boolean',
    );
  }
  return {
    tier: value.tier,
    injection_suspected: value.injection_suspected,
  };
}

function remoteEvidence(status, details = {}) {
  return {
    source: 'remote_model',
    status,
    ...details,
  };
}

function requireSignoff(base, advisory, reason) {
  if (base.decision === GUARD_DECISIONS.DENY) {
    return { ...base, advisory };
  }

  if (base.decision === GUARD_DECISIONS.ALLOW_WITH_SIGNOFF) {
    return {
      ...base,
      advisory,
      reasons: [reason, ...(base.reasons || [])],
    };
  }

  return {
    ...base,
    decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
    signoffRequired: true,
    requiredAssurance: 'A',
    reasons: [reason, ...(base.reasons || [])],
    advisory,
  };
}

function failClosed(base, code) {
  return requireSignoff(
    base,
    remoteEvidence('error', { error: code, raised: base.decision === GUARD_DECISIONS.ALLOW }),
    `Remote risk classifier failed closed (${code}); accountable human signoff is required.`,
  );
}

function applyRemoteOutput(base, output) {
  const requestsEscalation = output.tier !== GUARD_DECISIONS.ALLOW
    || output.injection_suspected;
  const advisory = remoteEvidence('ok', {
    requested_tier: output.tier,
    injection_suspected: output.injection_suspected,
    raised: base.decision === GUARD_DECISIONS.ALLOW && requestsEscalation,
  });

  if (!requestsEscalation || base.decision !== GUARD_DECISIONS.ALLOW) {
    return { ...base, advisory };
  }

  // A remote "deny" is still only perception. It raises a bare allow to
  // signoff; only the deterministic policy may issue a binding deny.
  return requireSignoff(
    base,
    advisory,
    'Remote risk classifier requested escalation; accountable human signoff is required.',
  );
}

/**
 * Build a classifier with injectable transport for deterministic tests.
 *
 * @param {{
 *   endpoint?: string,
 *   timeoutMs?: number|string,
 *   fetchImpl?: typeof fetch,
 * }} options
 */
export function createRemoteClassifier(options = {}) {
  const endpoint = configuredEndpoint(options.endpoint ?? process.env.EP_RISK_MODEL_URL);
  const timeoutMs = configuredTimeout(
    options.timeoutMs ?? process.env.EP_RISK_MODEL_TIMEOUT_MS,
  );
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('A Fetch API implementation is required for the remote classifier.');
  }

  return async function classifyRemote(input) {
    const base = evaluateGuardPolicy(input);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetchImpl(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(input),
        signal: controller.signal,
      });
      if (!response?.ok) {
        const status = Number.isInteger(response?.status) ? response.status : 'unknown';
        throw new RemoteModelError('http_error', `risk model returned HTTP ${status}`);
      }

      let body;
      try {
        body = await response.json();
      } catch {
        throw new RemoteModelError('malformed_response', 'response body is not valid JSON');
      }
      return applyRemoteOutput(base, validateRemoteOutput(body));
    } catch (error) {
      if (controller.signal.aborted) return failClosed(base, 'timeout');
      if (error instanceof RemoteModelError) return failClosed(base, error.code);
      return failClosed(base, 'network_error');
    } finally {
      clearTimeout(timeout);
    }
  };
}

export async function classify(input) {
  return createRemoteClassifier()(input);
}
