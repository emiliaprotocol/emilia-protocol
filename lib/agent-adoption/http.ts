// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { AgentAdoptionServiceError } from './service';

export const AGENT_ADOPTION_NO_STORE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, max-age=0',
  Pragma: 'no-cache',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
});

export function adoptionJson(value: unknown, status = 200): NextResponse {
  // Browser routes recover authority through a path-scoped HttpOnly cookie.
  // Never mirror the long-lived bearer into JavaScript-visible JSON, even if
  // an internal service result carries it for cookie issuance or RPC chaining.
  const browserValue = value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.hasOwn(value, 'session_token')
    ? Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'session_token'))
    : value;
  return NextResponse.json(browserValue, {
    status,
    headers: AGENT_ADOPTION_NO_STORE_HEADERS,
  });
}

export function adoptionError(error: unknown, operation: string): NextResponse {
  if (error instanceof AgentAdoptionServiceError) {
    return epProblem(error.status, error.code, error.message);
  }
  logger.error('[agent-adoption] operation failed', {
    kind: 'agent_adoption_operation_failed',
    operation,
  });
  return epProblem(503, 'agent_adoption_unavailable', 'Agent Adoption is temporarily unavailable.');
}
