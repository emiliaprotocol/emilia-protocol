// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors.js';

function protect<T extends NextResponse>(response: T): T {
  response.headers.set('cache-control', 'no-store, private');
  response.headers.set('pragma', 'no-cache');
  response.headers.set('referrer-policy', 'no-referrer');
  response.headers.set('x-content-type-options', 'nosniff');
  response.headers.set('x-frame-options', 'DENY');
  response.headers.set('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
  response.headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  return response;
}

export function approvalJson(body: unknown, init: ResponseInit = {}): NextResponse {
  return protect(NextResponse.json(body, init));
}

export function approvalProblem(
  status: number,
  code: string,
  detail: string,
  extras: Record<string, unknown> = {},
): NextResponse {
  return protect(epProblem(status, code, detail, { code, ...extras }));
}
