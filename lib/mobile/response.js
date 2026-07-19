// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors.js';

function protect(response) {
  response.headers.set('cache-control', 'no-store');
  response.headers.set('pragma', 'no-cache');
  response.headers.set('x-content-type-options', 'nosniff');
  response.headers.set('referrer-policy', 'no-referrer');
  return response;
}

export function mobileJson(body, init = {}) {
  return protect(NextResponse.json(body, init));
}

export function mobileProblem(status, code, detail, extras = {}) {
  return protect(epProblem(status, code, detail, extras));
}

const mobileResponses = { mobileJson, mobileProblem };

export default mobileResponses;
