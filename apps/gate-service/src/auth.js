// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

const MIN_TOKEN_LENGTH = 32;
const MAX_TOKEN_LENGTH = 1024;

function validToken(value) {
  return typeof value === 'string'
    && value.length >= MIN_TOKEN_LENGTH
    && value.length <= MAX_TOKEN_LENGTH
    && !/[\u0000-\u0020\u007f]/.test(value);
}

function oneAuthorizationHeader(request) {
  if (!request || !Array.isArray(request.rawHeaders)) return null;
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (String(request.rawHeaders[index]).toLowerCase() === 'authorization') count += 1;
  }
  const value = request.headers?.authorization;
  return count === 1 && typeof value === 'string' ? value : null;
}

/** Create a constant-time bearer-token authenticator for a BYOC Gate service. */
export function createStaticBearerAuthenticator(token) {
  if (!validToken(token)) {
    throw new Error(`Gate API token must be ${MIN_TOKEN_LENGTH}-${MAX_TOKEN_LENGTH} visible non-space characters`);
  }
  const expected = crypto.createHash('sha256').update(token, 'utf8').digest();
  return async function authenticateRequest(request) {
    const header = oneAuthorizationHeader(request);
    if (!header?.startsWith('Bearer ')) return false;
    const candidate = header.slice('Bearer '.length);
    if (!validToken(candidate)) return false;
    const actual = crypto.createHash('sha256').update(candidate, 'utf8').digest();
    return crypto.timingSafeEqual(actual, expected);
  };
}

export default createStaticBearerAuthenticator;
