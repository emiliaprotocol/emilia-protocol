// SPDX-License-Identifier: Apache-2.0
//
// airgap-keys.mjs — mint the self-host secrets for an air-gapped EP deployment.
//
// Generates a JWT secret and the service_role + anon JWTs PostgREST expects
// (HS256, signed with that secret). Run on a CONNECTED machine; paste the output
// into .env.airgap on the isolated host.
//
//   node scripts/airgap-keys.mjs            # fresh random secret
//   SUPABASE_JWT_SECRET=<hex> node scripts/airgap-keys.mjs   # reuse a secret

import crypto from 'node:crypto';
import * as jose from 'jose';

const secret = process.env.SUPABASE_JWT_SECRET || crypto.randomBytes(32).toString('hex');
const key = new TextEncoder().encode(secret);

async function sign(role) {
  return new jose.SignJWT({ role })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setIssuer('supabase')
    .setExpirationTime('10y')
    .sign(key);
}

const serviceRole = await sign('service_role');
const anon = await sign('anon');

console.log('# Paste into .env.airgap (air-gap secrets):');
console.log(`SUPABASE_JWT_SECRET=${secret}`);
console.log(`SUPABASE_SERVICE_ROLE_KEY=${serviceRole}`);
console.log(`SUPABASE_ANON_KEY=${anon}`);
console.error('\nGenerated HS256 service_role + anon JWTs (10y) signed with the JWT secret above.');
