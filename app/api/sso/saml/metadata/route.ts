// SPDX-License-Identifier: Apache-2.0
// GET /api/sso/saml/metadata — SP metadata XML for the IdP administrator.
// One SP entityID + ACS serves all tenants; per-tenant trust is the IdP cert
// configured at /api/sso/connections. Public (contains no secrets).

export const runtime = 'nodejs';

import type { NextRequest } from 'next/server';
import { buildSamlSp, spMetadata } from '@/lib/sso/saml';
import { spOrigin } from '@/lib/sso/config';

export async function GET(request: NextRequest): Promise<Response> {
  const origin = spOrigin(request);
  const sp = buildSamlSp({
    idpEntryPoint: 'https://placeholder.invalid/sso', // not used for metadata
    idpCert: 'PLACEHOLDER', // metadata generation does not consume the IdP cert
    spEntityId: `${origin}/api/sso/saml/metadata`,
    acsUrl: `${origin}/api/sso/saml/acs`,
  });
  return new Response(spMetadata(sp), {
    status: 200,
    headers: { 'Content-Type': 'application/xml' },
  });
}
