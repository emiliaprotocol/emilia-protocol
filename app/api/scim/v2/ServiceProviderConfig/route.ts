// SPDX-License-Identifier: Apache-2.0
// GET /api/scim/v2/ServiceProviderConfig — SCIM 2.0 capability document (RFC 7643 §5).
// Public: capability metadata carries no tenant data and IdPs fetch it during setup.

import { NextRequest, NextResponse } from 'next/server';
import { serviceProviderConfig } from '@/lib/scim/core';
import { scimJson, scimBaseUrl } from '@/lib/scim/http';

export async function GET(request: NextRequest): Promise<NextResponse> {
  return scimJson(serviceProviderConfig(scimBaseUrl(request)));
}
