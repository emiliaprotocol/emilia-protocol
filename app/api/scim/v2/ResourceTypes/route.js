// SPDX-License-Identifier: Apache-2.0
// GET /api/scim/v2/ResourceTypes — SCIM 2.0 resource types (RFC 7643 §6). Public.

import { resourceTypes } from '@/lib/scim/core';
import { scimJson, scimBaseUrl } from '@/lib/scim/http';

export async function GET(request) {
  return scimJson(resourceTypes(scimBaseUrl(request)));
}
