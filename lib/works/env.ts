// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — feature flag.
//
// The entire /works surface (pages and /api/works/* routes) is dark unless
// WORKS_V0=1 is set in the environment. Pages return 404 via notFound() and
// API routes return a 404 problem response, so merging this code never
// soft-launches the surface. Same env-function pattern as lib/env.ts flags
// (kept in its own module so the generated lib/env.js standalone-runtime
// companion does not need regeneration).

/**
 * Feature flag — EMILIA Marketplace v0 surface. When '1', the /works directory,
 * profile/listing/opportunity pages, and /api/works/* routes are served.
 * Any other value (including unset): every Works page and route is 404.
 */
export function isWorksV0Enabled(): boolean {
  return process.env.WORKS_V0 === '1';
}
