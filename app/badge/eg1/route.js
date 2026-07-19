// SPDX-License-Identifier: Apache-2.0
// GET /badge/eg1 — deprecated route retained for compatibility. It now emits
// only an amber static-declaration badge; static scans cannot establish EG-1.
//   /badge/eg1?score=87        -> amber "static 87/100"
//   /badge/eg1?label=my%20mcp  -> custom left label
// Served from /badge (not /api) so it carries no auth/rate policy and is not a
// protocol surface. Same generator as `@emilia-protocol/fire-drill`.

import { badgeSvg } from '../../../packages/fire-drill/index.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const scoreRaw = searchParams.get('score');
  const score = scoreRaw != null && Number.isFinite(Number(scoreRaw)) ? Math.max(0, Math.min(100, Number(scoreRaw))) : undefined;
  // Charset-clamp the label (belt-and-suspenders over badgeSvg's escaping): only
  // safe printable label characters, capped length.
  const label = (searchParams.get('label') || 'receipt declarations')
    .replace(/[^\w .\-/]/g, '')
    .slice(0, 40);

  const svg = badgeSvg({ score, label });
  return new Response(svg, {
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=300, s-maxage=300',
      // Defense-in-depth: even if served as a document, it cannot run script.
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox",
      'x-content-type-options': 'nosniff',
      'content-disposition': 'inline',
      'x-emilia-claim-scope': 'static-declarations-only; runtime-eg1-not-assessed',
    },
  });
}
