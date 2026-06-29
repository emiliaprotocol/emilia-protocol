// SPDX-License-Identifier: Apache-2.0
// GET /badge/eg1 — a shareable EG-1 SVG badge for READMEs and dashboards.
//   /badge/eg1?eg1=pass        -> green "EG-1 Enforced"
//   /badge/eg1?score=87        -> amber "87/100"
//   /badge/eg1?label=my%20mcp  -> custom left label
// Served from /badge (not /api) so it carries no auth/rate policy and is not a
// protocol surface. Same generator as `@emilia-protocol/fire-drill`.

import { badgeSvg } from '../../../packages/fire-drill/index.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const eg1 = searchParams.get('eg1') === 'fail' ? 'fail' : (searchParams.get('eg1') === 'pass' ? 'pass' : undefined);
  const scoreRaw = searchParams.get('score');
  const score = scoreRaw != null && Number.isFinite(Number(scoreRaw)) ? Math.max(0, Math.min(100, Number(scoreRaw))) : undefined;
  // Charset-clamp the label (belt-and-suspenders over badgeSvg's escaping): only
  // safe printable label characters, capped length.
  const label = (searchParams.get('label') || 'agent action firewall')
    .replace(/[^\w .\-/]/g, '')
    .slice(0, 40);

  const svg = badgeSvg({ eg1: eg1 ?? (score === undefined ? 'pass' : undefined), score, label });
  return new Response(svg, {
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=300, s-maxage=300',
      // Defense-in-depth: even if served as a document, it cannot run script.
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox",
      'x-content-type-options': 'nosniff',
      'content-disposition': 'inline',
    },
  });
}
