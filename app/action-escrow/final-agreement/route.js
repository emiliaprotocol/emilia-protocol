// SPDX-License-Identifier: Apache-2.0
import { runActionEscrowScenario } from '@/examples/action-escrow/scenario.mjs';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  const scenario = await runActionEscrowScenario();
  const download = new URL(request.url).searchParams.get('download') === '1';
  const disposition = download ? 'attachment' : 'inline';

  return new Response(scenario.pdf.bytes, {
    status: 200,
    headers: {
      'cache-control': 'no-store',
      'content-disposition': `${disposition}; filename="${scenario.pdf.filename}"`,
      'content-length': String(scenario.pdf.bytes.length),
      'content-type': scenario.pdf.media_type,
      'x-content-type-options': 'nosniff',
    },
  });
}
