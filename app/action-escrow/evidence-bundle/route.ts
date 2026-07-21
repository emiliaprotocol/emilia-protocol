// SPDX-License-Identifier: Apache-2.0
import { runActionEscrowScenario } from '@/examples/action-escrow/scenario.mjs';

export const dynamic = 'force-dynamic';

export async function GET() {
  const scenario = await runActionEscrowScenario();
  const body = JSON.stringify(scenario.bundle, null, 2);

  return new Response(body, {
    status: 200,
    headers: {
      'cache-control': 'no-store',
      'content-disposition': 'attachment; filename="action-escrow-AGR-KITCHEN-2048-MS-03-evidence.json"',
      'content-length': String(Buffer.byteLength(body, 'utf8')),
      'content-type': 'application/json; charset=utf-8',
      'x-content-type-options': 'nosniff',
    },
  });
}
