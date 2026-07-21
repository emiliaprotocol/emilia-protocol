// SPDX-License-Identifier: Apache-2.0
import { runActionEscrowScenario } from '@/examples/action-escrow/scenario.mjs';
import { canonicalize } from '@/packages/verify/index.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  const scenario = await runActionEscrowScenario();
  const body = canonicalize(scenario.projectRecordEvidence.evidence);

  return new Response(body, {
    status: 200,
    headers: {
      'cache-control': 'no-store',
      'content-disposition': 'attachment; filename="action-escrow-AGR-KITCHEN-2048-CCO-017-project-record.json"',
      'content-length': String(Buffer.byteLength(body, 'utf8')),
      'content-type': 'application/json; charset=utf-8',
      'x-content-type-options': 'nosniff',
    },
  });
}
