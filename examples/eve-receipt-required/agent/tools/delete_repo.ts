// SPDX-License-Identifier: Apache-2.0
//
// Eve tool: delete_repo — IRREVERSIBLE data destruction, gated by EMILIA.
// Same pattern as release_funds: no receipt bound to repo.delete:<owner/name>,
// no deletion. A receipt for repo A cannot delete repo B (target binding).

import { defineTool } from 'eve/tools';
import { z } from 'zod';
import { deleteRepoGate } from '../../lib/guards.mjs';

export default defineTool({
  description:
    'Permanently delete a repository. IRREVERSIBLE. Requires an EMILIA authorization receipt bound to ' +
    'repo.delete:<owner/name>. Omit emilia_receipt to receive a Receipt-Required challenge, then use the ' +
    'receipt-required skill to obtain one and retry.',
  inputSchema: z.object({
    owner: z.string().min(1),
    name: z.string().min(1),
    emilia_receipt: z.any().optional().describe('EP-RECEIPT-v1 authorizing repo.delete:<owner/name>.'),
  }),
  async execute({ owner, name, emilia_receipt }) {
    const target = `${owner}/${name}`;
    const result = await deleteRepoGate.run(emilia_receipt, { target }, async () => {
      // ── your real, irreversible deletion goes here (e.g. GitHub repos.delete).
      return { deleted: true, repo: target };
    });

    if (result.ok === false) {
      const failed = result as { ok: false; status: any; body: any };
      return { ok: false, receipt_required: true, status: failed.status, challenge: failed.body };
    }
    const succeeded = result as { ok: true; result: any; receiptId?: string };
    return { ok: true, ...succeeded.result, receipt: succeeded.receiptId };
  },
});
