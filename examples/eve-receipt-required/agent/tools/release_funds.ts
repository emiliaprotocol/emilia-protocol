// SPDX-License-Identifier: Apache-2.0
//
// Eve tool: release_funds — IRREVERSIBLE money movement, gated by EMILIA.
// The filename is the tool name the model sees.
//
// Pattern: the tool refuses to mutate unless it receives a valid EMILIA
// authorization receipt bound to funds.release:<destination>. No receipt → it
// returns a Receipt-Required challenge telling the agent exactly what to bring
// (the receipt-required skill explains how to obtain one and retry).

import { defineTool } from 'eve/tools';
import { z } from 'zod';
import { releaseFundsGate } from '../../lib/guards.mjs';

export default defineTool({
  description:
    'Release funds to a destination account. IRREVERSIBLE. Requires an EMILIA authorization receipt ' +
    'bound to funds.release:<destination> — a named human must have approved this exact transfer. ' +
    'If you do not have one, call this tool without emilia_receipt to get a Receipt-Required challenge, ' +
    'then follow the receipt-required skill to obtain one and retry.',
  inputSchema: z.object({
    amount: z.number().positive(),
    currency: z.string().min(1),
    destination: z.string().min(1).describe('destination account id / IBAN'),
    emilia_receipt: z
      .any()
      .optional()
      .describe('EP-RECEIPT-v1 authorizing funds.release:<destination>. Omit to receive the challenge.'),
  }),
  async execute({ amount, currency, destination, emilia_receipt }) {
    const result = await releaseFundsGate.run(
      emilia_receipt,
      { target: destination },
      async () => {
        // ── your real, irreversible mutation goes here (e.g. bank/PSP transfer).
        // It runs only after the receipt verifies; the receipt is consumed on
        // success (one-time) and released on failure (a transient error never
        // burns a valid approval).
        return { released: true, amount, currency, destination };
      },
    );

    if (result.ok === false) {
      // Receipt missing/invalid/replayed → do NOT mutate. Hand the model a
      // machine-readable challenge (HTTP 428-shaped) describing what to bring.
      const failed = result as { ok: false; status: any; body: any };
      return { ok: false, receipt_required: true, status: failed.status, challenge: failed.body };
    }
    const succeeded = result as { ok: true; result: any; receiptId?: string };
    return { ok: true, ...succeeded.result, receipt: succeeded.receiptId };
  },
});
