#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Offline verification CLI for signed outcome and reconciliation receipts. */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { strictJsonGate } from '../../packages/verify/strict-json.js';
import {
  RECONCILIATION_PROFILE,
  verifyOutcomeReceipt,
  verifyReconciliationReceipt,
} from './adapter.mjs';

export async function verifyReceiptFile(path, publicKey) {
  const raw = await readFile(path, 'utf8');
  const strict = strictJsonGate(raw);
  if (!strict.ok) return { valid: false, error: `receipt_json_refused:${strict.reason}` };
  const receipt = JSON.parse(raw);
  return receipt?.payload?.claim?.profile === RECONCILIATION_PROFILE
    ? verifyReconciliationReceipt(receipt, publicKey)
    : verifyOutcomeReceipt(receipt, publicKey);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [, , receiptPath, publicKey] = process.argv;
  if (!receiptPath || !publicKey) {
    process.stderr.write('Usage: node verify-receipt.mjs <receipt.json> <Ed25519-public-key-b64u>\n');
    process.exitCode = 2;
  } else {
    const result = await verifyReceiptFile(receiptPath, publicKey);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.valid === true ? 0 : 1;
  }
}
