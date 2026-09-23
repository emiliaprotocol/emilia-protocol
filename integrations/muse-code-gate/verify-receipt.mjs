#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Offline verification CLI for the adapter's signed outcome receipt. */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { strictJsonGate } from '../../packages/verify/strict-json.js';
import { verifyOutcomeReceipt } from './adapter.mjs';

export async function verifyReceiptFile(path, publicKey) {
  const raw = await readFile(path, 'utf8');
  const strict = strictJsonGate(raw);
  if (!strict.ok) return { valid: false, error: `receipt_json_refused:${strict.reason}` };
  return verifyOutcomeReceipt(JSON.parse(raw), publicKey);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [, , receiptPath, publicKey] = process.argv;
  if (!receiptPath || !publicKey) {
    process.stderr.write('Usage: node verify-receipt.mjs <outcome-receipt.json> <Ed25519-public-key-b64u>\n');
    process.exitCode = 2;
  } else {
    const result = await verifyReceiptFile(receiptPath, publicKey);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.valid === true ? 0 : 1;
  }
}

