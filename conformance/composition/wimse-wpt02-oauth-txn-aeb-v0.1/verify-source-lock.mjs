// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { SOURCE_LOCK, verifySourceLock } from './run.mjs';

const offline = verifySourceLock();
if (!offline.valid) {
  process.stderr.write(`${JSON.stringify(offline)}\n`);
  process.exitCode = 1;
} else if (!process.argv.includes('--network')) {
  process.stdout.write(`${JSON.stringify(offline)}\n`);
} else {
  const results = [];
  for (const source of SOURCE_LOCK.upstream) {
    const response = await fetch(source.url, { redirect: 'follow' });
    if (!response.ok) throw new Error(`source fetch failed: ${source.id} ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    results.push({
      id: source.id,
      valid: bytes.length === source.bytes && sha256 === source.sha256,
      bytes: bytes.length,
      sha256,
    });
  }
  process.stdout.write(`${JSON.stringify({ valid: results.every((entry) => entry.valid), results })}\n`);
  if (results.some((entry) => !entry.valid)) process.exitCode = 1;
}
