#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(
  await readFile(new URL('./manifest.json', import.meta.url), 'utf8'),
);

for (const mapping of manifest.mappings) {
  const response = await fetch(mapping.source_txt_url, {
    headers: { 'user-agent': 'emilia-caid-source-verifier/1' },
  });
  if (!response.ok) {
    throw new Error(`${mapping.draft}-${mapping.revision}: HTTP ${response.status}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== mapping.source_sha256) {
    throw new Error(
      `${mapping.draft}-${mapping.revision}: source hash mismatch ${actual}`,
    );
  }
  console.log(`PASS ${mapping.draft}-${mapping.revision} ${actual}`);
}

