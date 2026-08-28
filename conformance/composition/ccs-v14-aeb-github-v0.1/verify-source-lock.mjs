// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const commit = 'a3503b2bc48922f92a28c372003885a0831da02b';
const raw = `https://raw.githubusercontent.com/DSHCorrectover/ccs-conformance-vectors/${commit}`;
const expected = {
  manifest: '3e77eae3045eb2bc824c52b8d022b75029beaf56623841ce7c035a99e65a2ddd',
  receipt: '889855dc9fcebdb642bd7e0f369651015781b4c004227aef510feb1fb7cb4361',
};
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const fetchBytes = async (path) => {
  const response = await fetch(`${raw}/${path}`, { redirect: 'error' });
  assert.equal(response.status, 200, `${path}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
};

const manifest = await fetchBytes('vectors/v1.4.0-conformance/manifest.json');
const receipt = await fetchBytes('vectors/v1.4.0-conformance/01-allow/receipt.json');
const here = dirname(fileURLToPath(import.meta.url));
const checkedIn = await readFile(resolve(here, 'upstream-01-allow.receipt.json'));
assert.equal(sha256(manifest), expected.manifest);
assert.equal(sha256(receipt), expected.receipt);
assert.deepEqual(checkedIn, receipt);
process.stdout.write(`${JSON.stringify({ source: 'CCS-v1.4.0-conformance', commit, ...expected })}\n`);
