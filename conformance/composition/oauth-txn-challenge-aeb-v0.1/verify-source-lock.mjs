#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';

import { SOURCE_LOCK, verifySourceLock, verifyUpstreamSource } from './run.mjs';

const offline = verifySourceLock();
assert.equal(offline.valid, true, JSON.stringify(offline.failures));

if (process.argv.includes('--network')) {
  const network = await verifyUpstreamSource();
  assert.equal(network.valid, true, JSON.stringify(network));
  process.stdout.write(
    `SOURCE LOCK: network bytes matched ${SOURCE_LOCK.upstream.sha256} (${network.bytes} bytes)\n`,
  );
} else {
  process.stdout.write(
    `SOURCE LOCK: manifest and static native fixtures matched; upstream bytes were not fetched (${SOURCE_LOCK.upstream.id})\n`,
  );
}
