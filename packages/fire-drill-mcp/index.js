#!/usr/bin/env node

import { fileURLToPath } from 'node:url';

export * from './dist/index.js';

// Keep the published executable path stable while the implementation is
// emitted from TypeScript.
if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) {
  const { startServer } = await import('./dist/index.js');
  await startServer();
}
