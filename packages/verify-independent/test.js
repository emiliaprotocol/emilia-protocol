import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const RUNNER = path.join(REPO_ROOT, 'examples', 'external-verification', 'out', 'run-all.mjs');

console.log("Running conformance via run-all...");
const output = execFileSync(process.execPath, [RUNNER], { encoding: 'utf8', cwd: REPO_ROOT });

console.log(output);

if (output.includes('161/161') || output.includes('All 161')) {
  console.log("✅ SUCCESS: All 161/161 vectors verified");
  process.exit(0);
} else {
  console.error("Did not see 161/161 confirmation");
  process.exit(1);
}
