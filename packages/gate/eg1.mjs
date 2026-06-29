/**
 * EG-1 Conformance — runnable proof. Run: node eg1.mjs [--json]
 *
 * Self-certifies the reference EMILIA Gate against the eight EG-1 checks. An
 * adopter earns EG-1 by pointing this harness at THEIR integration: build your
 * gate trusting `harness.publicKey`, pass it to gateConformance(), and ship the
 * JSON report + the "EG-1 Enforced" badge.
 *
 *   import { createEg1Harness, gateConformance } from '@emilia-protocol/gate';
 *   const harness = createEg1Harness();
 *   const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey] });
 *   const report = await gateConformance({ gate, harness });
 *
 * Exit code is 0 only if all eight checks pass — CI-friendly.
 * @license Apache-2.0
 */
import { gateConformanceSelfTest } from './index.js';

const report = await gateConformanceSelfTest();

if (process.argv.includes('--json')) {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.passed ? 0 : 1);
}

const G = (s) => `\x1b[32m${s}\x1b[0m`;
const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s) => console.log(s);

line('='.repeat(64));
line('  EG-1 Conformance — does this integration ENFORCE EMILIA Gate?');
line('='.repeat(64));
for (const c of report.checks) {
  line(`  ${c.pass ? G('PASS') : R('FAIL')}  ${c.title}`);
}
line('  ' + '-'.repeat(60));
line(`  ${report.passed ? G(`✓ ${report.badge}`) : R(`✗ ${report.badge}`)}  (${report.summary.passed}/${report.summary.total})`);
line('='.repeat(64));
process.exit(report.passed ? 0 : 1);
