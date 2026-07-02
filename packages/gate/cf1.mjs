/**
 * CF-1 Consequence Firewall Conformance — runnable proof. Run: node cf1.mjs [--json]
 *
 * Self-certifies the reference EMILIA Gate against the CF-1 checks: the eight
 * EG-1 runtime checks plus the three category checks (action declared
 * consequential, wrong-authority refused, evidence verifiable offline).
 *
 * An adopter earns CF-1 by pointing this at THEIR integration: build your gate
 * trusting `harness.publicKey`, a sibling gate trusting a different key, and
 * pass both to cf1Conformance():
 *
 *   import { createEg1Harness, cf1Conformance, createTrustedActionFirewall,
 *            createDefaultActionRiskManifest } from '@emilia-protocol/gate';
 *   const harness = createEg1Harness();
 *   const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey] });
 *   const wrongGate = createTrustedActionFirewall({ trustedKeys: [createEg1Harness().publicKey] });
 *   const report = await cf1Conformance({ gate, wrongGate, harness, manifest: createDefaultActionRiskManifest() });
 *
 * Exit code is 0 only if all checks pass — CI-friendly.
 * @license Apache-2.0
 */
import { cf1ConformanceSelfTest } from './index.js';

const report = await cf1ConformanceSelfTest();

if (process.argv.includes('--json')) {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.passed ? 0 : 1);
}

const G = (s) => `\x1b[32m${s}\x1b[0m`;
const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s) => console.log(s);

line('='.repeat(66));
line('  CF-1 Conformance — is this integration a Consequence Firewall?');
line('='.repeat(66));
for (const c of report.checks) {
  line(`  ${c.pass ? G('PASS') : R('FAIL')}  ${c.title}`);
}
line('  ' + '-'.repeat(62));
line(`  ${report.passed ? G(`✓ ${report.badge}`) : R(`✗ ${report.badge}`)}  (${report.summary.passed}/${report.summary.total})`);
line('='.repeat(66));
process.exit(report.passed ? 0 : 1);
