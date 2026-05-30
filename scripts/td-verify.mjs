/**
 * AI Trust Desk — buyer-side claim verifier (CLI).
 *
 * @license Apache-2.0
 *
 * Thin wrapper over lib/trust-desk/page-verify.js (the same logic the
 * /api/trust-desk/verify endpoint runs) so the CLI and the server can never
 * disagree. Independently re-derives every binding on a published trust page:
 *
 *   content_integrity : content_hash === hash(published artifact bytes)
 *   payload_binding    : payload_hash === hash(canonical claim envelope)
 *   signature          : HMAC(key, payload_hash.signed_at) === signature
 *
 * Usage: node scripts/td-verify.mjs --slug acme-financial-2cdc3c
 */

import { verifyPublishedPage } from '../lib/trust-desk/page-verify.js';

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      args[key] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (!args.slug) {
  process.stderr.write('error: --slug <slug> is required\n');
  process.exit(2);
}

const result = verifyPublishedPage(args.slug);
if (!result.found) {
  process.stderr.write(`error: no published trust page for slug "${args.slug}"\n`);
  process.exit(2);
}

process.stdout.write(`\nVerifying trust page: ${result.company} (${result.slug})\n`);
process.stdout.write(`Claims: ${result.claim_count}\n\n`);

for (const claim of result.claims) {
  process.stdout.write(`${claim.passed ? '✓' : '✗'} ${claim.id} — ${claim.title}\n`);
  for (const [name, check] of Object.entries(claim.checks)) {
    const mark = check.ok === true ? '  ✓' : check.ok === false ? '  ✗' : '  ·';
    process.stdout.write(`${mark} ${name}: ${check.detail}\n`);
  }
  process.stdout.write('\n');
}

process.stdout.write(result.ok ? '✓ ALL CLAIMS VERIFIED\n\n' : '✗ VERIFICATION FAILED\n\n');
process.exit(result.ok ? 0 : 1);
