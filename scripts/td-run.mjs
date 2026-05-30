/**
 * AI Trust Desk — ops CLI: run the pipeline on a local questionnaire.
 *
 * @license Apache-2.0
 *
 * Runs intake → published trust page entirely on disk, no server required.
 * The deterministic path needs no API keys; set ANTHROPIC_API_KEY or
 * OPENAI_API_KEY to enable LLM answering for non-template questions.
 *
 * Usage:
 *   node scripts/td-run.mjs --file data/trust-desk/samples/sample-questionnaire.md \
 *     --company "Acme Financial" --email security@acme.example \
 *     --name "Jane Doe" --product "AI-native KYC for banks" \
 *     --cloud "AWS us-east-1" --soc2 type2 --buyer "Regional Bank"
 *
 * Output: the published trust page at /trust-desk/c/<slug> plus a JSON result.
 */

import { runPipeline } from '../lib/trust-desk/pipeline.js';
import { putEngagement } from '../lib/trust-desk/store.js';
import { newEngagementId, deriveSlug } from '../lib/trust-desk/ids.js';

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      args[key] = val;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.file) {
    process.stderr.write('error: --file <questionnaire> is required\n');
    process.exit(2);
  }

  const engagementId = newEngagementId();
  const intake = {
    company: args.company || 'Sample Vendor',
    website: args.website || null,
    contact_name: args.name || 'Security Team',
    contact_email: args.email || 'security@vendor.example',
    contact_role: args.role || 'Head of Security',
    product_description: args.product || 'AI product for financial services',
    selling_into: args.selling_into || 'financial_services',
    buyer_name: args.buyer || null,
    ai_uses_customer_data: args.ai_data || 'inference',
    cloud_provider: args.cloud || 'AWS us-east-1',
    model_providers: args.models || 'OpenAI, Anthropic',
    soc2_status: args.soc2 || 'in_progress',
    tier_preference: args.tier || 'packet',
  };

  const slug = deriveSlug(intake.company, engagementId);
  const engagement = {
    engagement_id: engagementId,
    slug,
    intake,
    questionnaire_path: args.file,
    questionnaire_filename: args.file.split('/').pop(),
    status: 'intake_received',
  };

  putEngagement(engagement);

  process.stdout.write(`\n▶ Running pipeline for engagement ${engagementId} (slug: ${slug})\n`);
  const result = await runPipeline({ engagement });

  process.stdout.write('\n── RESULT ──────────────────────────────────────────\n');
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');

  if (result.outcome === 'published' || result.outcome === 'published_partial') {
    process.stdout.write(`\n✓ Trust page: data/trust-desk/customers/${result.slug}.json\n`);
    process.stdout.write(`  Live route:  /trust-desk/c/${result.slug}\n`);
    process.stdout.write(`  Verify:      node scripts/td-verify.mjs --slug ${result.slug}\n\n`);
  } else if (result.outcome === 'escalated') {
    process.stdout.write(`\n⚠ Escalated to reviewer: ${result.reason}\n`);
    process.stdout.write(`  ${result.detail || ''}\n\n`);
  } else {
    process.stdout.write(`\n✗ Pipeline failed: ${result.error}\n\n`);
    process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err.stack || err.message}\n`);
  process.exit(1);
});
