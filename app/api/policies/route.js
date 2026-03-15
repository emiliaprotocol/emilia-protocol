import { NextResponse } from 'next/server';
import { TRUST_POLICIES } from '@/lib/scoring-v2';

/**
 * GET /api/policies — list all available trust policies
 * POST /api/policies — register a custom policy (future)
 * 
 * Policies are the decision layer of EP. Agents and systems evaluate
 * counterparties against structured policies, not raw numbers.
 */
export async function GET() {
  const policies = Object.entries(TRUST_POLICIES).map(([name, policy]) => ({
    name,
    description: getPolicyDescription(name),
    min_score: policy.min_score,
    min_confidence: policy.min_confidence,
    min_receipts: policy.min_receipts,
    max_dispute_rate: policy.max_dispute_rate,
    software_requirements: policy.software_requirements || null,
    family: getPolicyFamily(name),
  }));

  return NextResponse.json({
    protocol_version: 'EP/1.1',
    policies,
    families: ['commerce', 'software', 'marketplace', 'custom'],
    _note: 'Evaluate entities against policies with POST /api/trust/evaluate. Custom policies accepted as JSONB.',
  });
}

function getPolicyDescription(name) {
  const descriptions = {
    strict: 'High-value transactions. Requires established confidence, low dispute rate, minimum receipt history.',
    standard: 'Normal transactions. Balanced requirements for confidence and evidence.',
    permissive: 'Low-risk transactions. Minimal requirements — suitable for browsing and discovery.',
    discovery: 'Allow unevaluated entities. Use when exploring new counterparties or tools.',
    github_private_repo_safe_v1: 'GitHub Apps accessing private repositories. Requires publisher verification and safe permission class.',
    npm_buildtime_safe_v1: 'npm packages used in build pipelines. Requires trusted publishing and provenance verification.',
    browser_extension_safe_v1: 'Browser extensions. Requires publisher verification and safe permission class.',
    mcp_server_safe_v1: 'MCP servers connecting to agent workflows. Requires provenance verification and moderate confidence.',
  };
  return descriptions[name] || 'Custom policy';
}

function getPolicyFamily(name) {
  if (['strict', 'standard', 'permissive', 'discovery'].includes(name)) return 'commerce';
  if (name.includes('github') || name.includes('npm') || name.includes('browser') || name.includes('mcp')) return 'software';
  return 'custom';
}
