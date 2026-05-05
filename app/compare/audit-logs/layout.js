export const metadata = {
  title: 'Audit Logs vs Trust Receipts — Why Logs Aren\'t Enough for AI Agents',
  description:
    'Audit logs record what happened after the fact. EP trust receipts ' +
    'prove what was authorized before the action executed — cryptographically, ' +
    'offline-verifiable, and bound to the exact action context. Why high-risk ' +
    'AI agent actions need pre-action evidence, not post-action logs.',
  alternates: { canonical: '/compare/audit-logs' },
  openGraph: {
    title: 'Trust Receipts vs Audit Logs — Pre-Action Evidence for AI Agents',
    description:
      'Audit logs detect after the breach. EP trust receipts prove ' +
      'authorization before the action executes. Self-verifying, offline.',
    url: 'https://www.emiliaprotocol.ai/compare/audit-logs',
    type: 'article',
  },
  keywords: [
    'audit logs vs trust receipts',
    'AI agent audit trail',
    'pre-action evidence',
    'cryptographic audit AI',
    'tamper-proof AI audit',
    'self-verifying audit log',
    'NIST AI RMF evidence',
  ],
};

export default function CompareAuditLogsLayout({ children }) {
  return children;
}
