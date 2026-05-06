/**
 * Site-wide founder-fillable configuration.
 * @license Apache-2.0
 *
 * Centralizes the values that need real-human review before the site goes
 * to a procurement team. Bank third-party-risk teams and federal agency
 * intake reviewers cannot clear a vendor without these fields populated.
 *
 * Each TODO marker below is a one-line edit. After all TODOs are filled,
 * the /about, /legal/*, /security, and footer surfaces present a coherent
 * procurement-grade entity to the reader.
 */

export const ENTITY = {
  // TODO[founder]: legal entity name as registered (e.g. "EMILIA Protocol Inc.").
  legalName: 'EMILIA Protocol Foundation',
  // TODO[founder]: entity type (e.g. "Delaware C-Corporation", "Public Benefit Corporation").
  entityType: 'Open-source project (entity formation in progress)',
  // TODO[founder]: jurisdiction of registration (e.g. "Delaware, USA").
  jurisdiction: 'United States',
  // TODO[founder]: registered address. Use the actual registered-agent or HQ address.
  address: 'Mailing address available on request — contact team@emiliaprotocol.ai',
  // TODO[founder]: company registration number (Delaware file number, EIN, etc.) when available.
  registrationNumber: null,
  // Primary contact channel for procurement, security, and legal inquiries.
  email: 'team@emiliaprotocol.ai',
  securityEmail: 'security@emiliaprotocol.ai',
  legalEmail: 'legal@emiliaprotocol.ai',
  privacyEmail: 'privacy@emiliaprotocol.ai',
};

export const FOUNDERS = [
  // TODO[founder]: replace with real names + LinkedIn URLs + photo paths.
  // Anonymous founders are an automatic decline at any bank or agency
  // third-party-risk intake. The /about page surfaces these directly.
  {
    name: 'TODO[founder]: Founder Name',
    role: 'Founder & Maintainer',
    bio:
      'TODO[founder]: 2-3 sentence bio. Include: what role you held before ' +
      'EP, what you shipped that is verifiable, and why you are building ' +
      'pre-action authorization specifically.',
    linkedin: null, // TODO[founder]: 'https://www.linkedin.com/in/...'
    photo: null,    // TODO[founder]: '/about/founder.jpg' once added to public/about/
  },
];

export const ADVISORS = [
  // TODO[founder]: 2-5 named advisors before naming customers. Until at
  // least two advisors are named, leave this array empty — an empty
  // advisors block is more credible than a fabricated one.
  // Target profiles per docs/seo/STRATEGY.md and the strategic review:
  //   - Former OCC / FDIC / Federal Reserve examiner
  //   - Former Treasury OFAC / FinCEN official
  //   - Former CISA / GSA 18F
  //   - Bank CISO or fraud-operations head
  //   - Academic cryptographer / formal-methods researcher
];

export const SUB_PROCESSORS = [
  // Vendors that handle data on behalf of EMILIA Protocol customers.
  // Each entry: name, purpose, region, and the data category processed.
  // This list is referenced on /legal/sub-processors and is part of any
  // standard DPA. Update before adding any new third-party data flow.
  { name: 'Vercel Inc.', purpose: 'Web hosting, edge functions, deployment platform', region: 'United States (multi-region)', data: 'Page request metadata, ephemeral function payloads' },
  { name: 'Supabase, Inc.', purpose: 'Managed Postgres + RLS authorization for trust receipts and policy storage', region: 'United States (us-east, configurable)', data: 'Tenant policy data, trust receipts (signed), entity authority records' },
  { name: 'GitHub, Inc.', purpose: 'Source-code hosting, CI workflows, issue tracking', region: 'United States', data: 'Maintainer + contributor identity (public)' },
  { name: 'npm, Inc. (GitHub)', purpose: 'SDK distribution (@emilia-protocol/sdk, @emilia-protocol/verify)', region: 'United States', data: 'Public package metadata only' },
  { name: 'Cloudflare, Inc.', purpose: 'DNS, edge security, transit-layer DDoS mitigation', region: 'Global edge', data: 'Request metadata, IP addresses (transit only)' },
  // TODO[founder]: add Stripe (when payments wire up), email provider (Resend / Postmark),
  // analytics provider (if/when added), error tracking (Sentry, etc.).
];

export const COMPLIANCE_ROADMAP = {
  // Honest current state. Update only as items become real.
  current: [
    { item: 'Apache 2.0 license', status: 'shipped', evidence: 'github.com/emiliaprotocol/emilia-protocol/blob/main/LICENSE' },
    { item: 'NIST AI RMF mapping (governance + measurement)', status: 'shipped', evidence: '/spec' },
    { item: 'EU AI Act high-risk-system control mapping', status: 'shipped', evidence: '/spec' },
    { item: 'Formal verification — 26 TLA+ theorems, 35 Alloy facts in CI', status: 'shipped', evidence: '/spec, repo formal/ directory' },
    { item: 'Open conformance suite + reference implementations', status: 'shipped', evidence: '/adopt, /spec' },
    { item: 'Responsible disclosure policy + security.txt', status: 'shipped', evidence: '/.well-known/security.txt' },
  ],
  inProgress: [
    // TODO[founder]: list each item with a real target date and named
    // auditor/sponsor. Do NOT publish target dates you cannot hit — bank
    // procurement teams will remember a missed date longer than they
    // would have remembered no date at all.
    { item: 'External cryptographic-protocol review of the ceremony spec', status: 'planned', target: 'Pending pilot funding', auditor: 'Targeting Trail of Bits / NCC Group / Kudelski Security' },
    { item: 'SOC 2 Type I', status: 'planned', target: 'TODO[founder]: real target quarter once auditor is engaged', auditor: 'TODO[founder]: named auditor once contracted' },
    { item: 'Public bug bounty program', status: 'planned', target: 'Q3 2026', auditor: 'Targeting HackerOne or Immunefi' },
  ],
  intent: [
    { item: 'ISO/IEC 27001', note: 'Targeted for first enterprise pilot' },
    { item: 'StateRAMP authorization', note: 'Required for state benefit-integrity programs (GovGuard buyers)' },
    { item: 'FedRAMP Moderate ATO', note: 'Pursuing federal innovation-office sandbox engagement first; full ATO sequenced against named federal sponsor and Phase II SBIR / DARPA funding' },
    { item: 'PCI DSS / NYDFS Part 500 mapping', note: 'For FinGuard treasury-controls deployments' },
    { item: 'FFIEC IT Examination Handbook alignment', note: 'For community-bank and credit-union deployments' },
  ],
};
