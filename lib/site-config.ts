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
 *
 * Pages detect unfilled values via `isPlaceholder(value)` and render
 * clean stopgap copy instead of leaking the literal "TODO[founder]:"
 * marker text into production HTML.
 */

/**
 * True if `v` is null, empty, or a TODO sentinel.
 * Pages use this to decide whether to render the value or fall back to
 * stopgap copy.
 */
export function isPlaceholder(v: unknown): boolean {
  if (v == null) return true;
  if (typeof v !== 'string') return false;
  const s = v.trim();
  return s.length === 0 || s.startsWith('TODO[') || s.startsWith('TODO:');
}

export interface EntityInfo {
  legalName: string;
  entityType: string;
  jurisdiction: string;
  address: string;
  registrationNumber: string;
  email: string;
  securityEmail: string;
  legalEmail: string;
  privacyEmail: string;
}

export const ENTITY: EntityInfo = {
  // Operating entity for EMILIA Protocol: a dedicated Delaware C-Corporation,
  // "EMILIA Protocol, Inc.", incorporated 2026-06-03 (DE file no. 10647704),
  // formed via Stripe Atlas. (The earlier CA entity, Future Enterprises
  // Corporation, is separate and is not the EMILIA operating entity.)
  legalName: 'EMILIA Protocol, Inc.',
  entityType: 'Delaware C Corporation',
  // Used as governing-law / venue in /legal/terms and shown in the footer.
  // Delaware matches the state of incorporation — confirm Delaware vs.
  // California (principal place of business) with counsel.
  jurisdiction: 'Delaware, USA',
  // Public site shows country only — no city/state, no street address. Full
  // mailing address, phone, and EIN live on procurement / SAM.gov forms and are
  // provided on request; NEVER in this public file (public repo).
  address: 'United States',
  // Public entity registry number (Delaware file number — public record).
  // NEVER put the EIN here.
  registrationNumber: '10647704',
  // Primary contact channel for procurement, security, and legal inquiries.
  email: 'team@emiliaprotocol.ai',
  securityEmail: 'security@emiliaprotocol.ai',
  legalEmail: 'legal@emiliaprotocol.ai',
  privacyEmail: 'privacy@emiliaprotocol.ai',
};

export interface Founder {
  name: string;
  role: string;
  bio: string | null;
  linkedin: string | null;
  photo: string | null;
}

export const FOUNDERS: Founder[] = [
  // The /about page renders this directly. Anonymous founders are an automatic
  // decline at bank / agency third-party-risk intake — so the founder is named.
  // TODO[founder]: add a 2-3 sentence `bio`, your `linkedin` URL, and a
  // headshot at public/about/founder.jpg (then set `photo: '/about/founder.jpg'`).
  // Until then the card renders cleanly with an initials avatar and no bio.
  {
    name: 'Iman Schrock',
    role: 'Founder',
    bio: null,
    linkedin: null,
    photo: null,
  },
];

export interface Advisor {
  name: string;
  title: string;
  bio: string;
}

export const ADVISORS: Advisor[] = [
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

export interface SubProcessor {
  name: string;
  purpose: string;
  region: string;
  data: string;
}

export const SUB_PROCESSORS: SubProcessor[] = [
  // Vendors that handle data on behalf of EMILIA Protocol customers.
  // Each entry: name, purpose, region, and the data category processed.
  // This list is referenced on /legal/sub-processors and is part of any
  // standard DPA. Update before adding any new third-party data flow.
  { name: 'Vercel Inc.', purpose: 'Web hosting, edge functions, deployment platform', region: 'United States (multi-region)', data: 'Page request metadata, ephemeral function payloads' },
  { name: 'Supabase, Inc.', purpose: 'Managed Postgres + RLS authorization for trust receipts and policy storage', region: 'United States (us-east, configurable)', data: 'Tenant policy data, trust receipts (signed), entity authority records' },
  { name: 'GitHub, Inc.', purpose: 'Source-code hosting, CI workflows, issue tracking', region: 'United States', data: 'Maintainer + contributor identity (public)' },
  { name: 'npm, Inc. (GitHub)', purpose: 'SDK distribution (@emilia-protocol/sdk, @emilia-protocol/verify)', region: 'United States', data: 'Public package metadata only' },
  { name: 'Cloudflare, Inc.', purpose: 'DNS, edge security, transit-layer DDoS mitigation', region: 'Global edge', data: 'Request metadata, IP addresses (transit only)' },
  // AI Trust Desk — questionnaire answering. Customer-submitted questionnaire
  // text + product description are sent at inference time to draft sourced
  // answers, on zero-retention API tiers; not used to train provider models.
  { name: 'Anthropic, PBC', purpose: 'AI Trust Desk — LLM answer drafting (primary)', region: 'United States', data: 'Questionnaire question text, vendor product description (inference only; not used for training)' },
  { name: 'OpenAI, L.L.C.', purpose: 'AI Trust Desk — LLM answer drafting (fallback); embeddings for entity registration/search and needs-broadcast matching', region: 'United States', data: 'Questionnaire question text, vendor product description, entity/needs text submitted to registry endpoints (inference only; not used for training)' },
  { name: 'Resend (Plus Five Five, Inc.)', purpose: 'Transactional email — trust-page delivery + status notices', region: 'United States', data: 'Customer contact name + email, engagement reference' },
  { name: 'Stripe, Inc.', purpose: 'Payment processing for AI Trust Desk engagements', region: 'United States', data: 'Billing contact email; card data held by Stripe, never by us' },
  { name: 'Functional Software, Inc. (Sentry)', purpose: 'Error tracking and performance monitoring (up to 10% trace sample)', region: 'United States', data: 'Error class and structural telemetry only (HTTP method, trace IDs/status/timing, runtime/environment); no customer/user IP, headers, URLs/query strings, bodies, user data, breadcrumbs, locals, messages, attachments, span attributes, or receipt/action/signoff/authorization context' },
];

export interface ComplianceCurrentItem {
  item: string;
  status: string;
  evidence: string;
}

export interface ComplianceInProgressItem {
  item: string;
  status: string;
  target: string;
  auditor: string;
}

export interface ComplianceIntentItem {
  item: string;
  note: string;
}

export interface ComplianceRoadmap {
  current: ComplianceCurrentItem[];
  inProgress: ComplianceInProgressItem[];
  intent: ComplianceIntentItem[];
}

export const COMPLIANCE_ROADMAP: ComplianceRoadmap = {
  // Honest current state. Update only as items become real.
  current: [
    { item: 'Apache 2.0 license', status: 'shipped', evidence: 'github.com/emiliaprotocol/emilia-protocol/blob/main/LICENSE' },
    { item: 'NIST AI RMF mapping (governance + measurement)', status: 'shipped', evidence: 'github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/NIST-AI-RMF-MAPPING.md' },
    { item: 'EU AI Act high-risk-system control mapping', status: 'shipped', evidence: 'github.com/emiliaprotocol/emilia-protocol/blob/main/docs/compliance/EU-AI-ACT-MAPPING.md' },
    { item: 'Formal verification — 26 TLA+ theorems, 35 Alloy facts + 32 assertions across four models in CI', status: 'shipped', evidence: '/spec, repo formal/ directory' },
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
