// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — record model + validators.
//
// Six record kinds: builder, listing, activity, capability card, opportunity,
// submission. Validators take untrusted input and return typed ok/error
// results (fail-closed, no throws). Capability cards and opportunity
// funding/authority/eligibility statements are Claims (lib/works/claims.ts)
// so the VERIFIED/ASSERTED/UNKNOWN discipline is structural, not stylistic.
//
// Deliberately absent, by design: scores, rankings, leaderboards, stars, and
// any field that would let the surface call a listing "trustworthy" or "best".

import { validateClaim, type Claim } from './claims.js';

export const WORKS_ID_PATTERN = /^[a-z0-9][a-z0-9-]{2,63}$/;

export const BUILDER_KINDS = Object.freeze(['person', 'legal_entity'] as const);
export const LISTING_KINDS = Object.freeze(['agent', 'app', 'project'] as const);
export const LISTING_STATUSES = Object.freeze(['active', 'paused', 'archived'] as const);
export const ACTIVITY_TYPES = Object.freeze([
  'release', 'demo', 'deployment', 'conformance_run', 'integration',
] as const);
export const OPPORTUNITY_KINDS = Object.freeze([
  'problem', 'challenge', 'bounty', 'procurement_notice', 'collaboration',
] as const);

export interface BuilderRecord {
  builder_id: string;
  kind: (typeof BUILDER_KINDS)[number];
  /** The accountable person or legal entity behind the work. */
  name: string;
  summary?: string | null;
  /** Disclosed affiliations: employer, sponsor, investor, foundation, etc. */
  affiliations: Array<{ name: string; relation: string }>;
  /** How to reach the accountable party: https:// or mailto: route. */
  contact_route: string;
  links?: string[];
  example?: boolean;
  owner_tenant_id?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface ListingRecord {
  listing_id: string;
  builder_id: string;
  kind: (typeof LISTING_KINDS)[number];
  name: string;
  summary: string;
  repository_url?: string | null;
  service_url?: string | null;
  license?: string | null;
  supported_tasks: string[];
  interfaces: string[];
  operating_constraints: string[];
  status: (typeof LISTING_STATUSES)[number];
  example?: boolean;
  owner_tenant_id?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface ActivityRecord {
  activity_id: string;
  listing_id: string;
  builder_id: string;
  type: (typeof ACTIVITY_TYPES)[number];
  title: string;
  /** When the work item happened (ISO 8601). */
  occurred_at: string;
  /** Where the work item can be inspected. */
  source_url: string;
  /** What the work item covers — exact repo/release/workflow/environment. */
  scope: string;
  example?: boolean;
  owner_tenant_id?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface CapabilityCardRecord {
  card_id: string;
  builder_id: string;
  listing_id?: string | null;
  /** The contextual statement, carried as a disciplined Claim. */
  claim: Claim;
  example?: boolean;
  owner_tenant_id?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface OpportunityRecord {
  opportunity_id: string;
  kind: (typeof OPPORTUNITY_KINDS)[number];
  title: string;
  description: string;
  /** Who posted it — display name plus contact route. */
  posted_by: string;
  contact_route: string;
  /** Funding / authority / eligibility statements each carry claim status. */
  claims: Claim[];
  example?: boolean;
  owner_tenant_id?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface SubmissionRecord {
  submission_id: string;
  opportunity_id: string;
  builder_id: string;
  listing_id?: string | null;
  proposal: string;
  team?: string[] | null;
  example?: boolean;
  owner_tenant_id?: string | null;
  created_at?: string;
  updated_at?: string;
}

export type WorksRecord =
  | BuilderRecord
  | ListingRecord
  | ActivityRecord
  | CapabilityCardRecord
  | OpportunityRecord
  | SubmissionRecord;

export type ModelError = { ok: false; code: string; detail: string };
export type ModelOk<T> = { ok: true; record: T };
export type ModelResult<T> = ModelOk<T> | ModelError;

const MAX_NAME_CHARS = 200;
const MAX_SUMMARY_CHARS = 2000;
const MAX_URL_CHARS = 600;
const MAX_TAG_CHARS = 80;
const MAX_TAGS = 24;
const MAX_AFFILIATIONS = 24;
const MAX_LINKS = 24;
const MAX_PROPOSAL_CHARS = 8000;
const MAX_CLAIMS = 24;
const MAX_TEAM = 24;

function err(code: string, detail: string): ModelError {
  return { ok: false, code, detail };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) return null;
  return trimmed;
}

export function validWorksId(value: unknown): value is string {
  return typeof value === 'string' && WORKS_ID_PATTERN.test(value);
}

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 10
    && value.length <= 40
    && Number.isFinite(Date.parse(value));
}

/** Contact/source routes: https or mailto only — no javascript:, no data:. */
function validRoute(value: unknown): string | null {
  const route = boundedString(value, MAX_URL_CHARS);
  if (!route) return null;
  if (/^https:\/\/\S+$/i.test(route) || /^mailto:\S+@\S+$/i.test(route)) return route;
  return null;
}

function validHttpsUrl(value: unknown): string | null {
  const url = boundedString(value, MAX_URL_CHARS);
  if (!url) return null;
  return /^https:\/\/\S+$/i.test(url) ? url : null;
}

function stringArray(value: unknown, maxItems: number, maxChars: number): string[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const out: string[] = [];
  for (const item of value) {
    const bounded = boundedString(item, maxChars);
    if (!bounded) return null;
    out.push(bounded);
  }
  return out;
}

function oneOf<T extends readonly string[]>(value: unknown, allowed: T): T[number] | null {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value)
    ? (value as T[number])
    : null;
}

export function validateBuilder(input: unknown): ModelResult<BuilderRecord> {
  if (!isPlainObject(input)) return err('invalid_builder', 'builder must be an object');
  if (!validWorksId(input.builder_id)) return err('invalid_builder_id', 'builder_id must match [a-z0-9-], 3-64 chars');
  const kind = oneOf(input.kind, BUILDER_KINDS);
  if (!kind) return err('invalid_builder_kind', `kind must be one of: ${BUILDER_KINDS.join(', ')}`);
  const name = boundedString(input.name, MAX_NAME_CHARS);
  if (!name) return err('invalid_builder_name', 'name is required');
  const contactRoute = validRoute(input.contact_route);
  if (!contactRoute) return err('invalid_contact_route', 'contact_route must be an https:// or mailto: route');

  const affiliations: Array<{ name: string; relation: string }> = [];
  if (input.affiliations !== undefined && input.affiliations !== null) {
    if (!Array.isArray(input.affiliations) || input.affiliations.length > MAX_AFFILIATIONS) {
      return err('invalid_affiliations', 'affiliations must be an array of { name, relation }');
    }
    for (const item of input.affiliations) {
      if (!isPlainObject(item)) return err('invalid_affiliations', 'each affiliation must be an object');
      const affName = boundedString(item.name, MAX_NAME_CHARS);
      const relation = boundedString(item.relation, MAX_NAME_CHARS);
      if (!affName || !relation) return err('invalid_affiliations', 'each affiliation requires name and relation');
      affiliations.push({ name: affName, relation });
    }
  }

  let summary: string | null = null;
  if (input.summary !== undefined && input.summary !== null) {
    summary = boundedString(input.summary, MAX_SUMMARY_CHARS);
    if (!summary) return err('invalid_builder_summary', 'summary must be a non-empty string when present');
  }

  const links: string[] = [];
  if (input.links !== undefined && input.links !== null) {
    if (!Array.isArray(input.links) || input.links.length > MAX_LINKS) {
      return err('invalid_links', 'links must be an array of https URLs');
    }
    for (const link of input.links) {
      const url = validHttpsUrl(link);
      if (!url) return err('invalid_links', 'each link must be an https:// URL');
      links.push(url);
    }
  }

  return {
    ok: true,
    record: {
      builder_id: input.builder_id as string,
      kind,
      name,
      summary,
      affiliations,
      contact_route: contactRoute,
      links,
      example: input.example === true,
    },
  };
}

export function validateListing(input: unknown): ModelResult<ListingRecord> {
  if (!isPlainObject(input)) return err('invalid_listing', 'listing must be an object');
  if (!validWorksId(input.listing_id)) return err('invalid_listing_id', 'listing_id must match [a-z0-9-], 3-64 chars');
  if (!validWorksId(input.builder_id)) return err('invalid_builder_id', 'builder_id must match [a-z0-9-], 3-64 chars');
  const kind = oneOf(input.kind, LISTING_KINDS);
  if (!kind) return err('invalid_listing_kind', `kind must be one of: ${LISTING_KINDS.join(', ')}`);
  const name = boundedString(input.name, MAX_NAME_CHARS);
  if (!name) return err('invalid_listing_name', 'name is required');
  const summary = boundedString(input.summary, MAX_SUMMARY_CHARS);
  if (!summary) return err('invalid_listing_summary', 'summary is required');
  const status = oneOf(input.status ?? 'active', LISTING_STATUSES);
  if (!status) return err('invalid_listing_status', `status must be one of: ${LISTING_STATUSES.join(', ')}`);

  let repositoryUrl: string | null = null;
  if (input.repository_url !== undefined && input.repository_url !== null) {
    repositoryUrl = validHttpsUrl(input.repository_url);
    if (!repositoryUrl) return err('invalid_repository_url', 'repository_url must be an https:// URL when present');
  }
  let serviceUrl: string | null = null;
  if (input.service_url !== undefined && input.service_url !== null) {
    serviceUrl = validHttpsUrl(input.service_url);
    if (!serviceUrl) return err('invalid_service_url', 'service_url must be an https:// URL when present');
  }
  let license: string | null = null;
  if (input.license !== undefined && input.license !== null) {
    license = boundedString(input.license, MAX_TAG_CHARS);
    if (!license) return err('invalid_license', 'license must be a non-empty string when present');
  }

  const supportedTasks = stringArray(input.supported_tasks, MAX_TAGS, MAX_TAG_CHARS);
  if (!supportedTasks) return err('invalid_supported_tasks', 'supported_tasks must be an array of short strings');
  const interfaces = stringArray(input.interfaces, MAX_TAGS, MAX_TAG_CHARS);
  if (!interfaces) return err('invalid_interfaces', 'interfaces must be an array of short strings');
  const operatingConstraints = stringArray(input.operating_constraints, MAX_TAGS, MAX_SUMMARY_CHARS);
  if (!operatingConstraints) return err('invalid_operating_constraints', 'operating_constraints must be an array of strings');

  return {
    ok: true,
    record: {
      listing_id: input.listing_id as string,
      builder_id: input.builder_id as string,
      kind,
      name,
      summary,
      repository_url: repositoryUrl,
      service_url: serviceUrl,
      license,
      supported_tasks: supportedTasks,
      interfaces,
      operating_constraints: operatingConstraints,
      status,
      example: input.example === true,
    },
  };
}

export function validateActivity(input: unknown): ModelResult<ActivityRecord> {
  if (!isPlainObject(input)) return err('invalid_activity', 'activity must be an object');
  if (!validWorksId(input.activity_id)) return err('invalid_activity_id', 'activity_id must match [a-z0-9-], 3-64 chars');
  if (!validWorksId(input.listing_id)) return err('invalid_listing_id', 'listing_id must match [a-z0-9-], 3-64 chars');
  if (!validWorksId(input.builder_id)) return err('invalid_builder_id', 'builder_id must match [a-z0-9-], 3-64 chars');
  const type = oneOf(input.type, ACTIVITY_TYPES);
  if (!type) return err('invalid_activity_type', `type must be one of: ${ACTIVITY_TYPES.join(', ')}`);
  const title = boundedString(input.title, MAX_NAME_CHARS);
  if (!title) return err('invalid_activity_title', 'title is required');
  if (!isIsoTimestamp(input.occurred_at)) return err('invalid_occurred_at', 'occurred_at must be an ISO 8601 timestamp');
  const sourceUrl = validHttpsUrl(input.source_url);
  if (!sourceUrl) return err('invalid_source_url', 'source_url must be an https:// URL');
  const scope = boundedString(input.scope, MAX_SUMMARY_CHARS);
  if (!scope) return err('invalid_activity_scope', 'scope is required: name the exact repo/release/workflow/environment');

  return {
    ok: true,
    record: {
      activity_id: input.activity_id as string,
      listing_id: input.listing_id as string,
      builder_id: input.builder_id as string,
      type,
      title,
      occurred_at: input.occurred_at as string,
      source_url: sourceUrl,
      scope,
      example: input.example === true,
    },
  };
}

export function validateCapabilityCard(input: unknown): ModelResult<CapabilityCardRecord> {
  if (!isPlainObject(input)) return err('invalid_capability_card', 'capability card must be an object');
  if (!validWorksId(input.card_id)) return err('invalid_card_id', 'card_id must match [a-z0-9-], 3-64 chars');
  if (!validWorksId(input.builder_id)) return err('invalid_builder_id', 'builder_id must match [a-z0-9-], 3-64 chars');
  let listingId: string | null = null;
  if (input.listing_id !== undefined && input.listing_id !== null) {
    if (!validWorksId(input.listing_id)) return err('invalid_listing_id', 'listing_id must match [a-z0-9-], 3-64 chars');
    listingId = input.listing_id;
  }
  const claim = validateClaim(input.claim);
  if (!claim.ok) return claim;

  return {
    ok: true,
    record: {
      card_id: input.card_id as string,
      builder_id: input.builder_id as string,
      listing_id: listingId,
      claim: claim.claim,
      example: input.example === true,
    },
  };
}

export function validateOpportunity(input: unknown): ModelResult<OpportunityRecord> {
  if (!isPlainObject(input)) return err('invalid_opportunity', 'opportunity must be an object');
  if (!validWorksId(input.opportunity_id)) return err('invalid_opportunity_id', 'opportunity_id must match [a-z0-9-], 3-64 chars');
  const kind = oneOf(input.kind, OPPORTUNITY_KINDS);
  if (!kind) return err('invalid_opportunity_kind', `kind must be one of: ${OPPORTUNITY_KINDS.join(', ')}`);
  const title = boundedString(input.title, MAX_NAME_CHARS);
  if (!title) return err('invalid_opportunity_title', 'title is required');
  const description = boundedString(input.description, MAX_PROPOSAL_CHARS);
  if (!description) return err('invalid_opportunity_description', 'description is required');
  const postedBy = boundedString(input.posted_by, MAX_NAME_CHARS);
  if (!postedBy) return err('invalid_posted_by', 'posted_by is required');
  const contactRoute = validRoute(input.contact_route);
  if (!contactRoute) return err('invalid_contact_route', 'contact_route must be an https:// or mailto: route');

  const claims: Claim[] = [];
  if (input.claims !== undefined && input.claims !== null) {
    if (!Array.isArray(input.claims) || input.claims.length > MAX_CLAIMS) {
      return err('invalid_opportunity_claims', 'claims must be an array of claim objects');
    }
    for (const raw of input.claims) {
      const claim = validateClaim(raw);
      if (!claim.ok) return claim;
      claims.push(claim.claim);
    }
  }

  return {
    ok: true,
    record: {
      opportunity_id: input.opportunity_id as string,
      kind,
      title,
      description,
      posted_by: postedBy,
      contact_route: contactRoute,
      claims,
      example: input.example === true,
    },
  };
}

export function validateSubmission(input: unknown): ModelResult<SubmissionRecord> {
  if (!isPlainObject(input)) return err('invalid_submission', 'submission must be an object');
  if (!validWorksId(input.submission_id)) return err('invalid_submission_id', 'submission_id must match [a-z0-9-], 3-64 chars');
  if (!validWorksId(input.opportunity_id)) return err('invalid_opportunity_id', 'opportunity_id must match [a-z0-9-], 3-64 chars');
  if (!validWorksId(input.builder_id)) return err('invalid_builder_id', 'builder_id must match [a-z0-9-], 3-64 chars');
  let listingId: string | null = null;
  if (input.listing_id !== undefined && input.listing_id !== null) {
    if (!validWorksId(input.listing_id)) return err('invalid_listing_id', 'listing_id must match [a-z0-9-], 3-64 chars');
    listingId = input.listing_id;
  }
  const proposal = boundedString(input.proposal, MAX_PROPOSAL_CHARS);
  if (!proposal) return err('invalid_proposal', 'proposal is required');
  const team = stringArray(input.team, MAX_TEAM, MAX_NAME_CHARS);
  if (!team) return err('invalid_team', 'team must be an array of names');

  return {
    ok: true,
    record: {
      submission_id: input.submission_id as string,
      opportunity_id: input.opportunity_id as string,
      builder_id: input.builder_id as string,
      listing_id: listingId,
      proposal,
      team,
      example: input.example === true,
    },
  };
}
