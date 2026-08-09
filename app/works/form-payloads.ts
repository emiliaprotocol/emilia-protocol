// SPDX-License-Identifier: Apache-2.0

import type {
  BuilderRecord,
  ListingRecord,
  OpportunityRecord,
  SubmissionRecord,
} from '@/lib/works/model';
import type { Claim } from '@/lib/works/claims';

export type JoinFormInput = {
  builderId: string;
  builderKind: BuilderRecord['kind'];
  builderName: string;
  builderSummary: string;
  contactRoute: string;
  affiliationName: string;
  affiliationRelation: string;
  listingId: string;
  listingKind: ListingRecord['kind'];
  listingName: string;
  listingSummary: string;
  repositoryUrl: string;
  serviceUrl: string;
  license: string;
  supportedTasks: string;
  interfaces: string;
  operatingConstraints: string;
};

export type EntityRegistrationPayload = {
  entity_id: string;
  display_name: string;
  entity_type: 'agent' | 'service_provider';
  description: string;
  capabilities: string[];
  website_url?: string;
};

export type JoinPayloads = {
  entity: EntityRegistrationPayload;
  builder: BuilderRecord;
  listing: ListingRecord;
};

export type SponsorClaimStatus = 'ASSERTED' | 'UNKNOWN';

export type SponsorClaimInput = {
  statement: string;
  status: SponsorClaimStatus;
  scope: string;
  limitations: string;
};

export type OpportunityFormInput = {
  opportunityId: string;
  kind: OpportunityRecord['kind'];
  title: string;
  description: string;
  postedBy: string;
  contactRoute: string;
  funding: SponsorClaimInput;
  authority: SponsorClaimInput;
  eligibility: SponsorClaimInput | null;
};

export type SubmissionFormInput = {
  opportunityId: string;
  builderId: string;
  listingId: string;
  proposal: string;
  team: string;
  visibility: 'private' | 'public';
};

export type SubmissionPayload = SubmissionRecord & {
  visibility: 'private' | 'public';
};

export function splitEntries(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function optional(value: string): string | null {
  return value.trim() || null;
}

export function buildJoinPayloads(input: JoinFormInput): JoinPayloads {
  const supportedTasks = splitEntries(input.supportedTasks);
  const repositoryUrl = optional(input.repositoryUrl);
  const serviceUrl = optional(input.serviceUrl);
  const affiliationName = input.affiliationName.trim();
  const affiliationRelation = input.affiliationRelation.trim();
  const links = [...new Set([repositoryUrl, serviceUrl].filter((value): value is string => Boolean(value)))];

  return {
    entity: {
      entity_id: input.builderId.trim(),
      display_name: input.builderName.trim(),
      entity_type: input.listingKind === 'agent' ? 'agent' : 'service_provider',
      description: input.listingSummary.trim(),
      capabilities: supportedTasks,
      ...(serviceUrl || repositoryUrl ? { website_url: serviceUrl || repositoryUrl || undefined } : {}),
    },
    builder: {
      builder_id: input.builderId.trim(),
      kind: input.builderKind,
      name: input.builderName.trim(),
      summary: optional(input.builderSummary),
      affiliations: affiliationName && affiliationRelation
        ? [{ name: affiliationName, relation: affiliationRelation }]
        : [],
      contact_route: input.contactRoute.trim(),
      links,
    },
    listing: {
      listing_id: input.listingId.trim(),
      builder_id: input.builderId.trim(),
      kind: input.listingKind,
      name: input.listingName.trim(),
      summary: input.listingSummary.trim(),
      repository_url: repositoryUrl,
      service_url: serviceUrl,
      license: optional(input.license),
      supported_tasks: supportedTasks,
      interfaces: splitEntries(input.interfaces),
      operating_constraints: splitEntries(input.operatingConstraints),
      status: 'active',
    },
  };
}

function sponsorClaim(
  label: 'Funding' | 'Authority' | 'Eligibility',
  input: SponsorClaimInput,
  contactRoute: string,
  observedAt: string,
): Claim {
  // Frontend sponsor intake can record only claimant assertions or an unknown
  // state. Any unexpected value fails closed to UNKNOWN; verification happens
  // outside this self-service form and cannot be self-awarded here.
  const status: SponsorClaimStatus = input.status === 'ASSERTED' ? 'ASSERTED' : 'UNKNOWN';
  return {
    statement: `${label} — ${input.statement.trim()}`,
    status,
    scope: input.scope.trim(),
    source: status === 'ASSERTED'
      ? { kind: 'claimant', reference: contactRoute.trim() }
      : null,
    observed_at: observedAt,
    limitations: optional(input.limitations),
  };
}

export function buildOpportunityPayload(
  input: OpportunityFormInput,
  observedAt = new Date().toISOString(),
): OpportunityRecord {
  const claims = [
    sponsorClaim('Funding', input.funding, input.contactRoute, observedAt),
    sponsorClaim('Authority', input.authority, input.contactRoute, observedAt),
  ];
  if (input.eligibility?.statement.trim()) {
    claims.push(sponsorClaim('Eligibility', input.eligibility, input.contactRoute, observedAt));
  }

  return {
    opportunity_id: input.opportunityId.trim(),
    kind: input.kind,
    title: input.title.trim(),
    description: input.description.trim(),
    posted_by: input.postedBy.trim(),
    contact_route: input.contactRoute.trim(),
    claims,
  };
}

export function buildSubmissionPayload(
  input: SubmissionFormInput,
  submissionId: string,
): SubmissionPayload {
  return {
    submission_id: submissionId,
    opportunity_id: input.opportunityId.trim(),
    builder_id: input.builderId.trim(),
    listing_id: optional(input.listingId),
    proposal: input.proposal.trim(),
    team: splitEntries(input.team),
    visibility: input.visibility === 'public' ? 'public' : 'private',
  };
}
