// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — example seed content.
//
// Every record here is an EXAMPLE (example: true, rendered with an EXAMPLE
// tag) that demonstrates the Works surface using only facts derivable from
// this public repository at revision 6d7bc5d229d59f8b80b9de8b1bc8525ed3f273f7:
//
//   * VERIFIED cards cite a content-addressed artifact: the exact repo file
//     plus its SHA-256 (computed from the checked-out file).
//   * ASSERTED cards are self-reported runs of the repo's own checkers and
//     say so in their limitations.
//   * Nothing here scores, ranks, or calls anything trustworthy/safe/best.
//
// Seed records are read-only: the store overlays writable records on top and
// refuses writes to seed ids.

import type {
  ActivityRecord,
  BuilderRecord,
  CapabilityCardRecord,
  ListingRecord,
  OpportunityRecord,
  SubmissionRecord,
} from './model.js';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';
const REV = '6d7bc5d229d59f8b80b9de8b1bc8525ed3f273f7';
const REV_SHORT = REV.slice(0, 8);
const OBSERVED = '2026-08-08T00:00:00Z';
const T = OBSERVED;

const blob = (path: string) => `${REPO}/blob/${REV}/${path}`;
const tree = (path: string) => `${REPO}/tree/${REV}/${path}`;

// SHA-256 digests of the cited files at the revision above, computed at seed
// time with `shasum -a 256 <file>`.
const SHA = {
  conformanceManifest: 'e011fb3538f973cfcea6d02df79500af1d7ab74ee85667b46790633063294058',
  gateServicePkg: '8716d8ab1a00197d57d93b60f0b4eb6b01a6eec0efe32013b4cf479da8d4e07b',
  gatePkg: 'fba03c0f80fc1f224a7543c7d52d5f118ff468e8c1018b7075d0f53b118f762c',
  epVerifyPkg: '852770bd54cbf3b9a3e1a20404d3c16e3a3a74f5365786b3e058ca258e4760d8',
  epVerifyPyProject: 'f977cad9eed1ddfbe3bb3f29029918165ed9d716dea17361e67e279e1baf1fa0',
  mcpServerPkg: 'c81806608887f230d522a77638f6ddc0c075bd14bbe779e536769aab2079c274',
  attestPkg: 'a1ad51ba3ff5e0e4e95b86ebfe96a66754813f77d833e39a36555b05b52366a1',
  sdkTsPkg: '51f724aeb1977ffa37c2c866d8de3c47da47811842815428198e8c4369bc22de',
};

function manifestCard(
  cardId: string,
  listingId: string,
  filePath: string,
  sha256: string,
  statement: string,
): CapabilityCardRecord {
  return {
    card_id: cardId,
    builder_id: 'emilia-protocol-maintainers',
    listing_id: listingId,
    claim: {
      statement,
      status: 'VERIFIED',
      scope: `${filePath} at revision ${REV_SHORT} of emiliaprotocol/emilia-protocol`,
      source: { kind: 'content_addressed_artifact', reference: blob(filePath), sha256 },
      observed_at: T,
      expires_at: null,
      limitations: 'This verifies what the cited file declares at this revision — not runtime behavior, not registry publication, and not third-party review.',
    },
    example: true,
    owner_tenant_id: null,
  };
}

export const SEED_BUILDERS: BuilderRecord[] = [
  {
    builder_id: 'emilia-protocol-maintainers',
    kind: 'legal_entity',
    name: 'EMILIA Protocol maintainers (example)',
    summary: 'The maintainers of the EMILIA Protocol repository, reachable at the contact address published in the repository package manifests. Example profile: every listing below is one of the repository\'s own components.',
    affiliations: [
      { name: 'EMILIA Protocol', relation: 'maintainer' },
    ],
    contact_route: 'mailto:team@emiliaprotocol.ai',
    links: [REPO, 'https://www.emiliaprotocol.ai'],
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
];

export const SEED_LISTINGS: ListingRecord[] = [
  {
    listing_id: 'ep-gate-service',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'app',
    name: 'EMILIA Gate Service',
    summary: 'BYOC HTTP enforcement service for exact-action authorization and durable consequence control (package manifest description).',
    repository_url: tree('apps/gate-service'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['exact-action authorization', 'consequence control'],
    interfaces: ['HTTP'],
    operating_constraints: ['Bring-your-own-cloud deployment; see apps/gate-service in the repository.'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-gate',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'project',
    name: '@emilia-protocol/gate',
    summary: 'Deny-by-default enforcement library: runs a consequential action only on proof a named human authorized this exact action (package manifest description).',
    repository_url: tree('packages/gate'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['action gating', 'receipt-bound execution'],
    interfaces: ['Node.js library', 'CLI (ep-assure)'],
    operating_constraints: ['Deny-by-default posture as described by the package manifest.'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-mcp-server',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'app',
    name: '@emilia-protocol/mcp-server',
    summary: 'MCP server whose ep_guard_action tool holds a payment, deletion, or account change until a named human signs off, returning an offline-verifiable receipt (package manifest description).',
    repository_url: tree('mcp-server'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['agent tool-call gating', 'human sign-off'],
    interfaces: ['MCP', 'CLI (emilia-mcp)'],
    operating_constraints: ['Guards the tool calls routed through it; it does not observe actions taken outside MCP.'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-verify-cli',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'project',
    name: 'ep-verify (CLI)',
    summary: 'One-command offline check of an EP authorization receipt against issuer keys you pin; prints VERIFIED or REFUSED with a machine-readable reason (package manifest description).',
    repository_url: tree('packages/ep-verify'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['offline receipt verification'],
    interfaces: ['CLI (ep-verify)'],
    operating_constraints: ['Proves signature, binding, and anchor integrity — never business correctness (package manifest description).'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-verify-py',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'project',
    name: 'ep-verify (Python)',
    summary: 'One-line offline verifier for EMILIA Protocol authorization receipts; thin CLI over emilia-verify (pyproject description).',
    repository_url: tree('packages/ep-verify-py'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['offline receipt verification'],
    interfaces: ['CLI', 'Python library'],
    operating_constraints: ['Proves signature, binding, and anchor integrity against keys you pin; never business correctness (pyproject description).'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-attest',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'project',
    name: '@emilia-protocol/attest',
    summary: 'Binds relying-party-pinned identity bytes and subject to a work-product hash in a signed EP receipt; no identity, authority, or execution overclaim (package manifest description).',
    repository_url: tree('packages/attest'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['work-product attestation'],
    interfaces: ['Node.js library'],
    operating_constraints: ['Attests binding only; makes no identity, authority, or execution claims (package manifest description).'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-sdk-typescript',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'project',
    name: '@emilia-protocol/sdk',
    summary: 'Minimal TypeScript SDK for the EMILIA Protocol — 5 core endpoints + signoff (package manifest description).',
    repository_url: tree('sdks/typescript'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['protocol client integration'],
    interfaces: ['TypeScript library'],
    operating_constraints: ['Client SDK only; enforcement lives server-side.'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    listing_id: 'ep-conformance-catalog',
    builder_id: 'emilia-protocol-maintainers',
    kind: 'project',
    name: 'EP Conformance Suites',
    summary: 'The repository\'s cross-language conformance catalog: suites, vectors, and a content-addressed manifest recording per-implementation results.',
    repository_url: tree('conformance'),
    service_url: null,
    license: 'Apache-2.0',
    supported_tasks: ['conformance testing', 'cross-language consistency checks'],
    interfaces: ['Node.js test runners', 'JSON vectors'],
    operating_constraints: ['Manifest claim scope: current same-team cross-language consistency; not independent implementation evidence.'],
    status: 'active',
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
];

export const SEED_CARDS: CapabilityCardRecord[] = [
  {
    card_id: 'card-conformance-manifest',
    builder_id: 'emilia-protocol-maintainers',
    listing_id: 'ep-conformance-catalog',
    claim: {
      statement: 'The conformance manifest records 21 suites and 331 vectors with status "pass" for 3 same-team reference implementations (JavaScript, Python, Go).',
      status: 'VERIFIED',
      scope: `conformance/conformance-manifest.json at revision ${REV_SHORT} of emiliaprotocol/emilia-protocol`,
      source: {
        kind: 'content_addressed_artifact',
        reference: blob('conformance/conformance-manifest.json'),
        sha256: SHA.conformanceManifest,
      },
      observed_at: T,
      expires_at: null,
      limitations: 'The manifest\'s own claim_scope: current same-team cross-language consistency; not independent implementation evidence. Counts hold at this revision only.',
    },
    example: true,
    owner_tenant_id: null,
  },
  {
    card_id: 'card-conformance-claims-check',
    builder_id: 'emilia-protocol-maintainers',
    listing_id: 'ep-conformance-catalog',
    claim: {
      statement: 'A maintainer run of `npm run check:public-conformance-claims` at this revision reported PASS: 21 suites, 331 vectors, 359 external hostility cases; 8854 automated test cases across 532 files.',
      status: 'ASSERTED',
      scope: `scripts/check-public-conformance-claims.mjs at revision ${REV_SHORT} of emiliaprotocol/emilia-protocol`,
      source: {
        kind: 'claimant',
        reference: blob('scripts/check-public-conformance-claims.mjs'),
      },
      observed_at: T,
      expires_at: null,
      limitations: 'Self-reported run of the repository\'s own checker — reproduce with `npm run check:public-conformance-claims` at this revision. Not third-party verification.',
    },
    example: true,
    owner_tenant_id: null,
  },
  manifestCard(
    'card-gate-service-manifest',
    'ep-gate-service',
    'apps/gate-service/package.json',
    SHA.gateServicePkg,
    'The package manifest declares @emilia-protocol/gate-service 0.2.0 under Apache-2.0, described as a BYOC HTTP enforcement service for exact-action authorization and durable consequence control.',
  ),
  manifestCard(
    'card-gate-manifest',
    'ep-gate',
    'packages/gate/package.json',
    SHA.gatePkg,
    'The package manifest declares @emilia-protocol/gate 0.23.14 under Apache-2.0, described as deny-by-default enforcement that runs a consequential action only on proof a named human authorized this exact action.',
  ),
  manifestCard(
    'card-mcp-server-manifest',
    'ep-mcp-server',
    'mcp-server/package.json',
    SHA.mcpServerPkg,
    'The package manifest declares @emilia-protocol/mcp-server 2.0.1 under Apache-2.0, exposing the ep_guard_action MCP tool that holds an action until a named human signs off.',
  ),
  manifestCard(
    'card-ep-verify-manifest',
    'ep-verify-cli',
    'packages/ep-verify/package.json',
    SHA.epVerifyPkg,
    'The package manifest declares ep-verify 0.2.1 under Apache-2.0: a one-command offline receipt check against pinned issuer keys that prints VERIFIED or REFUSED with a machine-readable reason.',
  ),
  manifestCard(
    'card-ep-verify-py-manifest',
    'ep-verify-py',
    'packages/ep-verify-py/pyproject.toml',
    SHA.epVerifyPyProject,
    'The pyproject manifest declares ep-verify 0.2.0 under Apache-2.0: a one-line offline verifier for EP authorization receipts, a thin CLI over emilia-verify.',
  ),
  manifestCard(
    'card-attest-manifest',
    'ep-attest',
    'packages/attest/package.json',
    SHA.attestPkg,
    'The package manifest declares @emilia-protocol/attest 0.2.1 under Apache-2.0, binding relying-party-pinned identity bytes and subject to a work-product hash in a signed EP receipt.',
  ),
  manifestCard(
    'card-sdk-ts-manifest',
    'ep-sdk-typescript',
    'sdks/typescript/package.json',
    SHA.sdkTsPkg,
    'The package manifest declares @emilia-protocol/sdk 0.10.0 under Apache-2.0: a minimal TypeScript SDK covering 5 core endpoints plus signoff.',
  ),
];

export const SEED_ACTIVITY: ActivityRecord[] = [
  {
    activity_id: 'act-conformance-manifest',
    listing_id: 'ep-conformance-catalog',
    builder_id: 'emilia-protocol-maintainers',
    type: 'conformance_run',
    title: 'Cross-language conformance manifest present with 3 implementations at status pass',
    occurred_at: T,
    source_url: blob('conformance/conformance-manifest.json'),
    scope: `Observation of conformance/conformance-manifest.json as present at revision ${REV_SHORT}; the manifest, not this entry, is the record of the run.`,
    example: true,
    owner_tenant_id: null,
  },
  {
    activity_id: 'act-gate-service-manifest',
    listing_id: 'ep-gate-service',
    builder_id: 'emilia-protocol-maintainers',
    type: 'release',
    title: 'Version 0.2.0 declared in the gate-service package manifest',
    occurred_at: T,
    source_url: blob('apps/gate-service/package.json'),
    scope: `Declaration in apps/gate-service/package.json at revision ${REV_SHORT}; a version declaration, not an npm publish record.`,
    example: true,
    owner_tenant_id: null,
  },
  {
    activity_id: 'act-mcp-server-manifest',
    listing_id: 'ep-mcp-server',
    builder_id: 'emilia-protocol-maintainers',
    type: 'release',
    title: 'Version 2.0.1 declared in the mcp-server package manifest',
    occurred_at: T,
    source_url: blob('mcp-server/package.json'),
    scope: `Declaration in mcp-server/package.json at revision ${REV_SHORT}; a version declaration, not an npm publish record.`,
    example: true,
    owner_tenant_id: null,
  },
  {
    activity_id: 'act-ep-verify-manifest',
    listing_id: 'ep-verify-cli',
    builder_id: 'emilia-protocol-maintainers',
    type: 'release',
    title: 'Version 0.2.1 declared in the ep-verify package manifest',
    occurred_at: T,
    source_url: blob('packages/ep-verify/package.json'),
    scope: `Declaration in packages/ep-verify/package.json at revision ${REV_SHORT}; a version declaration, not an npm publish record.`,
    example: true,
    owner_tenant_id: null,
  },
  {
    activity_id: 'act-gate-manifest',
    listing_id: 'ep-gate',
    builder_id: 'emilia-protocol-maintainers',
    type: 'release',
    title: 'Version 0.23.14 declared in the gate package manifest',
    occurred_at: T,
    source_url: blob('packages/gate/package.json'),
    scope: `Declaration in packages/gate/package.json at revision ${REV_SHORT}; a version declaration, not an npm publish record.`,
    example: true,
    owner_tenant_id: null,
  },
];

export const SEED_OPPORTUNITIES: OpportunityRecord[] = [
  {
    opportunity_id: 'ex-reproduce-conformance',
    kind: 'challenge',
    title: 'Example: reproduce the cross-language conformance run at a pinned revision',
    description: 'Example opportunity demonstrating the Works submission flow. Check out emiliaprotocol/emilia-protocol at a pinned revision, run the conformance runners under conformance/, and publish your normalized results with the revision and environment you used. A reproduction by a party outside the maintainer team would be exactly that — a reproduction, recorded with its own scope.',
    posted_by: 'EMILIA Protocol maintainers (example)',
    contact_route: 'mailto:team@emiliaprotocol.ai',
    claims: [
      {
        statement: 'No funding is attached to this example opportunity.',
        status: 'ASSERTED',
        scope: 'This example opportunity record only.',
        source: { kind: 'claimant', reference: 'mailto:team@emiliaprotocol.ai' },
        observed_at: T,
        expires_at: null,
        limitations: 'Example content: this opportunity exists to demonstrate the surface.',
      },
      {
        statement: 'Open to any builder; no eligibility restriction is asserted.',
        status: 'ASSERTED',
        scope: 'This example opportunity record only.',
        source: { kind: 'claimant', reference: 'mailto:team@emiliaprotocol.ai' },
        observed_at: T,
        expires_at: null,
        limitations: null,
      },
    ],
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
  {
    opportunity_id: 'ex-mcp-integration',
    kind: 'collaboration',
    title: 'Example: record an agent-framework integration with the MCP guard tool',
    description: 'Example opportunity demonstrating the Works submission flow. Integrate an agent framework with the ep_guard_action MCP tool from mcp-server/ and record the integration as an activity item with a source link, the framework version, and the exact scope of what the guard covered.',
    posted_by: 'EMILIA Protocol maintainers (example)',
    contact_route: 'mailto:team@emiliaprotocol.ai',
    claims: [
      {
        statement: 'Funding for this example collaboration is not specified.',
        status: 'UNKNOWN',
        scope: 'This example opportunity record only.',
        source: null,
        observed_at: T,
        expires_at: null,
        limitations: 'Example content: an UNKNOWN status renders exactly like this so unspecified funding is never mistaken for funded.',
      },
    ],
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
];

export const SEED_SUBMISSIONS: SubmissionRecord[] = [
  {
    submission_id: 'ex-submission-conformance',
    opportunity_id: 'ex-reproduce-conformance',
    builder_id: 'emilia-protocol-maintainers',
    listing_id: 'ep-conformance-catalog',
    proposal: 'Example submission demonstrating the shape of a response: names the pinned revision, the runner commands under conformance/, the environment, and where normalized results will be published. A real submission would come from a builder account through the authenticated API.',
    team: null,
    example: true,
    owner_tenant_id: null,
    created_at: T,
    updated_at: T,
  },
];

export const SEED = Object.freeze({
  builders: SEED_BUILDERS,
  listings: SEED_LISTINGS,
  cards: SEED_CARDS,
  activity: SEED_ACTIVITY,
  opportunities: SEED_OPPORTUNITIES,
  submissions: SEED_SUBMISSIONS,
});
