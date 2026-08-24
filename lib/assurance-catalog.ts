// SPDX-License-Identifier: Apache-2.0

import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { CLAIM_ASSURANCE_REFERENCE_PAGE_PATH } from '@/lib/assurance-reference';

export type AssuranceCatalogueStatus =
  | 'Implemented'
  | 'Scoped engagement'
  | 'Not operating';

export type AssuranceCatalogueItem = Readonly<{
  id: string;
  name: string;
  status: AssuranceCatalogueStatus;
  summary: string;
  evidence: ReadonlyArray<Readonly<{ label: string; href: string }>>;
}>;

export const ASSURANCE_BOUNDARY_LINE =
  'Claims become evidence. Evidence can inform Gate. It never becomes authority by itself.';

export const ASSURANCE_CATALOGUE: ReadonlyArray<AssuranceCatalogueItem> = Object.freeze([
  Object.freeze({
    id: 'open-verification',
    name: 'Open verification and re-performance',
    status: 'Implemented',
    summary:
      'The public CLI, package format, and deterministic procedure let a third party rebuild and re-perform a supplied Gate evidence population under pinned inputs.',
    evidence: Object.freeze([
      Object.freeze({
        label: 'ep-assure CLI',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/gate/ep-assure.mjs',
      }),
      Object.freeze({
        label: 'Package specification',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-ASSURANCE-PACKAGE-SPEC.md',
      }),
    ]),
  }),
  Object.freeze({
    id: 'claim-assurance-reference',
    name: 'Claim Assurance reference record and resolver',
    status: 'Implemented',
    summary:
      'One deterministic, loudly synthetic Claim Case replays into a content-addressed Assurance Record. Exact lookup is public; there is no list, search, customer data, certificate, or production-registry claim.',
    evidence: Object.freeze([
      Object.freeze({
        label: 'Inspect and replay the record',
        href: CLAIM_ASSURANCE_REFERENCE_PAGE_PATH,
      }),
      Object.freeze({
        label: 'Claim Assurance specification',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CLAIM-ASSURANCE-SPEC.md',
      }),
    ]),
  }),
  Object.freeze({
    id: 'portable-records',
    name: 'Portable population assurance packages',
    status: 'Implemented',
    summary:
      'Public formats preserve the supplied population, pinned procedure, integrity results, divergence, exclusions, and outside-verifier statement for offline inspection.',
    evidence: Object.freeze([
      Object.freeze({
        label: 'Assurance package source',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/gate/src/reports/assurance-package.ts',
      }),
      Object.freeze({
        label: 'External verification example',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/external-verification',
      }),
    ]),
  }),
  Object.freeze({
    id: 'deployment-assurance',
    name: 'Managed deployment assurance',
    status: 'Scoped engagement',
    summary:
      'Customer-specific work can pin the protected boundary, evidence sources, profiles, keys, clocks, procedures, and handoff. Scope and commitments belong in the engagement.',
    evidence: Object.freeze([
      Object.freeze({ label: 'Assurance product brief', href: '/assurance#operating-model' }),
      Object.freeze({ label: 'Auditor procedure', href: '/auditors' }),
    ]),
  }),
  Object.freeze({
    id: 'continuous-assurance',
    name: 'Continuous assurance',
    status: 'Scoped engagement',
    summary:
      'Scheduled evidence capture, re-performance, drift review, retention, and relying-party handoff are deployment-scoped operations, not a general-availability service claim.',
    evidence: Object.freeze([
      Object.freeze({ label: 'Engagement entry point', href: '/pilot' }),
      Object.freeze({ label: 'Security boundaries', href: '/security' }),
    ]),
  }),
  Object.freeze({
    id: 'registry-resolver',
    name: 'Hosted registry and record lifecycle service',
    status: 'Not operating',
    summary:
      'EMILIA stewards the intended contract for customer-record lookup, status, supersession, and revocation. Beyond the fixed synthetic reference resolver, no hosted customer assurance registry or lifecycle service is represented as deployed.',
    evidence: Object.freeze([
      Object.freeze({
        label: 'Scheme design and prerequisites',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CERTIFICATION-SCHEME.md',
      }),
    ]),
  }),
  Object.freeze({
    id: 'certification-program',
    name: 'Independent certification program and mark',
    status: 'Not operating',
    summary:
      'EMILIA will steward uniform public criteria and future mark policy. Qualified independent assessors must retain their own evaluation and certification conclusions.',
    evidence: Object.freeze([
      Object.freeze({
        label: 'Public nonclaims and prerequisites',
        href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CERTIFICATION-SCHEME.md',
      }),
    ]),
  }),
]);

export const ASSURANCE_COMMERCIAL_ENTRY = Object.freeze({
  offerId: PROTECTED_WORKFLOW_PILOT.id,
  name: PROTECTED_WORKFLOW_PILOT.name,
  price: PROTECTED_WORKFLOW_PILOT.shortPriceLabel,
  duration: PROTECTED_WORKFLOW_PILOT.durationLabel,
  scope: PROTECTED_WORKFLOW_PILOT.workflowLabel,
  rollout: PROTECTED_WORKFLOW_PILOT.rolloutLabel,
  href: '/pricing',
});

export type TrustIndexItem = Readonly<{
  name: string;
  status: 'Published' | 'Public repository';
  description: string;
  href: string;
  external?: boolean;
}>;

export type TrustIndexGroup = Readonly<{
  title: string;
  items: ReadonlyArray<TrustIndexItem>;
}>;

export const TRUST_INDEX: ReadonlyArray<TrustIndexGroup> = Object.freeze([
  Object.freeze({
    title: 'Security and disclosure',
    items: Object.freeze([
      Object.freeze({
        name: 'Security',
        status: 'Published',
        description: 'Current public security boundaries, generated evidence counts, and conditional roadmap.',
        href: '/security',
      }),
      Object.freeze({
        name: 'Security contact',
        status: 'Published',
        description: 'Machine-readable disclosure contact and policy location.',
        href: '/.well-known/security.txt',
      }),
    ]),
  }),
  Object.freeze({
    title: 'Legal and data',
    items: Object.freeze([
      Object.freeze({
        name: 'Legal index',
        status: 'Published',
        description: 'Index of the public legal documents and legal contact.',
        href: '/legal',
      }),
      Object.freeze({
        name: 'Privacy policy',
        status: 'Published',
        description: 'Published data-handling, retention, and rights statement.',
        href: '/legal/privacy',
      }),
      Object.freeze({
        name: 'Terms of service',
        status: 'Published',
        description: 'Published terms for the covered products, software, and site.',
        href: '/legal/terms',
      }),
      Object.freeze({
        name: 'Sub-processors',
        status: 'Published',
        description: 'Published third-party service-provider disclosures.',
        href: '/legal/sub-processors',
      }),
    ]),
  }),
  Object.freeze({
    title: 'Engineering and assurance',
    items: Object.freeze([
      Object.freeze({
        name: 'Public repository',
        status: 'Public repository',
        description: 'Protocol, reference implementation, tests, vectors, and governed evidence sources.',
        href: 'https://github.com/emiliaprotocol/emilia-protocol',
        external: true,
      }),
      Object.freeze({
        name: 'Engineering evidence',
        status: 'Published',
        description: 'Generated proof taxonomy, bounded results, negative controls, and source links.',
        href: '/proof',
      }),
      Object.freeze({
        name: 'Assurance catalogue',
        status: 'Published',
        description: 'Implemented artifacts, scoped services, operating boundaries, and explicit nonclaims.',
        href: '/assurance',
      }),
      Object.freeze({
        name: 'Synthetic Claim Assurance record',
        status: 'Published',
        description: 'One deterministic reference record, exact resolver, and offline replay procedure with no customer data.',
        href: CLAIM_ASSURANCE_REFERENCE_PAGE_PATH,
      }),
    ]),
  }),
]);
