// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { createDavinciPasExportHandler } from '../app/api/v1/adapters/health/davinci-pas/export/route.js';
import { createDavinciPasReviewHandler } from '../app/api/v1/adapters/health/davinci-pas/review/route.js';

const ROOT = resolve(import.meta.dirname, '..');
const SPEC_PATHS = ['openapi.yaml', 'docs/api/govguard-v1.yaml'];
const REVIEW_PATH = '/api/v1/adapters/health/davinci-pas/review';
const EXPORT_PATH = '/api/v1/adapters/health/davinci-pas/export';
const TENANT = 'org:pas-contract';
const OPERATION_ID = 'operation:pas-contract';

function loadSpec(relativePath: string) {
  const source = readFileSync(resolve(ROOT, relativePath), 'utf8');
  const document = YAML.parseDocument(source, { uniqueKeys: true });
  return { relativePath, document, spec: document.toJS() };
}

function sortedStatuses(responses: Record<string, unknown>): string[] {
  return Object.keys(responses).sort();
}

function assertDescriptionOnlyResponses(responses: Record<string, unknown>): void {
  for (const response of Object.values(responses)) {
    expect(Object.keys(response as Record<string, unknown>)).toEqual(['description']);
    expect((response as { description?: unknown }).description).toEqual(expect.any(String));
  }
}

function authenticatedEntity() {
  return {
    entity: {
      entity_id: 'actor:pas-contract',
      organization_id: TENANT,
    },
  };
}

function exportRequest(): Request {
  const query = new URLSearchParams({
    organization_id: TENANT,
    operation_id: OPERATION_ID,
  });
  return new Request(`https://www.emiliaprotocol.ai${EXPORT_PATH}?${query}`);
}

const SPECS = SPEC_PATHS.map(loadSpec);

describe('Da Vinci PAS OpenAPI contract', () => {
  it('parses both specifications without duplicate keys, warnings, or malformed response maps', () => {
    for (const { relativePath, document, spec } of SPECS) {
      expect(
        document.errors.map((error) => error.message),
        `${relativePath} must parse without errors`,
      ).toEqual([]);
      expect(
        document.warnings.map((warning) => warning.message),
        `${relativePath} must parse without warnings`,
      ).toEqual([]);

      assertDescriptionOnlyResponses(spec.paths[REVIEW_PATH].post.responses);
      assertDescriptionOnlyResponses(spec.paths[EXPORT_PATH].get.responses);
    }
  });

  it('documents the complete review and export runtime status sets', () => {
    for (const { spec } of SPECS) {
      const review = spec.paths[REVIEW_PATH].post.responses;
      const exportResponses = spec.paths[EXPORT_PATH].get.responses;

      expect(sortedStatuses(review)).toEqual([
        '200',
        '201',
        '202',
        '400',
        '401',
        '403',
        '409',
        '422',
        '503',
      ]);
      expect(review['202'].description).toContain('INDETERMINATE');
      expect(review['202'].description.toLowerCase()).toContain('reconciliation');
      expect(review['202'].description.toLowerCase()).toContain('blind retry');

      expect(sortedStatuses(exportResponses)).toEqual([
        '200',
        '400',
        '401',
        '403',
        '404',
        '503',
      ]);
      expect(exportResponses['404'].description.toLowerCase()).toContain('no exportable packet');
      expect(exportResponses['503'].description.toLowerCase()).toContain('evidence store');
      expect(exportResponses['503'].description.toLowerCase()).toContain('export dependency');
    }
  });

  it('returns 202 when review execution enters INDETERMINATE custody', async () => {
    const handler = createDavinciPasReviewHandler({
      authenticate: async () => authenticatedEntity(),
      load_pas_context: async () => ({ source: 'server-observed' }),
      resolve_control: async () => ({
        execute: async () => ({
          ok: false,
          decision: 'INDETERMINATE',
          reason: 'pas_provider_outcome_indeterminate',
          operation_id: OPERATION_ID,
          reconciliation_required: true,
          retry_safe: false,
        }),
      }) as any,
    });
    const response = await handler(new Request(
      `https://www.emiliaprotocol.ai${REVIEW_PATH}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          organization_id: TENANT,
          operation: 'execute',
          operation_id: OPERATION_ID,
          pas_context_ref: 'pas-context:contract',
          proposal: {},
          approval_evidence: {},
          evaluation: {},
        }),
      },
    ) as any);

    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({
      decision: 'INDETERMINATE',
      reconciliation_required: true,
      retry_safe: false,
    });
  });

  it.each([
    ['pas_reliance_packet_not_available', 404],
    ['pas_evidence_store_unavailable', 503],
    ['pas_prepared_context_mismatch', 503],
  ])('maps export refusal %s to documented HTTP %i', async (reason, status) => {
    const handler = createDavinciPasExportHandler({
      authenticate: async () => authenticatedEntity(),
      resolve_control: async () => ({
        exportReliancePacket: async () => ({ ok: false, reason }),
      }) as any,
    });

    const response = await handler(exportRequest() as any);

    expect(response.status).toBe(status);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect((await response.json()).type).toContain(reason);
  });
});
