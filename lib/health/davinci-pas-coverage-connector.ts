// SPDX-License-Identifier: Apache-2.0
/**
 * Reference system-of-record connector for coverage reconciliation.
 *
 * The public request supplies only an opaque source reference. The deployment
 * owns `load`, which MUST retrieve the PAS resources through an authenticated
 * server-side connection to the pinned system of record. Raw FHIR and
 * caller-computed action identifiers are never accepted by `project`.
 */

import type { CoveragePopulationRecord } from '../../packages/gate/src/coverage-reconciliation-runner.js';
import {
  buildDavinciPasReviewBinding,
  verifyDavinciPasReviewBinding,
  type DavinciPasReviewBinding,
} from './davinci-pas-binding.js';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/;
const SOURCE_REFERENCE = /^[A-Za-z][A-Za-z0-9-]{0,63}\/[A-Za-z0-9][A-Za-z0-9.\-]{0,127}$/;
const CLASSIFICATIONS = new Set(['effect', 'excluded', 'exception']);

export interface DavinciPasCoverageProjectionRequest {
  record_id: string;
  source_record_ref: string;
  classification: 'effect' | 'excluded' | 'exception';
}
export interface DavinciPasCoverageSourceConnectorOptions {
  source_system_id: string;
  load: (sourceRecordRef: string) => Promise<unknown>;
}

export interface DavinciPasCoverageProjection {
  source_system_id: string;
  source_record_ref: string;
  record: CoveragePopulationRecord;
  binding: DavinciPasReviewBinding;
}

function validRequest(value: unknown): value is DavinciPasCoverageProjectionRequest {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const input = value as Record<string, unknown>;
  return Reflect.ownKeys(input).length === 3
    && IDENTIFIER.test(String(input.record_id ?? ''))
    && SOURCE_REFERENCE.test(String(input.source_record_ref ?? ''))
    && CLASSIFICATIONS.has(String(input.classification ?? ''));
}

export function createDavinciPasCoverageSourceConnector(
  options: DavinciPasCoverageSourceConnectorOptions,
) {
  if (!options || !IDENTIFIER.test(options.source_system_id)
      || typeof options.load !== 'function') {
    throw new TypeError('Da Vinci PAS coverage connector configuration invalid');
  }
  const sourceSystemId = options.source_system_id;

  return Object.freeze({
    source_system_id: sourceSystemId,
    async project(
      request: DavinciPasCoverageProjectionRequest,
    ): Promise<DavinciPasCoverageProjection> {
      if (!validRequest(request)) {
        throw new TypeError('Da Vinci PAS coverage projection request invalid');
      }
      const observed = await options.load(request.source_record_ref);
      const built = buildDavinciPasReviewBinding(observed);
      if (!built.ok) {
        throw new TypeError(`server-observed PAS record refused: ${built.reasons[0] ?? 'binding_invalid'}`);
      }
      const verified = verifyDavinciPasReviewBinding(built.binding, observed);
      if (!verified.valid) {
        throw new TypeError(`server-observed PAS record refused: ${verified.reasons[0] ?? 'binding_invalid'}`);
      }
      return Object.freeze({
        source_system_id: sourceSystemId,
        source_record_ref: request.source_record_ref,
        record: Object.freeze({
          record_id: request.record_id,
          caid: built.binding.caid,
          action_digest: built.binding.action_digest,
          classification: request.classification,
        }),
        binding: structuredClone(built.binding),
      });
    },
  });
}
