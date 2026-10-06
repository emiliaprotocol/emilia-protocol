// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';

import { computeCaid } from '@/caid/impl/js/caid.mjs';
import {
  activeCaidDefinition,
  CAID_REGISTRY_ENUM_SNAPSHOTS,
} from '@/lib/caid-registry';
import {
  BASELINE_CAID_INPUT,
  type CaidComparison,
  type CaidDemoAction,
  type CaidDemoInput,
} from './types';

type CaidComputed = {
  caid: string;
  digest: string;
  definition_sha256: string;
};

export class CaidDemoInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CaidDemoInputError';
  }
}

const PAYMENT_RELEASE_DEFINITION = activeCaidDefinition('payment.release.1');
const AMOUNT_PATTERN = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;

function validateInput(input: unknown): asserts input is CaidDemoInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new CaidDemoInputError('Enter an amount and destination reference');
  }

  const { amount, destinationReference } = input as Partial<CaidDemoInput>;
  if (typeof amount !== 'string' || amount.length > 64 || !AMOUNT_PATTERN.test(amount)) {
    throw new CaidDemoInputError('Enter an amount such as 82000.00');
  }
  if (typeof destinationReference !== 'string' || destinationReference.trim().length === 0) {
    throw new CaidDemoInputError('Enter a destination reference');
  }
  if (Buffer.byteLength(destinationReference, 'utf8') > 256) {
    throw new CaidDemoInputError('Destination references must be 256 UTF-8 bytes or fewer');
  }
}

function digestDestination(destinationReference: string): string {
  return `sha256:${crypto.createHash('sha256').update(destinationReference, 'utf8').digest('hex')}`;
}

export function buildDemoAction(input: CaidDemoInput): CaidDemoAction {
  validateInput(input);
  return {
    action_type: 'payment.release.1',
    amount: input.amount,
    currency: 'USD',
    beneficiary_account: digestDestination(input.destinationReference),
    payment_instruction_id: 'pi-demo-1042',
  };
}

function computeDemoCaid(action: CaidDemoAction): CaidComputed {
  const result = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: [PAYMENT_RELEASE_DEFINITION],
    enumSnapshots: CAID_REGISTRY_ENUM_SNAPSHOTS,
  });
  if (!result || typeof result.caid !== 'string') {
    const reasons = Array.isArray(result?.refusals) ? result.refusals.join(', ') : 'unknown refusal';
    throw new Error(`CAID computation refused: ${reasons}`);
  }
  return result as CaidComputed;
}

export function buildCaidComparison(input: CaidDemoInput): CaidComparison {
  validateInput(input);
  const approvedAction = buildDemoAction(BASELINE_CAID_INPUT);
  const proposedAction = buildDemoAction(input);
  const approved = computeDemoCaid(approvedAction);
  const proposed = computeDemoCaid(proposedAction);
  const recomputed = computeDemoCaid(approvedAction);
  const changedFields: CaidComparison['changedFields'] = [];
  if (input.amount !== BASELINE_CAID_INPUT.amount) changedFields.push('amount');
  if (input.destinationReference !== BASELINE_CAID_INPUT.destinationReference) changedFields.push('destination');

  return {
    approvedCaid: approved.caid,
    proposedCaid: proposed.caid,
    recomputedCaid: recomputed.caid,
    matchesApprovedAction: proposed.caid === approved.caid,
    changedFields,
    canonicalAction: proposedAction,
  };
}
