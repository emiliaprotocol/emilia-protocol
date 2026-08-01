// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import schema from '../docs/EP-PROVENANCE-RECEIPT.schema.json';

const linkSchema = {
  ...schema.$defs.delegationLink,
  $defs: schema.$defs,
};
const validateLink = new Ajv2020({ allErrors: true, strict: false }).compile(linkSchema);

function link(scope: string[]) {
  return {
    sequence: 0,
    delegation_id: 'ep_dlg_scope_grammar',
    delegator: 'ep:key:root#1',
    delegatee: 'ep:agent:worker',
    scope,
    expires_at: '2026-08-01T12:00:00Z',
    parent_ref: 'ep:key:root#1',
  };
}

describe('EP-PROVENANCE-CHAIN-v1 scope grammar', () => {
  it.each([
    '*',
    'payment.*',
    'payment.release',
    'model_to_matter.effect-release',
  ])('accepts the defined scope token %j', (token) => {
    expect(validateLink(link([token])), JSON.stringify(validateLink.errors)).toBe(true);
  });

  it.each([
    '.*',
    'payment..release',
    'payment*',
    '',
  ])('rejects the malformed scope token %j instead of widening it', (token) => {
    expect(validateLink(link([token])), JSON.stringify(validateLink.errors)).toBe(false);
  });
});
