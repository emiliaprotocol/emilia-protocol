// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  authEntityActor,
  authEntityDbId,
  authEntityId,
  authEntityIsOperator,
  authEntityObserveProfile,
  authEntityOrganizationId,
  authEntityReceiptSubmitter,
  authEntityScore,
} from '../lib/auth-projections.js';

describe('authenticated-actor projections', () => {
  it('resolves stable and database ids across supported entity shapes', () => {
    expect(authEntityId({})).toBe('');
    expect(authEntityId({ entity: 'ent-string' })).toBe('ent-string');
    expect(authEntityId({ entity: { entity_id: 'ent-protocol' } })).toBe('ent-protocol');
    expect(authEntityId({ entity: { id: 'ent-db' } })).toBe('ent-db');
    expect(authEntityId({ entity: {} })).toBe('');

    expect(authEntityDbId({})).toBe('');
    expect(authEntityDbId({ entity: 'ent-string' })).toBe('ent-string');
    expect(authEntityDbId({ entity: { id: 'ent-db' } })).toBe('ent-db');
    expect(authEntityDbId({ entity: { entity_id: 'ent-protocol' } })).toBe('ent-protocol');
    expect(authEntityDbId({ entity: {} })).toBe('');
  });

  it('builds the minimum actor projection and rejects missing actors', () => {
    expect(authEntityActor({})).toBeNull();
    expect(authEntityActor({ entity: 'ent-string' })).toEqual({
      id: 'ent-string',
      entity_id: 'ent-string',
    });
    expect(authEntityActor({ entity: { id: 'ent-db', entity_id: 'ent-protocol' } })).toEqual({
      id: 'ent-db',
      entity_id: 'ent-protocol',
    });
    expect(authEntityActor({ entity: { entity_id: 'ent-protocol' } })).toEqual({
      id: 'ent-protocol',
      entity_id: 'ent-protocol',
    });
    expect(authEntityActor({ entity: {} })).toEqual({ id: '', entity_id: '' });
  });

  it('projects organization, observe metadata, and operator state safely', () => {
    expect(authEntityOrganizationId({})).toBeNull();
    expect(authEntityOrganizationId({ entity: 'ent-string' })).toBeNull();
    expect(authEntityOrganizationId({ entity: { organization_id: 'org-1' } })).toBe('org-1');
    expect(authEntityOrganizationId({ entity: {} })).toBeNull();

    expect(authEntityObserveProfile({})).toBeNull();
    expect(authEntityObserveProfile({ entity: 'ent-string' })).toBeNull();
    expect(authEntityObserveProfile({ entity: [] })).toBeNull();
    expect(authEntityObserveProfile({ entity: {
      metadata: { pilot_sandbox: true },
      entity_id: 'ent-1',
      organization_id: 'org-1',
      display_name: 'Pilot',
      description: 'sandbox',
      entity_type: 'software',
      private_key_encrypted: 'must-not-project',
    } })).toEqual({
      metadata: { pilot_sandbox: true },
      entity_id: 'ent-1',
      organization_id: 'org-1',
      display_name: 'Pilot',
      description: 'sandbox',
      entity_type: 'software',
    });

    expect(authEntityIsOperator({ entity: { is_operator: true } })).toBe(true);
    expect(authEntityIsOperator({ entity: { is_operator: false } })).toBe(false);
    expect(authEntityIsOperator({ entity: 'ent-string' })).toBe(false);
    expect(authEntityIsOperator({})).toBe(false);
  });

  it('uses a safe default score and keeps submitter fields allowlisted', () => {
    expect(authEntityScore({ entity: { emilia_score: 91 } })).toBe(91);
    expect(authEntityScore({ entity: { emilia_score: '91' } })).toBe(50);
    expect(authEntityScore({ entity: 'ent-string' })).toBe(50);
    expect(authEntityScore({})).toBe(50);

    expect(authEntityReceiptSubmitter({})).toBeNull();
    expect(authEntityReceiptSubmitter({ entity: 'ent-string' })).toEqual({
      id: 'ent-string',
      entity_id: 'ent-string',
    });
    expect(authEntityReceiptSubmitter({ entity: {
      id: 'ent-db',
      entity_id: 'ent-protocol',
      emilia_score: 88,
      public_key: 'pub-key',
      api_key_hash: 'must-not-project',
    } })).toEqual({
      id: 'ent-db',
      entity_id: 'ent-protocol',
      emilia_score: 88,
      public_key: 'pub-key',
    });
    expect(authEntityReceiptSubmitter({ entity: {
      entity_id: 'ent-protocol',
      emilia_score: null,
    } })).toEqual({
      id: 'ent-protocol',
      entity_id: 'ent-protocol',
      emilia_score: 50,
      public_key: null,
    });
    expect(authEntityReceiptSubmitter({ entity: {} })).toEqual({
      id: '',
      entity_id: '',
      emilia_score: 50,
      public_key: null,
    });
  });
});
