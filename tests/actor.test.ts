/**
 * lib/actor.js — resolveActorRef coverage.
 */

import { describe, it, expect } from 'vitest';
import { resolveActorRef } from '../lib/actor.js';

describe('resolveActorRef', () => {
  it('returns fallback when actor is null', () => {
    expect(resolveActorRef(null)).toBe('system');
  });

  it('returns fallback when actor is undefined', () => {
    expect(resolveActorRef(undefined)).toBe('system');
  });

  it('returns fallback when actor is empty string', () => {
    expect(resolveActorRef('')).toBe('system');
  });

  it('returns the string when actor is a string', () => {
    expect(resolveActorRef('entity-abc')).toBe('entity-abc');
  });

  it('uses custom fallback', () => {
    expect(resolveActorRef(null, 'admin')).toBe('admin');
  });

  it('returns entity_id when actor is an object with entity_id', () => {
    expect(resolveActorRef({ entity_id: 'eid-1' })).toBe('eid-1');
  });

  it('returns id when actor object has no entity_id', () => {
    expect(resolveActorRef({ id: 'id-2' })).toBe('id-2');
  });

  it('returns fallback when actor object has neither entity_id nor id', () => {
    expect(resolveActorRef({ name: 'alice' })).toBe('system');
  });

  it('returns fallback when actor is a number (non-string non-object falsy-ish)', () => {
    // typeof 42 is 'number', not object or string — hits line 24
    expect(resolveActorRef(42)).toBe('system');
  });
});
