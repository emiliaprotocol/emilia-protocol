import { describe, it, expect } from 'vitest';
import { isPlaceholder, ENTITY, FOUNDERS, ADVISORS, SUB_PROCESSORS } from '@/lib/site-config';

describe('isPlaceholder', () => {
  it('treats null and undefined as placeholders', () => {
    expect(isPlaceholder(null)).toBe(true);
    expect(isPlaceholder(undefined)).toBe(true);
  });

  it('treats empty / whitespace-only strings as placeholders', () => {
    expect(isPlaceholder('')).toBe(true);
    expect(isPlaceholder('   ')).toBe(true);
  });

  it('treats TODO sentinels as placeholders', () => {
    expect(isPlaceholder('TODO[founder]: Founder Name')).toBe(true);
    expect(isPlaceholder('TODO: fill me')).toBe(true);
  });

  it('treats real values as non-placeholders', () => {
    expect(isPlaceholder('Future Enterprises Corporation')).toBe(false);
    expect(isPlaceholder('Iman Schrock')).toBe(false);
  });

  it('treats non-string, non-null values as non-placeholders', () => {
    expect(isPlaceholder(123)).toBe(false);
    expect(isPlaceholder({})).toBe(false);
    expect(isPlaceholder([])).toBe(false);
  });
});

describe('site-config data integrity (procurement-grade fields are real, not placeholders)', () => {
  it('ENTITY has a real legal name, type, jurisdiction, and contact email', () => {
    expect(isPlaceholder(ENTITY.legalName)).toBe(false);
    expect(isPlaceholder(ENTITY.entityType)).toBe(false);
    expect(isPlaceholder(ENTITY.jurisdiction)).toBe(false);
    expect(ENTITY.email).toMatch(/@/);
    // EIN must never be published in this public config.
    expect(JSON.stringify(ENTITY)).not.toMatch(/\b\d{2}-\d{7}\b/);
  });

  it('names at least one real founder', () => {
    const named = FOUNDERS.filter((f) => !isPlaceholder(f.name));
    expect(named.length).toBeGreaterThanOrEqual(1);
  });

  it('advisors is an array (honest empty allowed) and sub-processors are populated', () => {
    expect(Array.isArray(ADVISORS)).toBe(true);
    expect(SUB_PROCESSORS.length).toBeGreaterThan(0);
    for (const sp of SUB_PROCESSORS) {
      expect(isPlaceholder(sp.name)).toBe(false);
    }
  });
});
