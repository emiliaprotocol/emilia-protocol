import { describe, it, expect } from 'vitest';
import { EP_PROTOCOL_VERSION, EP_VERSION_STRING } from '../lib/protocol-version.js';

// ---------------------------------------------------------------------------
// protocol-version.js — structural and contract tests
//
// This module is used by /api/health to stamp every response with the
// protocol version. Tests verify the shape and invariants so that
// accidental changes are caught before deployment.
// ---------------------------------------------------------------------------

describe('EP_PROTOCOL_VERSION', () => {
  it('is a non-null object', () => {
    expect(EP_PROTOCOL_VERSION).toBeDefined();
    expect(typeof EP_PROTOCOL_VERSION).toBe('object');
  });

  it('has required fields: spec, scoring_model, weight_model, hash_algorithm, receipt_version', () => {
    expect(EP_PROTOCOL_VERSION).toHaveProperty('spec');
    expect(EP_PROTOCOL_VERSION).toHaveProperty('scoring_model');
    expect(EP_PROTOCOL_VERSION).toHaveProperty('weight_model');
    expect(EP_PROTOCOL_VERSION).toHaveProperty('hash_algorithm');
    expect(EP_PROTOCOL_VERSION).toHaveProperty('receipt_version');
  });

  it('spec is a semver-like string', () => {
    expect(typeof EP_PROTOCOL_VERSION.spec).toBe('string');
    expect(EP_PROTOCOL_VERSION.spec).toMatch(/^\d+\.\d+$/);
  });

  it('hash_algorithm is SHA-256', () => {
    expect(EP_PROTOCOL_VERSION.hash_algorithm).toBe('SHA-256');
  });

  it('receipt_version is a positive integer', () => {
    expect(Number.isInteger(EP_PROTOCOL_VERSION.receipt_version)).toBe(true);
    expect(EP_PROTOCOL_VERSION.receipt_version).toBeGreaterThan(0);
  });
});

describe('EP_VERSION_STRING', () => {
  it('is a non-empty string', () => {
    expect(typeof EP_VERSION_STRING).toBe('string');
    expect(EP_VERSION_STRING.length).toBeGreaterThan(0);
  });

  it('starts with EP/', () => {
    expect(EP_VERSION_STRING).toMatch(/^EP\//);
  });

  it('contains the spec version', () => {
    expect(EP_VERSION_STRING).toContain(EP_PROTOCOL_VERSION.spec);
  });
});
