import { describe, it, expect } from 'vitest';
import { validate, validateBody, Validator, ValidationError } from '../lib/validation/index.js';
import {
  validateHandshakeCreate,
  validatePresent,
  validateSignoffChallenge,
  validateSignoffAttest,
  validatePolicyCreate,
} from '../lib/validation/schemas.js';

// ============================================================================
// 1. Core validator — required field detection
// ============================================================================

describe('Validator: required()', () => {
  it('rejects null', () => {
    expect(() => validate(null, 'x').required().result).toThrow(ValidationError);
  });

  it('rejects undefined', () => {
    expect(() => validate(undefined, 'x').required().result).toThrow(ValidationError);
  });

  it('rejects empty string', () => {
    expect(() => validate('', 'x').required().result).toThrow(ValidationError);
  });

  it('accepts zero', () => {
    expect(validate(0, 'x').required().result).toBe(0);
  });

  it('accepts false', () => {
    expect(validate(false, 'x').required().result).toBe(false);
  });

  it('accepts non-empty string', () => {
    expect(validate('hello', 'x').required().result).toBe('hello');
  });
});

// ============================================================================
// 2. Type checking
// ============================================================================

describe('Validator: type checks', () => {
  it('string() rejects numbers', () => {
    expect(() => validate(123, 'x').string().result).toThrow(ValidationError);
  });

  it('string() accepts strings', () => {
    expect(validate('ok', 'x').string().result).toBe('ok');
  });

  it('isArray() rejects objects', () => {
    expect(() => validate({}, 'x').isArray().result).toThrow(ValidationError);
  });

  it('isArray() accepts arrays', () => {
    expect(validate([1], 'x').isArray().result).toEqual([1]);
  });

  it('isObject() rejects arrays', () => {
    expect(() => validate([], 'x').isObject().result).toThrow(ValidationError);
  });

  it('isObject() rejects null', () => {
    expect(() => validate(null, 'x').isObject().result).toThrow(ValidationError);
  });

  it('isObject() accepts plain objects', () => {
    expect(validate({ a: 1 }, 'x').isObject().result).toEqual({ a: 1 });
  });

  it('isBoolean() rejects strings', () => {
    expect(() => validate('true', 'x').isBoolean().result).toThrow(ValidationError);
  });

  it('isBoolean() accepts booleans', () => {
    expect(validate(true, 'x').isBoolean().result).toBe(true);
  });

  it('isNumber() rejects NaN', () => {
    expect(() => validate(NaN, 'x').isNumber().result).toThrow(ValidationError);
  });

  it('isNumber() accepts numbers', () => {
    expect(validate(42, 'x').isNumber().result).toBe(42);
  });
});

// ============================================================================
// 3. UUID format validation
// ============================================================================

describe('Validator: uuid()', () => {
  it('accepts valid v4 UUID', () => {
    expect(validate('550e8400-e29b-41d4-a716-446655440000', 'x').uuid().result)
      .toBe('550e8400-e29b-41d4-a716-446655440000');
  });

  it('rejects non-UUID string', () => {
    expect(() => validate('not-a-uuid', 'x').uuid().result).toThrow(ValidationError);
  });

  it('rejects numeric input', () => {
    expect(() => validate(12345, 'x').uuid().result).toThrow(ValidationError);
  });

  it('rejects UUID with wrong variant bits', () => {
    expect(() => validate('550e8400-e29b-41d4-c716-446655440000', 'x').uuid().result)
      .toThrow(ValidationError);
  });
});

// ============================================================================
// 4. Email validation
// ============================================================================

describe('Validator: email()', () => {
  it('accepts valid email', () => {
    expect(validate('user@example.com', 'x').email().result).toBe('user@example.com');
  });

  it('rejects missing @', () => {
    expect(() => validate('userexample.com', 'x').email().result).toThrow(ValidationError);
  });

  it('rejects missing domain', () => {
    expect(() => validate('user@', 'x').email().result).toThrow(ValidationError);
  });
});

// ============================================================================
// 5. OneOf constraint
// ============================================================================

describe('Validator: oneOf()', () => {
  it('accepts value in set', () => {
    expect(validate('basic', 'mode').oneOf(['basic', 'mutual']).result).toBe('basic');
  });

  it('accepts value in Set object', () => {
    expect(validate('mutual', 'mode').oneOf(new Set(['basic', 'mutual'])).result).toBe('mutual');
  });

  it('rejects value not in set', () => {
    expect(() => validate('invalid', 'mode').oneOf(['basic', 'mutual']).result)
      .toThrow(ValidationError);
  });

  it('error message lists allowed values', () => {
    try {
      validate('bad', 'mode').oneOf(['a', 'b']).result;
    } catch (e) {
      expect(e.errors[0]).toContain('a, b');
    }
  });
});

// ============================================================================
// 6. String length constraints
// ============================================================================

describe('Validator: length constraints', () => {
  it('maxLength accepts at boundary', () => {
    expect(validate('abc', 'x').maxLength(3).result).toBe('abc');
  });

  it('maxLength rejects over boundary', () => {
    expect(() => validate('abcd', 'x').maxLength(3).result).toThrow(ValidationError);
  });

  it('minLength accepts at boundary', () => {
    expect(validate('abc', 'x').minLength(3).result).toBe('abc');
  });

  it('minLength rejects below boundary', () => {
    expect(() => validate('ab', 'x').minLength(3).result).toThrow(ValidationError);
  });
});

// ============================================================================
// 7. Regex matching
// ============================================================================

describe('Validator: matches()', () => {
  it('accepts matching value', () => {
    expect(validate('2024-01-01T00:00:00Z', 'x').matches(/^\d{4}-\d{2}-\d{2}T/).result)
      .toBe('2024-01-01T00:00:00Z');
  });

  it('rejects non-matching value', () => {
    expect(() => validate('not-a-date', 'x').matches(/^\d{4}-\d{2}-\d{2}T/).result)
      .toThrow(ValidationError);
  });
});

// ============================================================================
// 8. Optional fields
// ============================================================================

describe('Validator: optional()', () => {
  it('skips checks for null when optional', () => {
    expect(validate(null, 'x').optional().string().result).toBe(null);
  });

  it('skips checks for undefined when optional', () => {
    expect(validate(undefined, 'x').optional().string().result).toBe(undefined);
  });

  it('still validates when value is present', () => {
    expect(() => validate(123, 'x').optional().string().result).toThrow(ValidationError);
  });
});

// ============================================================================
// 9. Multiple error accumulation
// ============================================================================

describe('Validator: error accumulation', () => {
  it('collects multiple errors from chained checks', () => {
    const v = validate(null, 'email');
    v.required().string().email();
    // required() fires, string() and email() also fire since value is null (not optional)
    expect(v.errors.length).toBeGreaterThanOrEqual(1);
  });

  it('ValidationError.errors is an array', () => {
    try {
      validate(null, 'x').required().result;
    } catch (e) {
      expect(Array.isArray(e.errors)).toBe(true);
      expect(e.errors[0]).toBe('x is required');
    }
  });
});

describe('validateBody: multi-field error accumulation', () => {
  it('collects errors from multiple fields', () => {
    const result = validateBody({}, {
      name:  (v) => validate(v, 'name').required().string().result,
      email: (v) => validate(v, 'email').required().email().result,
    });

    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(2);
  });

  it('returns data when all fields valid', () => {
    const result = validateBody(
      { name: 'Alice', email: 'alice@example.com' },
      {
        name:  (v) => validate(v, 'name').required().string().result,
        email: (v) => validate(v, 'email').required().email().result,
      },
    );

    expect(result.valid).toBe(true);
    expect(result.data).toEqual({ name: 'Alice', email: 'alice@example.com' });
  });

  it('rejects non-object body', () => {
    const result = validateBody(null, { x: (v) => v });
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toBe('Request body must be a JSON object');
  });
});

// ============================================================================
// 10. Schema: validateHandshakeCreate
// ============================================================================

describe('validateHandshakeCreate', () => {
  const validBody = {
    mode: 'basic',
    policy_id: 'pol_abc',
    parties: [
      { role: 'initiator', entity_ref: 'entity_1' },
      { role: 'responder', entity_ref: 'entity_2' },
    ],
  };

  it('accepts valid handshake body', () => {
    const result = validateHandshakeCreate(validBody);
    expect(result.valid).toBe(true);
    expect(result.data.mode).toBe('basic');
    expect(result.data.parties).toHaveLength(2);
  });

  it('rejects invalid mode', () => {
    const result = validateHandshakeCreate({ ...validBody, mode: 'bogus' });
    expect(result.valid).toBe(false);
  });

  it('rejects missing policy_id', () => {
    const { policy_id, ...rest } = validBody;
    const result = validateHandshakeCreate(rest);
    expect(result.valid).toBe(false);
  });

  it('rejects fewer than 2 parties', () => {
    const result = validateHandshakeCreate({
      ...validBody,
      parties: [{ role: 'initiator', entity_ref: 'e1' }],
    });
    expect(result.valid).toBe(false);
  });

  it('rejects invalid party role', () => {
    const result = validateHandshakeCreate({
      ...validBody,
      parties: [
        { role: 'hacker', entity_ref: 'e1' },
        { role: 'responder', entity_ref: 'e2' },
      ],
    });
    expect(result.valid).toBe(false);
  });

  it('rejects null body', () => {
    const result = validateHandshakeCreate(null);
    expect(result.valid).toBe(false);
  });

  it('passes through optional fields with defaults', () => {
    const result = validateHandshakeCreate(validBody);
    expect(result.data.action_type).toBe(null);
    expect(result.data.payload).toEqual({});
  });
});

// ============================================================================
// 11. Schema: validatePresent
// ============================================================================

describe('validatePresent', () => {
  const validBody = {
    party_role: 'initiator',
    presentation_type: 'self_asserted',
    claims: { name: 'Alice' },
  };

  it('accepts valid presentation body', () => {
    const result = validatePresent(validBody);
    expect(result.valid).toBe(true);
    expect(result.data.party_role).toBe('initiator');
  });

  it('rejects invalid presentation_type', () => {
    const result = validatePresent({ ...validBody, presentation_type: 'fake' });
    expect(result.valid).toBe(false);
  });

  it('rejects array as claims', () => {
    const result = validatePresent({ ...validBody, claims: [1, 2] });
    expect(result.valid).toBe(false);
  });

  it('accepts optional disclosure_mode', () => {
    const result = validatePresent({ ...validBody, disclosure_mode: 'selective' });
    expect(result.valid).toBe(true);
    expect(result.data.disclosure_mode).toBe('selective');
  });

  it('rejects invalid disclosure_mode', () => {
    const result = validatePresent({ ...validBody, disclosure_mode: 'public' });
    expect(result.valid).toBe(false);
  });
});

// ============================================================================
// 12. Schema: validateSignoffChallenge
// ============================================================================

describe('validateSignoffChallenge', () => {
  const validBody = {
    handshakeId: 'hs_abc',
    accountableActorRef: 'entity_human',
    signoffPolicyId: 'pol_signoff',
    bindingHash: 'sha256:abc123',
    requiredAssurance: 'high',
    allowedMethods: ['password', 'totp'],
    expiresAt: '2025-12-31T23:59:59Z',
  };

  it('accepts valid challenge body', () => {
    const result = validateSignoffChallenge(validBody);
    expect(result.valid).toBe(true);
  });

  it('rejects missing handshakeId', () => {
    const { handshakeId, ...rest } = validBody;
    const result = validateSignoffChallenge(rest);
    expect(result.valid).toBe(false);
  });

  it('rejects invalid expiresAt format', () => {
    const result = validateSignoffChallenge({ ...validBody, expiresAt: 'tomorrow' });
    expect(result.valid).toBe(false);
  });
});

// ============================================================================
// 13. Schema: validateSignoffAttest
// ============================================================================

describe('validateSignoffAttest', () => {
  const validBody = {
    humanEntityRef: 'entity_human',
    authMethod: 'api_key',
    assuranceLevel: 'high',
    channel: 'dashboard',
    attestationHash: 'sha256:abc123',
  };

  it('accepts valid attestation body', () => {
    const result = validateSignoffAttest(validBody);
    expect(result.valid).toBe(true);
    expect(result.data.authMethod).toBe('api_key');
  });

  it('rejects missing attestationHash', () => {
    const { attestationHash, ...rest } = validBody;
    const result = validateSignoffAttest(rest);
    expect(result.valid).toBe(false);
  });

  it('rejects all fields missing', () => {
    const result = validateSignoffAttest({});
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(5);
  });
});

// ============================================================================
// 14. Schema: validatePolicyCreate
// ============================================================================

describe('validatePolicyCreate', () => {
  const validBody = {
    name: 'custom_strict',
    description: 'High-value policy for important transactions',
    min_score: 80,
    min_confidence: 0.7,
    min_receipts: 5,
    max_dispute_rate: 0.05,
  };

  it('accepts valid policy body', () => {
    const result = validatePolicyCreate(validBody);
    expect(result.valid).toBe(true);
    expect(result.data.name).toBe('custom_strict');
    expect(result.data.family).toBe('custom');
  });

  it('rejects missing name', () => {
    const { name, ...rest } = validBody;
    const result = validatePolicyCreate(rest);
    expect(result.valid).toBe(false);
  });

  it('rejects non-numeric min_score', () => {
    const result = validatePolicyCreate({ ...validBody, min_score: 'high' });
    expect(result.valid).toBe(false);
  });

  it('rejects description over 1000 chars', () => {
    const result = validatePolicyCreate({ ...validBody, description: 'x'.repeat(1001) });
    expect(result.valid).toBe(false);
  });

  it('accepts optional software_requirements', () => {
    const result = validatePolicyCreate({
      ...validBody,
      software_requirements: { verified_publisher: true },
    });
    expect(result.valid).toBe(true);
    expect(result.data.software_requirements).toEqual({ verified_publisher: true });
  });

  it('rejects non-object software_requirements', () => {
    const result = validatePolicyCreate({
      ...validBody,
      software_requirements: 'yes',
    });
    expect(result.valid).toBe(false);
  });
});
