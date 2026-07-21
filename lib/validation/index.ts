/**
 * EP Input Validation — Lightweight, chainable, zero-dependency validation.
 *
 * This is the protocol's canonical validation framework. All API routes should
 * use this module for input validation instead of raw ad-hoc checks. This
 * ensures consistent error handling, testability, and a single source of truth
 * for field constraints and enum allowlists.
 *
 * Strict input validation at the API boundary. Designed to replace ad-hoc
 * field checks across route handlers with a composable, testable framework.
 *
 * @license Apache-2.0
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Enum allowlists for protocol fields that reach innerHTML sinks or
 * other output contexts. App-layer validation here ensures DB CHECK
 * constraints are not the sole XSS/injection guard. Add new enum
 * values here as the protocol evolves.
 */
export const ENUM_ALLOWLISTS = {
  provenance_tier: new Set([
    'self_reported', 'peer_verified', 'platform_verified',
    'bilateral', 'cryptographic', 'institutional',
  ]),
  entity_type: new Set([
    'agent', 'merchant', 'service_provider',
    'github_app', 'github_action', 'mcp_server', 'npm_package',
    'chrome_extension', 'shopify_app', 'marketplace_plugin', 'agent_tool',
  ]),
  trust_policy: new Set([
    'strict', 'standard', 'permissive', 'discovery',
    'mcp_server_safe_v1', 'github_app_standard_v1',
    'npm_package_safe_v1', 'chrome_extension_safe_v1',
  ]),
  confidence: new Set([
    'pending', 'insufficient', 'provisional', 'emerging', 'confident',
  ]),
};

export class ValidationError extends Error {
  errors: string[];

  constructor(errors: string[]) {
    super(`Validation failed: ${errors.join('; ')}`);
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

/**
 * Chainable validator for a single field. `value` is intentionally `any` —
 * it is an arbitrary field pulled off an untrusted request body, and every
 * method below is exactly the runtime check that establishes its real type.
 *
 * Usage:
 *   validate(body.email, 'email').required().string().email().result
 */
export class Validator {
  value: any;
  fieldName: string;
  errors: string[];
  _optional: boolean;

  constructor(value: any, fieldName: string) {
    this.value = value;
    this.fieldName = fieldName;
    this.errors = [];
    this._optional = false;
  }

  /** Mark field as optional — subsequent checks are skipped if value is null/undefined. */
  optional(): this {
    this._optional = true;
    return this;
  }

  /** Adds error if value is null, undefined, or empty string. */
  required(): this {
    if (this.value === null || this.value === undefined || this.value === '') {
      this.errors.push(`${this.fieldName} is required`);
    }
    return this;
  }

  /** Adds error if value is not a string (skipped for optional + missing). */
  string(): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string') {
      this.errors.push(`${this.fieldName} must be a string`);
    }
    return this;
  }

  /** Adds error if value is not a valid UUID v1-v7. */
  uuid(): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string' || !UUID_RE.test(this.value)) {
      this.errors.push(`${this.fieldName} must be a valid UUID`);
    }
    return this;
  }

  /** Adds error if value is not a valid email address. */
  email(): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string' || !EMAIL_RE.test(this.value)) {
      this.errors.push(`${this.fieldName} must be a valid email address`);
    }
    return this;
  }

  /** Adds error if value is not one of the allowed values. */
  oneOf(values: Set<any> | readonly any[]): this {
    if (this._isAbsent()) return this;
    const allowed = values instanceof Set ? values : new Set(values);
    if (!allowed.has(this.value)) {
      const list = [...allowed].join(', ');
      this.errors.push(`${this.fieldName} must be one of: ${list}`);
    }
    return this;
  }

  /** Adds error if string length exceeds n. */
  maxLength(n: number): this {
    if (this._isAbsent()) return this;
    if (typeof this.value === 'string' && this.value.length > n) {
      this.errors.push(`${this.fieldName} must be ${n} characters or fewer`);
    }
    return this;
  }

  /** Adds error if string length is below n. */
  minLength(n: number): this {
    if (this._isAbsent()) return this;
    if (typeof this.value === 'string' && this.value.length < n) {
      this.errors.push(`${this.fieldName} must be at least ${n} characters`);
    }
    return this;
  }

  /** Adds error if value is not an array. */
  isArray(): this {
    if (this._isAbsent()) return this;
    if (!Array.isArray(this.value)) {
      this.errors.push(`${this.fieldName} must be an array`);
    }
    return this;
  }

  /** Adds error if value is not a plain object (non-null, non-array). */
  isObject(): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'object' || this.value === null || Array.isArray(this.value)) {
      this.errors.push(`${this.fieldName} must be an object`);
    }
    return this;
  }

  /** Adds error if value is not a boolean. */
  isBoolean(): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'boolean') {
      this.errors.push(`${this.fieldName} must be a boolean`);
    }
    return this;
  }

  /** Adds error if value is not a number. */
  isNumber(): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'number' || Number.isNaN(this.value)) {
      this.errors.push(`${this.fieldName} must be a number`);
    }
    return this;
  }

  /** Adds error if value doesn't match the given regex. */
  matches(regex: RegExp): this {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string' || !regex.test(this.value)) {
      this.errors.push(`${this.fieldName} has an invalid format`);
    }
    return this;
  }

  /** Returns the value if valid, throws ValidationError if not. */
  get result(): any {
    if (this.errors.length > 0) {
      throw new ValidationError(this.errors);
    }
    return this.value;
  }

  // ── Internal ────────────────────────────────────────────────────────

  /** True when the field is optional and the value is absent. */
  _isAbsent(): boolean {
    if (this._optional && (this.value === null || this.value === undefined)) {
      return true;
    }
    return false;
  }
}

/**
 * Create a chainable validator for a single value.
 *
 *   validate(body.name, 'name').required().string().maxLength(255).result
 */
export function validate(value: any, fieldName: string): Validator {
  return new Validator(value, fieldName);
}

export interface ValidationSuccess<T = Record<string, any>> {
  valid: true;
  data: T;
}

export interface ValidationFailure {
  valid: false;
  errors: string[];
}

export type ValidationResult<T = Record<string, any>> = ValidationSuccess<T> | ValidationFailure;

/**
 * Validate multiple fields at once against a schema map.
 *
 * Schema is an object mapping field names to validator functions:
 *   { name: (v) => validate(v, 'name').required().string().result }
 *
 * Returns { valid: true, data } or { valid: false, errors: [...] }.
 */
export function validateBody(
  body: unknown,
  schema: Record<string, (value: any) => any>,
): ValidationResult {
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }

  const errors: string[] = [];
  const data: Record<string, any> = {};
  const bodyRecord = body as Record<string, any>;

  for (const [field, validator] of Object.entries(schema)) {
    try {
      data[field] = validator(bodyRecord[field]);
    } catch (err: any) {
      if (err instanceof ValidationError) {
        errors.push(...err.errors);
      } else {
        errors.push(`${field}: ${err.message}`);
      }
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, data };
}
