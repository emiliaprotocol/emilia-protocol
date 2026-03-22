/**
 * EP Input Validation — Lightweight, chainable, zero-dependency validation.
 *
 * Strict input validation at the API boundary. Designed to replace ad-hoc
 * field checks across route handlers with a composable, testable framework.
 *
 * @license Apache-2.0
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class ValidationError extends Error {
  constructor(errors) {
    super(`Validation failed: ${errors.join('; ')}`);
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

/**
 * Chainable validator for a single field.
 *
 * Usage:
 *   validate(body.email, 'email').required().string().email().result
 */
export class Validator {
  constructor(value, fieldName) {
    this.value = value;
    this.fieldName = fieldName;
    this.errors = [];
    this._optional = false;
  }

  /** Mark field as optional — subsequent checks are skipped if value is null/undefined. */
  optional() {
    this._optional = true;
    return this;
  }

  /** Adds error if value is null, undefined, or empty string. */
  required() {
    if (this.value === null || this.value === undefined || this.value === '') {
      this.errors.push(`${this.fieldName} is required`);
    }
    return this;
  }

  /** Adds error if value is not a string (skipped for optional + missing). */
  string() {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string') {
      this.errors.push(`${this.fieldName} must be a string`);
    }
    return this;
  }

  /** Adds error if value is not a valid UUID v1-v7. */
  uuid() {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string' || !UUID_RE.test(this.value)) {
      this.errors.push(`${this.fieldName} must be a valid UUID`);
    }
    return this;
  }

  /** Adds error if value is not a valid email address. */
  email() {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string' || !EMAIL_RE.test(this.value)) {
      this.errors.push(`${this.fieldName} must be a valid email address`);
    }
    return this;
  }

  /** Adds error if value is not one of the allowed values. */
  oneOf(values) {
    if (this._isAbsent()) return this;
    const allowed = values instanceof Set ? values : new Set(values);
    if (!allowed.has(this.value)) {
      const list = [...allowed].join(', ');
      this.errors.push(`${this.fieldName} must be one of: ${list}`);
    }
    return this;
  }

  /** Adds error if string length exceeds n. */
  maxLength(n) {
    if (this._isAbsent()) return this;
    if (typeof this.value === 'string' && this.value.length > n) {
      this.errors.push(`${this.fieldName} must be ${n} characters or fewer`);
    }
    return this;
  }

  /** Adds error if string length is below n. */
  minLength(n) {
    if (this._isAbsent()) return this;
    if (typeof this.value === 'string' && this.value.length < n) {
      this.errors.push(`${this.fieldName} must be at least ${n} characters`);
    }
    return this;
  }

  /** Adds error if value is not an array. */
  isArray() {
    if (this._isAbsent()) return this;
    if (!Array.isArray(this.value)) {
      this.errors.push(`${this.fieldName} must be an array`);
    }
    return this;
  }

  /** Adds error if value is not a plain object (non-null, non-array). */
  isObject() {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'object' || this.value === null || Array.isArray(this.value)) {
      this.errors.push(`${this.fieldName} must be an object`);
    }
    return this;
  }

  /** Adds error if value is not a boolean. */
  isBoolean() {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'boolean') {
      this.errors.push(`${this.fieldName} must be a boolean`);
    }
    return this;
  }

  /** Adds error if value is not a number. */
  isNumber() {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'number' || Number.isNaN(this.value)) {
      this.errors.push(`${this.fieldName} must be a number`);
    }
    return this;
  }

  /** Adds error if value doesn't match the given regex. */
  matches(regex) {
    if (this._isAbsent()) return this;
    if (typeof this.value !== 'string' || !regex.test(this.value)) {
      this.errors.push(`${this.fieldName} has an invalid format`);
    }
    return this;
  }

  /** Returns the value if valid, throws ValidationError if not. */
  get result() {
    if (this.errors.length > 0) {
      throw new ValidationError(this.errors);
    }
    return this.value;
  }

  // ── Internal ────────────────────────────────────────────────────────

  /** True when the field is optional and the value is absent. */
  _isAbsent() {
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
export function validate(value, fieldName) {
  return new Validator(value, fieldName);
}

/**
 * Validate multiple fields at once against a schema map.
 *
 * Schema is an object mapping field names to validator functions:
 *   { name: (v) => validate(v, 'name').required().string().result }
 *
 * Returns { valid: true, data } or { valid: false, errors: [...] }.
 */
export function validateBody(body, schema) {
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }

  const errors = [];
  const data = {};

  for (const [field, validator] of Object.entries(schema)) {
    try {
      data[field] = validator(body[field]);
    } catch (err) {
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
