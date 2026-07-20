// SPDX-License-Identifier: Apache-2.0

export const MOBILE_PRESENTATION_VERSION = 'EP-MOBILE-PRESENTATION-v1';

const PRESENTATION_MEMBERS = new Set([
  '@version',
  'title',
  'summary',
  'risk',
  'consequence',
  'material_fields',
]);
const FIELD_NAME = /^@?[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$/;
type AnyRecord = Record<string, any>;

function record(value: any): value is AnyRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function validUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function boundedText(value: any, maximum: number, { empty = false }: AnyRecord = {}): boolean {
  if (typeof value !== 'string') return false;
  const length = [...value].length;
  return length <= maximum
    && (empty || length > 0)
    && validUnicodeScalars(value)
    && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value);
}

/**
 * @param {[string, unknown]} left
 * @param {[string, unknown]} right
 */
function compareFieldNames([left]: any[], [right]: any[]): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function materialText(value: any): string {
  if (typeof value === 'string') {
    if (!boundedText(value, 4_096, { empty: true })) {
      throw new TypeError('mobile action strings must be bounded display text');
    }
    return value;
  }
  if (Number.isSafeInteger(value)) return String(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value === null) return 'null';
  throw new TypeError('mobile actions must be flat objects of strings, safe integers, booleans, or null');
}

export function projectMobileAction(action: AnyRecord): AnyRecord {
  if (!record(action)) throw new TypeError('mobile action must be an object');
  const fields = Object.entries(action);
  if (fields.length < 1 || fields.length > 64
      || fields.some(([name]) => !FIELD_NAME.test(name))) {
    throw new TypeError('mobile action must contain 1 to 64 controlled fields');
  }
  return Object.fromEntries(fields
    .map(([name, value]) => /** @type {[string, string]} */ ([name, materialText(value)]))
    .sort(compareFieldNames));
}

export function normalizeMobilePresentation(value: AnyRecord, { allowUnversioned = false }: AnyRecord = {}): AnyRecord {
  if (!record(value) || !Object.keys(value).every((key) => PRESENTATION_MEMBERS.has(key))) {
    throw new TypeError('mobile presentation has unknown or malformed members');
  }
  const version = value['@version'] ?? (allowUnversioned ? MOBILE_PRESENTATION_VERSION : null);
  if (version !== MOBILE_PRESENTATION_VERSION
      || !boundedText(value.title, 200)
      || !boundedText(value.summary, 2_000)
      || !boundedText(value.risk, 128)
      || !boundedText(value.consequence, 2_000, { empty: true })
      || !record(value.material_fields)) {
    throw new TypeError('mobile presentation does not satisfy EP-MOBILE-PRESENTATION-v1');
  }
  const fields = Object.entries(value.material_fields);
  if (fields.length < 1 || fields.length > 64
      || fields.some(([name, field]) => !FIELD_NAME.test(name) || !boundedText(field, 4_096, { empty: true }))) {
    throw new TypeError('mobile presentation material fields must be flat bounded strings');
  }
  return {
    '@version': MOBILE_PRESENTATION_VERSION,
    title: value.title,
    summary: value.summary,
    risk: value.risk,
    consequence: value.consequence,
    material_fields: Object.fromEntries(fields.sort(compareFieldNames)),
  };
}

export function normalizeControlledMobilePresentation(action: AnyRecord, value: AnyRecord, options: AnyRecord = {}): AnyRecord {
  const normalized = normalizeMobilePresentation(value, options);
  const expected = projectMobileAction(action);
  const names = Object.keys(expected);
  if (Object.keys(normalized.material_fields).length !== names.length
      || names.some((name) => normalized.material_fields[name] !== expected[name])) {
    throw new TypeError('mobile presentation does not exactly cover the controlled action');
  }
  return normalized;
}

export function validControlledMobilePresentation(action: AnyRecord, value: AnyRecord): boolean {
  try {
    normalizeControlledMobilePresentation(action, value);
    return true;
  } catch {
    return false;
  }
}

export function validMobilePresentation(value: AnyRecord): boolean {
  try {
    normalizeMobilePresentation(value);
    return true;
  } catch {
    return false;
  }
}

export default {
  MOBILE_PRESENTATION_VERSION,
  projectMobileAction,
  normalizeMobilePresentation,
  normalizeControlledMobilePresentation,
  validMobilePresentation,
  validControlledMobilePresentation,
};
