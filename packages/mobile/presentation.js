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
const FIELD_NAME = /^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$/;

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function boundedText(value, maximum, { empty = false } = {}) {
  if (typeof value !== 'string') return false;
  const length = [...value].length;
  return length <= maximum
    && (empty || length > 0)
    && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value);
}

export function normalizeMobilePresentation(value, { allowUnversioned = false } = {}) {
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
    material_fields: Object.fromEntries(fields.sort(([left], [right]) => left.localeCompare(right))),
  };
}

export function validMobilePresentation(value) {
  try {
    normalizeMobilePresentation(value);
    return true;
  } catch {
    return false;
  }
}

export default {
  MOBILE_PRESENTATION_VERSION,
  normalizeMobilePresentation,
  validMobilePresentation,
};
