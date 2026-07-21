// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  MOBILE_PRESENTATION_VERSION,
  normalizeControlledMobilePresentation,
  projectMobileAction,
} from './presentation.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const vectors = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'mobile/conformance/mobile-core.v1.json'),
  'utf8',
)).presentation_mapping;

function presentation(materialFields) {
  return {
    '@version': MOBILE_PRESENTATION_VERSION,
    title: 'Controlled action',
    summary: 'Review every exact raw field.',
    risk: 'consequential',
    consequence: 'The selected decision applies only to these exact values.',
    material_fields: materialFields,
  };
}

function expandVector(vector) {
  const action = structuredClone(vector.action);
  const materialFields = structuredClone(vector.material_fields);
  if (vector.repeat_scalar) {
    const value = String.fromCodePoint(vector.repeat_scalar.code_point).repeat(vector.repeat_scalar.count);
    action[vector.repeat_scalar.field] = value;
    materialFields[vector.repeat_scalar.field] = value;
  }
  return { ...vector, action, material_fields: materialFields };
}

test('projects every flat scalar action field losslessly across the shared vectors', () => {
  for (const item of vectors.filter((vector) => vector.expect === 'accept')) {
    const vector = expandVector(item);
    assert.deepEqual(projectMobileAction(vector.action), vector.material_fields, vector.id);
    assert.deepEqual(
      normalizeControlledMobilePresentation(vector.action, presentation(vector.material_fields)).material_fields,
      vector.material_fields,
      vector.id,
    );
  }
});

test('refuses omitted, changed, extra, and nested material fields across the shared vectors', () => {
  for (const item of vectors.filter((vector) => vector.expect === 'reject')) {
    const vector = expandVector(item);
    assert.throws(
      () => normalizeControlledMobilePresentation(vector.action, presentation(vector.material_fields)),
      TypeError,
      vector.id,
    );
  }
});

test('refuses strings containing non-scalar UTF-16', () => {
  assert.throws(() => projectMobileAction({ action_type: 'text.review', note: '\ud800' }), TypeError);
});
