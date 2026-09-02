// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE_ROOT = path.join(ROOT, 'standards/aiuc/incident-fields-v0');
const schema = JSON.parse(readFileSync(
  path.join(PACKAGE_ROOT, 'incident-fields.schema.json'),
  'utf8',
));
const example = JSON.parse(readFileSync(
  path.join(PACKAGE_ROOT, 'example-aiid-1152.json'),
  'utf8',
));

describe('AIUC incident-field JSON Schema', () => {
  it('compiles under JSON Schema 2020-12 and accepts the published example', () => {
    expect(schema.$id).toBe(
      'urn:emilia:aiuc:incident-action-authorization-field-group:v0.1',
    );
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const validate = ajv.compile(schema);

    expect(validate(example), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });
});
