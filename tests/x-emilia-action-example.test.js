// SPDX-License-Identifier: Apache-2.0
//
// x-emilia-action — the OpenAPI inline action-consequence extension.
//
// Proves the schema and the example agree (so the doc's example is real, not
// aspirational), and pins the invariants that keep the extension honest:
//   - it validates against public/schemas/x-emilia-action.schema.json;
//   - the action id is a canonical urn:ep:action:<family>.<action> URN;
//   - effects are advisory (present) AND authority is a real requirement, i.e.
//     the extension never ships an effects preview without an authority block.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import Ajv from 'ajv';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'public/schemas/x-emilia-action.schema.json'), 'utf8'));
const doc = yaml.load(fs.readFileSync(path.join(ROOT, 'examples/openapi/x-emilia-action.example.yaml'), 'utf8'));

// Pull every x-emilia-action object out of the example OpenAPI operations.
const annotations = Object.values(doc.paths).flatMap((p) =>
  Object.values(p).map((op) => op && op['x-emilia-action']).filter(Boolean),
);

const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

describe('x-emilia-action OpenAPI extension', () => {
  it('the example annotates at least one consequential operation', () => {
    expect(annotations.length).toBeGreaterThanOrEqual(1);
  });

  it.each(annotations.map((a, i) => [a.action || `#${i}`, a]))(
    '%s validates against the schema',
    (_label, ann) => {
      const ok = validate(ann);
      expect(ok, JSON.stringify(validate.errors, null, 2)).toBe(true);
    },
  );

  it('every annotation uses a canonical urn:ep:action URN and declares authority', () => {
    for (const a of annotations) {
      expect(a.action).toMatch(/^urn:ep:action:[a-z0-9_]+\.[a-z0-9_.]+$/);
      // Honest-composition invariant: an effects preview is never shipped as a
      // standalone risk label — it always rides an authority requirement.
      expect(a.authority, `${a.action} has effects but no authority block`).toBeTruthy();
      expect(typeof a.authority.receipt_required).toBe('boolean');
    }
  });

  it('rejects an effects preview that lowers or omits the authority control', () => {
    const bad = { action: 'urn:ep:action:finance.wire_transfer', effects: { reversibility: 'irreversible' } };
    expect(validate(bad)).toBe(false); // missing required "authority"
  });

  it('rejects a non-canonical action id', () => {
    const bad = { action: 'payment.release', effects: { reversibility: 'reversible' }, authority: { receipt_required: false } };
    expect(validate(bad)).toBe(false); // not a urn:ep:action URN
  });
});
