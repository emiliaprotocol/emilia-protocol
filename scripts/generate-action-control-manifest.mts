// SPDX-License-Identifier: Apache-2.0

import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ACTION_CONTROL_ACQUISITION_ACTION_TYPES,
  ACTION_CONTROL_AUTHORIZATION,
  validateActionControlManifest,
} from '../packages/gate/src/action-control-manifest.ts';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, 'public/.well-known/agent-action-control.json');
const manifest = JSON.parse(await readFile(output, 'utf8'));
// Validate the pre-extension manifest independently of any stale acquisition
// descriptors from an earlier generator version. Every other field must
// already be valid; this generator owns only the reference acquisition fields.
const baseline = structuredClone(manifest);
for (const action of baseline.actions || []) {
  if (action.control) {
    delete action.control.authorization;
    if (action.action_type === 'payment.release') {
      delete action.control.execution_binding?.caid_selector;
    }
  }
}
const legacyReport = validateActionControlManifest(baseline);
if (!legacyReport.ok) {
  throw new Error(`refusing to rewrite invalid action-control manifest: ${legacyReport.errors.join('; ')}`);
}

for (const action of manifest.actions) {
  if (action.receipt_required
      && ACTION_CONTROL_ACQUISITION_ACTION_TYPES.includes(action.action_type)) {
    action.control.authorization = { ...ACTION_CONTROL_AUTHORIZATION };
    action.control.execution_binding.caid_selector = { field: 'action_caid' };
  } else if (action.control && Object.hasOwn(action.control, 'authorization')) {
    delete action.control.authorization;
  }
}

const acquisitionReport = validateActionControlManifest(manifest, { requireAcquisition: true });
if (!acquisitionReport.ok) {
  throw new Error(`generated acquisition manifest is invalid: ${acquisitionReport.errors.join('; ')}`);
}

await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
