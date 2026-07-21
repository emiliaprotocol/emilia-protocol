#!/usr/bin/env node
/**
 * create-ep-profile — scaffold a third-party EP profile in the reserved
 * `urn:ep:profile:x-<vendor>:<name>` namespace. No permission, no core change.
 *
 * @license Apache-2.0
 *
 *   node scripts/create-ep-profile.mjs --vendor acme --name wire-approval
 *
 * Emits a self-contained plugin (<50 lines) + a conformance-vectors stub, and
 * prints how to register + verify. The plugin's validateBody may ONLY add
 * rejections — the envelope's PluginCannotWeaken invariant guarantees it can
 * never make a structurally-invalid envelope verify.
 */
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args: Record<string, any> = Object.fromEntries(process.argv.slice(2).reduce((a: any[], t: string, i: number, arr: string[]) => {
  if (t.startsWith('--')) a.push([t.slice(2), arr[i + 1]]);
  return a;
}, []));

const vendor: string = (args.vendor || '').toLowerCase();
const name: string = (args.name || '').toLowerCase();
const ok: RegExp = /^[a-z0-9][a-z0-9-]*$/;
if (!ok.test(vendor) || !ok.test(name)) {
  console.error('usage: create-ep-profile --vendor <slug> --name <slug>  (lowercase, alnum/hyphen)');
  process.exit(1);
}
const urn: string = `urn:ep:profile:x-${vendor}:${name}`;
const slug: string = `x-${vendor}-${name}`;
const pluginPath: string = path.join(root, `lib/envelope/profiles/${slug}.js`);
const vectorsPath: string = path.join(root, `conformance/vectors/${slug}.v1.json`);
mkdirSync(path.dirname(pluginPath), { recursive: true });
if (existsSync(pluginPath)) { console.error(`refusing to overwrite ${pluginPath}`); process.exit(1); }

const plugin: string = `// SPDX-License-Identifier: Apache-2.0
// EP profile: ${urn}  (third-party, reserved private-use namespace)
import { registerProfile } from '../envelope.js';

// Define your profile's body check. It receives the full envelope + verifier
// opts and returns { valid, checks, errors }. RULES: fail closed; verify any
// signature ONLY under a key the verifier PINNED (never a self-asserted key);
// you may ADD rejections but the envelope core already enforces version/profile/
// payload/alg — you cannot weaken those.
export function validateBody(env, opts = {}) {
  const checks = { body_present: false /* add your named checks */ };
  const errors = [];
  if (!env.payload || typeof env.payload !== 'object') {
    errors.push('missing payload');
    return { valid: false, checks, errors };
  }
  checks.body_present = true;
  // TODO: recompute hashes, verify proofs under opts.pinnedKeys, check bindings…
  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}

registerProfile('${urn}', { validateBody });
`;

const vectors: string = JSON.stringify({
  '@version': `${slug.toUpperCase()}-VECTORS-v1`,
  profile: urn,
  spec: `docs/profiles/${slug}.md`,
  description: 'Adversarial conformance vectors. must_reject = genuine forgeries that MUST verify { valid:false }; must_accept = well-formed cases.',
  must_reject: [{ id: 'a_example_reject', title: 'describe the attack', expected: { valid: false, failing_check: 'body_present' } }],
  must_accept: [{ id: 'z_well_formed', title: 'a valid envelope', expected: { valid: true } }],
}, null, 2) + '\n';

writeFileSync(pluginPath, plugin);
writeFileSync(vectorsPath, vectors);

console.log(`✓ created profile ${urn}
  plugin : lib/envelope/profiles/${slug}.js   (fill in validateBody)
  vectors: conformance/vectors/${slug}.v1.json
next:
  1. implement validateBody (fail closed; pin keys; you can only ADD rejections)
  2. add a descriptor row to lib/envelope/descriptors.js + import the plugin in lib/envelope/index.js
  3. run: node scripts/build-ep-registry.mjs   (re-generate the public registry)
  4. verify: import { verifyEnvelope } from 'lib/envelope'; verifyEnvelope({ ep:'EP-ENVELOPE-v1', profile:'${urn}', payload:{...} })`);
