#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
//   npx @emilia-protocol/scan protect <actions.json|--sample> [--out ./emilia] [--apply] [--force]
//
// Turns a scan into drop-in files: a reviewed action-control manifest and a
// guard module you review and import at the credential-owning dispatch boundary.
//
// SAFETY BOUNDARY (this is the whole point):
//   - DRY-RUN by default. It prints every file it WOULD write. Nothing is
//     touched until you pass --apply.
//   - It only ever CREATES NEW FILES under the output dir. It refuses to
//     overwrite an existing file unless you pass --force.
//   - It NEVER edits your existing source. The single call-site line is printed
//     as an instruction for you to apply, not silently spliced into your code.
//   - The generated guard fails closed: defaultIrreversible=true (any tool the
//     scan did not see is gated), and consent/signoff/issue adapters refuse
//     until you wire them. Nothing verifies until you pin issuer keys.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { scanActions } from './index.js';
import { readBoundedRegularFile } from './safe-file.mjs';

let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MCP_GUARD_INSTALL_SPEC = '@emilia-protocol/mcp-guard@0.5.0';

function lstatIfPresent(target) {
  try { return fs.lstatSync(target); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

const SAMPLE = [
  { name: 'getAccountBalance', description: 'Return the current balance for an account' },
  { name: 'sendWire', description: 'Send an outgoing wire transfer to a beneficiary' },
  { name: 'deployToProduction', description: 'Ship the current build to production' },
  { name: 'deleteCustomer', description: 'Permanently remove a customer record' },
  { name: 'summarizeTicket', description: 'Summarize a support ticket', annotations: { readOnlyHint: true } },
  { name: 'reconcileLedger', description: 'Reconcile the internal ledger and post adjustments' },
];

function ingest(file) {
  const raw = readBoundedRegularFile(file, MAX_INPUT_BYTES);
  const text = raw.toString('utf8');
  const gate = strictJsonGate(text);
  if (!gate.ok) throw new Error(`Input refused: ${gate.reason}.`);
  const j = JSON.parse(text);
  if (j && j.openapi && j.paths) {
    const actions = [];
    for (const [p, ops] of Object.entries(j.paths)) {
      for (const [m, op] of Object.entries(ops)) {
        if (!['get', 'post', 'put', 'patch', 'delete'].includes(m)) continue;
        actions.push({ name: op?.operationId || `${m} ${p}`, description: op?.summary || '', http_method: m, route_path: p });
      }
    }
    return { actions, source: 'openapi' };
  }
  const list = Array.isArray(j) ? j : Array.isArray(j.tools) ? j.tools : null;
  if (!list) throw new Error('Unrecognized input.');
  return { actions: list, source: 'mcp' };
}

const args = process.argv.slice(2);
let outDir = 'emilia';
let apply = false;
let force = false;
let sample = false;
let outSeen = false;
const positionals = [];
for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === '--out') {
    const candidate = args[index + 1];
    if (!candidate || candidate.startsWith('-')) {
      console.error('--out requires a value');
      process.exit(2);
    }
    if (outSeen) { console.error('duplicate option: --out'); process.exit(64); }
    outSeen = true;
    outDir = candidate;
    index += 1;
    continue;
  }
  if (arg === '--apply' || arg === '--force' || arg === '--sample') {
    const key = arg.slice(2);
    if ((key === 'apply' && apply) || (key === 'force' && force) || (key === 'sample' && sample)) {
      console.error(`duplicate option: ${arg}`);
      process.exit(64);
    }
    if (key === 'apply') apply = true;
    if (key === 'force') force = true;
    if (key === 'sample') sample = true;
    continue;
  }
  if (arg.startsWith('-')) {
    console.error(`unknown option: ${arg}`);
    process.exit(64);
  }
  positionals.push(arg);
}
if (positionals.length > 1 || (sample && positionals.length > 0)) {
  console.error('provide exactly one input file or --sample, not both');
  process.exit(64);
}
if (force && !apply) {
  console.error('--force requires --apply');
  process.exit(64);
}

let input;
if (sample) input = { actions: SAMPLE, source: 'mcp' };
else {
  const file = positionals[0];
  if (!file) { console.error('usage: codemod.mjs <actions.json|--sample> [--out dir] [--apply] [--force]'); process.exit(2); }
  input = ingest(file);
}

/** @type {any} */
const rep = scanActions(input.actions, { source: input.source });
if (input.source === 'openapi') {
  console.error(
    'OpenAPI protect is unavailable until durable one-use consumption is wired. '
    + 'Use `npx @emilia-protocol/scan <openapi.json>` for passive classification.',
  );
  process.exit(2);
}

// Build the guard's per-tool annotations from the scan. Gated + fail-closed
// actions => irreversible:true; read-only => irreversible:false. Anything the
// scan never saw is caught by defaultIrreversible:true.
const annEntries = rep.results.map(({ action, classification: c }) => {
  const gated = c.decision === 'gate' || c.decision === 'review_fail_closed';
  // The reviewed manifest is the action-identity contract. The wrapper must
  // bind the exact same action_type even for an unrecognized mutator that was
  // defaulted fail-closed; otherwise a receipt acquired from the manifest can
  // never satisfy the generated runtime guard.
  const actionType = rep.manifest.actions.find((a) => a.match?.tool === action.name)?.action_type || action.name;
  const note = c.decision === 'review_fail_closed' ? '  // REVIEW: unrecognized mutator, defaulted fail-closed — confirm or set false'
    : c.decision === 'gate' ? `  // ${c.assurance_class}` : '  // read-only';
  return gated
    ? `  ${JSON.stringify(action.name)}: { irreversible: true, action: ${JSON.stringify(actionType)} },${note}`
    : `  ${JSON.stringify(action.name)}: { irreversible: false },${note}`;
});

const guardJs = `// SPDX-License-Identifier: Apache-2.0
// GENERATED by @emilia-protocol/scan. REVIEW before use; correct any classification.
// Runtime audited against ${MCP_GUARD_INSTALL_SPEC}; install that exact release.
import { withMcpGuard } from '@emilia-protocol/mcp-guard';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(join(here, 'action-control.manifest.json'), 'utf8'));

// Pin your issuer/approver public keys OUT OF BAND (comma-separated base64url SPKI).
// Until this is set, every gated action fails closed.
const trustedKeys = (process.env.EP_TRUSTED_ISSUER_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);

// Per-tool flags from the scan. Edit to correct any false positive/negative.
const annotations = {
${annEntries.join('\n')}
};

/**
 * Wrap your MCP tool-call dispatcher for production.
 * The generator never silently downgrades authoritative state to memory.
 */
export function guardDispatch(dispatch, runtime = {}) {
  if (!runtime.ledger || !runtime.store) {
    throw new TypeError(
      '[emilia] production guard requires a durable provenance ledger and shared atomic consumption store',
    );
  }
  if (runtime.store.durable !== true
      || runtime.store.ownershipFenced !== true
      || runtime.store.permanentConsumption !== true
      || typeof runtime.store.reserve !== 'function'
      || typeof runtime.store.commit !== 'function'
      || typeof runtime.store.release !== 'function') {
    throw new TypeError('[emilia] production guard requires a durable, ownership-fenced, permanent consumption store');
  }
  const pinnedKeys = runtime.trustedKeys || trustedKeys;
  if (!Array.isArray(pinnedKeys) || pinnedKeys.length === 0) {
    throw new TypeError('[emilia] production guard requires at least one pinned trusted key');
  }
  return withMcpGuard(dispatch, {
    annotations,
    defaultIrreversible: true, // fail closed: any tool the scan did not see is gated
    verifyOpts: { trustedKeys: pinnedKeys },
    enforceDemand: true,
    ledger: runtime.ledger,
    store: runtime.store,
    requestConsent: runtime.requestConsent,
    requestClassASignoff: runtime.requestClassASignoff,
    issueReceipt: runtime.issueReceipt,
  });
}

/** Local setup check only. Never use ephemeral state in production. */
export function guardDispatchDemo(dispatch, runtime = {}) {
  if (process.env.NODE_ENV === 'production') {
    throw new TypeError('[emilia] demo guard is unavailable in production');
  }
  return withMcpGuard(dispatch, {
    annotations,
    defaultIrreversible: true,
    verifyOpts: {
      trustedKeys: Array.isArray(runtime.trustedKeys) ? runtime.trustedKeys : [],
      verifyAssurance: runtime.verifyAssurance,
    },
    enforceDemand: true,
    allowEphemeralLedger: true,
  });
}

export { manifest };
`;

const verifySetupJs = `// SPDX-License-Identifier: Apache-2.0
// GENERATED local setup check. It performs no network request and only invokes
// its own synthetic handler. Ephemeral state here is intentional and demo-only.
// It writes nothing unless --emit-handoff is explicit, and then only creates
// scan-adoption-handoff.json beside this file without replacing existing bytes.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import {
  closeSync,
  fsyncSync,
  linkSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bindToolAction } from '@emilia-protocol/mcp-guard';
import { guardDispatchDemo } from './guard.mjs';

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (typeof value === 'object') {
    return '{' + Object.keys(value).sort()
      .map((key) => JSON.stringify(key) + ':' + canonicalize(value[key]))
      .join(',') + '}';
  }
  return JSON.stringify(value);
}

function mintSyntheticReceipt(action, receiptId, privateKey, publicKey) {
  const payload = {
    receipt_id: receiptId,
    subject: 'agent:scan-local-rr1-fixture',
    created_at: new Date().toISOString(),
    claim: {
      action_type: action,
      outcome: 'allow_with_signoff',
      approver: 'ep:approver:synthetic-local-fixture',
    },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url'),
    },
    public_key: publicKey,
  };
}

const here = dirname(fileURLToPath(import.meta.url));
const manifestFile = 'action-control.manifest.json';
const manifestBytes = readFileSync(join(here, manifestFile));
const manifestDigest = 'sha256:' + createHash('sha256').update(manifestBytes).digest('hex');
const manifest = JSON.parse(manifestBytes.toString('utf8'));

const scaffoldFiles = ['guard.mjs', 'verify-setup.mjs', 'INTEGRATION.md'].map((file) => ({
  file,
  sha256: 'sha256:' + createHash('sha256').update(readFileSync(join(here, file))).digest('hex'),
}));
const scaffoldDigest = 'sha256:' + createHash('sha256')
  .update(Buffer.from(JSON.stringify(scaffoldFiles), 'utf8'))
  .digest('hex');

const cli = {
  emitHandoff: false,
  reviewedManifestDigest: null,
  selectedTools: [],
};
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  if (arg === '--emit-handoff') {
    cli.emitHandoff = true;
    continue;
  }
  if (arg === '--reviewed-manifest-digest') {
    if (cli.reviewedManifestDigest !== null) throw new Error('reviewed manifest digest may be supplied only once');
    const value = argv[i + 1];
    if (!value || value.startsWith('-')) throw new Error('reviewed manifest digest is required after --reviewed-manifest-digest');
    cli.reviewedManifestDigest = value;
    i += 1;
    continue;
  }
  if (arg === '--action') {
    const value = argv[i + 1];
    if (!value || value.startsWith('-')) throw new Error('a tool name is required after --action');
    if (value.length > 256) throw new Error('selected action name is too long');
    cli.selectedTools.push(value);
    i += 1;
    continue;
  }
  throw new Error('unknown verify-setup option');
}
if (cli.selectedTools.length > 32) throw new Error('at most 32 actions may be selected');
if (new Set(cli.selectedTools).size !== cli.selectedTools.length) throw new Error('selected actions must be unique');

const visibleConsequential = [];
const visibleByTool = new Map();
for (const action of Array.isArray(manifest?.actions) ? manifest.actions : []) {
  if (!String(action?.id || '').startsWith('discovered.')) continue;
  if (action?.receipt_required !== true || action?.match?.protocol !== 'mcp') continue;
  const tool = action.match.tool;
  if (typeof tool !== 'string' || tool.length === 0 || tool.length > 256) {
    throw new Error('reviewed manifest has an invalid visible consequential action');
  }
  if (visibleByTool.has(tool)) throw new Error('reviewed manifest has duplicate visible consequential actions');
  const selected = {
    id: String(action.id),
    selector: { protocol: 'mcp', tool },
    action_type: String(action.action_type),
    assurance_class: String(action.assurance_class),
    receipt_required: true,
  };
  visibleConsequential.push(selected);
  visibleByTool.set(tool, selected);
}

const selectedActions = cli.selectedTools.map((tool) => {
  const action = visibleByTool.get(tool);
  if (!action) throw new Error('selected tool is not a visible consequential action in the reviewed manifest');
  return action;
});

if (cli.emitHandoff) {
  if (cli.reviewedManifestDigest === null) throw new Error('reviewed manifest digest is required for handoff emission');
  if (cli.reviewedManifestDigest !== manifestDigest) throw new Error('reviewed manifest digest does not match the current manifest bytes');
  if (selectedActions.length === 0) throw new Error('at least one visible consequential action must be explicitly selected');
}

let syntheticHandlerCalls = 0;
const rawDispatch = async () => {
  syntheticHandlerCalls += 1;
  return { executed: true };
};
const keyPair = generateKeyPairSync('ed25519');
const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const guarded = guardDispatchDemo(rawDispatch, {
  trustedKeys: [publicKey],
  // This local fixture checks control flow, exact-action binding, and one-use
  // consumption. It does not claim a named human or hardware-backed assurance.
  verifyAssurance: (_receipt, { requiredTier }) => ({
    ok: true,
    tier: requiredTier,
    reason: 'synthetic_local_fixture',
  }),
});
const checkedActions = selectedActions.length > 0
  ? selectedActions
  : [visibleConsequential[0] || {
    id: 'synthetic.local-check',
    selector: { protocol: 'mcp', tool: '__emilia_local_consequential_check__' },
    action_type: '__emilia_local_consequential_check__',
    assurance_class: 'class_a',
    receipt_required: true,
  }];
const rr1Cases = [];
for (const [index, selected] of checkedActions.entries()) {
  const tool = selected.selector.tool;
  const approvedArgs = { rr1_fixture: { marker: 'approved', sequence: index + 1 } };
  const approvedAction = bindToolAction(tool, approvedArgs, selected.action_type);

  const beforeMissing = syntheticHandlerCalls;
  const missing = await guarded(tool, approvedArgs);
  assert.equal(missing?.ep_refused, true, 'missing receipt was not refused');
  assert.equal(missing?.code, 'emilia_receipt_required', 'unexpected refusal code');
  assert.equal(syntheticHandlerCalls, beforeMissing, 'missing receipt reached the synthetic handler');
  rr1Cases.push({
    case_id: 'RR1-01-missing-receipt:' + tool,
    expected: 'emilia_receipt_required',
    observed: missing.code,
    handler_calls_after: syntheticHandlerCalls,
  });

  const validReceipt = mintSyntheticReceipt(
    approvedAction,
    'rr1_valid_' + (index + 1),
    keyPair.privateKey,
    publicKey,
  );
  const admitted = await guarded(tool, { ...approvedArgs, __ep: { receipt: validReceipt } });
  assert.equal(
    admitted?.executed,
    true,
    'valid synthetic receipt was not admitted: ' + JSON.stringify(admitted),
  );
  assert.equal(syntheticHandlerCalls, beforeMissing + 1, 'valid receipt did not invoke exactly one synthetic handler');
  rr1Cases.push({
    case_id: 'RR1-02-valid-receipt:' + tool,
    expected: 'admitted',
    observed: 'admitted',
    handler_calls_after: syntheticHandlerCalls,
  });

  const substitutionReceipt = mintSyntheticReceipt(
    approvedAction,
    'rr1_substitution_' + (index + 1),
    keyPair.privateKey,
    publicKey,
  );
  const substituted = await guarded(tool, {
    rr1_fixture: { marker: 'substituted', sequence: index + 1 },
    __ep: { receipt: substitutionReceipt },
  });
  assert.equal(substituted?.rejected?.reason, 'action_mismatch', 'substituted action was not refused');
  assert.equal(syntheticHandlerCalls, beforeMissing + 1, 'substitution reached the synthetic handler');
  rr1Cases.push({
    case_id: 'RR1-03-action-substitution:' + tool,
    expected: 'action_mismatch',
    observed: substituted.rejected.reason,
    handler_calls_after: syntheticHandlerCalls,
  });

  const replay = await guarded(tool, { ...approvedArgs, __ep: { receipt: validReceipt } });
  assert.equal(replay?.rejected?.reason, 'replay_refused', 'spent receipt was not refused');
  assert.equal(syntheticHandlerCalls, beforeMissing + 1, 'replay reached the synthetic handler');
  rr1Cases.push({
    case_id: 'RR1-04-replay:' + tool,
    expected: 'replay_refused',
    observed: replay.rejected.reason,
    handler_calls_after: syntheticHandlerCalls,
  });
}
let unknownTool = '__emilia_unscanned_local_check__';
while (visibleByTool.has(unknownTool)) unknownTool += '_next';
const beforeUnknown = syntheticHandlerCalls;
const unknownResult = await guarded(unknownTool, {});
assert.equal(unknownResult?.ep_refused, true, 'an unscanned runtime tool was not refused');
assert.equal(syntheticHandlerCalls, beforeUnknown, 'an unscanned runtime tool reached the synthetic handler');

const rr1ResultCore = {
  profile: 'EP-RR-1-LOCAL-v1',
  manifest_sha256: manifestDigest,
  tested_actions: checkedActions.map((action) => ({
    selector: action.selector,
    action_type: action.action_type,
    assurance_class: action.assurance_class,
    receipt_required: action.receipt_required,
  })),
  cases: rr1Cases,
  synthetic_handler_calls: syntheticHandlerCalls,
};
const rr1ResultsDigest = 'sha256:' + createHash('sha256')
  .update(Buffer.from(JSON.stringify(rr1ResultCore), 'utf8'))
  .digest('hex');

console.log('EMILIA RR-1 CHECK: PASS — ' + rr1Cases.length + '/' + rr1Cases.length + ' cases matched the protected-action contract.');
console.log('The synthetic local handler ran exactly ' + (syntheticHandlerCalls === 1 ? 'once.' : syntheticHandlerCalls + ' times.'));
console.log("This proves only the generated local wrapper's synthetic receipt-required loop.");
console.log('Production still requires a durable ledger, shared atomic store, pinned keys, and a non-bypassable dispatch boundary.');
console.log('Manifest digest to review: ' + manifestDigest);
console.log('Generated scaffold digest: ' + scaffoldDigest);
console.log('RR-1 results digest: ' + rr1ResultsDigest);

if (cli.emitHandoff) {
  const handoff = {
    '@version': 'EP-SCAN-ADOPTION-HANDOFF-v2',
    reviewed_manifest: {
      file: manifestFile,
      sha256: manifestDigest,
    },
    generated_scaffold: {
      sha256: scaffoldDigest,
      files: scaffoldFiles,
    },
    selected_actions: selectedActions,
    local_refusal: {
      status: 'passed',
      claim: 'selected synthetic calls were refused by the generated local demo wrapper before the supplied handler',
      handler_called: false,
      state: 'ephemeral_demo_only',
      claim_boundary: {
        asserted: [
          'selected_actions_refused_locally',
          'supplied_handler_not_called',
        ],
        not_asserted: [
          'production_enforcement',
          'complete_mediation',
          'credential_isolation',
          'durable_state',
          'trusted_key_configuration',
          'signed_refusal_artifact',
          'public_verification',
        ],
      },
    },
    local_rr1: {
      status: 'passed',
      ...rr1ResultCore,
      results_digest: rr1ResultsDigest,
      state: 'ephemeral_demo_only',
      evidence_class: 'self_attested_local_reproduction',
      claim_boundary: {
        asserted: [
          'missing_receipt_refused',
          'synthetic_exact_action_admitted',
          'synthetic_action_substitution_refused',
          'synthetic_receipt_replay_refused',
        ],
        not_asserted: [
          'named_human_approval',
          'hardware_backed_assurance',
          'production_issuer_trust',
          'production_enforcement',
          'complete_mediation',
          'credential_isolation',
          'durable_state',
          'real_world_effect',
          'public_verification',
        ],
      },
    },
  };
  const target = join(here, 'scan-adoption-handoff.json');
  const temp = join(here, '.scan-adoption-handoff.' + process.pid + '.' + randomUUID() + '.tmp');
  let fd;
  try {
    fd = openSync(temp, 'wx', 0o600);
    writeFileSync(fd, JSON.stringify(handoff, null, 2) + '\\n', 'utf8');
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    linkSync(temp, target);
    unlinkSync(temp);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temp); } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') throw cleanupError;
    }
    if (error.code === 'EEXIST') throw new Error('Refusing to overwrite existing handoff');
    throw error;
  }
  console.log('Created owner-only scan-adoption-handoff.json beside the reviewed scaffold.');
}
`;

const integrationMd = `# EMILIA integration (generated)

0. Install the audited runtime guard exactly: \`npm install --save-exact ${MCP_GUARD_INSTALL_SPEC}\`
1. Review \`action-control.manifest.json\` and the \`annotations\` in \`guard.mjs\`.
   Downgrade any false positive; confirm every action marked REVIEW.
2. Add ONE line at your MCP tool-call dispatch site:

\`\`\`js
import { guardDispatch } from './${outDir}/guard.mjs';
// before: const result = await dispatch(name, args, extra);
const dispatch = guardDispatch(rawDispatch, {
  ledger,       // durable provenance ledger; verify it at startup
  store,        // shared atomic consumption store; never process-local in production
  trustedKeys,  // relying-party-pinned issuer/approver keys
  requestConsent,
  requestClassASignoff,
  issueReceipt,
});             // wrap once, at the non-bypassable choke point
\`\`\`

3. Before integration, run \`node ${outDir}/verify-setup.mjs\`. It makes no
   network request, launches no process, executes no consequential handler, and
   writes no file. It prints the exact manifest and scaffold digests to review.
4. After reviewing the manifest, you may explicitly create a privacy-bounded
   machine-readable handoff for selected consequential tools:

\`\`\`bash
node ${outDir}/verify-setup.mjs --emit-handoff --reviewed-manifest-digest sha256:<reviewed-digest> --action <reviewed-tool-name>
\`\`\`

   Repeat \`--action\` to select additional visible tools. The command creates
   owner-only \`${outDir}/scan-adoption-handoff.json\` without overwriting an
   existing file. It includes no tool arguments, credentials, ambient identity,
   host data, timestamps, or paths outside this output directory.
5. Pin keys and supply a durable provenance ledger plus a shared atomic
   consumption store. Wire the consent/signoff/issue adapters to your EP host.

Nothing is enforced until the wrapper owns every path to the provider credential,
the state is durable, and the keys are pinned. This scaffold proposes; it does not
protect on its own. A passed local refusal is not a signed refusal artifact,
public verification, production enforcement, or proof of complete mediation.
`;

const files = [
  { rel: path.join(outDir, 'action-control.manifest.json'), body: `${JSON.stringify(rep.manifest, null, 2)}\n` },
  { rel: path.join(outDir, 'guard.mjs'), body: guardJs },
  { rel: path.join(outDir, 'verify-setup.mjs'), body: verifySetupJs },
  { rel: path.join(outDir, 'INTEGRATION.md'), body: integrationMd },
];

const B = '\x1b[1m'; const D = '\x1b[2m'; const R = '\x1b[0m'; const Y = '\x1b[33m';
console.log(`\n${B}EMILIA codemod — ${input.source} surface, ${rep.counts.total} actions ` +
  `(${rep.counts.gate} gated, ${rep.counts.review_fail_closed} fail-closed for review)${R}`);

if (!apply) {
  console.log(`${Y}DRY RUN — nothing written. Re-run with --apply to create these files.${R}\n`);
  for (const f of files) {
    console.log(`${B}── would create: ${f.rel} ──${R}`);
    console.log(f.body.split('\n').slice(0, 40).map((l) => `${D}| ${R}${l}`).join('\n'));
    if (f.body.split('\n').length > 40) console.log(`${D}| … (${f.body.split('\n').length - 40} more lines)${R}`);
    console.log('');
  }
  process.exit(0);
}

// --apply: create NEW files only, never clobber without --force.
const existing = files.filter((f) => lstatIfPresent(f.rel));
if (existing.length && !force) {
  console.error(`${Y}Refusing to overwrite existing files (pass --force to replace):${R}`);
  for (const f of existing) console.error(`  ${f.rel}`);
  process.exit(1);
}
// Refuse symlink traversal even under --force. A generated security scaffold
// must never follow a presenter-created link and overwrite a file elsewhere.
const outAbsolute = path.resolve(outDir);
const relativeOut = path.relative(process.cwd(), outAbsolute);
if (relativeOut.startsWith('..') || path.isAbsolute(relativeOut)) {
  console.error(`${Y}Refusing output directory outside the current working directory: ${outDir}${R}`);
  process.exit(1);
}
if (!relativeOut || relativeOut.split(path.sep).filter(Boolean).length !== 1) {
  console.error(`${Y}Refusing nested output directory; choose one direct child of the current working directory: ${outDir}${R}`);
  process.exit(1);
}
let cursor = process.cwd();
for (const segment of relativeOut.split(path.sep).filter(Boolean)) {
  cursor = path.join(cursor, segment);
  const current = lstatIfPresent(cursor);
  if (current?.isSymbolicLink()) {
    console.error(`${Y}Refusing symlinked output path: ${cursor}${R}`);
    process.exit(1);
  }
}
for (const f of files) {
  const leaf = lstatIfPresent(f.rel);
  if (leaf?.isSymbolicLink()) {
    console.error(`${Y}Refusing symlinked output file: ${f.rel}${R}`);
    process.exit(1);
  }
  if (leaf && leaf.nlink > 1) {
    console.error(`${Y}Refusing hard-linked output file: ${f.rel}${R}`);
    process.exit(1);
  }
}
// Build the complete scaffold in a fresh sibling directory, then install the
// directory with rename. No write ever resolves through the caller-selected
// output path, so an ancestor/leaf symlink swap cannot redirect a file write.
const stage = fs.mkdtempSync(path.join(process.cwd(), `.${path.basename(relativeOut)}.stage-`));
fs.chmodSync(stage, 0o700);
let backup = null;
try {
  for (const f of files) {
    const leaf = path.relative(outDir, f.rel);
    if (!leaf || leaf.startsWith('..') || path.isAbsolute(leaf) || leaf.includes(path.sep)) {
      throw new Error(`Unsafe generated file path: ${f.rel}`);
    }
    const target = path.join(stage, leaf);
    const fd = fs.openSync(target, 'wx', 0o600);
    try {
      fs.writeFileSync(fd, f.body, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  const existingRoot = lstatIfPresent(outAbsolute);
  if (existingRoot && !force) {
    throw Object.assign(new Error(`Refusing to overwrite existing output directory: ${outDir}`), { code: 'EEXIST' });
  }
  if (existingRoot) {
    if (existingRoot.isSymbolicLink() || !existingRoot.isDirectory()) {
      throw new Error(`Refusing non-directory output path: ${outDir}`);
    }
    backup = path.join(process.cwd(), `.${path.basename(relativeOut)}.backup-${process.pid}-${randomUUID()}`);
    fs.renameSync(outAbsolute, backup);
    const moved = fs.lstatSync(backup);
    if (moved.dev !== existingRoot.dev || moved.ino !== existingRoot.ino) {
      throw new Error(`Output directory changed during replacement: ${outDir}`);
    }
  }
  fs.renameSync(stage, outAbsolute);
  if (backup) {
    fs.rmSync(backup, { recursive: true, force: false });
    backup = null;
  }
  for (const f of files) console.log(`  wrote ${f.rel}`);
} catch (error) {
  if (backup && !lstatIfPresent(outAbsolute)) fs.renameSync(backup, outAbsolute);
  try { fs.rmSync(stage, { recursive: true, force: true }); } catch {}
  throw error;
}
console.log(`\n${B}Done.${R} Now do steps 2 and 3 in ${path.join(outDir, 'INTEGRATION.md')} — nothing is enforced until you do.\n`);
