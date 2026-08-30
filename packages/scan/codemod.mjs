#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
//   npx @emilia-protocol/scan@0.5.0 protect <actions.json|--sample> [--out ./emilia]
//     [--action <selected-tool>] [--apply] [--verify] [--force]
//   npx @emilia-protocol/scan@0.5.0 protect <actions.json|--sample> [--out ./emilia]
//     --action <selected-tool> --reviewed
//
// Turns a scan into drop-in files: a proposed action-control manifest, a local
// Authority Map, and a guard module you review before importing it at the
// credential-owning dispatch boundary.
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
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { scanActions } from './index.js';
import { readBoundedRegularFile } from './safe-file.mjs';
import { renderAuthorityBrain, SCAN_INSTALL_SPEC, SCAN_PACKAGE_VERSION } from './brain.mjs';

let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_GENERATED_FILE_BYTES = 64 * 1024 * 1024;
const MCP_GUARD_VERSION = '0.6.0';
const MCP_GUARD_INSTALL_SPEC = `@emilia-protocol/mcp-guard@${MCP_GUARD_VERSION}`;
const GATE_STARTER_MARKER_FILE = '.emilia-gate-starter.json';
const GATE_STARTER_MARKER_VERSION = 'EP-GATE-STARTER-v1';
const CROSSING_PROFILES = new Set([
  'ccs-wang-draft08-v13',
  'cedulon-aeb-crossing-v0.1',
  'pinto-cbap1-aeb-v0.1',
]);
const GATE_STARTER_BOUND_FILES = Object.freeze([
  'action-control.manifest.json',
  'authority-map.html',
  'guard.mjs',
  'verify-setup.mjs',
  'INTEGRATION.md',
]);
const RESERVED_OUTPUT_ROOTS = new Set(['.git', '.hg', '.svn', 'node_modules']);
const SOURCE_CONFUSING = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const TERMINAL_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;

function terminalSafe(value) {
  return String(value).replace(TERMINAL_CONTROLS, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint === undefined
      ? '\\u{fffd}'
      : `\\u{${codePoint.toString(16).padStart(4, '0')}}`;
  });
}

function sourceSafeCliValue(value, label, maxLength = 4_096) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || SOURCE_CONFUSING.test(value)) {
    console.error(`${label} contains unsupported or source-confusing characters`);
    process.exit(64);
  }
  return value;
}

/** @param {string | null} value @param {string} label @returns {string} */
function requireParsedCliValue(value, label) {
  if (value === null) throw new Error(`internal invariant: ${label} was not parsed`);
  return value;
}

function lstatIfPresent(target) {
  try { return fs.lstatSync(target); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function assertAllowedOutputRoot(candidate) {
  const leaf = path.basename(path.resolve(candidate)).toLowerCase();
  if (RESERVED_OUTPUT_ROOTS.has(leaf)) {
    console.error(`Refusing reserved output directory: ${terminalSafe(candidate)}`);
    process.exit(64);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(candidate)) {
    console.error('--out must be a portable direct-child slug using only letters, numbers, dot, underscore, or hyphen');
    process.exit(64);
  }
}

function readOwnerOnlyGeneratedFile(target, label) {
  const stat = lstatIfPresent(target);
  if (!stat || stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1
      || (stat.mode & 0o077) !== 0 || stat.size > MAX_GENERATED_FILE_BYTES) {
    throw new Error(`Refusing unsafe or non-owner-only generated ${label}`);
  }
  return fs.readFileSync(target);
}

function validateGateStarterMarker(root, { exactEntries = false } = {}) {
  const rootStat = lstatIfPresent(root);
  if (!rootStat || rootStat.isSymbolicLink() || !rootStat.isDirectory()
      || (rootStat.mode & 0o077) !== 0) {
    throw new Error('Refusing a Gate Starter directory that is not an owner-only regular directory');
  }
  const markerBytes = readOwnerOnlyGeneratedFile(
    path.join(root, GATE_STARTER_MARKER_FILE),
    'Gate Starter marker',
  );
  const markerText = markerBytes.toString('utf8');
  const markerGate = strictJsonGate(markerText);
  if (!markerGate.ok) throw new Error('Refusing an invalid Gate Starter marker');
  const marker = JSON.parse(markerText);
  if (!marker || typeof marker !== 'object' || Array.isArray(marker)
      || marker['@version'] !== GATE_STARTER_MARKER_VERSION
      || marker.generator?.package !== '@emilia-protocol/scan'
      || marker.generator?.version !== SCAN_PACKAGE_VERSION
      || marker.artifact_state !== 'not_activated'
      || !/^sha256:[0-9a-f]{64}$/.test(marker.declared_surface_sha256)
      || !Array.isArray(marker.generated_files)
      || marker.generated_files.length !== GATE_STARTER_BOUND_FILES.length) {
    throw new Error('Refusing a directory without the current Gate Starter marker schema');
  }
  const markerNames = marker.generated_files.map((entry) => entry?.file);
  if (JSON.stringify(markerNames) !== JSON.stringify(GATE_STARTER_BOUND_FILES)) {
    throw new Error('Refusing a Gate Starter marker with an unexpected generated file set');
  }
  for (const entry of marker.generated_files) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || !/^sha256:[0-9a-f]{64}$/.test(entry.sha256)) {
      throw new Error('Refusing a Gate Starter marker with an invalid file digest');
    }
    const bytes = readOwnerOnlyGeneratedFile(path.join(root, entry.file), entry.file);
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    if (digest !== entry.sha256) {
      throw new Error(`Refusing a Gate Starter whose generated file digest changed: ${entry.file}`);
    }
  }
  if (exactEntries) {
    const actual = fs.readdirSync(root).sort();
    const expected = [...GATE_STARTER_BOUND_FILES, GATE_STARTER_MARKER_FILE].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error('Refusing to replace a Gate Starter directory with unrecognized or missing files');
    }
  }
  return marker;
}

function posixQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function installedMcpGuardVersion(cwd = process.cwd()) {
  try {
    let cursor = path.resolve(cwd);
    for (;;) {
      const packageFile = path.join(
        cursor,
        'node_modules',
        '@emilia-protocol',
        'mcp-guard',
        'package.json',
      );
      const stat = lstatIfPresent(packageFile);
      if (stat?.isFile()) {
        const parsed = JSON.parse(fs.readFileSync(fs.realpathSync(packageFile), 'utf8'));
        if (parsed?.name === '@emilia-protocol/mcp-guard') return parsed.version;
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) return null;
      cursor = parent;
    }
  } catch {
    return null;
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
let verify = false;
let reviewed = false;
let selectedTool = null;
let crossingProfile = null;
let crossingOut = null;
let outSeen = false;
let crossingOutSeen = false;
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
    outDir = sourceSafeCliValue(candidate, '--out', 255);
    index += 1;
    continue;
  }
  if (arg === '--action') {
    const candidate = args[index + 1];
    if (!candidate || candidate.startsWith('-')) {
      console.error('--action requires a tool name');
      process.exit(2);
    }
    if (selectedTool !== null) { console.error('exactly one --action may be selected'); process.exit(64); }
    selectedTool = sourceSafeCliValue(candidate, '--action tool name', 256);
    index += 1;
    continue;
  }
  if (arg === '--crossing-profile') {
    const candidate = args[index + 1];
    if (!candidate || candidate.startsWith('-')) {
      console.error('--crossing-profile requires a launch profile id');
      process.exit(2);
    }
    if (crossingProfile !== null) { console.error('duplicate option: --crossing-profile'); process.exit(64); }
    crossingProfile = sourceSafeCliValue(candidate, '--crossing-profile', 128);
    if (!CROSSING_PROFILES.has(crossingProfile)) {
      console.error(`unsupported crossing profile: ${terminalSafe(crossingProfile)}`);
      process.exit(64);
    }
    index += 1;
    continue;
  }
  if (arg === '--crossing-out') {
    const candidate = args[index + 1];
    if (!candidate || candidate.startsWith('-')) {
      console.error('--crossing-out requires a value');
      process.exit(2);
    }
    if (crossingOutSeen) { console.error('duplicate option: --crossing-out'); process.exit(64); }
    crossingOutSeen = true;
    crossingOut = sourceSafeCliValue(candidate, '--crossing-out', 128);
    index += 1;
    continue;
  }
  if (arg === '--apply' || arg === '--force' || arg === '--sample' || arg === '--verify' || arg === '--reviewed') {
    const key = arg.slice(2);
    if ((key === 'apply' && apply) || (key === 'force' && force) || (key === 'sample' && sample)
        || (key === 'verify' && verify) || (key === 'reviewed' && reviewed)) {
      console.error(`duplicate option: ${arg}`);
      process.exit(64);
    }
    if (key === 'apply') apply = true;
    if (key === 'force') force = true;
    if (key === 'sample') sample = true;
    if (key === 'verify') verify = true;
    if (key === 'reviewed') reviewed = true;
    continue;
  }
  if (arg.startsWith('-')) {
    console.error(`unknown option: ${terminalSafe(arg)}`);
    process.exit(64);
  }
  positionals.push(sourceSafeCliValue(arg, 'input path'));
}
if (positionals.length > 1 || (sample && positionals.length > 0)) {
  console.error('provide exactly one input file or --sample, not both');
  process.exit(64);
}
if (force && !apply) {
  console.error('--force requires --apply');
  process.exit(64);
}
if (verify && !apply) {
  console.error('--verify requires --apply');
  process.exit(64);
}
if (verify && selectedTool === null) {
  console.error('--verify requires exactly one --action');
  process.exit(64);
}
if (reviewed && (apply || force || verify)) {
  console.error('--reviewed validates an existing Gate Starter and cannot be combined with --apply, --force, or --verify');
  process.exit(64);
}
if (reviewed && selectedTool === null) {
  console.error('--reviewed requires exactly one --action');
  process.exit(64);
}
if (reviewed && crossingProfile === null) {
  console.error('--reviewed requires --crossing-profile with one supported launch profile');
  process.exit(64);
}
if (!reviewed && (crossingProfile !== null || crossingOut !== null)) {
  console.error('--crossing-profile and --crossing-out are valid only with --reviewed');
  process.exit(64);
}
if (reviewed && crossingOut === null) crossingOut = `${outDir}-crossing-lab`;
assertAllowedOutputRoot(outDir);
if (crossingOut !== null) {
  assertAllowedOutputRoot(crossingOut);
  if (crossingOut === outDir) {
    console.error('--crossing-out must differ from the Gate Starter directory');
    process.exit(64);
  }
}

let input;
let inputReference;
if (sample) {
  input = { actions: SAMPLE, source: 'mcp' };
  inputReference = '--sample';
}
else {
  const file = positionals[0];
  if (!file) {
    console.error('usage: codemod.mjs <actions.json|--sample> [--out dir] [--action tool] [--apply] [--verify] [--force] | <input> --action tool --reviewed --crossing-profile profile [--crossing-out dir]');
    process.exit(2);
  }
  input = ingest(file);
  inputReference = file;
}

/** @type {any} */
const rep = scanActions(input.actions, { source: input.source });
if (input.source === 'openapi') {
  console.error(
    'OpenAPI protect is unavailable until durable one-use consumption is wired. '
    + `Use \`npx ${SCAN_INSTALL_SPEC} <openapi.json>\` for passive classification.`,
  );
  process.exit(2);
}

const visibleConsequential = rep.results
  .filter(({ classification }) => (
    classification.decision === 'gate' || classification.decision === 'review_fail_closed'
  ))
  .map(({ action, classification }) => {
    const manifestAction = rep.manifest.actions.find((candidate) => (
      String(candidate?.id || '').startsWith('discovered.')
      && candidate?.match?.protocol === 'mcp'
      && candidate?.match?.tool === action.name
      && candidate?.receipt_required === true
    ));
    if (!manifestAction) throw new Error(`Consequential action is missing from the proposed manifest: ${action.name}`);
    return {
      tool: String(action.name),
      action_type: String(manifestAction.action_type),
      assurance_class: String(manifestAction.assurance_class),
    };
  });
const selectedContract = selectedTool === null
  ? null
  : visibleConsequential.find((candidate) => candidate.tool === selectedTool) || null;
if (selectedTool !== null && !selectedContract) {
  console.error(`Selected action is not one visible consequential MCP tool: ${terminalSafe(selectedTool)}`);
  process.exit(64);
}
const reviewPendingTools = selectedContract
  ? visibleConsequential.filter((candidate) => candidate.tool !== selectedContract.tool).map((candidate) => candidate.tool)
  : [];
const visibleReadOnlyTools = rep.results
  .filter(({ classification }) => classification.decision === 'pass_through')
  .map(({ action }) => String(action.name));
const declaredSurfaceDigest = `sha256:${createHash('sha256').update(Buffer.from(JSON.stringify({
  source: input.source,
  actions: rep.results.map(({ action, classification }) => ({
    tool: String(action.name),
    decision: String(classification.decision),
    receipt_required: classification.receipt_required === true,
    category: classification.category ? String(classification.category) : null,
    assurance_class: classification.assurance_class ? String(classification.assurance_class) : null,
  })),
}), 'utf8')).digest('hex')}`;
const selectedToolsLiteral = JSON.stringify(selectedContract ? [selectedContract.tool] : []);
const reviewPendingToolsLiteral = JSON.stringify(reviewPendingTools);
const visibleReadOnlyToolsLiteral = JSON.stringify(visibleReadOnlyTools);

if ((verify || reviewed) && installedMcpGuardVersion() !== MCP_GUARD_VERSION) {
  console.error(
    `Local verification requires the exact audited runtime. Install it first: npm install --save-exact ${MCP_GUARD_INSTALL_SPEC}`,
  );
  console.error('No Gate Starter bytes or reviewed handoff were written.');
  process.exit(1);
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

const selectedTools = new Set(${selectedToolsLiteral});
const reviewPendingTools = new Set(${reviewPendingToolsLiteral});
const visibleReadOnlyTools = new Set(${visibleReadOnlyToolsLiteral});

/**
 * A selected-action Gate Starter never lets a receipt silently activate a different
 * consequential tool. Those tools remain inert until the owner generates and
 * reviews a new Gate Starter for one of them.
 */
function enforceOwnerSelection(guarded) {
  if (selectedTools.size === 0) return guarded; // legacy surface-wide scaffold
  return async (name, args = {}, extra = {}) => {
    if (!selectedTools.has(name) && !visibleReadOnlyTools.has(name)) {
      const wasVisibleConsequential = reviewPendingTools.has(name);
      return {
        ep_refused: true,
        code: 'emilia_owner_review_required',
        action: String(name),
        reason: wasVisibleConsequential
          ? 'This visible consequential action was not selected in the reviewed Gate Starter.'
          : 'This runtime tool was not present as an owner-reviewed allowed action in the Gate Starter.',
        required: {
          owner_action: 'Review the declared surface and generate a new selected-action Gate Starter before retrying.',
        },
      };
    }
    return guarded(name, args, extra);
  };
}

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
  const guarded = withMcpGuard(dispatch, {
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
  return enforceOwnerSelection(guarded);
}

/** Local setup check only. Never use ephemeral state in production. */
export function guardDispatchDemo(dispatch, runtime = {}) {
  if (process.env.NODE_ENV === 'production') {
    throw new TypeError('[emilia] demo guard is unavailable in production');
  }
  const guarded = withMcpGuard(dispatch, {
    annotations,
    defaultIrreversible: true,
    verifyOpts: {
      trustedKeys: Array.isArray(runtime.trustedKeys) ? runtime.trustedKeys : [],
      verifyAssurance: runtime.verifyAssurance,
    },
    enforceDemand: true,
    allowEphemeralLedger: true,
  });
  return enforceOwnerSelection(guarded);
}

export const protectionSelection = Object.freeze({
  mode: selectedTools.size === 1 ? 'selected_action' : 'legacy_surface_review',
  declared_surface_sha256: ${JSON.stringify(declaredSurfaceDigest)},
  selected_tools: Object.freeze([...selectedTools]),
  visible_read_only_tools: Object.freeze([...visibleReadOnlyTools]),
  review_pending_tools: Object.freeze([...reviewPendingTools]),
  claim_boundary: Object.freeze({
    selected_action: 'eligible only for the generated local receipt-required check until production integration is complete',
    review_pending_or_unseen: 'refused before receipt processing by this generated wrapper',
    production: 'not established by this generated scaffold',
  }),
});

export { manifest };
`;

const verifySetupJs = `// SPDX-License-Identifier: Apache-2.0
// GENERATED local setup check. It performs no network request and only invokes
// its own synthetic handler. Ephemeral state here is intentional and demo-only.
// It writes nothing unless --emit-handoff is explicit. A reviewed launch-profile
// selection then creates an owner-only seed, an unsealed Lab workspace, and the
// adoption handoff without replacing existing bytes.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bindToolAction } from '@emilia-protocol/mcp-guard';
import { guardDispatchDemo, protectionSelection } from './guard.mjs';

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

// Keep the published EP-SCAN-ADOPTION-HANDOFF-v2 runtime-scaffold contract
// stable. authority-map.html is generated atomically beside these files, but
// remains a presentation artifact outside the v2 scaffold binding.
const scaffoldFiles = ['guard.mjs', 'verify-setup.mjs', 'INTEGRATION.md'].map((file) => ({
  file,
  sha256: 'sha256:' + createHash('sha256').update(readFileSync(join(here, file))).digest('hex'),
}));
const scaffoldDigest = 'sha256:' + createHash('sha256')
  .update(Buffer.from(JSON.stringify(scaffoldFiles), 'utf8'))
  .digest('hex');

const cli = {
  emitHandoff: false,
  acknowledgeReviewedManifest: false,
  requireGeneratedSelection: false,
  expectedSurfaceDigest: null,
  reviewedManifestDigest: null,
  selectedTools: [],
  crossingProfile: null,
  crossingOut: null,
};
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  if (arg === '--emit-handoff') {
    cli.emitHandoff = true;
    continue;
  }
  if (arg === '--acknowledge-reviewed-manifest') {
    if (cli.acknowledgeReviewedManifest) throw new Error('review acknowledgement may be supplied only once');
    cli.acknowledgeReviewedManifest = true;
    continue;
  }
  if (arg === '--require-generated-selection') {
    if (cli.requireGeneratedSelection) throw new Error('generated selection requirement may be supplied only once');
    cli.requireGeneratedSelection = true;
    continue;
  }
  if (arg === '--expected-surface-digest') {
    if (cli.expectedSurfaceDigest !== null) throw new Error('expected surface digest may be supplied only once');
    const value = argv[i + 1];
    if (!value || !/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error('a canonical expected surface digest is required');
    cli.expectedSurfaceDigest = value;
    i += 1;
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
  if (arg === '--crossing-profile') {
    const value = argv[i + 1];
    if (!value || !${JSON.stringify([...CROSSING_PROFILES])}.includes(value)) {
      throw new Error('a supported launch profile is required after --crossing-profile');
    }
    if (cli.crossingProfile !== null) throw new Error('crossing profile may be supplied only once');
    cli.crossingProfile = value;
    i += 1;
    continue;
  }
  if (arg === '--crossing-out') {
    const value = argv[i + 1];
    if (!value || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
      throw new Error('a portable direct-child directory is required after --crossing-out');
    }
    if (cli.crossingOut !== null) throw new Error('crossing output may be supplied only once');
    cli.crossingOut = value;
    i += 1;
    continue;
  }
  throw new Error('unknown verify-setup option');
}
if (cli.selectedTools.length > 32) throw new Error('at most 32 actions may be selected');
if (new Set(cli.selectedTools).size !== cli.selectedTools.length) throw new Error('selected actions must be unique');
if (cli.acknowledgeReviewedManifest && cli.reviewedManifestDigest !== null) {
  throw new Error('choose either current-manifest review acknowledgement or an explicit reviewed manifest digest');
}
if (cli.acknowledgeReviewedManifest && !cli.emitHandoff) {
  throw new Error('--acknowledge-reviewed-manifest requires --emit-handoff');
}
if (cli.requireGeneratedSelection && !cli.emitHandoff) {
  throw new Error('--require-generated-selection requires --emit-handoff');
}
if ((cli.crossingProfile === null) !== (cli.crossingOut === null)) {
  throw new Error('--crossing-profile and --crossing-out must be supplied together');
}
if (cli.crossingProfile !== null && !cli.emitHandoff) {
  throw new Error('Crossing Lab generation requires --emit-handoff');
}

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
  const materialFields = action?.execution_binding?.required_fields;
  if (!Array.isArray(materialFields) || materialFields.length === 0 || materialFields.length > 64
      || !materialFields.every((field) => typeof field === 'string' && field.length > 0 && field.length <= 256)
      || new Set(materialFields).size !== materialFields.length || !materialFields.includes('action_type')) {
    throw new Error('reviewed manifest has invalid material fields for a consequential action');
  }
  const selected = {
    id: String(action.id),
    selector: { protocol: 'mcp', tool },
    action_type: String(action.action_type),
    assurance_class: String(action.assurance_class),
    receipt_required: true,
    material_fields: materialFields,
  };
  visibleConsequential.push(selected);
  visibleByTool.set(tool, selected);
}

const generatedSelectedTools = Array.isArray(protectionSelection?.selected_tools)
  ? protectionSelection.selected_tools
  : [];
if (generatedSelectedTools.length > 1
    || generatedSelectedTools.some((tool) => typeof tool !== 'string' || !visibleByTool.has(tool))) {
  throw new Error('generated Gate Starter selection is invalid');
}
if (cli.expectedSurfaceDigest !== null
    && protectionSelection?.declared_surface_sha256 !== cli.expectedSurfaceDigest) {
  throw new Error('current declared surface does not match the generated Gate Starter');
}
if (cli.requireGeneratedSelection && generatedSelectedTools.length !== 1) {
  throw new Error('reviewed shortcut requires an existing selected-action Gate Starter');
}
if (generatedSelectedTools.length === 1) {
  if (cli.selectedTools.length === 0) cli.selectedTools.push(generatedSelectedTools[0]);
  if (cli.selectedTools.length !== 1 || cli.selectedTools[0] !== generatedSelectedTools[0]) {
    throw new Error('selected tool does not match the generated Gate Starter');
  }
}

const selectedActions = cli.selectedTools.map((tool) => {
  const action = visibleByTool.get(tool);
  if (!action) throw new Error('selected tool is not a visible consequential action in the reviewed manifest');
  return action;
});
const handoffSelectedActions = selectedActions.map(({ material_fields: _materialFields, ...action }) => action);

if (cli.emitHandoff) {
  if (cli.acknowledgeReviewedManifest) cli.reviewedManifestDigest = manifestDigest;
  if (cli.reviewedManifestDigest === null) {
    throw new Error('reviewed manifest digest or --acknowledge-reviewed-manifest is required for handoff emission');
  }
  if (cli.reviewedManifestDigest !== manifestDigest) throw new Error('reviewed manifest digest does not match the current manifest bytes');
  if (selectedActions.length === 0) throw new Error('at least one visible consequential action must be explicitly selected');
  if (cli.crossingProfile !== null && selectedActions.length !== 1) {
    throw new Error('Crossing Lab generation requires exactly one reviewed consequential action');
  }
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
const unknownArgs = { rr1_fixture: { marker: 'unscanned-runtime-tool' } };
let unknownResult;
if (generatedSelectedTools.length === 1) {
  const unknownAction = bindToolAction(unknownTool, unknownArgs, unknownTool);
  const exactUnknownReceipt = mintSyntheticReceipt(
    unknownAction,
    'rr1_unscanned_exact_receipt',
    keyPair.privateKey,
    publicKey,
  );
  unknownResult = await guarded(unknownTool, {
    ...unknownArgs,
    __ep: { receipt: exactUnknownReceipt },
  });
  assert.equal(
    unknownResult?.code,
    'emilia_owner_review_required',
    'an exact synthetic receipt admitted an unscanned runtime tool',
  );
  console.log('Selected-action boundary refused an exact synthetic receipt for an unscanned runtime tool.');
} else {
  unknownResult = await guarded(unknownTool, unknownArgs);
  assert.equal(unknownResult?.ep_refused, true, 'an unscanned runtime tool was not refused');
}
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

function createOwnerOnlyJson(target, value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\\n', 'utf8');
  const temp = join(dirname(target), '.' + basename(target) + '.' + process.pid + '.' + randomUUID() + '.tmp');
  let fd;
  try {
    fd = openSync(temp, 'wx', 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    linkSync(temp, target);
    unlinkSync(temp);
    return bytes;
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temp); } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') throw cleanupError;
    }
    if (error.code === 'EEXIST') throw new Error('Refusing to overwrite existing generated adoption artifact');
    throw error;
  }
}

if (cli.emitHandoff) {
  const handoff = {
    '@version': cli.crossingProfile === null
      ? 'EP-SCAN-ADOPTION-HANDOFF-v2'
      : 'EP-SCAN-ADOPTION-HANDOFF-v3',
    reviewed_manifest: {
      file: manifestFile,
      sha256: manifestDigest,
    },
    generated_scaffold: {
      sha256: scaffoldDigest,
      files: scaffoldFiles,
    },
    selected_actions: handoffSelectedActions,
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
  const seedTarget = join(here, 'scan-crossing-seed.json');
  const workspaceTarget = cli.crossingOut === null ? null : resolve(process.cwd(), cli.crossingOut);
  if (existsSync(target)) throw new Error('Refusing to overwrite existing handoff');
  if (cli.crossingProfile !== null && (existsSync(seedTarget) || existsSync(workspaceTarget))) {
    throw new Error('Refusing to overwrite existing Crossing Lab seed or workspace');
  }
  let workspaceCreated = false;
  if (cli.crossingProfile !== null) {
    const selectedAction = selectedActions[0];
    const {
      CROSSING_LAB_VERIFY_VERSION,
      crossingLabScanProfileContract,
      initCrossingLabFromScanSeed,
    } = await import('@emilia-protocol/verify/crossing-lab');
    const seed = {
      '@version': 'EP-SCAN-CROSSING-SEED-v1',
      verify_version: CROSSING_LAB_VERIFY_VERSION,
      profile_id: cli.crossingProfile,
      profile_contract: crossingLabScanProfileContract(cli.crossingProfile),
      profile_compatibility: 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED',
      reviewed_manifest: {
        file: manifestFile,
        sha256: manifestDigest,
      },
      generated_scaffold_sha256: scaffoldDigest,
      local_rr1_results_digest: rr1ResultsDigest,
      selected_action: selectedAction,
      selected_action_digest: 'sha256:' + createHash('sha256')
        .update(Buffer.from(canonicalize(selectedAction), 'utf8'))
        .digest('hex'),
      operator_confirmation: {
        status: 'required',
        workspace_state: 'unsealed',
        required_inputs: [
          'native_artifact',
          'adapter_bytes',
          'trust_roots',
          'status_source',
          'relying_party_id',
          'exact_material_fields',
          'profile_compatibility_confirmation',
        ],
      },
    };
    const seedBytes = createOwnerOnlyJson(seedTarget, seed);
    initCrossingLabFromScanSeed(seedTarget, workspaceTarget);
    workspaceCreated = true;
    handoff.crossing_seed = {
      file: 'scan-crossing-seed.json',
      sha256: 'sha256:' + createHash('sha256').update(seedBytes).digest('hex'),
    };
  }
  // Deliberately avoid pathname-based rollback. If a later safe-create fails,
  // already-created owner-only artifacts remain for operator inspection rather
  // than risking deletion of a concurrent replacement.
  createOwnerOnlyJson(target, handoff);
  console.log('Created owner-only scan-adoption-handoff.json beside the reviewed Gate Starter.');
  if (workspaceCreated) {
    console.log('Created an unsealed Crossing Lab workspace at ' + workspaceTarget + '.');
    console.log('Operator-supplied native evidence, adapter bytes, trust roots, status, relying party, and material values are still required.');
  }
}
`;

const integrationMd = `# EMILIA integration (generated)

Gate Starter mode: ${selectedContract ? `one selected action (${selectedContract.tool})` : 'legacy surface-wide review'}.
${selectedContract
    ? `Every other visible consequential action is review-pending and is refused by the generated wrapper before receipt processing: ${reviewPendingTools.length > 0 ? reviewPendingTools.map((tool) => `\`${tool}\``).join(', ') : 'none'}.`
    : 'No single action was selected. This preserves the legacy surface-wide scaffold behavior.'}

0. Install the audited runtime guard exactly: \`npm install --save-exact ${MCP_GUARD_INSTALL_SPEC}\`
1. Review \`action-control.manifest.json\` and the \`annotations\` in \`guard.mjs\`.
${selectedContract
    ? `   Confirm the selected \`${selectedContract.tool}\` mapping. Every other visible consequential action remains intentionally review-pending; generate a separately reviewed starter before admitting one of them.`
    : '   Downgrade any false positive; confirm every action marked REVIEW.'}
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
4. Read \`${outDir}/action-control.manifest.json\` and \`${outDir}/authority-map.html\`.
   After reviewing the exact generated bytes, you may explicitly create a
   privacy-bounded machine-readable handoff without copying a digest:

\`\`\`bash
${selectedContract
    ? `npx ${SCAN_INSTALL_SPEC} protect ${inputReference === '--sample' ? '--sample' : posixQuote(inputReference.startsWith('-') ? `./${inputReference}` : inputReference)} --out ${posixQuote(outDir)} --action ${posixQuote(selectedContract.tool)} --reviewed --crossing-profile <launch-profile>`
    : `node ${outDir}/verify-setup.mjs --emit-handoff --acknowledge-reviewed-manifest --action <reviewed-tool-name>`}
\`\`\`

   The command validates the existing manifest against the current input,
   reruns RR-1, and creates an owner-only handoff and seed plus an explicitly
   unsealed Crossing Lab workspace without overwriting existing artifacts. The
   seed includes no tool arguments, credentials, ambient
   identity, host data, timestamps, or paths outside this output directory.
   If you edited the manifest during review, use the explicit
   \`verify-setup.mjs --reviewed-manifest-digest ...\` path so the exact edited
   bytes, rather than a fresh scanner proposal, are acknowledged.
5. Pin keys and supply a durable provenance ledger plus a shared atomic
   consumption store. Wire the consent/signoff/issue adapters to your EP host.

Nothing is enforced until the wrapper owns every path to the provider credential,
the state is durable, and the keys are pinned. This scaffold proposes; it does not
protect on its own. A passed local refusal is not a signed refusal artifact,
public verification, production enforcement, or proof of complete mediation.
`;

const authorityMapHtml = renderAuthorityBrain(rep, {
  inputReference,
  outputDirectory: outDir,
  starterSelectedTool: selectedContract?.tool ?? null,
});

const starterFiles = [
  { rel: path.join(outDir, 'action-control.manifest.json'), body: `${JSON.stringify(rep.manifest, null, 2)}\n` },
  { rel: path.join(outDir, 'authority-map.html'), body: authorityMapHtml },
  { rel: path.join(outDir, 'guard.mjs'), body: guardJs },
  { rel: path.join(outDir, 'verify-setup.mjs'), body: verifySetupJs },
  { rel: path.join(outDir, 'INTEGRATION.md'), body: integrationMd },
];
const marker = {
  '@version': GATE_STARTER_MARKER_VERSION,
  generator: {
    package: '@emilia-protocol/scan',
    version: SCAN_PACKAGE_VERSION,
  },
  artifact_state: 'not_activated',
  selected_action: selectedContract?.tool ?? null,
  declared_surface_sha256: declaredSurfaceDigest,
  generated_files: starterFiles.map((file) => ({
    file: path.basename(file.rel),
    sha256: `sha256:${createHash('sha256').update(Buffer.from(file.body, 'utf8')).digest('hex')}`,
  })),
  claim_boundary: 'Generated local review artifact. It is not production protection or proof of complete mediation.',
};
const files = [
  ...starterFiles,
  {
    rel: path.join(outDir, GATE_STARTER_MARKER_FILE),
    body: `${JSON.stringify(marker, null, 2)}\n`,
  },
];

const B = '\x1b[1m'; const D = '\x1b[2m'; const R = '\x1b[0m'; const Y = '\x1b[33m';
console.log(`\n${B}EMILIA codemod — ${input.source} surface, ${rep.counts.total} actions ` +
  `(${rep.counts.gate} gated, ${rep.counts.review_fail_closed} fail-closed for review)${R}`);

if (reviewed) {
  const reviewedSelectedTool = requireParsedCliValue(selectedTool, 'reviewed selected tool');
  const reviewedCrossingProfile = requireParsedCliValue(crossingProfile, 'reviewed crossing profile');
  const reviewedCrossingOut = requireParsedCliValue(crossingOut, 'reviewed crossing output');
  const outAbsolute = path.resolve(outDir);
  const relativeOut = path.relative(process.cwd(), outAbsolute);
  if (relativeOut.startsWith('..') || path.isAbsolute(relativeOut)
      || !relativeOut || relativeOut.split(path.sep).filter(Boolean).length !== 1) {
    console.error(`${Y}Refusing reviewed Gate Starter outside one direct-child output directory: ${outDir}${R}`);
    process.exit(1);
  }
  const root = lstatIfPresent(outAbsolute);
  if (!root || root.isSymbolicLink() || !root.isDirectory()) {
    console.error(`${Y}Refusing reviewed mode without an existing regular Gate Starter directory: ${outDir}${R}`);
    process.exit(1);
  }
  const requiredPackFiles = [...GATE_STARTER_BOUND_FILES, GATE_STARTER_MARKER_FILE];
  for (const leaf of requiredPackFiles) {
    const target = path.join(outAbsolute, leaf);
    const stat = lstatIfPresent(target);
    if (!stat || stat.isSymbolicLink() || !stat.isFile() || stat.nlink > 1) {
      console.error(`${Y}Refusing unsafe or incomplete reviewed Gate Starter file: ${path.join(outDir, leaf)}${R}`);
      process.exit(1);
    }
  }
  let existingMarker;
  try {
    existingMarker = validateGateStarterMarker(outAbsolute);
  } catch (error) {
    console.error(`${Y}${terminalSafe(error instanceof Error ? error.message : error)}${R}`);
    process.exit(1);
  }
  if (existingMarker.selected_action === null) {
    console.error(`${Y}Reviewed shortcut requires an existing selected-action Gate Starter.${R}`);
    process.exit(1);
  }
  if (existingMarker.selected_action !== reviewedSelectedTool) {
    console.error(`${Y}Selected tool does not match the generated Gate Starter.${R}`);
    process.exit(1);
  }
  if (existingMarker.declared_surface_sha256 !== declaredSurfaceDigest) {
    console.error(`${Y}Current declared surface does not match the generated Gate Starter.${R}`);
    process.exit(1);
  }
  const existingManifest = readBoundedRegularFile(
    path.join(outAbsolute, 'action-control.manifest.json'),
    MAX_INPUT_BYTES,
  );
  const expectedManifest = Buffer.from(`${JSON.stringify(rep.manifest, null, 2)}\n`, 'utf8');
  if (!existingManifest.equals(expectedManifest)) {
    console.error(
      `${Y}Refusing shortcut: the existing manifest is not the current scanner proposal. `
      + 'Use verify-setup.mjs with its explicit reviewed digest to acknowledge reviewed edits.' + `${R}`,
    );
    process.exit(1);
  }
  for (const expected of starterFiles.filter((file) => path.basename(file.rel) !== 'authority-map.html')) {
    const existing = readOwnerOnlyGeneratedFile(
      path.join(outAbsolute, path.basename(expected.rel)),
      path.basename(expected.rel),
    );
    if (!existing.equals(Buffer.from(expected.body, 'utf8'))) {
      console.error(
        `${Y}Refusing shortcut: ${path.basename(expected.rel)} is not the current generated Gate Starter byte sequence. `
        + 'Use verify-setup.mjs with an explicit reviewed manifest digest for deliberately edited runtime files.' + `${R}`,
      );
      process.exit(1);
    }
  }
  console.log(`${B}Existing selected-action Gate Starter validated. Running RR-1 and binding the reviewed bytes.${R}`);
  const verified = spawnSync(process.execPath, [
    path.join(outAbsolute, 'verify-setup.mjs'),
    '--emit-handoff',
    '--acknowledge-reviewed-manifest',
    '--require-generated-selection',
    '--expected-surface-digest',
    declaredSurfaceDigest,
    '--action',
    reviewedSelectedTool,
    '--crossing-profile',
    reviewedCrossingProfile,
    '--crossing-out',
    reviewedCrossingOut,
  ], { cwd: process.cwd(), stdio: 'inherit' });
  if (verified.error) throw verified.error;
  if (verified.status !== 0) {
    console.error(`${Y}Reviewed handoff was not emitted because the local verification failed.${R}`);
    process.exit(verified.status ?? 1);
  }
  console.log(`${B}Reviewed handoff created without changing the Gate Starter.${R}\n`);
  process.exit(0);
}

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
const replaceableRoot = lstatIfPresent(outAbsolute);
if (replaceableRoot && force) {
  try {
    validateGateStarterMarker(outAbsolute, { exactEntries: true });
  } catch (error) {
    console.error(`${Y}${terminalSafe(error instanceof Error ? error.message : error)}${R}`);
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
    validateGateStarterMarker(backup, { exactEntries: true });
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
if (verify) {
  const verifiedSelectedTool = requireParsedCliValue(selectedTool, 'verified selected tool');
  console.log(`\n${B}Running the selected action's local four-case RR-1 check.${R}`);
  const checked = spawnSync(process.execPath, [
    path.resolve(outDir, 'verify-setup.mjs'),
    '--action',
    verifiedSelectedTool,
    '--expected-surface-digest',
    declaredSurfaceDigest,
  ], { cwd: process.cwd(), stdio: 'inherit' });
  if (checked.error) throw checked.error;
  if (checked.status !== 0) {
    console.error(`${Y}The Gate Starter was created, but local verification failed. No handoff was emitted.${R}`);
    process.exit(checked.status ?? 1);
  }
}
console.log(`\n${B}Done.${R} Review ${path.join(outDir, 'authority-map.html')} and ${path.join(outDir, 'action-control.manifest.json')}. Nothing is enforced until the wrapper owns the credential boundary.${R}\n`);
