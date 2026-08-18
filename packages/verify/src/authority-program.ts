// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-PROGRAM-v1 — pure, offline authority-composition verifier.
 *
 * This module verifies a relying-party-pinned signed program and immutable,
 * organization-signed stage receipts. It deliberately has no store, clock,
 * scheduler, transition API, threshold grammar, execution path, revocation
 * mutation, reconciliation, or policy evaluation.
 *
 * AEC means an EP Authorization Evidence Chain requirement/result. AOM means
 * an EP Action Outcome Manifest requirement/result. AOM is an explicit wire
 * contract here; it is not silently treated as EP-OUTCOME-BINDING or any other
 * existing outcome artifact. Native AEC, AOM, and capability verifiers remain
 * separately owned and are injected by the relying party.
 */
import crypto from 'node:crypto';

import { canonicalize } from './index.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileSignature,
  type AgileSigningKey,
  type AgilityOptions,
} from './pq-signature-agility.js';

type Obj = Record<string, any>;
type VerificationCallback = (context: Readonly<Obj>) => unknown;

export const AUTHORITY_PROGRAM_VERSION = 'EP-AUTHORITY-PROGRAM-v1';
export const AUTHORITY_PROGRAM_DOMAIN = 'EP-AUTHORITY-PROGRAM-v1\0';
export const AUTHORITY_STAGE_RECEIPT_VERSION = 'EP-AUTHORITY-STAGE-RECEIPT-v1';
export const AUTHORITY_STAGE_RECEIPT_DOMAIN = 'EP-AUTHORITY-STAGE-RECEIPT-v1\0';
export const AUTHORITY_PROGRAM_RESULT_VERSION = 'EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
// Join the deployed CAID v1 wire format; an authority-program-only digest
// label would sever this artifact from the CAID registry and its vectors.
const ROOT_CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const MAX_STAGES = 64;
const MAX_DEPTH = 32;
const MAX_BRANCHES = 32;
const MAX_INPUT_NODES = 4096;
const MAX_INPUT_STRING_BYTES = 1024 * 1024;

const own = (value: unknown, key: string): boolean => (
  value !== null
  && typeof value === 'object'
  && Object.prototype.hasOwnProperty.call(value, key)
);

function record(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value: unknown, required: string[]): value is Obj {
  if (!record(value)) return false;
  const keys = Object.keys(value);
  return keys.length === required.length
    && required.every((key) => own(value, key));
}

function boundedPlainJson(value: unknown): boolean {
  const stack = [{ value, depth: 0 }];
  const seen = new WeakSet<object>();
  let nodes = 0;
  let stringBytes = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    nodes += 1;
    if (nodes > MAX_INPUT_NODES || current.depth > MAX_DEPTH + 8) return false;
    if (current.value === null || typeof current.value === 'boolean') continue;
    if (typeof current.value === 'string') {
      stringBytes += Buffer.byteLength(current.value, 'utf8');
      if (stringBytes > MAX_INPUT_STRING_BYTES) return false;
      continue;
    }
    if (typeof current.value === 'number') {
      if (!Number.isSafeInteger(current.value)) return false;
      continue;
    }
    if (!record(current.value) && !Array.isArray(current.value)) return false;
    if (seen.has(current.value)) return false;
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      if (current.value.length > MAX_INPUT_NODES) return false;
      const ownKeys = Reflect.ownKeys(current.value);
      const expectedKeys = new Set([
        'length',
        ...Array.from({ length: current.value.length }, (_, index) => String(index)),
      ]);
      if (ownKeys.some((key) => typeof key !== 'string')
          || ownKeys.length !== expectedKeys.size
          || ownKeys.some((key) => !expectedKeys.has(key as string))) return false;
      for (let index = 0; index < current.value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(current.value, String(index));
        if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) return false;
        stack.push({ value: descriptor.value, depth: current.depth + 1 });
      }
      continue;
    }
    const ownKeys = Reflect.ownKeys(current.value);
    if (ownKeys.some((key) => typeof key !== 'string') || ownKeys.length > MAX_INPUT_NODES) return false;
    for (const key of ownKeys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(current.value, key);
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) return false;
      stringBytes += Buffer.byteLength(key, 'utf8');
      if (stringBytes > MAX_INPUT_STRING_BYTES) return false;
      stack.push({ value: descriptor.value, depth: current.depth + 1 });
    }
  }
  return true;
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER.test(value);
}

function canonicalBase64url(value: unknown, expectedBytes?: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0
      || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) return null;
  return expectedBytes === undefined || decoded.length === expectedBytes ? decoded : null;
}

function loadEd25519Key(value: unknown): crypto.KeyObject | null {
  try {
    if (typeof value !== 'string') return null;
    const der = canonicalBase64url(value, 44);
    if (!der) return null;
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function unsigned(value: Obj): Obj {
  const body: Obj = {};
  for (const [key, member] of Object.entries(value)) {
    if (key !== 'proof') body[key] = member;
  }
  return body;
}

function signingBytes(value: Obj, domain: string): Buffer {
  return Buffer.from(`${domain}${canonicalize(unsigned(value))}`, 'utf8');
}

function verifyEd25519(value: Obj, domain: string, publicKey: unknown): boolean {
  const key = loadEd25519Key(publicKey);
  const signature = canonicalBase64url(value.proof?.signature_b64u, 64);
  if (!key || !signature) return false;
  try {
    return crypto.verify(null, signingBytes(value, domain), key, signature);
  } catch {
    return false;
  }
}

function validProof(value: unknown, { program = false }: { program?: boolean } = {}): boolean {
  const required = program
    ? ['algorithm', 'organization_id', 'key_id', 'signature_b64u']
    : ['algorithm', 'key_id', 'signature_b64u'];
  return exactObject(value, required)
    && value.algorithm === 'Ed25519'
    && (!program || identifier(value.organization_id))
    && identifier(value.key_id)
    && canonicalBase64url(value.signature_b64u, 64) !== null;
}

function uniqueDigests(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.length <= MAX_STAGES
    && value.every((member) => typeof member === 'string' && DIGEST.test(member))
    && new Set(value).size === value.length;
}

interface StageDescription {
  type: 'stage';
  stage_id: string;
  authority: { organization_id: string; key_id: string };
  aec_requirement_digest: string;
  aom_requirement_digest: string;
  capability_requirement_digest: string;
}

interface ParallelDescription {
  type: 'parallel';
  parallel_id: string;
  allocation_requirement_digest: string;
  allocation_proof_digest: string;
  branches: unknown[];
}

interface ExpressionAnalysis {
  predecessors: Record<string, string[]>;
  stages: Map<string, StageDescription>;
  parallels: ParallelDescription[];
}

function validStage(value: unknown): value is StageDescription {
  return exactObject(value, [
    'type',
    'stage_id',
    'authority',
    'aec_requirement_digest',
    'aom_requirement_digest',
    'capability_requirement_digest',
  ])
    && value.type === 'stage'
    && identifier(value.stage_id)
    && exactObject(value.authority, ['organization_id', 'key_id'])
    && identifier(value.authority.organization_id)
    && identifier(value.authority.key_id)
    && typeof value.aec_requirement_digest === 'string'
    && DIGEST.test(value.aec_requirement_digest)
    && typeof value.aom_requirement_digest === 'string'
    && DIGEST.test(value.aom_requirement_digest)
    && typeof value.capability_requirement_digest === 'string'
    && DIGEST.test(value.capability_requirement_digest);
}

function analyzeExpression(expression: unknown): ExpressionAnalysis | null {
  const predecessors: Record<string, string[]> = {};
  const stages = new Map<string, StageDescription>();
  const parallels: ParallelDescription[] = [];
  const parallelIds = new Set<string>();

  const walk = (node: unknown, incoming: string[], depth: number): string[] | null => {
    if (depth > MAX_DEPTH || !record(node)) return null;
    if (node.type === 'stage') {
      if (!validStage(node) || stages.has(node.stage_id) || stages.size >= MAX_STAGES) return null;
      stages.set(node.stage_id, node);
      predecessors[node.stage_id] = [...new Set(incoming)].sort();
      return [node.stage_id];
    }
    if (node.type === 'sequence') {
      if (!exactObject(node, ['type', 'children'])
          || !Array.isArray(node.children)
          || node.children.length < 2
          || node.children.length > MAX_BRANCHES) return null;
      let exits = incoming;
      for (const child of node.children) {
        const next = walk(child, exits, depth + 1);
        if (!next) return null;
        exits = next;
      }
      return exits;
    }
    if (node.type === 'parallel') {
      if (!exactObject(node, [
        'type',
        'parallel_id',
        'allocation_requirement_digest',
        'allocation_proof_digest',
        'branches',
      ])
          || !identifier(node.parallel_id)
          || parallelIds.has(node.parallel_id)
          || typeof node.allocation_requirement_digest !== 'string'
          || !DIGEST.test(node.allocation_requirement_digest)
          || typeof node.allocation_proof_digest !== 'string'
          || !DIGEST.test(node.allocation_proof_digest)
          || !Array.isArray(node.branches)
          || node.branches.length < 2
          || node.branches.length > MAX_BRANCHES) return null;
      parallelIds.add(node.parallel_id);
      parallels.push(node as unknown as ParallelDescription);
      const exits: string[] = [];
      for (const branch of node.branches) {
        const branchExits = walk(branch, incoming, depth + 1);
        if (!branchExits) return null;
        exits.push(...branchExits);
      }
      return [...new Set(exits)].sort();
    }
    return null;
  };

  const exits = walk(expression, [], 0);
  return exits && stages.size > 0 ? { predecessors, stages, parallels } : null;
}

function validProgramEnvelope(value: unknown): value is Obj {
  return exactObject(value, [
    '@version',
    'program_id',
    'root_caid',
    'root_action_digest',
    'expression',
    'proof',
  ])
    && value['@version'] === AUTHORITY_PROGRAM_VERSION
    && identifier(value.program_id)
    && typeof value.root_caid === 'string'
    && ROOT_CAID.test(value.root_caid)
    && typeof value.root_action_digest === 'string'
    && DIGEST.test(value.root_action_digest)
    && validProof(value.proof, { program: true });
}

function validJoin(value: unknown): value is Obj {
  return exactObject(value, ['requirement_digest', 'result_digest'])
    && typeof value.requirement_digest === 'string'
    && DIGEST.test(value.requirement_digest)
    && typeof value.result_digest === 'string'
    && DIGEST.test(value.result_digest);
}

function validCapabilityJoin(value: unknown): value is Obj {
  return exactObject(value, ['requirement_digest', 'input_digest', 'output_digest'])
    && typeof value.requirement_digest === 'string'
    && DIGEST.test(value.requirement_digest)
    && typeof value.input_digest === 'string'
    && DIGEST.test(value.input_digest)
    && typeof value.output_digest === 'string'
    && DIGEST.test(value.output_digest);
}

function validStageReceipt(value: unknown): value is Obj {
  return exactObject(value, [
    '@version',
    'receipt_id',
    'program_digest',
    'root_caid',
    'root_action_digest',
    'stage_id',
    'issuer',
    'predecessor_receipt_digests',
    'aec',
    'aom',
    'capability',
    'proof',
  ])
    && value['@version'] === AUTHORITY_STAGE_RECEIPT_VERSION
    && identifier(value.receipt_id)
    && typeof value.program_digest === 'string'
    && DIGEST.test(value.program_digest)
    && typeof value.root_caid === 'string'
    && ROOT_CAID.test(value.root_caid)
    && typeof value.root_action_digest === 'string'
    && DIGEST.test(value.root_action_digest)
    && identifier(value.stage_id)
    && exactObject(value.issuer, ['organization_id', 'key_id'])
    && identifier(value.issuer.organization_id)
    && identifier(value.issuer.key_id)
    && uniqueDigests(value.predecessor_receipt_digests)
    && validJoin(value.aec)
    && validJoin(value.aom)
    && validCapabilityJoin(value.capability)
    && validProof(value.proof)
    && value.proof.key_id === value.issuer.key_id;
}

function failure(
  reason: string,
  program: unknown = null,
  programDigest: string | null = null,
): Obj {
  return {
    '@version': AUTHORITY_PROGRAM_RESULT_VERSION,
    valid: false,
    program_digest: programDigest,
    root_caid: record(program) && typeof program.root_caid === 'string' ? program.root_caid : null,
    root_action_digest: record(program) && typeof program.root_action_digest === 'string'
      ? program.root_action_digest
      : null,
    stage_receipt_digests: {},
    parallel_allocation_status: null,
    root_action_binding_status: null,
    freshness_proven: false,
    revocation_checked: false,
    execution_proven: false,
    reason,
  };
}

function safeCallback(callback: unknown, context: Obj): unknown {
  if (typeof callback !== 'function') return null;
  try {
    return (callback as VerificationCallback)(Object.freeze(structuredClone(context)));
  } catch {
    return null;
  }
}

function validEvidenceResult(value: unknown): value is Obj {
  return exactObject(value, ['valid', 'requirement_digest', 'result_digest'])
    && value.valid === true
    && typeof value.requirement_digest === 'string'
    && DIGEST.test(value.requirement_digest)
    && typeof value.result_digest === 'string'
    && DIGEST.test(value.result_digest);
}

function validCapabilityResult(value: unknown): value is Obj {
  return exactObject(value, [
    'valid',
    'narrowed',
    'requirement_digest',
    'input_digest',
    'output_digest',
  ])
    && value.valid === true
    && typeof value.narrowed === 'boolean'
    && typeof value.requirement_digest === 'string'
    && DIGEST.test(value.requirement_digest)
    && typeof value.input_digest === 'string'
    && DIGEST.test(value.input_digest)
    && typeof value.output_digest === 'string'
    && DIGEST.test(value.output_digest);
}

function validParallelResult(value: unknown): value is Obj {
  return exactObject(value, [
    'valid',
    'authoritative',
    'parallel_id',
    'requirement_digest',
    'proof_digest',
  ])
    && value.valid === true
    && typeof value.authoritative === 'boolean'
    && identifier(value.parallel_id)
    && typeof value.requirement_digest === 'string'
    && DIGEST.test(value.requirement_digest)
    && typeof value.proof_digest === 'string'
    && DIGEST.test(value.proof_digest);
}

function validRootActionBindingResult(value: unknown): value is Obj {
  return exactObject(value, [
    'valid',
    'root_caid',
    'root_action_digest',
  ])
    && value.valid === true
    && typeof value.root_caid === 'string'
    && ROOT_CAID.test(value.root_caid)
    && typeof value.root_action_digest === 'string'
    && DIGEST.test(value.root_action_digest);
}

/** Digest of the exact signed authority-program envelope. */
export function authorityProgramDigest(program: unknown): string {
  return digest(program);
}

/** Digest of the exact signed immutable stage receipt. */
export function authorityStageReceiptDigest(receipt: unknown): string {
  return digest(receipt);
}

/**
 * Derive each stage's immediate predecessor stage IDs from a recursive
 * series/parallel expression. Arbitrary DAG edges are never accepted.
 */
export function deriveAuthorityProgramPredecessors(expression: unknown): Record<string, string[]> {
  const analysis = analyzeExpression(expression);
  if (!analysis) throw new Error('invalid authority-program series/parallel expression');
  return structuredClone(analysis.predecessors);
}

/**
 * Verify a signed authority program and all immutable stage receipts.
 *
 * The callbacks are relying-party-owned pure adapters to native verifiers.
 * Their returned objects are closed and must bind the exact signed digests.
 * No callback result can authorize execution; the result explicitly reports
 * `freshness_proven: false`, `revocation_checked: false`, and
 * `execution_proven: false`.
 */
function verifyAuthorityProgramCore(
  program: unknown,
  stageReceipts: unknown,
  options: {
    programPin?: Obj;
    stageKeys?: Obj;
    verifyAec?: VerificationCallback;
    verifyAom?: VerificationCallback;
    verifyCapabilityNarrowing?: VerificationCallback;
    verifyParallelAllocation?: VerificationCallback;
    verifyRootActionBinding?: VerificationCallback;
  } = {},
): Obj {
  if (!validProgramEnvelope(program)) return failure('invalid_program_envelope');
  const analysis = analyzeExpression(program.expression);
  if (!analysis) return failure('invalid_program_expression', program);
  const programDigest = authorityProgramDigest(program);

  if (!exactObject(options.programPin, [
    'digest',
    'organization_id',
    'key_id',
    'public_key',
  ])
      || typeof options.programPin.digest !== 'string'
      || !DIGEST.test(options.programPin.digest)
      || !identifier(options.programPin.organization_id)
      || !identifier(options.programPin.key_id)
      || typeof options.programPin.public_key !== 'string') {
    return failure('invalid_program_pin', program, programDigest);
  }
  if (options.programPin.digest !== programDigest) {
    return failure('program_digest_mismatch', program, programDigest);
  }
  if (program.proof.organization_id !== options.programPin.organization_id
      || program.proof.key_id !== options.programPin.key_id) {
    return failure('program_signer_mismatch', program, programDigest);
  }
  if (!verifyEd25519(program, AUTHORITY_PROGRAM_DOMAIN, options.programPin.public_key)) {
    return failure('invalid_program_signature', program, programDigest);
  }

  const rootActionBinding = safeCallback(options.verifyRootActionBinding, {
    program_digest: programDigest,
    root_caid: program.root_caid,
    root_action_digest: program.root_action_digest,
  });
  if (!validRootActionBindingResult(rootActionBinding)) {
    return failure('root_action_binding_unproven', program, programDigest);
  }
  if (rootActionBinding.root_caid !== program.root_caid
      || rootActionBinding.root_action_digest !== program.root_action_digest) {
    return failure('root_action_binding_mismatch', program, programDigest);
  }

  if (!Array.isArray(stageReceipts) || stageReceipts.length !== analysis.stages.size) {
    return failure('stage_receipt_set_mismatch', program, programDigest);
  }
  const receipts = new Map<string, Obj>();
  const receiptIds = new Set<string>();
  for (const receipt of stageReceipts) {
    if (!validStageReceipt(receipt)) return failure('invalid_stage_receipt', program, programDigest);
    if (receipts.has(receipt.stage_id) || receiptIds.has(receipt.receipt_id)) {
      return failure('duplicate_stage_receipt', program, programDigest);
    }
    receipts.set(receipt.stage_id, receipt);
    receiptIds.add(receipt.receipt_id);
  }
  for (const stageId of analysis.stages.keys()) {
    if (!receipts.has(stageId)) return failure('stage_receipt_set_mismatch', program, programDigest);
  }

  const receiptDigests = new Map<string, string>();
  for (const [stageId, receipt] of receipts) {
    receiptDigests.set(stageId, authorityStageReceiptDigest(receipt));
  }

  for (const [stageId, stage] of analysis.stages) {
    const receipt = receipts.get(stageId)!;
    if (receipt.program_digest !== programDigest) {
      return failure('stage_program_digest_mismatch', program, programDigest);
    }
    if (receipt.root_caid !== program.root_caid) {
      return failure('stage_root_caid_mismatch', program, programDigest);
    }
    if (receipt.root_action_digest !== program.root_action_digest) {
      return failure('stage_root_action_digest_mismatch', program, programDigest);
    }
    if (receipt.issuer.organization_id !== stage.authority.organization_id
        || receipt.issuer.key_id !== stage.authority.key_id) {
      return failure('stage_authority_mismatch', program, programDigest);
    }
    const organizationKeys = record(options.stageKeys) && record(options.stageKeys[stage.authority.organization_id])
      ? options.stageKeys[stage.authority.organization_id]
      : null;
    const stagePublicKey = organizationKeys?.[stage.authority.key_id];
    if (!verifyEd25519(receipt, AUTHORITY_STAGE_RECEIPT_DOMAIN, stagePublicKey)) {
      return failure('invalid_stage_signature', program, programDigest);
    }

    const expectedPredecessors = analysis.predecessors[stageId]
      .map((predecessorId) => receiptDigests.get(predecessorId)!)
      .sort();
    if (canonicalize(receipt.predecessor_receipt_digests) !== canonicalize(expectedPredecessors)) {
      return failure('predecessor_receipt_digest_mismatch', program, programDigest);
    }

    if (receipt.aec.requirement_digest !== stage.aec_requirement_digest) {
      return failure('aec_requirement_mismatch', program, programDigest);
    }
    const aec = safeCallback(options.verifyAec, {
      stage_id: stageId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: receipt.aec.requirement_digest,
      result_digest: receipt.aec.result_digest,
    });
    if (!validEvidenceResult(aec)
        || aec.requirement_digest !== receipt.aec.requirement_digest
        || aec.result_digest !== receipt.aec.result_digest) {
      return failure('aec_verification_mismatch', program, programDigest);
    }

    if (receipt.aom.requirement_digest !== stage.aom_requirement_digest) {
      return failure('aom_requirement_mismatch', program, programDigest);
    }
    const aom = safeCallback(options.verifyAom, {
      stage_id: stageId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: receipt.aom.requirement_digest,
      result_digest: receipt.aom.result_digest,
    });
    if (!validEvidenceResult(aom)
        || aom.requirement_digest !== receipt.aom.requirement_digest
        || aom.result_digest !== receipt.aom.result_digest) {
      return failure('aom_verification_mismatch', program, programDigest);
    }

    if (receipt.capability.requirement_digest !== stage.capability_requirement_digest) {
      return failure('capability_requirement_mismatch', program, programDigest);
    }
    const capability = safeCallback(options.verifyCapabilityNarrowing, {
      stage_id: stageId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: receipt.capability.requirement_digest,
      input_digest: receipt.capability.input_digest,
      output_digest: receipt.capability.output_digest,
    });
    if (!validCapabilityResult(capability)) {
      return failure('capability_verification_failed', program, programDigest);
    }
    if (!capability.narrowed) return failure('capability_not_narrowed', program, programDigest);
    if (capability.requirement_digest !== receipt.capability.requirement_digest
        || capability.input_digest !== receipt.capability.input_digest
        || capability.output_digest !== receipt.capability.output_digest) {
      return failure('capability_verification_mismatch', program, programDigest);
    }
  }

  for (const parallel of analysis.parallels) {
    const branchBindings = parallel.branches.map((branch) => {
      const stageIds: string[] = [];
      const collect = (node: any): void => {
        if (node.type === 'stage') {
          stageIds.push(node.stage_id);
          return;
        }
        for (const child of node.type === 'sequence' ? node.children : node.branches) collect(child);
      };
      collect(branch);
      return stageIds.sort().map((stageId) => {
        const receipt = receipts.get(stageId)!;
        return {
          stage_id: stageId,
          receipt_digest: receiptDigests.get(stageId),
          capability_input_digest: receipt.capability.input_digest,
          capability_output_digest: receipt.capability.output_digest,
        };
      });
    });
    const allocation = safeCallback(options.verifyParallelAllocation, {
      parallel_id: parallel.parallel_id,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: parallel.allocation_requirement_digest,
      proof_digest: parallel.allocation_proof_digest,
      branches: branchBindings,
    });
    if (!validParallelResult(allocation) || !allocation.authoritative) {
      return failure('parallel_allocation_unproven', program, programDigest);
    }
    if (allocation.parallel_id !== parallel.parallel_id
        || allocation.requirement_digest !== parallel.allocation_requirement_digest
        || allocation.proof_digest !== parallel.allocation_proof_digest) {
      return failure('parallel_allocation_mismatch', program, programDigest);
    }
  }

  const orderedDigests = Object.fromEntries(
    [...receiptDigests.entries()].sort(([left], [right]) => left.localeCompare(right)),
  );
  return {
    '@version': AUTHORITY_PROGRAM_RESULT_VERSION,
    valid: true,
    program_digest: programDigest,
    root_caid: program.root_caid,
    root_action_digest: program.root_action_digest,
    stage_receipt_digests: orderedDigests,
    parallel_allocation_status: analysis.parallels.length > 0 ? 'verified' : 'not_applicable',
    root_action_binding_status: 'verified',
    freshness_proven: false,
    revocation_checked: false,
    execution_proven: false,
    reason: null,
  };
}

export function verifyAuthorityProgram(
  program: unknown,
  stageReceipts: unknown,
  options: {
    programPin?: Obj;
    stageKeys?: Obj;
    verifyAec?: VerificationCallback;
    verifyAom?: VerificationCallback;
    verifyCapabilityNarrowing?: VerificationCallback;
    verifyParallelAllocation?: VerificationCallback;
    verifyRootActionBinding?: VerificationCallback;
  } = {},
): Obj {
  try {
    if (!record(options)) return failure('malformed_input');
    if (!boundedPlainJson(program)
        || !boundedPlainJson(stageReceipts)
        || (options.programPin !== undefined && !boundedPlainJson(options.programPin))
        || (options.stageKeys !== undefined && !boundedPlainJson(options.stageKeys))) {
      return failure('malformed_input');
    }
    const snapshotOptions = {
      programPin: structuredClone(options.programPin),
      stageKeys: structuredClone(options.stageKeys),
      verifyAec: options.verifyAec,
      verifyAom: options.verifyAom,
      verifyCapabilityNarrowing: options.verifyCapabilityNarrowing,
      verifyParallelAllocation: options.verifyParallelAllocation,
      verifyRootActionBinding: options.verifyRootActionBinding,
    };
    return verifyAuthorityProgramCore(
      structuredClone(program),
      structuredClone(stageReceipts),
      snapshotOptions,
    );
  } catch {
    return failure('malformed_input');
  }
}

// ===========================================================================
// EP-AUTHORITY-PROGRAM-v2 / EP-AUTHORITY-STAGE-RECEIPT-v2 -- hybrid
// (Ed25519 + ML-DSA-65) program and stage-receipt signatures
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to BOTH signed
 * artifact types this module verifies:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `proof`, a wire-format change, so each artifact takes a new `@version`
 *    (EP-AUTHORITY-PROGRAM-v1 -> -v2, EP-AUTHORITY-STAGE-RECEIPT-v1 -> -v2).
 *    verifyAuthorityProgram() above is untouched: validProgramEnvelope and
 *    validStageReceipt still require the v1 `@version` markers, so a v2
 *    program or receipt refuses on `invalid_program_envelope` /
 *    `invalid_stage_receipt` BEFORE any signature inspection, and never
 *    throws.
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }). Neither v1 nor v2 embeds public key material in
 *    the proof itself -- verification always looks the key up from the
 *    relying-party-pinned `programPin` / `stageKeys`, exactly as v1 does; v2
 *    only widens each pin to carry BOTH halves (`public_key`, `pq_public_key`).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (signingBytesV2 below, alongside the existing domain tag and
 *    the unsigned body). Drop the ML-DSA leg and narrow `required_algorithms`
 *    and the surviving Ed25519 signature no longer verifies, because the
 *    bytes changed.
 * 4. V1 COMPATIBILITY. v1 programs and receipts keep verifying, unchanged,
 *    through verifyAuthorityProgram (which stays synchronous). v2 verification
 *    is ASYNC (ML-DSA verification is async), so it is a SEPARATE entry point
 *    (verifyAuthorityProgramV2); verifyAuthorityProgramAny() routes on the
 *    program's `@version` for callers holding a mixed bag. The v1 verifier is
 *    never made async.
 * 5. NAMED REFUSALS. Every failure path returns a named `reason`; nothing
 *    throws on caller input (mirroring v1's `failure()` helper). An absent
 *    ML-DSA backend surfaces as a refused signature check, never a skipped
 *    check and never a pass on the classical leg alone.
 *
 * HONEST BOUNDARIES carry over unchanged from v1: this module deliberately has
 * no store, clock, scheduler, transition API, threshold grammar, execution
 * path, revocation mutation, reconciliation, or policy evaluation --
 * `freshness_proven`, `revocation_checked`, and `execution_proven` are always
 * `false`. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * v2 does NOT retroactively protect programs or receipts already issued under
 * v1.
 */

export const AUTHORITY_PROGRAM_V2_VERSION = 'EP-AUTHORITY-PROGRAM-v2';
const AUTHORITY_PROGRAM_V2_DOMAIN = `${AUTHORITY_PROGRAM_V2_VERSION}\0`;
export const AUTHORITY_STAGE_RECEIPT_V2_VERSION = 'EP-AUTHORITY-STAGE-RECEIPT-v2';
const AUTHORITY_STAGE_RECEIPT_V2_DOMAIN = `${AUTHORITY_STAGE_RECEIPT_V2_VERSION}\0`;
export const AUTHORITY_PROGRAM_V2_RESULT_VERSION = 'EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v2';

/** The registered required algorithm set, in canonical order. */
export const AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

/** v2 pin: BOTH public halves for one signer, keyed the same way v1's pins are. */
export interface AuthorityV2KeyPin {
  public_key: string;
  pq_public_key: string;
}

function algorithmSetMatchesRegisteredV2(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS[i]);
}

function validAgileSignatureSetShape(value: unknown): value is AgileSignature[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  const presented = new Set<string>();
  for (const s of value) {
    if (!record(s) || typeof (s as Obj).alg !== 'string' || typeof (s as Obj).sig !== 'string') return false;
    if (presented.has((s as Obj).alg as string)) return false;
    presented.add((s as Obj).alg as string);
  }
  if (presented.size !== AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS.length) return false;
  return AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS.every((alg) => presented.has(alg));
}

function validProofV2(value: unknown, { program = false }: { program?: boolean } = {}): boolean {
  const required = program
    ? ['profile', 'required_algorithms', 'organization_id', 'key_id', 'signatures']
    : ['profile', 'required_algorithms', 'key_id', 'signatures'];
  const expectedProfile = program ? AUTHORITY_PROGRAM_V2_VERSION : AUTHORITY_STAGE_RECEIPT_V2_VERSION;
  return exactObject(value, required)
    && value.profile === expectedProfile
    && algorithmSetMatchesRegisteredV2(value.required_algorithms)
    && (!program || identifier(value.organization_id))
    && identifier(value.key_id)
    && validAgileSignatureSetShape(value.signatures);
}

/**
 * The bytes BOTH legs sign: the SAME unsigned body v1 signs (everything but
 * `proof`) plus the committed `required_algorithms` set, under the v2 domain
 * tag. Recomputed independently by the verifier from the PRESENTED fields and
 * the REGISTERED set.
 */
function signingBytesV2(value: Obj, domain: string, requiredAlgorithms: readonly string[]): Buffer {
  if (!algorithmSetMatchesRegisteredV2(requiredAlgorithms)) {
    throw new Error('signingBytesV2: algorithm set is not the registered v2 set');
  }
  return Buffer.from(
    `${domain}${canonicalize({ ...unsigned(value), required_algorithms: [...requiredAlgorithms] })}`,
    'utf8',
  );
}

async function verifyHybridSet(
  value: Obj,
  domain: string,
  pin: AuthorityV2KeyPin | null | undefined,
  agility: AgilityOptions,
): Promise<boolean> {
  if (!pin || typeof pin.public_key !== 'string' || typeof pin.pq_public_key !== 'string'
    || pin.public_key.length === 0 || pin.pq_public_key.length === 0) return false;
  const signatures = (value.proof as Obj)?.signatures;
  if (!validAgileSignatureSetShape(signatures)) return false;
  let bytes: Buffer;
  try {
    bytes = signingBytesV2(value, domain, AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS);
  } catch {
    return false;
  }
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(bytes),
      signatures,
      [
        { alg: 'Ed25519', public_key: pin.public_key },
        { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
      ],
      { ...agility, policy: 'hybrid_all', requiredAlgorithms: [...AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS] },
    );
  } catch {
    return false;
  }
  return setResult?.verified === true;
}

function validProgramEnvelopeV2(value: unknown): value is Obj {
  return exactObject(value, [
    '@version',
    'program_id',
    'root_caid',
    'root_action_digest',
    'expression',
    'proof',
  ])
    && value['@version'] === AUTHORITY_PROGRAM_V2_VERSION
    && identifier(value.program_id)
    && typeof value.root_caid === 'string'
    && ROOT_CAID.test(value.root_caid)
    && typeof value.root_action_digest === 'string'
    && DIGEST.test(value.root_action_digest)
    && validProofV2(value.proof, { program: true });
}

function validStageReceiptV2(value: unknown): value is Obj {
  return exactObject(value, [
    '@version',
    'receipt_id',
    'program_digest',
    'root_caid',
    'root_action_digest',
    'stage_id',
    'issuer',
    'predecessor_receipt_digests',
    'aec',
    'aom',
    'capability',
    'proof',
  ])
    && value['@version'] === AUTHORITY_STAGE_RECEIPT_V2_VERSION
    && identifier(value.receipt_id)
    && typeof value.program_digest === 'string'
    && DIGEST.test(value.program_digest)
    && typeof value.root_caid === 'string'
    && ROOT_CAID.test(value.root_caid)
    && typeof value.root_action_digest === 'string'
    && DIGEST.test(value.root_action_digest)
    && identifier(value.stage_id)
    && exactObject(value.issuer, ['organization_id', 'key_id'])
    && identifier(value.issuer.organization_id)
    && identifier(value.issuer.key_id)
    && uniqueDigests(value.predecessor_receipt_digests)
    && validJoin(value.aec)
    && validJoin(value.aom)
    && validCapabilityJoin(value.capability)
    && validProofV2(value.proof)
    && value.proof.key_id === value.issuer.key_id;
}

function failureV2(
  reason: string,
  program: unknown = null,
  programDigest: string | null = null,
): Obj {
  return {
    '@version': AUTHORITY_PROGRAM_V2_RESULT_VERSION,
    valid: false,
    program_digest: programDigest,
    root_caid: record(program) && typeof program.root_caid === 'string' ? program.root_caid : null,
    root_action_digest: record(program) && typeof program.root_action_digest === 'string'
      ? program.root_action_digest
      : null,
    stage_receipt_digests: {},
    parallel_allocation_status: null,
    root_action_binding_status: null,
    freshness_proven: false,
    revocation_checked: false,
    execution_proven: false,
    reason,
  };
}

/** Digest of the exact signed v2 authority-program envelope. */
export function authorityProgramDigestV2(program: unknown): string {
  return digest(program);
}

/** Digest of the exact signed immutable v2 stage receipt. */
export function authorityStageReceiptDigestV2(receipt: unknown): string {
  return digest(receipt);
}

interface AuthorityProgramV2Options {
  programPin?: Obj;
  stageKeys?: Obj;
  verifyAec?: VerificationCallback;
  verifyAom?: VerificationCallback;
  verifyCapabilityNarrowing?: VerificationCallback;
  verifyParallelAllocation?: VerificationCallback;
  verifyRootActionBinding?: VerificationCallback;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}

/**
 * Verify a signed v2 authority program and all immutable v2 stage receipts.
 * FAIL-CLOSED hybrid twin of verifyAuthorityProgramCore; a v2 signature NEVER
 * verifies on one leg alone. Structurally identical walk to the v1 core
 * (shared, crypto-free helpers: analyzeExpression, digest computation, the
 * evidence/capability/parallel callback contracts); only the two signature
 * checks are hybrid and async.
 */
async function verifyAuthorityProgramCoreV2(
  program: unknown,
  stageReceipts: unknown,
  options: AuthorityProgramV2Options = {},
): Promise<Obj> {
  if (!validProgramEnvelopeV2(program)) return failureV2('invalid_program_envelope');
  const analysis = analyzeExpression(program.expression);
  if (!analysis) return failureV2('invalid_program_expression', program);
  const programDigest = authorityProgramDigestV2(program);
  const agility: AgilityOptions = {};
  if (options.mldsaBackend !== undefined) agility.mldsaBackend = options.mldsaBackend;
  if (options.mldsaBackendLoader !== undefined) agility.mldsaBackendLoader = options.mldsaBackendLoader;

  if (!exactObject(options.programPin, [
    'digest',
    'organization_id',
    'key_id',
    'public_key',
    'pq_public_key',
  ])
      || typeof options.programPin.digest !== 'string'
      || !DIGEST.test(options.programPin.digest)
      || !identifier(options.programPin.organization_id)
      || !identifier(options.programPin.key_id)
      || typeof options.programPin.public_key !== 'string'
      || typeof options.programPin.pq_public_key !== 'string') {
    return failureV2('invalid_program_pin', program, programDigest);
  }
  if (options.programPin.digest !== programDigest) {
    return failureV2('program_digest_mismatch', program, programDigest);
  }
  if (program.proof.organization_id !== options.programPin.organization_id
      || program.proof.key_id !== options.programPin.key_id) {
    return failureV2('program_signer_mismatch', program, programDigest);
  }
  const programSigned = await verifyHybridSet(
    program,
    AUTHORITY_PROGRAM_V2_DOMAIN,
    { public_key: options.programPin.public_key, pq_public_key: options.programPin.pq_public_key },
    agility,
  );
  if (!programSigned) {
    return failureV2('invalid_program_signature', program, programDigest);
  }

  const rootActionBinding = safeCallback(options.verifyRootActionBinding, {
    program_digest: programDigest,
    root_caid: program.root_caid,
    root_action_digest: program.root_action_digest,
  });
  if (!validRootActionBindingResult(rootActionBinding)) {
    return failureV2('root_action_binding_unproven', program, programDigest);
  }
  if (rootActionBinding.root_caid !== program.root_caid
      || rootActionBinding.root_action_digest !== program.root_action_digest) {
    return failureV2('root_action_binding_mismatch', program, programDigest);
  }

  if (!Array.isArray(stageReceipts) || stageReceipts.length !== analysis.stages.size) {
    return failureV2('stage_receipt_set_mismatch', program, programDigest);
  }
  const receipts = new Map<string, Obj>();
  const receiptIds = new Set<string>();
  for (const receipt of stageReceipts) {
    if (!validStageReceiptV2(receipt)) return failureV2('invalid_stage_receipt', program, programDigest);
    if (receipts.has(receipt.stage_id) || receiptIds.has(receipt.receipt_id)) {
      return failureV2('duplicate_stage_receipt', program, programDigest);
    }
    receipts.set(receipt.stage_id, receipt);
    receiptIds.add(receipt.receipt_id);
  }
  for (const stageId of analysis.stages.keys()) {
    if (!receipts.has(stageId)) return failureV2('stage_receipt_set_mismatch', program, programDigest);
  }

  const receiptDigests = new Map<string, string>();
  for (const [stageId, receipt] of receipts) {
    receiptDigests.set(stageId, authorityStageReceiptDigestV2(receipt));
  }

  for (const [stageId, stage] of analysis.stages) {
    const receipt = receipts.get(stageId)!;
    if (receipt.program_digest !== programDigest) {
      return failureV2('stage_program_digest_mismatch', program, programDigest);
    }
    if (receipt.root_caid !== program.root_caid) {
      return failureV2('stage_root_caid_mismatch', program, programDigest);
    }
    if (receipt.root_action_digest !== program.root_action_digest) {
      return failureV2('stage_root_action_digest_mismatch', program, programDigest);
    }
    if (receipt.issuer.organization_id !== stage.authority.organization_id
        || receipt.issuer.key_id !== stage.authority.key_id) {
      return failureV2('stage_authority_mismatch', program, programDigest);
    }
    const organizationKeys = record(options.stageKeys) && record(options.stageKeys[stage.authority.organization_id])
      ? options.stageKeys[stage.authority.organization_id]
      : null;
    const stagePin = organizationKeys?.[stage.authority.key_id] as AuthorityV2KeyPin | undefined;
    const stageSigned = await verifyHybridSet(receipt, AUTHORITY_STAGE_RECEIPT_V2_DOMAIN, stagePin, agility);
    if (!stageSigned) {
      return failureV2('invalid_stage_signature', program, programDigest);
    }

    const expectedPredecessors = analysis.predecessors[stageId]
      .map((predecessorId) => receiptDigests.get(predecessorId)!)
      .sort();
    if (canonicalize(receipt.predecessor_receipt_digests) !== canonicalize(expectedPredecessors)) {
      return failureV2('predecessor_receipt_digest_mismatch', program, programDigest);
    }

    if (receipt.aec.requirement_digest !== stage.aec_requirement_digest) {
      return failureV2('aec_requirement_mismatch', program, programDigest);
    }
    const aec = safeCallback(options.verifyAec, {
      stage_id: stageId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: receipt.aec.requirement_digest,
      result_digest: receipt.aec.result_digest,
    });
    if (!validEvidenceResult(aec)
        || aec.requirement_digest !== receipt.aec.requirement_digest
        || aec.result_digest !== receipt.aec.result_digest) {
      return failureV2('aec_verification_mismatch', program, programDigest);
    }

    if (receipt.aom.requirement_digest !== stage.aom_requirement_digest) {
      return failureV2('aom_requirement_mismatch', program, programDigest);
    }
    const aom = safeCallback(options.verifyAom, {
      stage_id: stageId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: receipt.aom.requirement_digest,
      result_digest: receipt.aom.result_digest,
    });
    if (!validEvidenceResult(aom)
        || aom.requirement_digest !== receipt.aom.requirement_digest
        || aom.result_digest !== receipt.aom.result_digest) {
      return failureV2('aom_verification_mismatch', program, programDigest);
    }

    if (receipt.capability.requirement_digest !== stage.capability_requirement_digest) {
      return failureV2('capability_requirement_mismatch', program, programDigest);
    }
    const capability = safeCallback(options.verifyCapabilityNarrowing, {
      stage_id: stageId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: receipt.capability.requirement_digest,
      input_digest: receipt.capability.input_digest,
      output_digest: receipt.capability.output_digest,
    });
    if (!validCapabilityResult(capability)) {
      return failureV2('capability_verification_failed', program, programDigest);
    }
    if (!capability.narrowed) return failureV2('capability_not_narrowed', program, programDigest);
    if (capability.requirement_digest !== receipt.capability.requirement_digest
        || capability.input_digest !== receipt.capability.input_digest
        || capability.output_digest !== receipt.capability.output_digest) {
      return failureV2('capability_verification_mismatch', program, programDigest);
    }
  }

  for (const parallel of analysis.parallels) {
    const branchBindings = parallel.branches.map((branch) => {
      const stageIds: string[] = [];
      const collect = (node: any): void => {
        if (node.type === 'stage') {
          stageIds.push(node.stage_id);
          return;
        }
        for (const child of node.type === 'sequence' ? node.children : node.branches) collect(child);
      };
      collect(branch);
      return stageIds.sort().map((stageId) => {
        const receipt = receipts.get(stageId)!;
        return {
          stage_id: stageId,
          receipt_digest: receiptDigests.get(stageId),
          capability_input_digest: receipt.capability.input_digest,
          capability_output_digest: receipt.capability.output_digest,
        };
      });
    });
    const allocation = safeCallback(options.verifyParallelAllocation, {
      parallel_id: parallel.parallel_id,
      program_digest: programDigest,
      root_caid: program.root_caid,
      root_action_digest: program.root_action_digest,
      requirement_digest: parallel.allocation_requirement_digest,
      proof_digest: parallel.allocation_proof_digest,
      branches: branchBindings,
    });
    if (!validParallelResult(allocation) || !allocation.authoritative) {
      return failureV2('parallel_allocation_unproven', program, programDigest);
    }
    if (allocation.parallel_id !== parallel.parallel_id
        || allocation.requirement_digest !== parallel.allocation_requirement_digest
        || allocation.proof_digest !== parallel.allocation_proof_digest) {
      return failureV2('parallel_allocation_mismatch', program, programDigest);
    }
  }

  const orderedDigests = Object.fromEntries(
    [...receiptDigests.entries()].sort(([left], [right]) => left.localeCompare(right)),
  );
  return {
    '@version': AUTHORITY_PROGRAM_V2_RESULT_VERSION,
    valid: true,
    program_digest: programDigest,
    root_caid: program.root_caid,
    root_action_digest: program.root_action_digest,
    stage_receipt_digests: orderedDigests,
    parallel_allocation_status: analysis.parallels.length > 0 ? 'verified' : 'not_applicable',
    root_action_binding_status: 'verified',
    freshness_proven: false,
    revocation_checked: false,
    execution_proven: false,
    reason: null,
  };
}

/** Public, fail-closed hybrid entry point. Never throws on caller input. */
export async function verifyAuthorityProgramV2(
  program: unknown,
  stageReceipts: unknown,
  options: AuthorityProgramV2Options = {},
): Promise<Obj> {
  try {
    if (!record(options)) return failureV2('malformed_input');
    if (!boundedPlainJson(program)
        || !boundedPlainJson(stageReceipts)
        || (options.programPin !== undefined && !boundedPlainJson(options.programPin))
        || (options.stageKeys !== undefined && !boundedPlainJson(options.stageKeys))) {
      return failureV2('malformed_input');
    }
    const snapshotOptions: AuthorityProgramV2Options = {
      programPin: structuredClone(options.programPin),
      stageKeys: structuredClone(options.stageKeys),
      verifyAec: options.verifyAec,
      verifyAom: options.verifyAom,
      verifyCapabilityNarrowing: options.verifyCapabilityNarrowing,
      verifyParallelAllocation: options.verifyParallelAllocation,
      verifyRootActionBinding: options.verifyRootActionBinding,
      mldsaBackend: options.mldsaBackend,
      mldsaBackendLoader: options.mldsaBackendLoader,
    };
    return await verifyAuthorityProgramCoreV2(
      structuredClone(program),
      structuredClone(stageReceipts),
      snapshotOptions,
    );
  } catch {
    return failureV2('malformed_input');
  }
}

/** Route a program of EITHER version to its own verifier, on `program['@version']`. */
export async function verifyAuthorityProgramAny(
  program: unknown,
  stageReceipts: unknown,
  options: Parameters<typeof verifyAuthorityProgram>[2] & AuthorityProgramV2Options = {},
): Promise<Obj> {
  if (record(program) && program['@version'] === AUTHORITY_PROGRAM_V2_VERSION) {
    return verifyAuthorityProgramV2(program, stageReceipts, options);
  }
  return verifyAuthorityProgram(program, stageReceipts, options);
}

/**
 * Sign a v2 program envelope (relying-party issuance helper; not exercised by
 * verification). Throws on issuer misuse; there is no caller/attacker input to
 * fail-close over on the signing side.
 */
export async function signAuthorityProgramV2(
  body: Omit<Obj, '@version' | 'proof'>,
  organizationId: string,
  keyId: string,
  signers: AgileSigningKey[],
  options: AgilityOptions = {},
): Promise<Obj> {
  const candidate = { '@version': AUTHORITY_PROGRAM_V2_VERSION, ...body };
  const bytes = signingBytesV2(candidate, AUTHORITY_PROGRAM_V2_DOMAIN, AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(new Uint8Array(bytes), signers, options);
  const signed = {
    ...candidate,
    proof: {
      profile: AUTHORITY_PROGRAM_V2_VERSION,
      required_algorithms: [...AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS],
      organization_id: organizationId,
      key_id: keyId,
      signatures,
    },
  };
  if (!validProgramEnvelopeV2(signed)) throw new Error('signAuthorityProgramV2: minted an invalid v2 program envelope');
  return signed;
}

/** Sign a v2 stage receipt. See signAuthorityProgramV2 for the issuance boundary note. */
export async function signAuthorityStageReceiptV2(
  body: Omit<Obj, '@version' | 'proof'>,
  keyId: string,
  signers: AgileSigningKey[],
  options: AgilityOptions = {},
): Promise<Obj> {
  const candidate = { '@version': AUTHORITY_STAGE_RECEIPT_V2_VERSION, ...body };
  const bytes = signingBytesV2(candidate, AUTHORITY_STAGE_RECEIPT_V2_DOMAIN, AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(new Uint8Array(bytes), signers, options);
  const signed = {
    ...candidate,
    proof: {
      profile: AUTHORITY_STAGE_RECEIPT_V2_VERSION,
      required_algorithms: [...AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS],
      key_id: keyId,
      signatures,
    },
  };
  if (!validStageReceiptV2(signed)) throw new Error('signAuthorityStageReceiptV2: minted an invalid v2 stage receipt');
  return signed;
}
