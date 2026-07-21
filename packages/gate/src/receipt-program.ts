// SPDX-License-Identifier: Apache-2.0

/**
 * Receipt-program execution profile for EMILIA Gate.
 *
 * This module is intentionally a composition kernel, not a second policy
 * engine or ledger. Gate remains the authorization/effect boundary, the
 * capability store remains the atomic budget/replay authority, CAID remains
 * material-action identity, and the Gate evidence log remains the execution
 * history. The kernel freezes those inputs into one signed, offline-checkable
 * execution certificate.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';

import { canonicalize } from './execution-binding.js';
import { canonicalEvidenceJson, verifyEvidenceRecord } from './evidence.js';

export const RECEIPT_PROGRAM_VERSION = 'EP-RECEIPT-PROGRAM-v1';
export const RECEIPT_PROGRAM_CERTIFICATE_VERSION = 'EP-RECEIPT-PROGRAM-CERTIFICATE-v1';
export const RECEIPT_PROGRAM_SIGNATURE_ALGORITHM = 'Ed25519';

const CAID_RE = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const MAX_ID_BYTES = 256;
const MAX_CANONICAL_BYTES = 1024 * 1024;
const MAX_PROGRAM_BYTES = 512 * 1024;
const MAX_RESULT_BYTES = 128 * 1024;
const MAX_CERTIFICATE_CORE_BYTES = 768 * 1024;
const FORBIDDEN_RUNTIME_TRUST_FIELDS = new Set([
  'allowEphemeralState',
  'certificatePrivateKey',
  'certificateSigner',
  'effectTimeoutMs',
  'gate',
  'now',
  'operationIdField',
  'projectResult',
  'resolveCaid',
  'trustedCertificateKeys',
]);

function sha256(value: any): string {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalDigest(value: any): string {
  return `sha256:${sha256(Buffer.from(canonicalize(value), 'utf8'))}`;
}

function isRecord(value: any): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: any): boolean {
  if (!isRecord(value)) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function hasExactKeys(value: any, keys: readonly string[]): boolean {
  if (!isDataRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function validInstant(value: any): boolean {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function deepFreeze(value: any): any {
  if (!value || typeof value !== 'object') return value;
  const stack = [value];
  const seen = new WeakSet();
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) stack.push(child);
    Object.freeze(current);
  }
  return value;
}

function cloneCanonical(value: any, label: string, freeze = true, maxBytes = MAX_CANONICAL_BYTES): any {
  let snapshot;
  try {
    // Validate the caller's graph before cloning. The canonicalizer inspects
    // descriptors without invoking accessors and bounds depth, nodes, strings,
    // aliases, arrays, numbers, and Unicode.
    const canonical = canonicalize(value);
    snapshot = structuredClone(value);
    if (Buffer.byteLength(canonical, 'utf8') > maxBytes) {
      throw new Error('canonical value exceeds byte limit');
    }
  } catch {
    throw new TypeError(`${label} must be bounded canonical JSON`);
  }
  return freeze ? deepFreeze(snapshot) : snapshot;
}

function placeholderId(value: any): string {
  return typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= MAX_ID_BYTES
    ? value : 'invalid';
}

function boundedId(value: any, label: string): string {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > MAX_ID_BYTES) {
    throw new TypeError(`${label} must be a non-empty string of at most ${MAX_ID_BYTES} bytes`);
  }
  return value;
}

function keyObject(value: any, label: string): any {
  try {
    const key = value?.type === 'private' ? value : createPrivateKey(value);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    return key;
  } catch {
    throw new TypeError(`${label} must be an Ed25519 private key`);
  }
}

function publicKeyB64u(privateKey: any): string {
  return createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}

function publicKeyObject(publicKey: any): any {
  const bytes = Buffer.from(publicKey, 'base64url');
  if (bytes.toString('base64url') !== publicKey) throw new Error('non-canonical public key');
  const key = createPublicKey({
    key: Buffer.from(publicKey, 'base64url'),
    type: 'spki',
    format: 'der',
  });
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong public key type');
  return key;
}

function canonicalSignature(value: any): { bytes: Buffer; encoded: string } {
  const bytes = Buffer.isBuffer(value)
    ? Buffer.from(value)
    : typeof value === 'string' ? Buffer.from(value, 'base64url') : null;
  if (!bytes || bytes.length !== 64) throw new Error('certificate signer returned an invalid signature');
  const encoded = bytes.toString('base64url');
  if (typeof value === 'string' && encoded !== value) {
    throw new Error('certificate signer returned a non-canonical signature');
  }
  return { bytes, encoded };
}

function configureCertificateSigner({
  certificatePrivateKey,
  certificateSigner,
  allowEphemeralState,
}: any): any {
  if (certificateSigner !== undefined && certificatePrivateKey !== undefined) {
    throw new TypeError('configure exactly one certificate signer');
  }
  if (certificateSigner !== undefined) {
    if (!isDataRecord(certificateSigner)) {
      throw new TypeError('certificateSigner must be a data object');
    }
    const publicKey = certificateSigner.publicKey ?? certificateSigner.publicKeySpkiB64u;
    if (typeof publicKey !== 'string' || typeof certificateSigner.sign !== 'function'
        || typeof certificateSigner.keyId !== 'string') {
      throw new TypeError('certificateSigner requires keyId, publicKey, and async sign(bytes)');
    }
    publicKeyObject(publicKey);
    if (!allowEphemeralState && !['kms', 'hsm'].includes(certificateSigner.custody)) {
      throw new Error('receipt program production certificate signer custody must be kms or hsm');
    }
    return Object.freeze({
      keyId: boundedId(certificateSigner.keyId, 'certificateSigner.keyId'),
      publicKey,
      sign: certificateSigner.sign,
    });
  }
  if (!allowEphemeralState) {
    throw new Error('receipt program production mode requires an external KMS/HSM certificate signer');
  }
  const privateKey = keyObject(certificatePrivateKey, 'certificatePrivateKey');
  return Object.freeze({
    keyId: 'local-dev',
    publicKey: publicKeyB64u(privateKey),
    sign: async (bytes: Buffer) => sign(null, bytes, privateKey),
  });
}

function instant(now: any): string {
  const value = typeof now === 'function' ? now() : now;
  if (!Number.isFinite(Number(value))) throw new TypeError('receipt program clock must return a finite value');
  return new Date(Number(value)).toISOString();
}

function valueAtPath(value: any, path: string): any {
  let current = value;
  for (const segment of path.split('.')) {
    if (!isRecord(current) || !Object.prototype.hasOwnProperty.call(current, segment)) return undefined;
    current = current[segment];
  }
  return current;
}

function normalizeResolvedCaid(value: any): string | null {
  if (typeof value === 'string') return value;
  if (isRecord(value) && value.ok === true && typeof value.caid === 'string') return value.caid;
  return null;
}

function opcodeSteps(opcodes: readonly string[]): any {
  return opcodes.map((opcode, sequence) => Object.freeze({ sequence, opcode }));
}

function operationFromExecution(record: any): any {
  return record?.detail?.capability?.operation_id ?? null;
}

function evidenceReference(record: any): any {
  if (!record) return null;
  return deepFreeze({
    seq: Number.isSafeInteger(record.seq) ? record.seq : null,
    record_id: typeof record.record_id === 'string' ? record.record_id : null,
    hash: typeof record.hash === 'string' ? record.hash : null,
    prev_hash: typeof record.prev_hash === 'string' ? record.prev_hash : null,
    kind: typeof record.kind === 'string' ? record.kind : null,
    allow: typeof record.allow === 'boolean' ? record.allow : null,
    outcome: typeof record.outcome === 'string' ? record.outcome : null,
    authorizes_decision: typeof record.authorizes_decision === 'string'
      ? record.authorizes_decision : null,
    observed_action_hash: typeof record.observed_action_hash === 'string'
      ? record.observed_action_hash : null,
    operation_id: operationFromExecution(record),
  });
}

function certificateCore({
  context,
  program,
  programDigest,
  outcome,
  reason,
  result,
  authorizationRef,
  executionRef,
  steps,
  startedAt,
  completedAt,
}: any): any {
  return {
    '@version': RECEIPT_PROGRAM_CERTIFICATE_VERSION,
    context,
    program,
    program_digest: programDigest,
    outcome,
    reason,
    result,
    result_digest: result === null ? null : canonicalDigest(result),
    authorization_ref: authorizationRef,
    execution_ref: executionRef,
    steps,
    started_at: startedAt,
    completed_at: completedAt,
  };
}

async function signCertificate(core: any, signer: any): Promise<any> {
  if (Buffer.byteLength(canonicalize(core), 'utf8') > MAX_CERTIFICATE_CORE_BYTES) {
    throw new Error('receipt program certificate exceeds byte limit');
  }
  const stateRoot = canonicalDigest(core);
  const signed = { ...core, state_root: stateRoot };
  const signedBytes = Buffer.from(canonicalize(signed), 'utf8');
  const signature = canonicalSignature(await signer.sign(signedBytes));
  if (!verify(null, signedBytes, publicKeyObject(signer.publicKey), signature.bytes)) {
    throw new Error('certificate signer returned a signature that does not verify');
  }
  return deepFreeze({
    ...signed,
    signature: {
      algorithm: RECEIPT_PROGRAM_SIGNATURE_ALGORITHM,
      public_key: signer.publicKey,
      value: signature.encoded,
    },
  });
}

function makeResult(certificate: any): any {
  return Object.freeze({
    ok: certificate.outcome === 'executed',
    outcome: certificate.outcome,
    reason: certificate.reason,
    result: certificate.result,
    certificate,
  });
}

function failReason(error: any, fallback: string): string {
  return typeof error?.message === 'string' && error.message.startsWith('receipt_program:')
    ? error.message.slice('receipt_program:'.length)
    : fallback;
}

/**
 * Build a receipt-program kernel over an already configured Gate.
 * Trust configuration is constructor-pinned and cannot be supplied per run.
 *
 * options.gate: configured EMILIA Gate
 * options.resolveCaid: synchronous pinned CAID resolver, (action) => string|object
 * options.operationIdField: dot-path to the stable operation id in observed action
 * options.certificatePrivateKey: test/demo-only Ed25519 operator key
 * options.certificateSigner: external KMS/HSM signer
 * options.certificateContext: pinned issuer, tenant, environment, audience, and key id
 * options.projectResult: pinned disclosure projection, (result) => any|Promise<any>
 * options.effectTimeoutMs: provider deadline in milliseconds (default 30000)
 * options.allowEphemeralState: explicit test/demo opt-in (default false)
 * options.now: number|(() => number), default Date.now
 */
export function createReceiptProgramKernel({
  gate,
  resolveCaid,
  operationIdField,
  certificatePrivateKey,
  certificateSigner,
  certificateContext,
  projectResult = null,
  effectTimeoutMs = 30_000,
  allowEphemeralState = false,
  now = Date.now,
}: any = {}) {
  if (!gate || typeof gate.run !== 'function' || !gate.evidence) {
    throw new TypeError('createReceiptProgramKernel requires a configured Gate with an evidence log');
  }
  if (typeof resolveCaid !== 'function') {
    throw new TypeError('createReceiptProgramKernel requires a pinned synchronous CAID resolver');
  }
  boundedId(operationIdField, 'operationIdField');
  if (!allowEphemeralState && (gate.evidence.durable !== true || gate.evidence.strict !== true
      || gate.evidence.forkAware !== true || gate.evidence.atomicAppend !== true
      || gate.capabilityStore?.durable !== true)) {
    throw new Error('receipt program production mode requires a durable atomic evidence log and durable capability store');
  }
  if (!Number.isSafeInteger(effectTimeoutMs) || effectTimeoutMs < 1 || effectTimeoutMs > 600_000) {
    throw new TypeError('effectTimeoutMs must be an integer from 1 to 600000');
  }
  if (!allowEphemeralState && typeof projectResult !== 'function') {
    throw new Error('receipt program production mode requires a pinned projectResult function');
  }
  if (projectResult !== null && typeof projectResult !== 'function') {
    throw new TypeError('projectResult must be a function');
  }
  const signer = configureCertificateSigner({
    certificatePrivateKey,
    certificateSigner,
    allowEphemeralState,
  });
  const context = cloneCanonical(certificateContext, 'certificateContext');
  if (!hasExactKeys(context, ['issuer', 'tenant', 'environment', 'audience', 'key_id'])) {
    throw new TypeError('certificateContext must contain exactly issuer, tenant, environment, audience, and key_id');
  }
  for (const field of ['issuer', 'tenant', 'environment', 'audience', 'key_id']) {
    boundedId(context[field], `certificateContext.${field}`);
  }
  if (context.key_id !== signer.keyId) {
    throw new Error('certificateContext.key_id must equal the configured signer keyId');
  }

  async function issueCertificate(input: any): Promise<any> {
    const core = certificateCore({ ...input, context });
    let certificate;
    try {
      certificate = await signCertificate(core, signer);
    } catch {
      return Object.freeze({
        ok: false,
        outcome: input.outcome,
        reason: 'certificate_signing_failed',
        result: input.result,
        certificate: null,
        certificate_evidence: null,
      });
    }
    try {
      const certificateEvidence = await gate.evidence.record({
        kind: 'receipt_program_certificate',
        program_digest: certificate.program_digest,
        operation_id: certificate.program.operation_id,
        outcome: certificate.outcome,
        state_root: certificate.state_root,
        certificate,
      });
      return Object.freeze({
        ...makeResult(certificate),
        certificate_evidence: deepFreeze(structuredClone(certificateEvidence)),
      });
    } catch {
      return Object.freeze({
        ok: false,
        outcome: input.outcome,
        reason: 'certificate_persistence_failed',
        result: input.result,
        certificate,
        certificate_evidence: null,
      });
    }
  }

  async function refuseEarly({ program, programDigest, reason, startedAt, matched = false }: any): Promise<any> {
    return issueCertificate({
      program,
      programDigest,
      outcome: 'refused',
      reason,
      result: null,
      authorizationRef: null,
      executionRef: null,
      steps: opcodeSteps(matched
        ? ['RECEIPT', 'MATCH', 'REFUSE', 'CERTIFY']
        : ['RECEIPT', 'REFUSE', 'CERTIFY']),
      startedAt,
      completedAt: instant(now),
    });
  }

  return Object.freeze({
    version: RECEIPT_PROGRAM_VERSION,
    signer_public_key: signer.publicKey,
    certificate_context: context,

    /**
     * Execute one consequential receipt instruction through Gate.
     * The effect MUST return a bounded canonical-JSON evidence projection, not
     * a raw provider object. A projection failure occurs after provider entry
     * and is therefore committed as indeterminate.
     */
    async run(request: any = {}, effect: any): Promise<any> {
      const startedAt = instant(now);
      if (!isRecord(request) || typeof effect !== 'function') {
        throw new TypeError('receipt program run requires an object request and effect function');
      }
      const capabilityDescriptor = Object.getOwnPropertyDescriptor(request, 'capability');
      if (!isDataRecord(request) || !capabilityDescriptor
          || !isDataRecord(capabilityDescriptor.value)) {
        const placeholder = deepFreeze({
          '@version': RECEIPT_PROGRAM_VERSION,
          program_id: 'invalid',
          instruction_id: 'invalid',
          operation_id: 'invalid',
          caid: 'invalid',
          action_digest: null,
          capability_receipt_digest: null,
          selector: {},
          observed_action: {},
        });
        return refuseEarly({
          program: placeholder,
          programDigest: canonicalDigest(placeholder),
          reason: 'program_invalid',
          startedAt,
        });
      }
      for (const field of FORBIDDEN_RUNTIME_TRUST_FIELDS) {
        if (Object.prototype.hasOwnProperty.call(request, field)) {
          const placeholder = deepFreeze({
            '@version': RECEIPT_PROGRAM_VERSION,
            program_id: placeholderId(request.programId),
            instruction_id: placeholderId(request.instructionId),
            operation_id: placeholderId(request.capability?.operationId),
            caid: placeholderId(request.caid),
            action_digest: null,
            capability_receipt_digest: null,
            selector: {},
            observed_action: {},
          });
          return refuseEarly({
            program: placeholder,
            programDigest: canonicalDigest(placeholder),
            reason: 'runtime_trust_configuration_refused',
            startedAt,
          });
        }
      }

      let program: any;
      let programDigest: any;
      let operationId: any;
      let actionDigest: any;
      let executionCapability: any;
      let executionReceipt: any = null;
      try {
        const programId = boundedId(request.programId, 'programId');
        const instructionId = boundedId(request.instructionId, 'instructionId');
        operationId = boundedId(request.capability?.operationId, 'capability.operationId');
        if (!CAID_RE.test(request.caid)) throw new Error('receipt_program:caid_invalid');
        const observedAction = cloneCanonical(request.observedAction, 'observedAction');
        const selector = cloneCanonical(request.selector ?? {}, 'selector');
        const capabilityReceipt = cloneCanonical(request.capability?.capabilityReceipt, 'capabilityReceipt');
        const capabilityProjection = cloneCanonical(request.capability?.action, 'capability.action');
        const secret = Buffer.isBuffer(request.capability?.secret)
          ? Buffer.from(request.capability.secret)
          : request.capability?.secret;
        const shares = request.capability?.shares === undefined
          ? undefined : cloneCanonical(request.capability.shares, 'capability.shares');
        executionCapability = Object.freeze({
          capabilityReceipt: structuredClone(capabilityReceipt),
          ...(shares === undefined ? { secret } : { shares: structuredClone(shares) }),
          action: structuredClone(capabilityProjection),
          operationId,
        });
        executionReceipt = request.receipt === undefined || request.receipt === null
          ? null : cloneCanonical(request.receipt, 'receipt');
        const actionOperationId = valueAtPath(observedAction, operationIdField);
        actionDigest = canonicalDigest(observedAction);
        program = deepFreeze({
          '@version': RECEIPT_PROGRAM_VERSION,
          program_id: programId,
          instruction_id: instructionId,
          operation_id: operationId,
          operation_id_field: operationIdField,
          caid: request.caid,
          action_digest: actionDigest,
          capability_receipt_digest: canonicalDigest(capabilityReceipt),
          capability_projection: capabilityProjection,
          selector,
          observed_action: observedAction,
        });
        if (Buffer.byteLength(canonicalize(program), 'utf8') > MAX_PROGRAM_BYTES) {
          throw new Error('receipt_program:program_too_large');
        }
        programDigest = canonicalDigest(program);
        if (actionOperationId !== operationId) {
          return refuseEarly({ program, programDigest, reason: 'program_operation_binding_failed', startedAt });
        }
        const resolved = resolveCaid(structuredClone(observedAction));
        if (resolved && typeof resolved.then === 'function') {
          return refuseEarly({ program, programDigest, reason: 'caid_resolver_async_refused', startedAt });
        }
        if (normalizeResolvedCaid(resolved) !== request.caid) {
          return refuseEarly({ program, programDigest, reason: 'caid_mismatch', startedAt });
        }
        if (request.expectedProgramDigest !== undefined && request.expectedProgramDigest !== programDigest) {
          return refuseEarly({
            program,
            programDigest,
            reason: 'program_digest_mismatch',
            startedAt,
            matched: true,
          });
        }
      } catch (error) {
        const placeholder = deepFreeze({
          '@version': RECEIPT_PROGRAM_VERSION,
          program_id: placeholderId(request.programId),
          instruction_id: placeholderId(request.instructionId),
          operation_id: placeholderId(request.capability?.operationId),
          caid: placeholderId(request.caid),
          action_digest: null,
          capability_receipt_digest: null,
          selector: {},
          observed_action: {},
        });
        return refuseEarly({
          program: placeholder,
          programDigest: canonicalDigest(placeholder),
          reason: failReason(error, 'program_invalid'),
          startedAt,
        });
      }

      let projectedResult: any = null;
      let effectEntered = false;
      let gateResult: any = null;
      let caught: any = null;
      try {
        gateResult = await gate.run({
          selector: program.selector,
          receipt: executionReceipt,
          observedAction: program.observed_action,
          capability: executionCapability,
        }, async (authorization: any, operation: any) => {
          effectEntered = true;
          // Gate owns these values. Give provider code frozen copies so it can
          // neither rewrite the decision later used for evidence nor mutate
          // the operation context Gate retains.
          const authorizationSnapshot = deepFreeze(structuredClone(authorization));
          const operationSnapshot = deepFreeze(structuredClone(operation));
          const abortController = new AbortController();
          const providerOperation = Object.freeze({
            ...operationSnapshot,
            signal: abortController.signal,
          });
          let rawResult;
          let timeoutId: any;
          try {
            const provider = Promise.resolve().then(
              () => effect(authorizationSnapshot, providerOperation),
            );
            const deadline = new Promise((_, reject) => {
              timeoutId = setTimeout(() => {
                abortController.abort('receipt_program_effect_timeout');
                reject(new Error('receipt_program_effect_timeout'));
              }, effectTimeoutMs);
            });
            rawResult = await Promise.race([provider, deadline]);
          } catch (cause) {
            const error: any = new Error('receipt_program_provider_failed');
            error.cause = cause;
            throw error;
          } finally {
            if (timeoutId !== undefined) clearTimeout(timeoutId);
          }
          const projection = projectResult === null
            ? rawResult : await projectResult(rawResult);
          projectedResult = cloneCanonical(
            projection,
            'receipt program effect result',
            true,
            MAX_RESULT_BYTES,
          );
          if (!isRecord(projectedResult)) {
            throw new TypeError('receipt program effect result must be a canonical JSON object');
          }
          return structuredClone(projectedResult);
        });
      } catch (error) {
        caught = error;
      }

      const caughtOutcome = caught?.emiliaGateOutcome ?? null;
      let executionRecord: any = gateResult?.execution
        ?? (gateResult?.evidence?.kind === 'execution' ? gateResult.evidence : null)
        ?? caughtOutcome?.execution
        ?? null;
      let authorizationRecord: any = gateResult?.authorization?.evidence
        ?? caughtOutcome?.authorizationEvidence
        ?? null;
      const executionRef = evidenceReference(executionRecord);
      const authorizationRef = evidenceReference(authorizationRecord);

      if (caughtOutcome?.reason === 'execution_evidence_unavailable' && !executionRecord) {
        return Object.freeze({
          ok: false,
          outcome: caughtOutcome.outcome ?? (effectEntered ? 'indeterminate' : 'refused'),
          reason: 'execution_evidence_unavailable',
          result: caughtOutcome.result ?? projectedResult,
          certificate: null,
          certificate_evidence: null,
        });
      }

      if (gateResult?.ok === true && caught === null) {
        return issueCertificate({
          program,
          programDigest,
          outcome: 'executed',
          reason: null,
          result: projectedResult,
          authorizationRef,
          executionRef,
          steps: opcodeSteps(['RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT', 'CERTIFY']),
          startedAt,
          completedAt: instant(now),
        });
      }

      if (caughtOutcome?.outcome === 'executed') {
        if (!executionRecord) {
          return Object.freeze({
            ok: false,
            outcome: 'executed',
            reason: 'execution_evidence_unavailable',
            result: caughtOutcome.result ?? projectedResult,
            certificate: null,
            certificate_evidence: null,
          });
        }
        return issueCertificate({
          program,
          programDigest,
          outcome: 'executed',
          reason: null,
          result: caughtOutcome.result ?? projectedResult,
          authorizationRef,
          executionRef,
          steps: opcodeSteps(['RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT', 'CERTIFY']),
          startedAt,
          completedAt: instant(now),
        });
      }

      const evidenceIndeterminate = executionRecord?.outcome === 'indeterminate';
      if (effectEntered || evidenceIndeterminate) {
        return issueCertificate({
          program,
          programDigest,
          outcome: 'indeterminate',
          reason: executionRecord ? 'effect_indeterminate' : 'execution_evidence_unavailable',
          result: null,
          authorizationRef,
          executionRef,
          steps: opcodeSteps(['RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT_INDETERMINATE', 'HALT', 'CERTIFY']),
          startedAt,
          completedAt: instant(now),
        });
      }

      const reason = gateResult?.capability?.reason
        ?? gateResult?.refusal?.reason
        ?? gateResult?.authorization?.reason
        ?? failReason(caught, 'gate_refused');
      return issueCertificate({
        program,
        programDigest,
        outcome: 'refused',
        reason,
        result: null,
        authorizationRef,
        executionRef: null,
        steps: opcodeSteps(['RECEIPT', 'MATCH', 'REFUSE', 'CERTIFY']),
        startedAt,
        completedAt: instant(now),
      });
    },

    /**
     * Explicit crash-recovery path. It scans the durable evidence history only
     * when requested and returns every independently verified certificate for
     * one program digest; it never guesses which attempt a caller intended.
     */
    async recoverCertificates(programDigest: any): Promise<any> {
      if (!SHA256_RE.test(programDigest)) {
        return Object.freeze({ ok: false, reason: 'program_digest_invalid', certificates: [] });
      }
      let records;
      try { records = await gate.evidence.all(); } catch {
        return Object.freeze({ ok: false, reason: 'certificate_recovery_unavailable', certificates: [] });
      }
      if (!Array.isArray(records)) {
        return Object.freeze({ ok: false, reason: 'certificate_recovery_malformed', certificates: [] });
      }
      const recovered: any[] = [];
      for (const record of records) {
        if (record?.kind !== 'receipt_program_certificate'
            || record.program_digest !== programDigest) continue;
        const checked = verifyReceiptProgramCertificate(record.certificate, {
          trustedCertificateKeys: { [context.key_id]: signer.publicKey },
          resolveCaid,
          expectedContext: context,
          certificateEvidence: record,
          verifyCertificateInclusion: (candidate: any) => (
            canonicalEvidenceJson(candidate) === canonicalEvidenceJson(record)
          ),
          requireAtomicCertificateEvidence: !allowEphemeralState,
        });
        if (!checked.ok) {
          return Object.freeze({ ok: false, reason: 'certificate_recovery_invalid', certificates: [] });
        }
        recovered.push(deepFreeze({
          certificate: structuredClone(record.certificate),
          certificate_evidence: structuredClone(record),
          verification: checked,
        }));
      }
      return Object.freeze({
        ok: true,
        reason: null,
        certificates: Object.freeze(recovered),
      });
    },
  });
}

function verificationFailure(reason: string): any {
  return Object.freeze({ ok: false, reason });
}

/**
 * Verify the certificate's operator signature, content addresses, program
 * binding, and Gate evidence linkage. This proves exact certificate integrity
 * under a pinned operator key; it does not prove an external provider told the
 * truth or replace verification of the referenced receipt/capability artifacts.
 *
 * options.trustedCertificateKeys?: Record<string, string>
 * options.resolveCaid?: ((action: any) => any)|null
 * options.expectedContext?: object|null
 * options.certificateEvidence?: any
 * options.verifyCertificateInclusion?: (((record: any, expectation: any) => any)|null)
 * options.requireAtomicCertificateEvidence?: boolean
 */
export function verifyReceiptProgramCertificate(certificate: any, {
  trustedCertificateKeys = {},
  resolveCaid = null,
  expectedContext = null,
  certificateEvidence = null,
  verifyCertificateInclusion = null,
  requireAtomicCertificateEvidence = false,
}: any = {}): any {
  try {
    const versionDescriptor = isDataRecord(certificate)
      ? Object.getOwnPropertyDescriptor(certificate, '@version') : null;
    if (versionDescriptor?.value !== RECEIPT_PROGRAM_CERTIFICATE_VERSION) {
      return verificationFailure('certificate_version_invalid');
    }
    const snapshot = cloneCanonical(certificate, 'certificate', false);
    const completeCertificate = structuredClone(snapshot);
    if (!hasExactKeys(snapshot, [
      '@version',
      'context',
      'program',
      'program_digest',
      'outcome',
      'reason',
      'result',
      'result_digest',
      'authorization_ref',
      'execution_ref',
      'steps',
      'started_at',
      'completed_at',
      'state_root',
      'signature',
    ])) return verificationFailure('certificate_schema_invalid');
    const signature = snapshot.signature;
    if (!hasExactKeys(signature, ['algorithm', 'public_key', 'value'])
        || signature.algorithm !== RECEIPT_PROGRAM_SIGNATURE_ALGORITHM
        || typeof signature.public_key !== 'string' || typeof signature.value !== 'string') {
      return verificationFailure('certificate_signature_invalid');
    }
    const claimedKeyId = snapshot.context?.key_id;
    if (!isDataRecord(trustedCertificateKeys)
        || typeof claimedKeyId !== 'string'
        || trustedCertificateKeys[claimedKeyId] !== signature.public_key) {
      return verificationFailure('certificate_signer_not_trusted');
    }
    delete snapshot.signature;
    const signatureBytes = Buffer.from(signature.value, 'base64url');
    if (signatureBytes.length !== 64 || signatureBytes.toString('base64url') !== signature.value
        || !verify(
      null,
      Buffer.from(canonicalize(snapshot), 'utf8'),
      publicKeyObject(signature.public_key),
      signatureBytes,
    )) return verificationFailure('certificate_signature_invalid');

    const stateRoot = snapshot.state_root;
    delete snapshot.state_root;
    if (!SHA256_RE.test(stateRoot) || canonicalDigest(snapshot) !== stateRoot) {
      return verificationFailure('certificate_state_root_mismatch');
    }
    const signed = { ...snapshot, state_root: stateRoot };
    const certificateCoreSnapshot: any = { ...signed };
    delete certificateCoreSnapshot.state_root;
    if (Buffer.byteLength(canonicalize(certificateCoreSnapshot), 'utf8')
        > MAX_CERTIFICATE_CORE_BYTES) {
      return verificationFailure('certificate_size_invalid');
    }
    if (!hasExactKeys(signed.context, ['issuer', 'tenant', 'environment', 'audience', 'key_id'])
        || Object.values(signed.context).some((value) => typeof value !== 'string'
          || value.length === 0 || Buffer.byteLength(value, 'utf8') > MAX_ID_BYTES)) {
      return verificationFailure('certificate_context_invalid');
    }
    if (!isRecord(expectedContext)) {
      return verificationFailure('certificate_context_required');
    }
    let expectedContextSnapshot;
    try { expectedContextSnapshot = cloneCanonical(expectedContext, 'expectedContext'); } catch {
      return verificationFailure('certificate_context_invalid');
    }
    if (canonicalize(expectedContextSnapshot) !== canonicalize(signed.context)) {
      return verificationFailure('certificate_context_mismatch');
    }
    if (!validInstant(signed.started_at) || !validInstant(signed.completed_at)
        || Date.parse(signed.completed_at) < Date.parse(signed.started_at)) {
      return verificationFailure('certificate_time_invalid');
    }
    const program = signed.program;
    if (!isRecord(program) || program['@version'] !== RECEIPT_PROGRAM_VERSION) {
      return verificationFailure('certificate_program_invalid');
    }
    if (Buffer.byteLength(canonicalize(program), 'utf8') > MAX_PROGRAM_BYTES) {
      return verificationFailure('certificate_program_invalid');
    }
    if (!SHA256_RE.test(signed.program_digest) || canonicalDigest(program) !== signed.program_digest) {
      return verificationFailure('certificate_program_digest_mismatch');
    }
    if (!['executed', 'indeterminate', 'refused'].includes(signed.outcome)) {
      return verificationFailure('certificate_outcome_invalid');
    }
    if ((signed.outcome === 'executed' && signed.reason !== null)
        || (signed.outcome !== 'executed' && typeof signed.reason !== 'string')) {
      return verificationFailure('certificate_reason_invalid');
    }
    const completeProgram = hasExactKeys(program, [
      '@version',
      'program_id',
      'instruction_id',
      'operation_id',
      'operation_id_field',
      'caid',
      'action_digest',
      'capability_receipt_digest',
      'capability_projection',
      'selector',
      'observed_action',
    ])
      && [program.program_id, program.instruction_id, program.operation_id, program.operation_id_field]
        .every((value) => typeof value === 'string' && value.length > 0
          && Buffer.byteLength(value, 'utf8') <= MAX_ID_BYTES)
      && isRecord(program.capability_projection)
      && isRecord(program.selector)
      && isRecord(program.observed_action);
    const executableProgram = completeProgram
      && CAID_RE.test(program.caid)
      && SHA256_RE.test(program.action_digest)
      && SHA256_RE.test(program.capability_receipt_digest)
      && valueAtPath(program.observed_action, program.operation_id_field) === program.operation_id
      && canonicalDigest(program.observed_action) === program.action_digest;
    if (signed.outcome !== 'refused' && !executableProgram) {
      return verificationFailure('certificate_program_invalid');
    }
    if (executableProgram) {
      if (typeof resolveCaid !== 'function') {
        return verificationFailure('certificate_caid_resolver_required');
      }
      const resolved = resolveCaid(structuredClone(program.observed_action));
      if (resolved && typeof resolved.then === 'function') {
        return verificationFailure('certificate_caid_resolver_async_refused');
      }
      const resolvedCaid = normalizeResolvedCaid(resolved);
      if (signed.outcome === 'refused' && signed.reason === 'caid_mismatch') {
        if (resolvedCaid === program.caid) return verificationFailure('certificate_refusal_evidence_mismatch');
      } else if (resolvedCaid !== program.caid) {
        return verificationFailure('certificate_caid_mismatch');
      }
    }
    if (!Array.isArray(signed.steps) || signed.steps.length === 0
        || signed.steps.some((step: any, index: number) => !hasExactKeys(step, ['sequence', 'opcode'])
          || step.sequence !== index || typeof step.opcode !== 'string')) {
      return verificationFailure('certificate_steps_invalid');
    }
    const expectedOpcodes = signed.outcome === 'executed'
      ? ['RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT', 'CERTIFY']
      : signed.outcome === 'indeterminate'
        ? ['RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT_INDETERMINATE', 'HALT', 'CERTIFY']
        : executableProgram && !['caid_mismatch', 'caid_resolver_async_refused'].includes(signed.reason)
          ? ['RECEIPT', 'MATCH', 'REFUSE', 'CERTIFY']
          : ['RECEIPT', 'REFUSE', 'CERTIFY'];
    if (canonicalize(signed.steps.map((step: any) => step.opcode)) !== canonicalize(expectedOpcodes)) {
      return verificationFailure('certificate_steps_outcome_mismatch');
    }
    if (signed.result === null) {
      if (signed.result_digest !== null) return verificationFailure('certificate_result_digest_mismatch');
    } else {
      if (!isRecord(signed.result)
          || Buffer.byteLength(canonicalize(signed.result), 'utf8') > MAX_RESULT_BYTES) {
        return verificationFailure('certificate_result_invalid');
      }
      if (!SHA256_RE.test(signed.result_digest)
          || canonicalDigest(signed.result) !== signed.result_digest) {
        return verificationFailure('certificate_result_digest_mismatch');
      }
    }
    const authorization = signed.authorization_ref;
    const execution = signed.execution_ref;
    const validReference = (reference: any, kind: string): boolean => reference === null || (hasExactKeys(reference, [
      'seq', 'record_id', 'hash', 'prev_hash', 'kind', 'allow', 'outcome',
      'authorizes_decision', 'observed_action_hash', 'operation_id',
    ])
      && Number.isSafeInteger(reference.seq) && reference.seq >= 0
      && (reference.record_id === null || (typeof reference.record_id === 'string'
        && reference.record_id.length > 0
        && Buffer.byteLength(reference.record_id, 'utf8') <= MAX_ID_BYTES))
      && /^[0-9a-f]{64}$/.test(reference.hash)
      && (reference.prev_hash === 'genesis' || /^[0-9a-f]{64}$/.test(reference.prev_hash))
      && reference.kind === kind
      && (reference.allow === null || typeof reference.allow === 'boolean')
      && (reference.outcome === null || (typeof reference.outcome === 'string'
        && reference.outcome.length > 0
        && Buffer.byteLength(reference.outcome, 'utf8') <= MAX_ID_BYTES))
      && (reference.authorizes_decision === null || /^[0-9a-f]{64}$/.test(reference.authorizes_decision))
      && (reference.observed_action_hash === null || /^[0-9a-f]{64}$/.test(reference.observed_action_hash))
      && (reference.operation_id === null || (typeof reference.operation_id === 'string'
        && reference.operation_id.length > 0
        && Buffer.byteLength(reference.operation_id, 'utf8') <= MAX_ID_BYTES)));
    if (!validReference(authorization, 'decision')) return verificationFailure('certificate_authorization_ref_invalid');
    if (!validReference(execution, 'execution')) return verificationFailure('certificate_execution_ref_invalid');
    if (authorization && (typeof authorization.allow !== 'boolean'
        || (authorization.allow === true && typeof authorization.outcome !== 'string'))) {
      return verificationFailure('certificate_authorization_ref_invalid');
    }
    if (execution && (execution.allow !== null
        || !['executed', 'indeterminate'].includes(execution.outcome))) {
      return verificationFailure('certificate_execution_ref_invalid');
    }
    if (authorization && execution && execution.seq <= authorization.seq) {
      return verificationFailure('certificate_evidence_order_invalid');
    }
    if (authorization && execution && execution.authorizes_decision !== authorization.hash) {
      return verificationFailure('certificate_evidence_link_mismatch');
    }
    const bareActionDigest = executableProgram ? program.action_digest.slice('sha256:'.length) : null;
    if (authorization && authorization.observed_action_hash !== bareActionDigest) {
      return verificationFailure('certificate_authorization_binding_mismatch');
    }
    if (signed.outcome !== 'refused' && authorization?.allow !== true) {
      return verificationFailure('certificate_authorization_binding_mismatch');
    }
    if (execution && (execution.observed_action_hash !== bareActionDigest
        || execution.operation_id !== program.operation_id)) {
      return verificationFailure('certificate_execution_binding_mismatch');
    }
    if (signed.outcome === 'executed') {
      if (signed.result === null || !authorization || !execution || execution.outcome !== 'executed') {
        return verificationFailure('certificate_executed_evidence_incomplete');
      }
    } else if (signed.result !== null) {
      return verificationFailure('certificate_nonexecuted_result_present');
    }
    if (signed.outcome === 'indeterminate') {
      if (execution === null && signed.reason !== 'execution_evidence_unavailable') {
        return verificationFailure('certificate_indeterminate_evidence_incomplete');
      }
      if (execution !== null && execution.outcome !== 'indeterminate') {
        return verificationFailure('certificate_indeterminate_evidence_mismatch');
      }
    }
    let certificatePersisted = false;
    if (certificateEvidence !== null) {
      const expectedEntry = {
        kind: 'receipt_program_certificate',
        program_digest: signed.program_digest,
        operation_id: program.operation_id,
        outcome: signed.outcome,
        state_root: stateRoot,
        certificate: completeCertificate,
      };
      if (!verifyEvidenceRecord(certificateEvidence, {
        atomicRequired: requireAtomicCertificateEvidence,
        expectedEntry,
      })) return verificationFailure('certificate_evidence_invalid');
      if (typeof verifyCertificateInclusion !== 'function') {
        return verificationFailure('certificate_evidence_inclusion_verifier_required');
      }
      let included;
      try {
        included = verifyCertificateInclusion(structuredClone(certificateEvidence), deepFreeze({
          expected_entry: structuredClone(expectedEntry),
          expected_context: structuredClone(expectedContextSnapshot),
          program_digest: signed.program_digest,
          state_root: stateRoot,
          atomic_required: requireAtomicCertificateEvidence,
        }));
      } catch {
        return verificationFailure('certificate_evidence_not_included');
      }
      if (included && typeof included.then === 'function') {
        return verificationFailure('certificate_evidence_inclusion_async_refused');
      }
      if (included !== true) return verificationFailure('certificate_evidence_not_included');
      certificatePersisted = true;
    } else if (requireAtomicCertificateEvidence) {
      return verificationFailure('certificate_evidence_required');
    }
    return Object.freeze({
      ok: true,
      certificate_valid: true,
      execution_succeeded: signed.outcome === 'executed',
      reason: null,
      outcome: signed.outcome,
      program_digest: signed.program_digest,
      state_root: stateRoot,
      signer: signature.public_key,
      evidence_complete: Boolean(authorization && (signed.outcome === 'refused' || execution)),
      certificate_persisted: certificatePersisted,
      caid_reperformed: executableProgram,
    });
  } catch {
    return verificationFailure('certificate_malformed');
  }
}

export default {
  RECEIPT_PROGRAM_VERSION,
  RECEIPT_PROGRAM_CERTIFICATE_VERSION,
  RECEIPT_PROGRAM_SIGNATURE_ALGORITHM,
  createReceiptProgramKernel,
  verifyReceiptProgramCertificate,
};
