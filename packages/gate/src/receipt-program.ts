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
// Opt-in FIPS operation-policy consult at the certificate signer call site
// (see issueCertificate below). A genuine declared dependency of
// @emilia-protocol/gate, same as @emilia-protocol/verify/pq-signature-agility
// elsewhere in this package.
import { checkOperationPolicy, type FipsPosture } from '@emilia-protocol/verify/fips-mode';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgileSigningKey,
  type AgileSignature,
} from '@emilia-protocol/verify/pq-signature-agility';

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
  'fipsPosture',
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
  // ONE core builder for both certificate versions; only the marker differs.
  certificateVersion = RECEIPT_PROGRAM_CERTIFICATE_VERSION,
}: any): any {
  return {
    '@version': certificateVersion,
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
  // OPT-IN. When configured, every issuance consults checkOperationPolicy()
  // (packages/verify/src/fips-mode.ts) for the certificate's signature
  // algorithm (RECEIPT_PROGRAM_SIGNATURE_ALGORITHM = 'Ed25519') before
  // signing. A denied policy refuses issuance with a named
  // fips_policy_denied:<reason> -- it never signs anyway and never throws.
  // Left undefined (the default), issuance is BYTE-IDENTICAL to before this
  // option existed: the consult does not run, matching every other FIPS-mode
  // adoption in this repo (fips-mode.ts is consulted at call sites; nothing
  // is on by default).
  fipsPosture,
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
    // OPT-IN FIPS consult, only when a posture was configured at construction.
    // checkOperationPolicy never throws; a denied policy refuses issuance
    // BEFORE the signer is ever called, never a skipped check and never a
    // silent sign-anyway. With fipsPosture undefined this block does not run.
    if (fipsPosture !== undefined) {
      const policy = checkOperationPolicy(RECEIPT_PROGRAM_SIGNATURE_ALGORITHM, fipsPosture as FipsPosture);
      if (policy.permitted !== true) {
        return Object.freeze({
          ok: false,
          outcome: input.outcome,
          reason: `fips_policy_denied:${policy.reason}`,
          result: input.result,
          certificate: null,
          certificate_evidence: null,
        });
      }
    }
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

    return verifyCertificateBodyAfterSignature(
      snapshot,
      completeCertificate,
      signature.public_key,
      RECEIPT_PROGRAM_VERSION,
      {
        resolveCaid,
        expectedContext,
        certificateEvidence,
        verifyCertificateInclusion,
        requireAtomicCertificateEvidence,
      },
    );
  } catch {
    return verificationFailure('certificate_malformed');
  }
}

/**
 * ONE post-signature verification body for both certificate versions. The v1
 * and v2 verifiers differ only in the envelope they authenticate (flat
 * Ed25519 `signature` vs the hybrid signature SET) and in which receipt-program
 * profile marker the embedded program must carry. Everything after the
 * signature -- state root, context pin, time window, program binding, CAID
 * reperformance, opcode trace, result digest, evidence-reference linkage, and
 * the certificate-evidence inclusion check -- is this one body, so the two
 * cannot drift.
 */
function verifyCertificateBodyAfterSignature(
  snapshot: any,
  completeCertificate: any,
  signerPublicKey: string,
  programVersion: string,
  {
    resolveCaid = null,
    expectedContext = null,
    certificateEvidence = null,
    verifyCertificateInclusion = null,
    requireAtomicCertificateEvidence = false,
  }: any = {},
): any {
  try {
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
    if (!isRecord(program) || program['@version'] !== programVersion) {
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
      signer: signerPublicKey,
      evidence_complete: Boolean(authorization && (signed.outcome === 'refused' || execution)),
      certificate_persisted: certificatePersisted,
      caid_reperformed: executableProgram,
    });
  } catch {
    return verificationFailure('certificate_malformed');
  }
}

// ===========================================================================
// EP-RECEIPT-PROGRAM-v2 / EP-RECEIPT-PROGRAM-CERTIFICATE-v2
// the hybrid (Ed25519 + ML-DSA-65) execution certificate
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the receipt-program execution
 * certificate, and moves the PROGRAM marker with the certificate: an
 * EP-RECEIPT-PROGRAM-CERTIFICATE-v2 certificate freezes an
 * EP-RECEIPT-PROGRAM-v2 program.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, public_key,
 *    value}` becomes `signature: {profile, required_algorithms, public_key,
 *    key_id, pq_public_key, pq_key_id, signatures}`, a wire-format change, so
 *    the certificate takes a new `@version` (-v1 -> -v2) and the program it
 *    embeds takes one too, because the program's own `@version` is inside the
 *    signed core. verifyReceiptProgramCertificate above is UNCHANGED and
 *    refuses a v2 certificate at `certificate_version_invalid`, on the version
 *    marker, as its FIRST check -- before it reads the signature at all, and
 *    without crashing.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim. Ed25519 keeps its base64url SPKI DER
 *    public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (receiptProgramCertificateV2SigningBytes), alongside the core and its
 *    state root. Drop the ML-DSA leg and narrow the set to ["Ed25519"] and the
 *    surviving Ed25519 signature no longer verifies. Leave the set intact and
 *    the missing leg is a structural refusal. The verifier rebuilds the bytes
 *    from the REGISTERED set and from the core it independently recomputed.
 * 4. V1 COMPATIBILITY. verifyReceiptProgramCertificate stays SYNCHRONOUS and
 *    untouched, and createReceiptProgramKernel still mints v1 certificates
 *    with byte-identical behavior. verifyReceiptProgramCertificateV2 is a
 *    SEPARATE async entry point (ML-DSA verification is inherently async);
 *    verifyReceiptProgramCertificateStatement routes on `@version`. Everything
 *    after the signature check is ONE shared body
 *    (verifyCertificateBodyAfterSignature), so the two versions cannot drift
 *    on state root, context, program binding, CAID reperformance, opcode
 *    trace, evidence linkage, or inclusion.
 * 5. NAMED REFUSALS. Verification never throws on caller input; every failure
 *    is `{ok:false, reason}`. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable`, never a skipped check and never a pass on the
 *    classical leg.
 *
 * THE FIPS CONSULT, PRESERVED AND EXTENDED. The kernel's opt-in `fipsPosture`
 * consult (issueCertificate, above) is unchanged. The v2 issuer consults
 * checkOperationPolicy() for BOTH registered algorithms before the signer is
 * called. Under a posture that is not verifiably FIPS-inactive, ML-DSA-65's
 * policy is a REFUSAL unless the deployment explicitly acknowledges the
 * unvalidated implementation (`allowUnvalidatedMldsa: true`). Under a plainly
 * non-FIPS posture no acknowledgment is required. Left undefined, the consult
 * does not run.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: a verified certificate proves exact
 * certificate integrity under pinned operator keys. It does not prove an
 * external provider told the truth, and it does not replace verification of
 * the referenced receipt/capability artifacts. The ML-DSA-65 backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently
 * audited and not a FIPS validated module, and its secret key is
 * software-held: this profile does NOT satisfy a kms/hsm-only custody
 * requirement, and issuing under it is not a certification claim.
 */

export const RECEIPT_PROGRAM_V2_VERSION = 'EP-RECEIPT-PROGRAM-v2';
export const RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION = 'EP-RECEIPT-PROGRAM-CERTIFICATE-v2';
const RECEIPT_PROGRAM_CERTIFICATE_V2_DOMAIN = `${RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION}\0`;

/** The registered required algorithm set, in canonical order. */
export const RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const CERTIFICATE_V2_SIGNATURE_KEYS = [
  'profile', 'required_algorithms', 'public_key', 'key_id',
  'pq_public_key', 'pq_key_id', 'signatures',
] as const;

/** A v2 certificate signer pin: BOTH public halves, pinned out of band. */
export interface ReceiptProgramV2KeyPin {
  /** Ed25519 base64url SPKI DER. */
  public_key: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key: string;
}

/**
 * An injected hybrid signer. Structurally the `signSet()` contract of
 * lib/key-custody.ts's HybridCustodySigner: sign the SAME bytes under every
 * required algorithm, in canonical order. Accepted structurally rather than
 * imported because @emilia-protocol/gate does not depend on the app-tier lib/
 * tree; a HybridCustodySigner satisfies this shape as-is.
 */
export interface ReceiptProgramV2SignSetSigner {
  keyId: string;
  custody?: string;
  publicKeys: ReceiptProgramV2KeyPin;
  signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<
    Array<{ alg: string; sig: string; key_id?: string }>
  >;
}

function receiptV2AlgorithmSetRegistered(algorithms: any): boolean {
  return Array.isArray(algorithms)
    && algorithms.length === RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a: any, i: number) => a === RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS[i]);
}

/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function receiptPqKeyId(publicKeyRawB64u: any): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:receipt-program-key:ml-dsa-65:sha256:${sha256(raw)}`;
  } catch {
    return '';
  }
}

/**
 * The bytes BOTH legs sign: the certificate core plus its recomputed
 * state_root, under the v2 domain tag, plus the committed
 * `required_algorithms` set. Recomputed independently by the verifier from the
 * PRESENTED core and the REGISTERED set. See move 3 above.
 */
export function receiptProgramCertificateV2SigningBytes(
  signedCore: any,
  requiredAlgorithms: readonly string[] = RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!isRecord(signedCore)) throw new TypeError('receipt program certificate v2 signing body is invalid');
  if (!receiptV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('receiptProgramCertificateV2SigningBytes: algorithm set is not the registered EP-RECEIPT-PROGRAM-CERTIFICATE-v2 set');
  }
  return Buffer.from(
    RECEIPT_PROGRAM_CERTIFICATE_V2_DOMAIN
    + canonicalize({ ...signedCore, required_algorithms: [...requiredAlgorithms] }),
    'utf8',
  );
}

/**
 * Issue one hybrid execution certificate over an already assembled core. The
 * signer is either a local key pair (test/demo) or an injected signSet signer;
 * every returned signature set is verified against the configured public
 * halves before the certificate leaves this function.
 */
export async function issueReceiptProgramCertificateV2(
  input: any,
  {
    keys,
    signer,
    fipsPosture,
    allowUnvalidatedMldsa = false,
  }: {
    keys?: {
      ed: { privateKey: any; publicKey?: string };
      pq: { secretKey: Uint8Array | string; publicKey: string };
    };
    signer?: ReceiptProgramV2SignSetSigner;
    fipsPosture?: FipsPosture;
    allowUnvalidatedMldsa?: boolean;
  } = {},
): Promise<any> {
  const hasKeys = keys !== undefined;
  const hasSigner = signer !== undefined;
  if (hasKeys === hasSigner) {
    throw new TypeError('configure exactly one receipt program certificate v2 signer');
  }
  const core = certificateCore({
    ...input,
    certificateVersion: RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION,
  });
  if (Buffer.byteLength(canonicalize(core), 'utf8') > MAX_CERTIFICATE_CORE_BYTES) {
    throw new Error('receipt program certificate exceeds byte limit');
  }
  const requiredAlgorithms = [...RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS];
  const signed = { ...core, state_root: canonicalDigest(core) };
  const signedBytes = receiptProgramCertificateV2SigningBytes(signed, requiredAlgorithms);

  // OPT-IN FIPS consult, BOTH algorithms, BEFORE the signer is called.
  if (fipsPosture !== undefined) {
    for (const alg of requiredAlgorithms) {
      const policy = checkOperationPolicy(alg, fipsPosture, {
        allow_unvalidated_mldsa: allowUnvalidatedMldsa === true,
      });
      if (policy.permitted !== true) {
        throw new Error(`receipt program certificate v2 issuance refused: fips_policy_denied:${alg}:${policy.reason}`);
      }
    }
  }

  let signatures: AgileSignature[];
  let publicKeys: ReceiptProgramV2KeyPin;
  let keyId: string;
  if (hasKeys) {
    if (!keys!.ed?.privateKey || !keys!.pq?.secretKey || typeof keys!.pq?.publicKey !== 'string') {
      throw new TypeError('receipt program certificate v2 keys require ed.privateKey, pq.secretKey, and pq.publicKey');
    }
    const edKey = keyObject(keys!.ed.privateKey, 'keys.ed.privateKey');
    const signingKeys: AgileSigningKey[] = [
      { alg: 'Ed25519', private_key: edKey },
      { alg: 'ML-DSA-65', private_key: keys!.pq.secretKey },
    ];
    signatures = await signAgileSet(new Uint8Array(signedBytes), signingKeys);
    publicKeys = {
      public_key: keys!.ed.publicKey ?? publicKeyB64u(edKey),
      pq_public_key: keys!.pq.publicKey,
    };
    keyId = core.context?.key_id;
  } else {
    if (!isDataRecord(signer) || typeof signer!.signSet !== 'function'
        || !isRecord(signer!.publicKeys)
        || typeof signer!.publicKeys.public_key !== 'string'
        || typeof signer!.publicKeys.pq_public_key !== 'string'
        || typeof signer!.keyId !== 'string') {
      throw new TypeError('receipt program certificate v2 signer requires keyId, publicKeys { public_key, pq_public_key }, and signSet(bytes)');
    }
    const set = await signer!.signSet(signedBytes, { profile: RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION });
    if (!Array.isArray(set)
        || !requiredAlgorithms.every((alg, index) => set[index]?.alg === alg
          && typeof set[index]?.sig === 'string')) {
      throw new Error('receipt program certificate v2 signer returned a malformed signature set');
    }
    signatures = set.map((entry) => ({ alg: entry.alg, sig: entry.sig }));
    publicKeys = {
      public_key: signer!.publicKeys.public_key,
      pq_public_key: signer!.publicKeys.pq_public_key,
    };
    keyId = signer!.keyId;
  }

  publicKeyObject(publicKeys.public_key);
  const pqKeyId = receiptPqKeyId(publicKeys.pq_public_key);
  if (!pqKeyId) throw new TypeError('receipt program certificate v2 ML-DSA-65 public key must be raw base64url bytes');
  if (keyId !== core.context?.key_id) {
    throw new Error('receipt program certificate v2 context.key_id must equal the configured signer keyId');
  }

  const certificate = deepFreeze({
    ...signed,
    signature: {
      profile: RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      public_key: publicKeys.public_key,
      key_id: keyId,
      pq_public_key: publicKeys.pq_public_key,
      pq_key_id: pqKeyId,
      signatures,
    },
  });
  const selfCheck = await verifyReceiptProgramCertificateV2(certificate, {
    trustedCertificateKeys: { [keyId]: publicKeys },
    expectedContext: core.context,
    resolveCaid: input?.resolveCaid ?? null,
  });
  // The self-check re-runs the full verifier over the bytes just produced. The
  // one reason it may legitimately report is certificate_caid_resolver_required:
  // CAID reperformance is a RELYING-PARTY input (an issuer re-resolving its own
  // CAID would prove nothing), so an issuer that did not hand one in gets the
  // structural checks only. Every other refusal is an issuance failure.
  if (selfCheck.ok !== true && selfCheck.reason !== 'certificate_caid_resolver_required') {
    throw new Error(`receipt program certificate v2 self-verification failed: ${selfCheck.reason}`);
  }
  return certificate;
}

/**
 * FAIL-CLOSED hybrid certificate verifier. Never throws on caller input; a v2
 * certificate NEVER verifies on one leg alone. Everything after the signature
 * is the same body the v1 verifier runs.
 */
export async function verifyReceiptProgramCertificateV2(certificate: any, {
  trustedCertificateKeys = {},
  resolveCaid = null,
  expectedContext = null,
  certificateEvidence = null,
  verifyCertificateInclusion = null,
  requireAtomicCertificateEvidence = false,
  mldsaBackend,
  mldsaBackendLoader,
}: any = {}): Promise<any> {
  try {
    // 1. Version marker FIRST, exactly as v1 does. A v1 certificate refuses
    //    here, the mirror image of the v1 verifier refusing a v2 certificate.
    const versionDescriptor = isDataRecord(certificate)
      ? Object.getOwnPropertyDescriptor(certificate, '@version') : null;
    if (versionDescriptor?.value !== RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION) {
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
    if (!hasExactKeys(signature, CERTIFICATE_V2_SIGNATURE_KEYS as unknown as string[])
        || signature.profile !== RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION
        || typeof signature.public_key !== 'string'
        || typeof signature.pq_public_key !== 'string'
        || typeof signature.key_id !== 'string'
        || typeof signature.pq_key_id !== 'string') {
      return verificationFailure('certificate_signature_invalid');
    }

    // 2. Committed algorithm set: exact and order-sensitive. A narrowed set is
    //    the stripping attack's cover story, refused structurally here and
    //    (independently) by the signature check, which rebuilds the bytes from
    //    the REGISTERED set regardless of what the certificate claims.
    if (!receiptV2AlgorithmSetRegistered(signature.required_algorithms)) {
      return verificationFailure('certificate_algorithm_set_unsupported');
    }

    // 3. Exactly one signature per required algorithm.
    const signatures = Array.isArray(signature.signatures) ? signature.signatures : null;
    if (!signatures) return verificationFailure('certificate_signature_set_invalid');
    const presented = new Set<string>();
    for (const entry of signatures) {
      if (!isRecord(entry) || typeof entry.alg !== 'string' || typeof entry.sig !== 'string') {
        return verificationFailure('certificate_signature_set_invalid');
      }
      if (presented.has(entry.alg)) return verificationFailure('certificate_signature_set_invalid');
      presented.add(entry.alg);
    }
    for (const alg of RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return verificationFailure('certificate_signature_leg_missing');
    }
    for (const alg of presented) {
      if (!(RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return verificationFailure('certificate_signature_set_invalid');
      }
    }

    // 4. Signer keys: BOTH halves pinned, and the presented halves must equal
    //    the pinned ones. Identified-but-not-trusted, per leg: a key id pinned
    //    for v1 only (a bare Ed25519 SPKI string) does NOT satisfy a v2 pin.
    const claimedKeyId = snapshot.context?.key_id;
    const pin = isDataRecord(trustedCertificateKeys) && typeof claimedKeyId === 'string'
      ? trustedCertificateKeys[claimedKeyId] : null;
    if (!isRecord(pin)
        || typeof pin.public_key !== 'string' || typeof pin.pq_public_key !== 'string'
        || pin.public_key !== signature.public_key
        || pin.pq_public_key !== signature.pq_public_key
        || signature.key_id !== claimedKeyId
        || receiptPqKeyId(pin.pq_public_key) === ''
        || signature.pq_key_id !== receiptPqKeyId(pin.pq_public_key)) {
      return verificationFailure('certificate_signer_not_trusted');
    }
    // Curve-pinned: a non-Ed25519 SPKI presented as the classical half fails
    // here as well as in the signature check.
    try { publicKeyObject(pin.public_key); } catch {
      return verificationFailure('certificate_signer_not_trusted');
    }

    // 5. Signature set over bytes rebuilt from the PRESENTED core and the
    //    REGISTERED algorithm set, under the PINNED keys. Never fall back to
    //    the certificate's own self-asserted key material.
    delete snapshot.signature;
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(receiptProgramCertificateV2SigningBytes(
          snapshot, RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS,
        )),
        signatures,
        [
          { alg: 'Ed25519', public_key: pin.public_key },
          { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
        ],
        {
          ...(mldsaBackend === undefined ? {} : { mldsaBackend }),
          ...(mldsaBackendLoader === undefined ? {} : { mldsaBackendLoader }),
          policy: 'hybrid_all',
          requiredAlgorithms: [...RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      // verifyAgileSignatureSet documents that it never throws; an injected
      // backend that does is still a refusal here, never a pass.
      setResult = null;
    }
    if (setResult?.verified !== true) {
      return verificationFailure(
        `certificate_signature_invalid:${String(setResult?.reason ?? 'signature_set_unverified')}`,
      );
    }

    return verifyCertificateBodyAfterSignature(
      snapshot,
      completeCertificate,
      signature.public_key,
      RECEIPT_PROGRAM_V2_VERSION,
      {
        resolveCaid,
        expectedContext,
        certificateEvidence,
        verifyCertificateInclusion,
        requireAtomicCertificateEvidence,
      },
    );
  } catch {
    return verificationFailure('certificate_malformed');
  }
}

/**
 * Route a certificate of EITHER version to its verifier. v1 certificates keep
 * the exact v1 verdict; v2 certificates get the hybrid check. A certificate
 * whose `@version` is neither refuses through the v1 verifier, which is the
 * fail-closed answer.
 */
export async function verifyReceiptProgramCertificateStatement(
  certificate: any,
  options: any = {},
): Promise<any> {
  if (isDataRecord(certificate)
      && Object.getOwnPropertyDescriptor(certificate, '@version')?.value
        === RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION) {
    return verifyReceiptProgramCertificateV2(certificate, options);
  }
  return verifyReceiptProgramCertificate(certificate, options);
}

export default {
  RECEIPT_PROGRAM_VERSION,
  RECEIPT_PROGRAM_CERTIFICATE_VERSION,
  RECEIPT_PROGRAM_SIGNATURE_ALGORITHM,
  RECEIPT_PROGRAM_V2_VERSION,
  RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION,
  RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS,
  createReceiptProgramKernel,
  verifyReceiptProgramCertificate,
  receiptProgramCertificateV2SigningBytes,
  issueReceiptProgramCertificateV2,
  verifyReceiptProgramCertificateV2,
  verifyReceiptProgramCertificateStatement,
};
