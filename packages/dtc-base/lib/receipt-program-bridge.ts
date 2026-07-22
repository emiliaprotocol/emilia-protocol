// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

import {
  Contract,
  ethers,
  type ContractRunner,
  type TypedDataDomain,
  type TypedDataField,
} from 'ethers';

export type JsonObject = Record<string, unknown>;
type Awaitable<T> = T | Promise<T>;

export interface TypedDataSigner extends ContractRunner {
  getAddress(): Promise<string>;
  signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, unknown>,
  ): Promise<string>;
}

export interface ReceiptProgramRequest extends JsonObject {
  programId?: unknown;
  instructionId?: unknown;
  caid?: unknown;
  selector?: JsonObject;
  observedAction?: unknown;
  receipt?: unknown;
  capability?: {
    operationId?: unknown;
    capabilityReceipt?: JsonObject;
    action?: unknown;
    [key: string]: unknown;
  };
}

export interface GateAuthorization extends JsonObject {
  allow?: boolean;
}

export interface GateOperation extends JsonObject {
  operationId?: string;
  actionDigest?: string;
  providerIdempotencyKey?: string;
}

export interface ReceiptProgram extends JsonObject {
  '@version': string;
  program_id: unknown;
  instruction_id: unknown;
  operation_id: string;
  operation_id_field: string;
  caid: string;
  action_digest: string;
  capability_receipt_digest: string;
  capability_projection: unknown;
  selector: JsonObject;
  observed_action: unknown;
}

export interface CompiledReceiptProgram {
  readonly program: Readonly<ReceiptProgram>;
  readonly programDigest: string;
  readonly receiptHash: string;
  readonly caidHash: string;
  readonly actionHash: string;
  readonly programHash: string;
  readonly inputHash: string;
}

export interface BridgeContext {
  authorization: GateAuthorization;
  operation: GateOperation;
  compiled: CompiledReceiptProgram;
}

export interface AuthorizationContext extends BridgeContext {
  program: ReceiptProgram;
  programDigest: string;
}

export interface SettlementAmountContext<T extends JsonObject> extends BridgeContext {
  result: T;
}

export interface DtcBaseEvidence {
  readonly operation_id: string;
  readonly program_hash: string;
  readonly invocation_hash: string;
  readonly provider_request_id: string;
  readonly evidence_hash: string;
  readonly certificate_hash: string;
}

export type DtcBoundResult<T extends JsonObject> = T & {
  readonly dtc_base: DtcBaseEvidence;
};

export interface ReceiptProgramBaseBridgeOptions {
  contract?: Contract;
  bridgeSigner?: TypedDataSigner;
  payerSigner?: TypedDataSigner;
  executorSigner?: TypedDataSigner;
  providerSigner?: TypedDataSigner;
  merchant?: string;
  operationIdField?: string;
  assertGateAuthorization?: (context: AuthorizationContext) => Awaitable<boolean>;
  nextNonce?: (context: BridgeContext) => Awaitable<unknown>;
  expiresAt?: (context: BridgeContext) => Awaitable<unknown>;
  maxAmount?: (context: BridgeContext) => Awaitable<unknown>;
  settledAmount?: <T extends JsonObject>(context: SettlementAmountContext<T>) => Awaitable<unknown>;
  now?: () => Awaitable<unknown>;
}

export interface ReceiptProgramBaseBridge {
  readonly addresses: Readonly<{
    bridge: string;
    payer: string;
    executor: string;
    provider: string;
    merchant: string;
  }>;
  readonly domain: Readonly<TypedDataDomain>;
  wrap<T extends JsonObject>(
    request: ReceiptProgramRequest,
    effect: (authorization: GateAuthorization, operation: GateOperation) => Awaitable<T>,
  ): (
    authorization: GateAuthorization,
    operation: GateOperation,
  ) => Promise<DtcBoundResult<T>>;
}

interface Invocation extends JsonObject {
  operationId: string;
  invocationHash: string;
  providerRequestId: string;
  observedAt: bigint;
}

interface BridgeError extends Error {
  dtcSettlementError?: unknown;
  dtcCancellationError?: unknown;
}

interface SettlementTransaction {
  wait(): Promise<unknown>;
}

interface SettlementOperationState {
  status: bigint;
  certificateHash: string;
}

export type DtcBaseSettlementContract = Contract & {
  setProviderSigner(merchant: string, signer: string): Promise<SettlementTransaction>;
  hashAuthorization(value: JsonObject): Promise<string>;
  reserve(
    authorization: JsonObject,
    signature: string,
    overrides: { value: bigint },
  ): Promise<SettlementTransaction>;
  markInvoked(invocation: JsonObject, signature: string): Promise<SettlementTransaction>;
  providerBindings(merchant: string): Promise<{ signer: string; version: unknown }>;
  submitOutcome(outcome: JsonObject, signature: string): Promise<SettlementTransaction>;
  reconcile(outcome: JsonObject, signature: string): Promise<SettlementTransaction>;
  cancelBeforeInvocation(operationId: string): Promise<SettlementTransaction>;
  getOperation(operationId: string): Promise<SettlementOperationState>;
  totalLocked(): Promise<bigint>;
  totalClaimable(): Promise<bigint>;
  claimable(account: string): Promise<bigint>;
  hashOutcome(outcome: JsonObject): Promise<string>;
  DEFAULT_ADMIN_ROLE(): Promise<string>;
  AUTHORIZATION_SIGNER_ROLE(): Promise<string>;
  hasRole(role: string, account: string): Promise<boolean>;
};

export function asDtcBaseSettlementContract(value: unknown): DtcBaseSettlementContract {
  return value as DtcBaseSettlementContract;
}

export function connectDtcBaseSettlementContract(
  settlement: DtcBaseSettlementContract,
  runner: unknown,
): DtcBaseSettlementContract {
  return asDtcBaseSettlementContract(settlement.connect(runner as ContractRunner));
}

type Canonicalize = (value: unknown) => string;
const gateBindingModule = await import(
  new URL('../../../gate/execution-binding.js', import.meta.url).href
) as { canonicalize: Canonicalize };
const { canonicalize } = gateBindingModule;

const AUTHORIZATION_FIELDS: TypedDataField[] = [
    { name: 'receiptHash', type: 'bytes32' },
    { name: 'caid', type: 'bytes32' },
    { name: 'actionHash', type: 'bytes32' },
    { name: 'programHash', type: 'bytes32' },
    { name: 'inputHash', type: 'bytes32' },
    { name: 'payer', type: 'address' },
    { name: 'executor', type: 'address' },
    { name: 'merchant', type: 'address' },
    { name: 'authorizationSigner', type: 'address' },
    { name: 'providerSigner', type: 'address' },
    { name: 'maxAmount', type: 'uint256' },
    { name: 'expiresAt', type: 'uint64' },
    { name: 'providerConfigVersion', type: 'uint64' },
    { name: 'nonce', type: 'uint256' },
];
Object.freeze(AUTHORIZATION_FIELDS);
export const AUTHORIZATION_TYPES: Record<string, TypedDataField[]> = Object.freeze({
  Authorization: AUTHORIZATION_FIELDS,
});

const INVOCATION_FIELDS: TypedDataField[] = [
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'observedAt', type: 'uint64' },
];
Object.freeze(INVOCATION_FIELDS);
export const INVOCATION_TYPES: Record<string, TypedDataField[]> = Object.freeze({
  Invocation: INVOCATION_FIELDS,
});

const OUTCOME_FIELDS: TypedDataField[] = [
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'evidenceHash', type: 'bytes32' },
    { name: 'priorOutcomeDigest', type: 'bytes32' },
    { name: 'amount', type: 'uint256' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'kind', type: 'uint8' },
];
Object.freeze(OUTCOME_FIELDS);
export const OUTCOME_TYPES: Record<string, TypedDataField[]> = Object.freeze({
  Outcome: OUTCOME_FIELDS,
});

const RECEIPT_PROGRAM_VERSION = 'EP-RECEIPT-PROGRAM-v1';
const UINT64_MAX = (1n << 64n) - 1n;

function sha256Bytes(value: Uint8Array): string {
  return `0x${createHash('sha256').update(value).digest('hex')}`;
}

function canonicalHash(value: unknown): string {
  return sha256Bytes(Buffer.from(canonicalize(value), 'utf8'));
}

function utf8Hash(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('value must be a non-empty string');
  }
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

function valueAtPath(value: unknown, path: string): unknown {
  let current = value;
  for (const segment of path.split('.')) {
    if (!current || typeof current !== 'object' || !Object.hasOwn(current, segment)) return undefined;
    current = (current as JsonObject)[segment];
  }
  return current;
}

function normalizeDigest(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (/^sha256:[0-9a-f]{64}$/.test(value)) return `0x${value.slice(7)}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(value)) return value.toLowerCase();
  if (/^[0-9a-fA-F]{64}$/.test(value)) return `0x${value.toLowerCase()}`;
  return null;
}

function asUint(
  value: unknown,
  label: string,
  { nonzero = false, max = null }: { nonzero?: boolean; max?: bigint | null } = {},
): bigint {
  let result: bigint;
  try {
    result = BigInt(value as string | number | bigint | boolean);
  } catch {
    throw new TypeError(`${label} must be an integer`);
  }
  if (result < 0n || (nonzero && result === 0n) || (max !== null && result > max)) {
    throw new RangeError(`${label} is out of range`);
  }
  return result;
}

function requireSigner(value: unknown, label: string): TypedDataSigner {
  if (!value || typeof value !== 'object') {
    throw new TypeError(`${label} must be an ethers signer with signTypedData`);
  }
  const candidate = value as Partial<TypedDataSigner>;
  if (typeof candidate.getAddress !== 'function' || typeof candidate.signTypedData !== 'function') {
    throw new TypeError(`${label} must be an ethers signer with signTypedData`);
  }
  return value as TypedDataSigner;
}

async function signerAddress(signer: TypedDataSigner, label: string): Promise<string> {
  try {
    return ethers.getAddress(await signer.getAddress());
  } catch (error) {
    throw new TypeError(`${label} must expose a valid EVM address`, { cause: error });
  }
}

function requireCallback<T>(value: T | undefined, name: string): T {
  if (typeof value !== 'function') throw new TypeError(`${name} must be constructor-pinned`);
  return value;
}

function bridgeError(value: unknown): BridgeError {
  if (value instanceof Error) return value as BridgeError;
  return new Error('DTC bridge failed with a non-Error value', { cause: value });
}

export function compileReceiptProgram(
  request: ReceiptProgramRequest,
  operationIdField: string,
): CompiledReceiptProgram {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('receipt-program request must be an object');
  }
  if (typeof operationIdField !== 'string' || operationIdField.length === 0) {
    throw new TypeError('operationIdField must be a non-empty string');
  }
  const operationId = request.capability?.operationId;
  if (typeof operationId !== 'string' || operationId.length === 0) {
    throw new TypeError('request capability operationId is required');
  }
  if (typeof request.caid !== 'string' || request.caid.length === 0) {
    throw new TypeError('request caid is required');
  }

  const observedAction = structuredClone(request.observedAction);
  const selector = structuredClone(request.selector ?? {});
  const capabilityReceipt = structuredClone(request.capability?.capabilityReceipt);
  const capabilityProjection = structuredClone(request.capability?.action);
  if (valueAtPath(observedAction, operationIdField) !== operationId) {
    throw new Error('receipt-program operation binding failed');
  }

  const program: ReceiptProgram = {
    '@version': RECEIPT_PROGRAM_VERSION,
    program_id: request.programId,
    instruction_id: request.instructionId,
    operation_id: operationId,
    operation_id_field: operationIdField,
    caid: request.caid,
    action_digest: `sha256:${canonicalHash(observedAction).slice(2)}`,
    capability_receipt_digest: `sha256:${canonicalHash(capabilityReceipt).slice(2)}`,
    capability_projection: capabilityProjection,
    selector,
    observed_action: observedAction,
  };
  const programHash = canonicalHash(program);
  const receipt = request.receipt ?? request.capability?.capabilityReceipt?.receipt;
  if (!receipt) throw new Error('DTC bridge requires the exact base receipt');
  const actionHash = normalizeDigest(program.action_digest);
  if (actionHash === null) throw new Error('DTC bridge produced an invalid action digest');

  return Object.freeze({
    program: Object.freeze(program),
    programDigest: `sha256:${programHash.slice(2)}`,
    receiptHash: canonicalHash(receipt),
    caidHash: utf8Hash(request.caid),
    actionHash,
    programHash,
    inputHash: canonicalHash({
      selector,
      capability_projection: capabilityProjection,
      observed_action: observedAction,
    }),
  });
}

/**
 * Construct an experimental receipt-program -> Base effect adapter.
 *
 * The adapter is fail-closed and constructor-pins every trust callback. It is
 * still a two-ledger saga: EMILIA's capability reservation and the Base
 * reservation are not one atomic transaction. Production use requires an
 * outbox/recovery design and an independently reviewed custody model.
 */
export async function createReceiptProgramBaseBridge(
  options: ReceiptProgramBaseBridgeOptions = {},
): Promise<ReceiptProgramBaseBridge> {
  const { contract } = options;
  if (!contract || typeof contract.hashAuthorization !== 'function') {
    throw new TypeError('contract must be a DTCBaseSettlement ethers contract');
  }
  const settlement = asDtcBaseSettlementContract(contract);

  const assertGateAuthorization = requireCallback(
    options.assertGateAuthorization,
    'assertGateAuthorization',
  );
  const nextNonce = requireCallback(options.nextNonce, 'nextNonce');
  const expiresAt = requireCallback(options.expiresAt, 'expiresAt');
  const maxAmount = requireCallback(options.maxAmount, 'maxAmount');
  const settledAmount = requireCallback(options.settledAmount, 'settledAmount');
  const now = requireCallback(
    options.now ?? (async () => BigInt(Math.floor(Date.now() / 1000))),
    'now',
  );

  const bridgeSigner = requireSigner(options.bridgeSigner, 'bridgeSigner');
  const payerSigner = requireSigner(options.payerSigner, 'payerSigner');
  const executorSigner = requireSigner(options.executorSigner, 'executorSigner');
  const providerSigner = requireSigner(options.providerSigner, 'providerSigner');
  const addresses = Object.freeze({
    bridge: await signerAddress(bridgeSigner, 'bridgeSigner'),
    payer: await signerAddress(payerSigner, 'payerSigner'),
    executor: await signerAddress(executorSigner, 'executorSigner'),
    provider: await signerAddress(providerSigner, 'providerSigner'),
    merchant: ethers.getAddress(options.merchant as string),
  });
  const provider = settlement.runner?.provider;
  if (!provider) throw new TypeError('contract must have a connected provider');
  const network = await provider.getNetwork();
  const domain = Object.freeze({
    name: 'EMILIA DTC Base Settlement',
    version: '2',
    chainId: network.chainId,
    verifyingContract: await settlement.getAddress(),
  });

  function wrap<T extends JsonObject>(
    request: ReceiptProgramRequest,
    effect: (authorization: GateAuthorization, operation: GateOperation) => Awaitable<T>,
  ): (
    authorization: GateAuthorization,
    operation: GateOperation,
  ) => Promise<DtcBoundResult<T>> {
    if (typeof effect !== 'function') throw new TypeError('effect must be a function');
    const compiled = compileReceiptProgram(request, options.operationIdField as string);

    return async function dtcBoundEffect(
      authorization: GateAuthorization,
      operation: GateOperation,
    ): Promise<DtcBoundResult<T>> {
      const authorizationAccepted = await assertGateAuthorization({
        authorization: structuredClone(authorization),
        operation: structuredClone(operation),
        compiled,
        program: structuredClone(compiled.program),
        programDigest: compiled.programDigest,
      });
      if (authorizationAccepted !== true || authorization?.allow !== true) {
        throw new Error('DTC bridge refused unverified Gate authorization');
      }
      if (operation?.operationId !== compiled.program.operation_id) {
        throw new Error('DTC bridge operation ID mismatch');
      }
      if (normalizeDigest(operation?.actionDigest) !== compiled.actionHash) {
        throw new Error('DTC bridge action digest mismatch');
      }

      const binding = await settlement.providerBindings(addresses.merchant);
      if (ethers.getAddress(binding.signer) !== addresses.provider) {
        throw new Error('DTC bridge provider signer does not match the live merchant binding');
      }
      const providerConfigVersion = asUint(binding.version, 'providerConfigVersion', {
        nonzero: true,
        max: UINT64_MAX,
      });
      const context: BridgeContext = { authorization, operation, compiled };
      const nonce = asUint(await nextNonce(context), 'nonce', { nonzero: true });
      const expiry = asUint(await expiresAt(context), 'expiresAt', {
        nonzero: true,
        max: UINT64_MAX,
      });
      const reservationAmount = asUint(await maxAmount(context), 'maxAmount', { nonzero: true });
      const observedNow = asUint(await now(), 'now', { nonzero: true, max: UINT64_MAX });
      if (expiry <= observedNow) throw new Error('DTC bridge expiry must be in the future');

      const baseAuthorization = {
        receiptHash: compiled.receiptHash,
        caid: compiled.caidHash,
        actionHash: compiled.actionHash,
        programHash: compiled.programHash,
        inputHash: compiled.inputHash,
        payer: addresses.payer,
        executor: addresses.executor,
        merchant: addresses.merchant,
        authorizationSigner: addresses.bridge,
        providerSigner: addresses.provider,
        maxAmount: reservationAmount,
        expiresAt: expiry,
        providerConfigVersion,
        nonce,
      };
      const authorizationSignature = await bridgeSigner.signTypedData(
        domain,
        AUTHORIZATION_TYPES,
        baseAuthorization,
      );
      const onchainOperationId = await settlement.hashAuthorization(baseAuthorization);
      let reserved = false;
      let boundaryEntered = false;
      let invocation: Invocation | null = null;

      try {
        const payerContract = connectDtcBaseSettlementContract(settlement, payerSigner);
        await (await payerContract.reserve(baseAuthorization, authorizationSignature, {
          value: reservationAmount,
        })).wait();
        reserved = true;

        invocation = {
          operationId: onchainOperationId,
          invocationHash: canonicalHash({
            operation_id: operation.operationId,
            provider_idempotency_key: operation.providerIdempotencyKey,
            action_digest: compiled.program.action_digest,
            program_digest: compiled.programDigest,
          }),
          providerRequestId: utf8Hash(operation.providerIdempotencyKey),
          observedAt: asUint(await now(), 'invocation observedAt', { nonzero: true, max: UINT64_MAX }),
        };
        const invocationSignature = await providerSigner.signTypedData(
          domain,
          INVOCATION_TYPES,
          invocation,
        );
        const executorContract = connectDtcBaseSettlementContract(settlement, executorSigner);
        await (await executorContract.markInvoked(invocation, invocationSignature)).wait();
        boundaryEntered = true;

        const result = await effect(authorization, operation);
        const terminalAmount = asUint(
          await settledAmount({ result, authorization, operation, compiled }),
          'settledAmount',
          { nonzero: true },
        );
        if (terminalAmount > reservationAmount) throw new Error('settledAmount exceeds maxAmount');
        const outcome = {
          operationId: onchainOperationId,
          invocationHash: invocation.invocationHash,
          providerRequestId: invocation.providerRequestId,
          evidenceHash: canonicalHash(result),
          priorOutcomeDigest: ethers.ZeroHash,
          amount: terminalAmount,
          observedAt: asUint(await now(), 'outcome observedAt', { nonzero: true, max: UINT64_MAX }),
          kind: 1,
        };
        await (await settlement.submitOutcome(
          outcome,
          await providerSigner.signTypedData(domain, OUTCOME_TYPES, outcome),
        )).wait();
        const operationState = await settlement.getOperation(onchainOperationId);

        return Object.freeze({
          ...structuredClone(result),
          dtc_base: Object.freeze({
            operation_id: onchainOperationId,
            program_hash: compiled.programHash,
            invocation_hash: invocation.invocationHash,
            provider_request_id: invocation.providerRequestId,
            evidence_hash: outcome.evidenceHash,
            certificate_hash: operationState.certificateHash,
          }),
        }) as DtcBoundResult<T>;
      } catch (caught) {
        const error = bridgeError(caught);
        if (boundaryEntered && invocation !== null) {
          const uncertain = {
            operationId: onchainOperationId,
            invocationHash: invocation.invocationHash,
            providerRequestId: invocation.providerRequestId,
            evidenceHash: canonicalHash({
              '@type': 'EP-DTC-PROVIDER-UNCERTAINTY-v1',
              operation_id: operation.operationId,
              provider_request_id: operation.providerIdempotencyKey,
              reason: 'provider_response_unavailable',
            }),
            priorOutcomeDigest: ethers.ZeroHash,
            amount: 0n,
            observedAt: asUint(await now(), 'indeterminate observedAt', {
              nonzero: true,
              max: UINT64_MAX,
            }),
            kind: 3,
          };
          try {
            await (await settlement.submitOutcome(
              uncertain,
              await providerSigner.signTypedData(domain, OUTCOME_TYPES, uncertain),
            )).wait();
          } catch (settlementError) {
            error.dtcSettlementError = settlementError;
          }
        } else if (reserved) {
          try {
            const payerContract = connectDtcBaseSettlementContract(settlement, payerSigner);
            await (await payerContract.cancelBeforeInvocation(onchainOperationId)).wait();
          } catch (cancellationError) {
            error.dtcCancellationError = cancellationError;
          }
        }
        throw error;
      }
    };
  }

  return Object.freeze({ addresses, domain, wrap });
}
