// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { ethers } from 'ethers';

import { canonicalize } from '../../gate/execution-binding.js';

export const AUTHORIZATION_TYPES = Object.freeze({
  Authorization: Object.freeze([
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
  ]),
});

export const INVOCATION_TYPES = Object.freeze({
  Invocation: Object.freeze([
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'observedAt', type: 'uint64' },
  ]),
});

export const OUTCOME_TYPES = Object.freeze({
  Outcome: Object.freeze([
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'evidenceHash', type: 'bytes32' },
    { name: 'priorOutcomeDigest', type: 'bytes32' },
    { name: 'amount', type: 'uint256' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'kind', type: 'uint8' },
  ]),
});

const RECEIPT_PROGRAM_VERSION = 'EP-RECEIPT-PROGRAM-v1';
const UINT64_MAX = (1n << 64n) - 1n;

function sha256Bytes(value) {
  return `0x${createHash('sha256').update(value).digest('hex')}`;
}

function canonicalHash(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), 'utf8'));
}

function utf8Hash(value) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError('value must be a non-empty string');
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

function valueAtPath(value, path) {
  let current = value;
  for (const segment of path.split('.')) {
    if (!current || typeof current !== 'object' || !Object.hasOwn(current, segment)) return undefined;
    current = current[segment];
  }
  return current;
}

function normalizeDigest(value) {
  if (typeof value !== 'string') return null;
  if (/^sha256:[0-9a-f]{64}$/.test(value)) return `0x${value.slice(7)}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(value)) return value.toLowerCase();
  if (/^[0-9a-fA-F]{64}$/.test(value)) return `0x${value.toLowerCase()}`;
  return null;
}

function asUint(value, label, { nonzero = false, max = null } = {}) {
  let result;
  try { result = BigInt(value); } catch { throw new TypeError(`${label} must be an integer`); }
  if (result < 0n || (nonzero && result === 0n) || (max !== null && result > max)) {
    throw new RangeError(`${label} is out of range`);
  }
  return result;
}

async function signerAddress(signer, label) {
  if (!signer || typeof signer.getAddress !== 'function' || typeof signer.signTypedData !== 'function') {
    throw new TypeError(`${label} must be an ethers signer with signTypedData`);
  }
  return ethers.getAddress(await signer.getAddress());
}

export function compileReceiptProgram(request, operationIdField) {
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
  const observedAction = structuredClone(request.observedAction);
  const selector = structuredClone(request.selector ?? {});
  const capabilityReceipt = structuredClone(request.capability?.capabilityReceipt);
  const capabilityProjection = structuredClone(request.capability?.action);
  if (valueAtPath(observedAction, operationIdField) !== operationId) {
    throw new Error('receipt-program operation binding failed');
  }

  const program = {
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

  return Object.freeze({
    program: Object.freeze(program),
    programDigest: `sha256:${programHash.slice(2)}`,
    receiptHash: canonicalHash(receipt),
    caidHash: utf8Hash(request.caid),
    actionHash: normalizeDigest(program.action_digest),
    programHash,
    inputHash: canonicalHash({
      selector,
      capability_projection: capabilityProjection,
      observed_action: observedAction,
    }),
  });
}

/**
 * Construct a private receipt-program -> Base effect adapter.
 *
 * The adapter is fail-closed and constructor-pins every trust callback. It is
 * still a two-ledger saga: EMILIA's capability reservation and the Base
 * reservation are not one atomic transaction. Production use requires an
 * outbox/recovery design and an independently reviewed custody model.
 */
export async function createReceiptProgramBaseBridge({
  contract,
  bridgeSigner,
  payerSigner,
  executorSigner,
  providerSigner,
  merchant,
  operationIdField,
  assertGateAuthorization,
  nextNonce,
  expiresAt,
  maxAmount,
  settledAmount,
  now = async () => BigInt(Math.floor(Date.now() / 1000)),
} = {}) {
  if (!contract || typeof contract.hashAuthorization !== 'function') {
    throw new TypeError('contract must be a DTCBaseSettlement ethers contract');
  }
  for (const [name, callback] of Object.entries({
    assertGateAuthorization,
    nextNonce,
    expiresAt,
    maxAmount,
    settledAmount,
    now,
  })) {
    if (typeof callback !== 'function') throw new TypeError(`${name} must be constructor-pinned`);
  }
  const addresses = Object.freeze({
    bridge: await signerAddress(bridgeSigner, 'bridgeSigner'),
    payer: await signerAddress(payerSigner, 'payerSigner'),
    executor: await signerAddress(executorSigner, 'executorSigner'),
    provider: await signerAddress(providerSigner, 'providerSigner'),
    merchant: ethers.getAddress(merchant),
  });
  const network = await contract.runner.provider.getNetwork();
  const domain = Object.freeze({
    name: 'EMILIA DTC Base Settlement',
    version: '2',
    chainId: network.chainId,
    verifyingContract: await contract.getAddress(),
  });

  function wrap(request, effect) {
    if (typeof effect !== 'function') throw new TypeError('effect must be a function');
    const compiled = compileReceiptProgram(request, operationIdField);

    return async function dtcBoundEffect(authorization, operation) {
      const authorizationAccepted = await assertGateAuthorization({
        authorization: structuredClone(authorization),
        operation: structuredClone(operation),
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

      const binding = await contract.providerBindings(addresses.merchant);
      if (ethers.getAddress(binding.signer) !== addresses.provider) {
        throw new Error('DTC bridge provider signer does not match the live merchant binding');
      }
      const providerConfigVersion = asUint(binding.version, 'providerConfigVersion', {
        nonzero: true,
        max: UINT64_MAX,
      });
      const nonce = asUint(await nextNonce({ authorization, operation, compiled }), 'nonce', { nonzero: true });
      const expiry = asUint(await expiresAt({ authorization, operation, compiled }), 'expiresAt', {
        nonzero: true,
        max: UINT64_MAX,
      });
      const reservationAmount = asUint(
        await maxAmount({ authorization, operation, compiled }),
        'maxAmount',
        { nonzero: true },
      );
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
      const onchainOperationId = await contract.hashAuthorization(baseAuthorization);
      let reserved = false;
      let boundaryEntered = false;
      let invocation = null;

      try {
        await (await contract.connect(payerSigner).reserve(baseAuthorization, authorizationSignature, {
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
        const invocationSignature = await providerSigner.signTypedData(domain, INVOCATION_TYPES, invocation);
        await (await contract.connect(executorSigner).markInvoked(invocation, invocationSignature)).wait();
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
        await (await contract.submitOutcome(
          outcome,
          await providerSigner.signTypedData(domain, OUTCOME_TYPES, outcome),
        )).wait();
        const operationState = await contract.getOperation(onchainOperationId);

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
        });
      } catch (error) {
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
            observedAt: asUint(await now(), 'indeterminate observedAt', { nonzero: true, max: UINT64_MAX }),
            kind: 3,
          };
          try {
            await (await contract.submitOutcome(
              uncertain,
              await providerSigner.signTypedData(domain, OUTCOME_TYPES, uncertain),
            )).wait();
          } catch (settlementError) {
            error.dtcSettlementError = settlementError;
          }
        } else if (reserved) {
          try {
            await (await contract.connect(payerSigner).cancelBeforeInvocation(onchainOperationId)).wait();
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
