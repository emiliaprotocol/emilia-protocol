import assert from 'node:assert/strict';

import type {} from '@nomicfoundation/hardhat-ethers';
import hre from 'hardhat';

import {
  AUTHORIZATION_TYPES,
  INVOCATION_TYPES,
  OUTCOME_TYPES,
  asDtcBaseSettlementContract,
  connectDtcBaseSettlementContract,
} from '../lib/receipt-program-bridge.js';

const { ethers } = hre;

async function latestTimestamp(): Promise<bigint> {
  const block = await ethers.provider.getBlock('latest');
  if (!block) throw new Error('latest block is unavailable');
  return BigInt(block.timestamp);
}

async function main(): Promise<void> {
  const [admin, bridge, provider, payer, executor, merchant] = await ethers.getSigners();
  if (!admin || !bridge || !provider || !payer || !executor || !merchant) {
    throw new Error('demo requires six funded local signers');
  }

  const Factory = await ethers.getContractFactory('DTCBaseSettlement');
  const settlement = asDtcBaseSettlementContract(
    await Factory.deploy(admin.address, bridge.address),
  );
  await settlement.waitForDeployment();
  await (await settlement.setProviderSigner(merchant.address, provider.address)).wait();

  const chainId = (await ethers.provider.getNetwork()).chainId;
  const domain = {
    name: 'EMILIA DTC Base Settlement',
    version: '2',
    chainId,
    verifyingContract: await settlement.getAddress(),
  };
  const authorization = {
    receiptHash: ethers.sha256(ethers.toUtf8Bytes('EP-RECEIPT-v1:demo')),
    caid: ethers.sha256(ethers.toUtf8Bytes('EP-CAID-v1:purchase:blue-bicycle')),
    actionHash: ethers.sha256(ethers.toUtf8Bytes('purchase blue bicycle')),
    programHash: ethers.sha256(ethers.toUtf8Bytes('EP-PROGRAM-v1:purchase-program')),
    inputHash: ethers.sha256(ethers.toUtf8Bytes('{"item":"blue bicycle","merchant":"demo"}')),
    payer: payer.address,
    executor: executor.address,
    merchant: merchant.address,
    authorizationSigner: bridge.address,
    providerSigner: provider.address,
    maxAmount: ethers.parseEther('0.2'),
    expiresAt: (await latestTimestamp()) + 3600n,
    providerConfigVersion: 1n,
    nonce: 1n,
  };
  const authorizationSignature = await bridge.signTypedData(
    domain,
    AUTHORIZATION_TYPES,
    authorization,
  );
  const operationId = await settlement.hashAuthorization(authorization);
  const payerSettlement = connectDtcBaseSettlementContract(settlement, payer);
  await (await payerSettlement.reserve(authorization, authorizationSignature, {
    value: authorization.maxAmount,
  })).wait();

  const invocation = {
    operationId,
    invocationHash: ethers.sha256(ethers.toUtf8Bytes('provider-invocation:demo-001')),
    providerRequestId: ethers.sha256(ethers.toUtf8Bytes('provider-request-id:demo-001')),
    observedAt: await latestTimestamp(),
  };
  const executorSettlement = connectDtcBaseSettlementContract(settlement, executor);
  await (await executorSettlement.markInvoked(
    invocation,
    await provider.signTypedData(domain, INVOCATION_TYPES, invocation),
  )).wait();

  const uncertain = {
    operationId,
    invocationHash: invocation.invocationHash,
    providerRequestId: invocation.providerRequestId,
    evidenceHash: ethers.sha256(ethers.toUtf8Bytes('provider-timeout:demo-001')),
    priorOutcomeDigest: ethers.ZeroHash,
    amount: 0n,
    observedAt: await latestTimestamp(),
    kind: 3,
  };
  await (await settlement.submitOutcome(
    uncertain,
    await provider.signTypedData(domain, OUTCOME_TYPES, uncertain),
  )).wait();
  assert.equal((await settlement.getOperation(operationId)).status, 3n);
  assert.equal(await settlement.totalLocked(), authorization.maxAmount);
  assert.equal(await settlement.totalClaimable(), 0n);

  const terminal = {
    operationId,
    invocationHash: invocation.invocationHash,
    providerRequestId: invocation.providerRequestId,
    evidenceHash: ethers.sha256(ethers.toUtf8Bytes('provider-settlement-record:demo-001')),
    priorOutcomeDigest: await settlement.hashOutcome(uncertain),
    amount: ethers.parseEther('0.15'),
    observedAt: await latestTimestamp(),
    kind: 1,
  };
  const adminSettlement = connectDtcBaseSettlementContract(settlement, admin);
  await (await adminSettlement.reconcile(
    terminal,
    await provider.signTypedData(domain, OUTCOME_TYPES, terminal),
  )).wait();

  const operation = await settlement.getOperation(operationId);
  assert.equal(operation.status, 4n);
  assert.equal(await settlement.totalLocked(), 0n);
  assert.equal(await settlement.claimable(merchant.address), terminal.amount);
  assert.equal(await settlement.claimable(payer.address), authorization.maxAmount - terminal.amount);

  process.stdout.write(`${JSON.stringify({
    scenario: 'provider executed but initial response timed out',
    result: 'INDETERMINATE funds remained frozen until authenticated reconciliation',
    operationId,
    receiptHash: authorization.receiptHash,
    caid: authorization.caid,
    invocationHash: invocation.invocationHash,
    providerRequestId: invocation.providerRequestId,
    terminalEvidenceHash: terminal.evidenceHash,
    certificateHash: operation.certificateHash,
    merchantClaimWei: (await settlement.claimable(merchant.address)).toString(),
    payerRemainderWei: (await settlement.claimable(payer.address)).toString(),
  }, null, 2)}\n`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
