const { expect } = require('chai');
const { ethers } = require('hardhat');
const { time } = require('@nomicfoundation/hardhat-network-helpers');

const AUTHORIZATION_TYPES = {
  Authorization: [
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
  ],
};

const INVOCATION_TYPES = {
  Invocation: [
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'observedAt', type: 'uint64' },
  ],
};

const OUTCOME_TYPES = {
  Outcome: [
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'evidenceHash', type: 'bytes32' },
    { name: 'priorOutcomeDigest', type: 'bytes32' },
    { name: 'amount', type: 'uint256' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'kind', type: 'uint8' },
  ],
};

const OUTCOME = Object.freeze({ SUCCEEDED: 1, FAILED: 2, INDETERMINATE: 3 });
const STATUS = Object.freeze({ RESERVED: 1n, INVOKED: 2n, INDETERMINATE: 3n, SUCCEEDED: 4n });
const PARTY_AGREEMENT = 3n;

describe('DTCBaseSettlement hostile cases', function () {
  let settlement;
  let secondSettlement;
  let admin;
  let bridge;
  let provider;
  let rotatedProvider;
  let payer;
  let executor;
  let merchant;
  let attacker;
  let domain;

  beforeEach(async function () {
    [admin, bridge, provider, rotatedProvider, payer, executor, merchant, attacker] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory('DTCBaseSettlement');
    settlement = await Factory.deploy(admin.address, bridge.address);
    secondSettlement = await Factory.deploy(admin.address, bridge.address);
    await Promise.all([settlement.waitForDeployment(), secondSettlement.waitForDeployment()]);
    await settlement.connect(admin).setProviderSigner(merchant.address, provider.address);
    await secondSettlement.connect(admin).setProviderSigner(merchant.address, provider.address);
    domain = await settlementDomain(settlement);
  });

  async function settlementDomain(contract) {
    return {
      name: 'EMILIA DTC Base Settlement',
      version: '2',
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await contract.getAddress(),
    };
  }

  async function authorization(sequence = 1n, overrides = {}) {
    return {
      receiptHash: ethers.id(`hostile-receipt-${sequence}`),
      caid: ethers.sha256(ethers.toUtf8Bytes(`EP-CAID-v1:hostile-${sequence}`)),
      actionHash: ethers.id(`action-${sequence}`),
      programHash: ethers.id(`program-${sequence}`),
      inputHash: ethers.id(`input-${sequence}`),
      payer: payer.address,
      executor: executor.address,
      merchant: merchant.address,
      authorizationSigner: bridge.address,
      providerSigner: provider.address,
      maxAmount: ethers.parseEther('1'),
      expiresAt: BigInt(await time.latest()) + 3600n,
      providerConfigVersion: 1n,
      nonce: sequence,
      ...overrides,
    };
  }

  async function reserve(sequence = 1n, overrides = {}, contract = settlement, signer = bridge, signingDomain = domain) {
    const auth = await authorization(sequence, overrides);
    const signature = await signer.signTypedData(signingDomain, AUTHORIZATION_TYPES, auth);
    const operationId = await contract.hashAuthorization(auth);
    const payerAccount = auth.payer === payer.address ? payer : attacker;
    await contract.connect(payerAccount).reserve(auth, signature, { value: auth.maxAmount });
    return { auth, operationId, authorizationSignature: signature };
  }

  async function invocationFor(prepared, sequence = 1n, overrides = {}) {
    return {
      operationId: prepared.operationId,
      invocationHash: ethers.id(`invocation-${sequence}`),
      providerRequestId: ethers.id(`provider-request-${sequence}`),
      observedAt: BigInt(await time.latest()),
      ...overrides,
    };
  }

  async function invoke(sequence = 1n, overrides = {}) {
    const prepared = await reserve(sequence, overrides);
    const invocation = await invocationFor(prepared, sequence);
    const signature = await provider.signTypedData(domain, INVOCATION_TYPES, invocation);
    await settlement.connect(executor).markInvoked(invocation, signature);
    return { ...prepared, invocation, invocationSignature: signature };
  }

  async function outcomeFor(prepared, kind, amount = 0n, label = 'evidence', overrides = {}) {
    return {
      operationId: prepared.operationId,
      invocationHash: prepared.invocation.invocationHash,
      providerRequestId: prepared.invocation.providerRequestId,
      evidenceHash: ethers.id(`${label}-${prepared.operationId}`),
      priorOutcomeDigest: ethers.ZeroHash,
      amount,
      observedAt: BigInt(await time.latest()),
      kind,
      ...overrides,
    };
  }

  async function signOutcome(value, signer = provider, signingDomain = domain) {
    return signer.signTypedData(signingDomain, OUTCOME_TYPES, value);
  }

  it('domain-separates authorization, invocation, and outcome signatures by contract', async function () {
    const auth = await authorization();
    const firstSignature = await bridge.signTypedData(domain, AUTHORIZATION_TYPES, auth);
    await expect(
      secondSettlement.connect(payer).reserve(auth, firstSignature, { value: auth.maxAmount }),
    ).to.be.revertedWithCustomError(secondSettlement, 'InvalidAuthorization');

    const prepared = await reserve();
    const invocation = await invocationFor(prepared);
    const secondDomain = await settlementDomain(secondSettlement);
    await expect(
      settlement.connect(executor).markInvoked(
        invocation,
        await provider.signTypedData(secondDomain, INVOCATION_TYPES, invocation),
      ),
    ).to.be.revertedWithCustomError(settlement, 'InvalidProviderEvidence');
  });

  it('pins provider signer and configuration version against the pre-reservation rebinding race', async function () {
    const auth = await authorization();
    const signature = await bridge.signTypedData(domain, AUTHORIZATION_TYPES, auth);
    await settlement.connect(admin).setProviderSigner(merchant.address, rotatedProvider.address);
    await expect(
      settlement.connect(payer).reserve(auth, signature, { value: auth.maxAmount }),
    ).to.be.revertedWithCustomError(settlement, 'ProviderBindingMismatch');

    const wrongVersion = { ...auth, providerSigner: rotatedProvider.address, providerConfigVersion: 1n };
    await expect(
      settlement.connect(payer).reserve(
        wrongVersion,
        await bridge.signTypedData(domain, AUTHORIZATION_TYPES, wrongVersion),
        { value: wrongVersion.maxAmount },
      ),
    ).to.be.revertedWithCustomError(settlement, 'ProviderBindingMismatch');
  });

  it('does not let the executor lock funds without provider-authenticated boundary entry', async function () {
    const prepared = await reserve();
    const invocation = await invocationFor(prepared);
    await expect(
      settlement.connect(executor).markInvoked(
        invocation,
        await attacker.signTypedData(domain, INVOCATION_TYPES, invocation),
      ),
    ).to.be.revertedWithCustomError(settlement, 'InvalidProviderEvidence');
    expect((await settlement.getOperation(prepared.operationId)).status).to.equal(STATUS.RESERVED);

    await settlement.connect(admin).pauseSettlements();
    await expect(
      settlement.connect(executor).markInvoked(
        invocation,
        await provider.signTypedData(domain, INVOCATION_TYPES, invocation),
      ),
    ).to.be.revertedWithCustomError(settlement, 'SettlementsPaused');

    await time.increaseTo(prepared.auth.expiresAt + 1n);
    await settlement.cancelExpired(prepared.operationId);
    expect(await settlement.totalLocked()).to.equal(0);
  });

  it('requires provider outcomes to attest the exact invocation and provider request', async function () {
    const prepared = await invoke();
    const wrongInvocation = await outcomeFor(prepared, OUTCOME.SUCCEEDED, 1n, 'wrong-invocation', {
      invocationHash: ethers.id('substituted-invocation'),
    });
    await expect(settlement.submitOutcome(wrongInvocation, await signOutcome(wrongInvocation)))
      .to.be.revertedWithCustomError(settlement, 'OutcomeNotBoundToInvocation');

    const wrongRequest = { ...wrongInvocation, invocationHash: prepared.invocation.invocationHash,
      providerRequestId: ethers.id('substituted-request') };
    await expect(settlement.submitOutcome(wrongRequest, await signOutcome(wrongRequest)))
      .to.be.revertedWithCustomError(settlement, 'OutcomeNotBoundToInvocation');
  });

  it('prevents two operations from claiming one provider request or invocation', async function () {
    const first = await invoke();
    await settlement.connect(admin).setProviderSigner(merchant.address, rotatedProvider.address);
    const second = await reserve(2n, {
      providerSigner: rotatedProvider.address,
      providerConfigVersion: 2n,
    });
    const replay = await invocationFor(second, 2n, {
      invocationHash: first.invocation.invocationHash,
      providerRequestId: first.invocation.providerRequestId,
    });
    await expect(
      settlement.connect(executor).markInvoked(
        replay,
        await rotatedProvider.signTypedData(domain, INVOCATION_TYPES, replay),
      ),
    ).to.be.revertedWithCustomError(settlement, 'ProviderRequestAlreadyConsumed');
  });

  it('contains a compromised frozen provider and still permits two-party recovery while paused', async function () {
    const prepared = await invoke();
    await settlement.connect(admin).pauseSettlements();
    await settlement.connect(admin).revokeProviderSigner(provider.address);
    const providerSuccess = await outcomeFor(prepared, OUTCOME.SUCCEEDED, ethers.parseEther('0.5'), 'compromised');
    await expect(settlement.submitOutcome(providerSuccess, await signOutcome(providerSuccess)))
      .to.be.revertedWithCustomError(settlement, 'SettlementsPaused');
    await settlement.connect(admin).unpauseSettlements();
    await expect(settlement.submitOutcome(providerSuccess, await signOutcome(providerSuccess)))
      .to.be.revertedWithCustomError(settlement, 'ProviderSignerRevoked');

    await settlement.connect(admin).pauseSettlements();
    const agreement = await outcomeFor(prepared, OUTCOME.SUCCEEDED, ethers.parseEther('0.4'), 'party-agreement');
    await settlement.settleByAgreement(
      agreement,
      await signOutcome(agreement, payer),
      await signOutcome(agreement, merchant),
    );
    const operation = await settlement.getOperation(prepared.operationId);
    expect(operation.status).to.equal(STATUS.SUCCEEDED);
    expect(operation.resolution).to.equal(PARTY_AGREEMENT);
  });

  it('requires reconciliation evidence to be causally chained and temporally newer', async function () {
    const prepared = await invoke();
    const uncertain = await outcomeFor(prepared, OUTCOME.INDETERMINATE, 0n, 'uncertain');
    await settlement.submitOutcome(uncertain, await signOutcome(uncertain));
    const uncertainDigest = await settlement.hashOutcome(uncertain);

    const unchained = await outcomeFor(prepared, OUTCOME.SUCCEEDED, 1n, 'unchained');
    await expect(settlement.connect(admin).reconcile(unchained, await signOutcome(unchained)))
      .to.be.revertedWithCustomError(settlement, 'InvalidPriorOutcome');

    const stale = { ...unchained, priorOutcomeDigest: uncertainDigest, observedAt: uncertain.observedAt };
    await expect(settlement.connect(admin).reconcile(stale, await signOutcome(stale)))
      .to.be.revertedWithCustomError(settlement, 'InvalidObservationTime');
    expect(await settlement.totalLocked()).to.equal(prepared.auth.maxAmount);
  });

  it('does not allow one provider evidence hash to settle multiple operations', async function () {
    const first = await invoke();
    const second = await invoke(2n);
    const evidenceHash = ethers.id('one-external-evidence');
    const firstOutcome = await outcomeFor(first, OUTCOME.SUCCEEDED, 1n, 'first', { evidenceHash });
    await settlement.submitOutcome(firstOutcome, await signOutcome(firstOutcome));
    const secondOutcome = await outcomeFor(second, OUTCOME.SUCCEEDED, 1n, 'second', { evidenceHash });
    await expect(settlement.submitOutcome(secondOutcome, await signOutcome(secondOutcome)))
      .to.be.revertedWithCustomError(settlement, 'EvidenceAlreadyConsumed');
  });

  it('namespaces receipt and nonce replay protection by authorization signer and payer', async function () {
    const first = await reserve();
    const sameNonce = await authorization(2n, { nonce: first.auth.nonce });
    await expect(
      settlement.connect(payer).reserve(
        sameNonce,
        await bridge.signTypedData(domain, AUTHORIZATION_TYPES, sameNonce),
        { value: sameNonce.maxAmount },
      ),
    ).to.be.revertedWithCustomError(settlement, 'AuthorizationNonceAlreadyConsumed');

    const otherPayer = await authorization(1n, {
      receiptHash: first.auth.receiptHash,
      payer: attacker.address,
    });
    await settlement.connect(attacker).reserve(
      otherPayer,
      await bridge.signTypedData(domain, AUTHORIZATION_TYPES, otherPayer),
      { value: otherPayer.maxAmount },
    );
  });

  it('supports EIP-1271 bridge and provider signers across all signed boundaries', async function () {
    const Wallet = await ethers.getContractFactory('MockERC1271Signer');
    const bridgeWallet = await Wallet.deploy(bridge.address);
    const providerWallet = await Wallet.deploy(provider.address);
    await Promise.all([bridgeWallet.waitForDeployment(), providerWallet.waitForDeployment()]);
    await settlement.connect(admin).grantRole(
      await settlement.AUTHORIZATION_SIGNER_ROLE(),
      await bridgeWallet.getAddress(),
    );
    await settlement.connect(admin).setProviderSigner(merchant.address, await providerWallet.getAddress());

    const auth = await authorization(3n, {
      authorizationSigner: await bridgeWallet.getAddress(),
      providerSigner: await providerWallet.getAddress(),
      providerConfigVersion: 2n,
    });
    const operationId = await settlement.hashAuthorization(auth);
    await settlement.connect(payer).reserve(
      auth,
      await bridge.signTypedData(domain, AUTHORIZATION_TYPES, auth),
      { value: auth.maxAmount },
    );
    const prepared = { auth, operationId };
    const invocation = await invocationFor(prepared, 3n);
    await settlement.connect(executor).markInvoked(
      invocation,
      await provider.signTypedData(domain, INVOCATION_TYPES, invocation),
    );
    const complete = { ...prepared, invocation };
    const success = await outcomeFor(complete, OUTCOME.SUCCEEDED, 1n, 'erc1271');
    await settlement.submitOutcome(success, await provider.signTypedData(domain, OUTCOME_TYPES, success));
    expect((await settlement.getOperation(operationId)).status).to.equal(STATUS.SUCCEEDED);
  });

  it('cannot terminally settle or release one operation twice', async function () {
    const prepared = await invoke();
    const success = await outcomeFor(prepared, OUTCOME.SUCCEEDED, ethers.parseEther('0.5'), 'terminal');
    const signature = await signOutcome(success);
    await settlement.submitOutcome(success, signature);
    const claimable = await settlement.totalClaimable();
    await expect(settlement.submitOutcome(success, signature)).to.be.revertedWithCustomError(settlement, 'InvalidState');
    expect(await settlement.totalClaimable()).to.equal(claimable);
  });

  it('keeps a receipt consumed after cancellation and terminal failure', async function () {
    const soon = BigInt(await time.latest()) + 5n;
    const cancelled = await reserve(4n, { expiresAt: soon });
    await time.increaseTo(soon + 1n);
    await settlement.cancelExpired(cancelled.operationId);
    const retry = await authorization(5n, { receiptHash: cancelled.auth.receiptHash });
    await expect(
      settlement.connect(payer).reserve(
        retry,
        await bridge.signTypedData(domain, AUTHORIZATION_TYPES, retry),
        { value: retry.maxAmount },
      ),
    ).to.be.revertedWithCustomError(settlement, 'ReceiptAlreadyConsumed');

    const failed = await invoke(6n);
    const failure = await outcomeFor(failed, OUTCOME.FAILED, 0n, 'failure');
    await settlement.submitOutcome(failure, await signOutcome(failure));
    const failureRetry = await authorization(7n, { receiptHash: failed.auth.receiptHash });
    await expect(
      settlement.connect(payer).reserve(
        failureRetry,
        await bridge.signTypedData(domain, AUTHORIZATION_TYPES, failureRetry),
        { value: failureRetry.maxAmount },
      ),
    ).to.be.revertedWithCustomError(settlement, 'ReceiptAlreadyConsumed');
  });

  it('rejects zero commitments, invalid amounts, and future-dated evidence', async function () {
    const zeroCaid = await authorization(8n, { caid: ethers.ZeroHash });
    await expect(
      settlement.connect(payer).reserve(
        zeroCaid,
        await bridge.signTypedData(domain, AUTHORIZATION_TYPES, zeroCaid),
        { value: zeroCaid.maxAmount },
      ),
    ).to.be.revertedWithCustomError(settlement, 'ZeroDigest');

    const prepared = await invoke(9n);
    const badFailure = await outcomeFor(prepared, OUTCOME.FAILED, 1n, 'bad-failure');
    await expect(settlement.submitOutcome(badFailure, await signOutcome(badFailure)))
      .to.be.revertedWithCustomError(settlement, 'InvalidOutcomeAmount');
    const future = await outcomeFor(prepared, OUTCOME.SUCCEEDED, 1n, 'future', {
      observedAt: BigInt(await time.latest()) + 600n,
    });
    await expect(settlement.submitOutcome(future, await signOutcome(future)))
      .to.be.revertedWithCustomError(settlement, 'InvalidObservationTime');
  });

  it('does not permit withdrawal reentrancy and lets contract claimants redirect value', async function () {
    const Receiver = await ethers.getContractFactory('ReentrantWithdrawer');
    const receiver = await Receiver.deploy(await settlement.getAddress());
    await receiver.waitForDeployment();
    await settlement.connect(admin).setProviderSigner(await receiver.getAddress(), provider.address);
    const prepared = await invoke(10n, {
      merchant: await receiver.getAddress(),
      providerConfigVersion: 1n,
    });
    const amount = ethers.parseEther('0.65');
    const success = await outcomeFor(prepared, OUTCOME.SUCCEEDED, amount, 'reentrant');
    await settlement.submitOutcome(success, await signOutcome(success));
    await receiver.attackWithdraw();
    expect(await receiver.received()).to.equal(amount);
    expect(await receiver.reentrySucceeded()).to.equal(false);

    const redirected = await invoke(11n, {
      merchant: await receiver.getAddress(),
      providerConfigVersion: 1n,
    });
    const redirectAmount = ethers.parseEther('0.2');
    const redirectOutcome = await outcomeFor(redirected, OUTCOME.SUCCEEDED, redirectAmount, 'redirect');
    await settlement.submitOutcome(redirectOutcome, await signOutcome(redirectOutcome));
    await receiver.redirectWithdraw(attacker.address);
    expect(await settlement.claimable(await receiver.getAddress())).to.equal(0);
  });

  it('maintains liabilities when forced ETH makes raw balance larger than accounting', async function () {
    const prepared = await reserve(12n);
    const forced = ethers.parseEther('0.1');
    const address = await settlement.getAddress();
    const currentBalance = await ethers.provider.getBalance(address);
    await ethers.provider.send('hardhat_setBalance', [address, ethers.toBeHex(currentBalance + forced)]);
    expect(await settlement.accountedBalance()).to.equal(prepared.auth.maxAmount);
    expect(await ethers.provider.getBalance(address)).to.equal(prepared.auth.maxAmount + forced);
  });

  it('enforces a delayed two-step transfer of default administration', async function () {
    expect(await settlement.defaultAdminDelay()).to.equal(172800n);
    await settlement.connect(admin).beginDefaultAdminTransfer(attacker.address);
    await expect(settlement.connect(attacker).acceptDefaultAdminTransfer()).to.be.reverted;
    await time.increase(172801);
    await settlement.connect(attacker).acceptDefaultAdminTransfer();
    expect(await settlement.defaultAdmin()).to.equal(attacker.address);
  });
});
