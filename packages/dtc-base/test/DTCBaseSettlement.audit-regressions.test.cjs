const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('DTCBaseSettlement hostile-review regressions', function () {
  it('exposes provider-confirmed invocation, signer quarantine, party recovery, and redirected withdrawal', async function () {
    const [admin, bridge] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory('DTCBaseSettlement');
    const settlement = await Factory.deploy(admin.address, bridge.address);
    await settlement.waitForDeployment();
    const functions = settlement.interface.fragments
      .filter((fragment) => fragment.type === 'function')
      .map((fragment) => fragment.name);

    expect(functions).to.include('hashInvocation');
    expect(functions).to.include('revokeProviderSigner');
    expect(functions).to.include('pauseSettlements');
    expect(functions).to.include('settleByAgreement');
    expect(functions).to.include('withdrawTo');
  });
});
