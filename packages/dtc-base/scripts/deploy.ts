import type {} from '@nomicfoundation/hardhat-ethers';
import hre from 'hardhat';

import { asDtcBaseSettlementContract } from '../lib/receipt-program-bridge.js';

const { ethers, network } = hre;

const DEPLOY_ACK = 'I_UNDERSTAND_THIS_IS_EXPERIMENTAL_UNAUDITED_CODE';
const ALLOWED_REMOTE_CHAIN = 84532n;

function requiredAddress(name: string): string {
  const value = process.env[name];
  if (!value || !ethers.isAddress(value) || value === ethers.ZeroAddress) {
    throw new Error(`${name} must be a non-zero EVM address`);
  }
  return ethers.getAddress(value);
}

async function main(): Promise<void> {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const isLocal = network.name === 'hardhat' || network.name === 'localhost';
  if (!isLocal) {
    if (chainId !== ALLOWED_REMOTE_CHAIN) {
      throw new Error(`refusing unsupported chain ${chainId}; this script permits Base Sepolia only`);
    }
    if (process.env.DTC_DEPLOY_ACK !== DEPLOY_ACK) {
      throw new Error('refusing remote deployment without the experimental-unaudited-code acknowledgement');
    }
  }

  const signers = await ethers.getSigners();
  const deployer = signers[0];
  const defaultBridge = signers[1];
  if (!deployer || !defaultBridge) throw new Error('deployment requires two funded signers');

  const admin = isLocal
    ? (process.env.DTC_ADMIN_ADDRESS || deployer.address)
    : requiredAddress('DTC_ADMIN_ADDRESS');
  const bridge = isLocal
    ? (process.env.DTC_AUTHORIZATION_SIGNER_ADDRESS || defaultBridge.address)
    : requiredAddress('DTC_AUTHORIZATION_SIGNER_ADDRESS');

  const Factory = await ethers.getContractFactory('DTCBaseSettlement');
  const settlement = asDtcBaseSettlementContract(await Factory.deploy(admin, bridge));
  await settlement.waitForDeployment();

  const merchantRaw = process.env.DTC_INITIAL_MERCHANT_ADDRESS;
  const providerRaw = process.env.DTC_INITIAL_PROVIDER_SIGNER_ADDRESS;
  if (Boolean(merchantRaw) !== Boolean(providerRaw)) {
    throw new Error(
      'set both DTC_INITIAL_MERCHANT_ADDRESS and DTC_INITIAL_PROVIDER_SIGNER_ADDRESS, or neither',
    );
  }
  if (merchantRaw && providerRaw) {
    if (ethers.getAddress(admin) !== ethers.getAddress(deployer.address)) {
      throw new Error('initial provider binding requires the deployer to be the configured admin');
    }
    await (await settlement.setProviderSigner(
      requiredAddress('DTC_INITIAL_MERCHANT_ADDRESS'),
      requiredAddress('DTC_INITIAL_PROVIDER_SIGNER_ADDRESS'),
    )).wait();
  }

  const address = await settlement.getAddress();
  const adminRole = await settlement.DEFAULT_ADMIN_ROLE();
  const authorizationRole = await settlement.AUTHORIZATION_SIGNER_ROLE();
  if (!(await settlement.hasRole(adminRole, admin))) {
    throw new Error('post-deploy admin role verification failed');
  }
  if (!(await settlement.hasRole(authorizationRole, bridge))) {
    throw new Error('post-deploy authorization signer role verification failed');
  }

  process.stdout.write(`${JSON.stringify({
    status: 'DEPLOYED_EXPERIMENTAL_UNAUDITED',
    network: network.name,
    chainId: chainId.toString(),
    contract: address,
    admin,
    authorizationSigner: bridge,
    implementationCodeHash: ethers.keccak256(await ethers.provider.getCode(address)),
  }, null, 2)}\n`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
