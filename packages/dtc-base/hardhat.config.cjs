require('@nomicfoundation/hardhat-ethers');
require('@nomicfoundation/hardhat-chai-matchers');
require('solidity-coverage');

const networks = {};
if (process.env.BASE_SEPOLIA_RPC_URL) {
  networks.baseSepolia = {
    url: process.env.BASE_SEPOLIA_RPC_URL,
    chainId: 84532,
    accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
  };
}

module.exports = {
  solidity: {
    version: '0.8.26',
    settings: {
      evmVersion: 'cancun',
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 500,
      },
    },
  },
  networks,
};
