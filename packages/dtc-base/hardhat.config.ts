import hardhatEthers from '@nomicfoundation/hardhat-ethers';
import hardhatEthersChaiMatchers from '@nomicfoundation/hardhat-ethers-chai-matchers';
import hardhatMocha from '@nomicfoundation/hardhat-mocha';
import hardhatNetworkHelpers from '@nomicfoundation/hardhat-network-helpers';
import { defineConfig } from 'hardhat/config';

const baseSepolia = process.env.BASE_SEPOLIA_RPC_URL
  ? {
      baseSepolia: {
        type: 'http' as const,
        chainType: 'op' as const,
        chainId: 84532,
        url: process.env.BASE_SEPOLIA_RPC_URL,
        accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      },
    }
  : {};

export default defineConfig({
  plugins: [hardhatEthers, hardhatEthersChaiMatchers, hardhatMocha, hardhatNetworkHelpers],
  solidity: {
    profiles: {
      default: {
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
    },
  },
  networks: {
    hardhatMainnet: {
      type: 'edr-simulated',
      chainType: 'l1',
    },
    ...baseSepolia,
  },
});
