import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const packageJson = JSON.parse(readFileSync(resolve(PACKAGE_ROOT, 'package.json'), 'utf8'));

if (packageJson.private !== true) throw new Error('DTC Base must remain private:true to prevent npm publication');
const deploymentScripts = Object.keys(packageJson.scripts ?? {}).filter((name) => name.startsWith('deploy:'));
if (deploymentScripts.length !== 1 || deploymentScripts[0] !== 'deploy:base-sepolia') {
  throw new Error('Base Sepolia must remain the only declared remote deployment target');
}

const hardhatConfigPath = resolve(PACKAGE_ROOT, 'hardhat.config.ts');
const previousRpcUrl = process.env.BASE_SEPOLIA_RPC_URL;
process.env.BASE_SEPOLIA_RPC_URL = 'http://127.0.0.1:8545';
const { default: hardhatConfig } = await import(pathToFileURL(hardhatConfigPath).href);
if (previousRpcUrl === undefined) delete process.env.BASE_SEPOLIA_RPC_URL;
else process.env.BASE_SEPOLIA_RPC_URL = previousRpcUrl;
const remoteNetworks = Object.entries(hardhatConfig.networks ?? {})
  .filter(([, network]) => network.type === 'http')
  .map(([name]) => name);
if (remoteNetworks.length !== 1 || remoteNetworks[0] !== 'baseSepolia') {
  throw new Error(`unexpected configured remote networks: ${remoteNetworks.join(', ') || '(none)'}`);
}
if (hardhatConfig.networks.baseSepolia.chainId !== 84532) {
  throw new Error('Base Sepolia must remain pinned to chain ID 84532');
}

const environmentExample = readFileSync(resolve(PACKAGE_ROOT, '.env.example'), 'utf8');
const rpcVariables = [...environmentExample.matchAll(/^([A-Z0-9_]+_RPC_URL)=/gm)].map((match) => match[1]);
if (rpcVariables.length !== 1 || rpcVariables[0] !== 'BASE_SEPOLIA_RPC_URL') {
  throw new Error(`unexpected remote RPC variables: ${rpcVariables.join(', ') || '(none)'}`);
}

const deploySource = readFileSync(resolve(PACKAGE_ROOT, 'scripts/deploy.ts'), 'utf8');
if (!deploySource.includes('const ALLOWED_REMOTE_CHAIN = 84532n;')) {
  throw new Error('deployment guard must remain pinned to Base Sepolia chain ID 84532');
}

process.stdout.write('verified private:true and Base Sepolia-only package policy\n');
