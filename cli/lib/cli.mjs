import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { EPClient } from './client.mjs';

function line(stream, value = '') {
  stream.write(`${value}\n`);
}

function json(stream, value) {
  line(stream, JSON.stringify(value, null, 2));
}

function flag(args, name) {
  const index = args.indexOf(`--${name}`);
  if (index < 0 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

function usage(stream, env) {
  const baseUrl = env.EP_BASE_URL || 'https://emiliaprotocol.ai';
  line(stream, `
EMILIA Protocol CLI

Offline evidence:
  ep verify <file.json> [more.json...] [verifier options]
      Verify receipts, bundles, proofs, signoffs, quorum, and provenance locally.
      No EMILIA server or network connection is required.

Hosted API:
  ep profile <entity_id>                    Get a trust profile
  ep evaluate <entity_id> [--policy X]      Evaluate a profile against policy
  ep preflight <entity_id> [--policy X]     Run install preflight
  ep register <entity_id> [--name "Name"]   Register an entity
  ep submit <entity_id> --ref <ref>         Submit a receipt
  ep verify-remote <receipt_id>              Query the hosted public verifier
  ep dispute <dispute_id>                    Check dispute status
  ep dispute file <receipt_id> --reason X    File a dispute
  ep appeal <dispute_id> --reason X          Appeal a dispute resolution
  ep score <entity_id>                       Get legacy compatibility score
  ep policies                                List trust policies
  ep health                                  Check API health

Environment:
  EP_BASE_URL  API base URL (default: ${baseUrl})
  EP_API_KEY   API key for write operations

Examples:
  ep verify receipt.json
  ep verify receipt.json --key MCowBQYDK2VwAyEA...
  ep profile merchant-xyz
  ep evaluate merchant-xyz --policy strict
  ep submit merchant-xyz --ref order_123 --behavior completed
`);
}

export function resolveVerifierCli() {
  try {
    return join(dirname(fileURLToPath(import.meta.resolve('@emilia-protocol/verify'))), 'cli.js');
  } catch {
    return fileURLToPath(new URL('../../packages/verify/cli.js', import.meta.url));
  }
}

export function runOfflineVerifier(args, { stdout, stderr } = {}) {
  const result = spawnSync(process.execPath, [resolveVerifierCli(), ...args], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.stdout) stdout.write(result.stdout);
  if (result.stderr) stderr.write(result.stderr);
  if (result.error) {
    line(stderr, `Error: verifier failed to start: ${result.error.message}`);
    return 1;
  }
  return Number.isInteger(result.status) ? result.status : 1;
}

function requireApiKey(apiKey, stderr) {
  if (apiKey) return true;
  line(stderr, 'Error: EP_API_KEY is required for this write operation.');
  return false;
}

export async function runCli(
  args,
  {
    env = process.env,
    stdout = process.stdout,
    stderr = process.stderr,
    client: suppliedClient,
  } = {},
) {
  const command = args[0];
  if (!command || ['--help', '-h', 'help'].includes(command)) {
    usage(stdout, env);
    return 0;
  }

  if (command === 'verify') {
    if (args.length < 2) {
      line(stderr, 'Usage: ep verify <file.json> [more.json...] [verifier options]');
      return 1;
    }
    return runOfflineVerifier(args.slice(1), { stdout, stderr });
  }

  const baseUrl = env.EP_BASE_URL || 'https://emiliaprotocol.ai';
  const apiKey = env.EP_API_KEY || '';
  let client;
  try {
    client = suppliedClient || new EPClient(baseUrl, apiKey);
  } catch (error) {
    line(stderr, `Error: ${error.message}`);
    return 1;
  }

  try {
    switch (command) {
      case 'register': {
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep register <entity_id> [--name "Name"] [--type agent]');
          return 1;
        }
        if (!requireApiKey(apiKey, stderr)) return 1;
        json(stdout, await client.register(id, flag(args, 'name') || id, flag(args, 'type') || 'agent'));
        return 0;
      }
      case 'profile': {
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep profile <entity_id>');
          return 1;
        }
        json(stdout, await client.profile(id));
        return 0;
      }
      case 'evaluate': {
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep evaluate <entity_id> [--policy X]');
          return 1;
        }
        json(stdout, await client.evaluate(id, flag(args, 'policy') || 'standard'));
        return 0;
      }
      case 'submit': {
        const id = args[1];
        const reference = flag(args, 'ref');
        if (!id || !reference) {
          line(stderr, 'Usage: ep submit <entity_id> --ref <transaction_ref> [--behavior completed]');
          return 1;
        }
        if (!requireApiKey(apiKey, stderr)) return 1;
        json(stdout, await client.submit(id, reference, flag(args, 'behavior') || 'completed'));
        return 0;
      }
      case 'preflight': {
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep preflight <entity_id> [--policy X]');
          return 1;
        }
        json(stdout, await client.preflight(id, flag(args, 'policy') || 'standard'));
        return 0;
      }
      case 'verify-remote': {
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep verify-remote <receipt_id>');
          return 1;
        }
        json(stdout, await client.verifyRemote(id));
        return 0;
      }
      case 'score': {
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep score <entity_id>');
          return 1;
        }
        json(stdout, await client.score(id));
        return 0;
      }
      case 'dispute': {
        if (args[1] === 'file') {
          const receiptId = args[2];
          const reason = flag(args, 'reason');
          if (!receiptId || !reason) {
            line(stderr, 'Usage: ep dispute file <receipt_id> --reason <reason>');
            return 1;
          }
          if (!requireApiKey(apiKey, stderr)) return 1;
          json(stdout, await client.fileDispute(receiptId, reason));
          return 0;
        }
        const id = args[1];
        if (!id) {
          line(stderr, 'Usage: ep dispute <dispute_id>');
          return 1;
        }
        json(stdout, await client.dispute(id));
        return 0;
      }
      case 'appeal': {
        const id = args[1];
        const reason = flag(args, 'reason');
        if (!id || !reason) {
          line(stderr, 'Usage: ep appeal <dispute_id> --reason <reason>');
          return 1;
        }
        if (!requireApiKey(apiKey, stderr)) return 1;
        json(stdout, await client.appeal(id, reason));
        return 0;
      }
      case 'policies':
        json(stdout, await client.policies());
        return 0;
      case 'health':
        json(stdout, await client.health());
        return 0;
      default:
        line(stderr, `Unknown command: ${command}`);
        usage(stderr, env);
        return 1;
    }
  } catch (error) {
    line(stderr, `Error: ${error.message}`);
    return 1;
  }
}
