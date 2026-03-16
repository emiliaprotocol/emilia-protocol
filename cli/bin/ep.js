#!/usr/bin/env node
/**
 * EP CLI — EMILIA Protocol command-line interface
 * 
 * Usage:
 *   ep profile <entityId>                     Look up a trust profile
 *   ep evaluate <entityId> [--policy strict]  Evaluate against a trust policy
 *   ep preflight <entityId> [--policy mcp_server_safe_v1]  Software install preflight
 *   ep register <entityId> --name "Name"      Register a new entity
 *   ep submit <entityId> --ref <txRef> --behavior completed  Submit a receipt
 *   ep verify <receiptId>                     Verify a receipt
 *   ep dispute <receiptId> --reason <reason>  File a dispute
 *   ep appeal <disputeId> --reason "..."      Appeal a resolution
 *   ep policies                               List all trust policies
 *   ep health                                 Check API health
 * 
 * Environment:
 *   EP_BASE_URL   API base (default: https://emiliaprotocol.ai)
 *   EP_API_KEY    API key for write operations
 */

const BASE = process.env.EP_BASE_URL || 'https://emiliaprotocol.ai';
const API_KEY = process.env.EP_API_KEY || '';

const args = process.argv.slice(2);
const command = args[0];

function flag(name) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return null;
  return args[i + 1] || true;
}

async function epFetch(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (opts.auth && API_KEY) headers['Authorization'] = `Bearer ${API_KEY}`;
  
  const url = `${BASE}${path}`;
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  
  const data = await res.json();
  if (!res.ok) {
    console.error(`Error ${res.status}: ${data.error || JSON.stringify(data)}`);
    process.exit(1);
  }
  return data;
}

function print(data) {
  console.log(JSON.stringify(data, null, 2));
}

async function main() {
  if (!command || command === '--help' || command === '-h') {
    console.log(`
EP CLI — EMILIA Protocol

Commands:
  ep profile <entityId>                     Look up trust profile
  ep evaluate <entityId> [--policy P]       Evaluate against policy (default: standard)
  ep preflight <entityId> [--policy P]      Software install preflight
  ep register <entityId> --name "Name"      Register entity
  ep submit <entityId> --ref R --behavior B Submit receipt
  ep verify <receiptId>                     Verify receipt
  ep dispute <receiptId> --reason R         File dispute
  ep appeal <disputeId> --reason "..."      Appeal resolution
  ep policies                               List trust policies
  ep health                                 API health check

Environment:
  EP_BASE_URL   ${BASE}
  EP_API_KEY    ${API_KEY ? '(set)' : '(not set)'}
`);
    return;
  }

  switch (command) {
    case 'profile': {
      const id = args[1];
      if (!id) { console.error('Usage: ep profile <entityId>'); process.exit(1); }
      print(await epFetch(`/api/trust/profile/${encodeURIComponent(id)}`));
      break;
    }

    case 'evaluate': {
      const id = args[1];
      const policy = flag('policy') || 'standard';
      if (!id) { console.error('Usage: ep evaluate <entityId> [--policy P]'); process.exit(1); }
      print(await epFetch('/api/trust/evaluate', {
        method: 'POST', body: { entity_id: id, policy },
      }));
      break;
    }

    case 'preflight': {
      const id = args[1];
      const policy = flag('policy') || 'mcp_server_safe_v1';
      if (!id) { console.error('Usage: ep preflight <entityId> [--policy P]'); process.exit(1); }
      print(await epFetch('/api/trust/install-preflight', {
        method: 'POST', body: { entity_id: id, policy },
      }));
      break;
    }

    case 'register': {
      const id = args[1];
      const name = flag('name');
      const type = flag('type') || 'agent';
      if (!id || !name) { console.error('Usage: ep register <entityId> --name "Name" [--type agent]'); process.exit(1); }
      print(await epFetch('/api/entities/register', {
        method: 'POST', auth: true,
        body: { entity_id: id, display_name: name, entity_type: type },
      }));
      break;
    }

    case 'submit': {
      const id = args[1];
      const ref = flag('ref');
      const behavior = flag('behavior') || 'completed';
      if (!id || !ref) { console.error('Usage: ep submit <entityId> --ref <txRef> [--behavior completed]'); process.exit(1); }
      print(await epFetch('/api/receipts/submit', {
        method: 'POST', auth: true,
        body: { entity_id: id, transaction_ref: ref, agent_behavior: behavior },
      }));
      break;
    }

    case 'verify': {
      const id = args[1];
      if (!id) { console.error('Usage: ep verify <receiptId>'); process.exit(1); }
      print(await epFetch(`/api/verify/${encodeURIComponent(id)}`));
      break;
    }

    case 'dispute': {
      const receiptId = args[1];
      const reason = flag('reason');
      if (!receiptId || !reason) { console.error('Usage: ep dispute <receiptId> --reason <reason>'); process.exit(1); }
      print(await epFetch('/api/disputes/file', {
        method: 'POST', auth: true,
        body: { receipt_id: receiptId, reason },
      }));
      break;
    }

    case 'appeal': {
      const disputeId = args[1];
      const reason = flag('reason');
      if (!disputeId || !reason) { console.error('Usage: ep appeal <disputeId> --reason "..."'); process.exit(1); }
      print(await epFetch('/api/disputes/appeal', {
        method: 'POST', auth: true,
        body: { dispute_id: disputeId, reason },
      }));
      break;
    }

    case 'policies': {
      print(await epFetch('/api/policies'));
      break;
    }

    case 'health': {
      print(await epFetch('/api/health'));
      break;
    }

    default:
      console.error(`Unknown command: ${command}. Run 'ep --help' for usage.`);
      process.exit(1);
  }
}

main().catch(err => { console.error(err.message); process.exit(1); });
