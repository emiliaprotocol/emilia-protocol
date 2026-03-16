#!/usr/bin/env node
/**
 * @emilia-protocol/cli
 * 
 * Usage:
 *   ep register <entity_id> --name "Display Name" [--type agent]
 *   ep profile <entity_id>
 *   ep evaluate <entity_id> [--policy strict|standard|permissive|discovery]
 *   ep submit <entity_id> --ref <transaction_ref> [--behavior completed]
 *   ep preflight <entity_id> [--policy mcp_server_safe_v1]
 *   ep score <entity_id>
 *   ep dispute <dispute_id>
 *   ep policies
 *   ep health
 * 
 * Environment:
 *   EP_BASE_URL  — API base (default: https://emiliaprotocol.ai)
 *   EP_API_KEY   — API key for write operations
 */

import { EPClient } from '../lib/client.mjs';

const BASE = process.env.EP_BASE_URL || 'https://emiliaprotocol.ai';
const KEY = process.env.EP_API_KEY || '';

const client = new EPClient(BASE, KEY);
const args = process.argv.slice(2);
const cmd = args[0];

function flag(name) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}

function print(data) {
  console.log(JSON.stringify(data, null, 2));
}

function usage() {
  console.log(`
EMILIA Protocol CLI

Commands:
  ep register <id> --name "Name"  Register a new entity
  ep profile <id>                 Get trust profile
  ep evaluate <id> [--policy X]   Evaluate against policy (default: standard)
  ep submit <id> --ref <ref>      Submit a receipt
  ep preflight <id> [--policy X]  Run install preflight
  ep score <id>                   Get compatibility score (legacy)
  ep dispute <dispute_id>         Check dispute status
  ep policies                     List all trust policies
  ep health                       Check API health

Environment:
  EP_BASE_URL    API base URL (default: https://emiliaprotocol.ai)
  EP_API_KEY     API key for write operations

Examples:
  ep profile merchant-xyz
  ep evaluate merchant-xyz --policy strict
  ep submit merchant-xyz --ref order_123 --behavior completed
  ep preflight mcp-server-abc --policy mcp_server_safe_v1
`);
}

async function run() {
  try {
    switch (cmd) {
      case 'register': {
        const id = args[1];
        const name = flag('name') || id;
        const type = flag('type') || 'agent';
        if (!id) { console.error('Usage: ep register <entity_id> --name "Name"'); process.exit(1); }
        print(await client.register(id, name, type));
        break;
      }
      case 'profile': {
        const id = args[1];
        if (!id) { console.error('Usage: ep profile <entity_id>'); process.exit(1); }
        const p = await client.profile(id);
        console.log(`\n  ${p.display_name || id}`);
        console.log(`  Confidence: ${p.current_confidence}`);
        console.log(`  Score: ${p.compat_score}/100`);
        console.log(`  Evidence: ${p.effective_evidence_current} (quality-gated: ${p.quality_gated_evidence_current ?? 'n/a'})`);
        console.log(`  Established: ${p.historical_establishment ? 'Yes' : 'No'}`);
        console.log(`  Receipts: ${p.receipt_count}\n`);
        if (p.trust_profile?.behavioral) {
          console.log(`  Behavioral:`);
          console.log(`    Completion: ${p.trust_profile.behavioral.completion_rate}%`);
          console.log(`    Dispute:    ${p.trust_profile.behavioral.dispute_rate}%\n`);
        }
        break;
      }
      case 'evaluate': {
        const id = args[1];
        const policy = flag('policy') || 'standard';
        if (!id) { console.error('Usage: ep evaluate <entity_id> [--policy X]'); process.exit(1); }
        const r = await client.evaluate(id, policy);
        console.log(`\n  Policy: ${policy}`);
        console.log(`  Pass: ${r.pass ? '✓ YES' : '✗ NO'}`);
        console.log(`  Score: ${r.score}/100`);
        console.log(`  Confidence: ${r.confidence}`);
        if (r.failures?.length) {
          console.log(`  Failures:`);
          r.failures.forEach(f => console.log(`    - ${f}`));
        }
        console.log('');
        break;
      }
      case 'submit': {
        const id = args[1];
        const ref = flag('ref');
        const behavior = flag('behavior') || 'completed';
        if (!id || !ref) { console.error('Usage: ep submit <entity_id> --ref <transaction_ref>'); process.exit(1); }
        if (!KEY) { console.error('EP_API_KEY required for write operations.'); process.exit(1); }
        print(await client.submit(id, ref, behavior));
        break;
      }
      case 'preflight': {
        const id = args[1];
        const policy = flag('policy') || 'standard';
        if (!id) { console.error('Usage: ep preflight <entity_id> [--policy X]'); process.exit(1); }
        const r = await client.preflight(id, policy);
        const icon = r.decision === 'allow' ? '✓' : r.decision === 'deny' ? '✗' : '⚠';
        console.log(`\n  ${icon} ${r.decision?.toUpperCase()} — ${id}`);
        console.log(`  Policy: ${r.policy_used || policy}`);
        if (r.reasons?.length) {
          r.reasons.forEach(reason => console.log(`    ${reason}`));
        }
        console.log('');
        break;
      }
      case 'score': {
        const id = args[1];
        if (!id) { console.error('Usage: ep score <entity_id>'); process.exit(1); }
        print(await client.score(id));
        break;
      }
      case 'dispute': {
        const id = args[1];
        if (!id) { console.error('Usage: ep dispute <dispute_id>'); process.exit(1); }
        print(await client.dispute(id));
        break;
      }
      case 'policies': {
        print(await client.policies());
        break;
      }
      case 'health': {
        const h = await client.health();
        console.log(`\n  EP Health: ${h.status || 'ok'}`);
        console.log(`  Version: ${h.protocol_version || 'unknown'}\n`);
        break;
      }
      case '--help':
      case '-h':
      case 'help':
      case undefined:
        usage();
        break;
      default:
        console.error(`Unknown command: ${cmd}`);
        usage();
        process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

run();
