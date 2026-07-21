#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from mobile-live-demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import process from 'node:process';
import QRCode from 'qrcode';
const SCENARIOS = new Set(['grid', 'treasury', 'healthcare']);
const APPROVER = /^[A-Za-z0-9:_.@-]{3,128}$/;
function argumentsFrom(argv) {
    const result = {};
    for (let index = 0; index < argv.length; index += 1) {
        const item = argv[index];
        if (item === '--json')
            result.json = true;
        else if (item === '--help' || item === '-h')
            result.help = true;
        else if (item.startsWith('--')) {
            const value = argv[index + 1];
            if (!value || value.startsWith('--'))
                throw new Error(`${item} requires a value`);
            result[item.slice(2)] = value;
            index += 1;
        }
        else
            throw new Error(`unknown argument: ${item}`);
    }
    return result;
}
function usage() {
    return `Usage:
  npm run mobile:live-demo -- --approver <id> [--scenario grid|treasury|healthcare]

Environment:
  EMILIA_API_KEY       Required API key; never printed.
  EMILIA_API_BASE_URL  Optional origin. Defaults to https://www.emiliaprotocol.ai.

Options:
  --json               Emit machine-readable output without the terminal QR.
  --help               Show this help.`;
}
async function post(baseURL, apiKey, path, body) {
    const response = await fetch(new URL(path, baseURL), {
        method: 'POST',
        headers: {
            authorization: `Bearer ${apiKey}`,
            'content-type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15_000),
    });
    const text = await response.text();
    let parsed;
    try {
        parsed = text ? JSON.parse(text) : {};
    }
    catch {
        parsed = { detail: text };
    }
    if (!response.ok) {
        throw new Error(`${path} refused with HTTP ${response.status}: ${parsed.detail || parsed.error || parsed.code || 'unknown error'}`);
    }
    return parsed;
}
async function main() {
    const args = argumentsFrom(process.argv.slice(2));
    if (args.help) {
        process.stdout.write(`${usage()}\n`);
        return;
    }
    const apiKey = process.env.EMILIA_API_KEY?.trim();
    const approver = args.approver || process.env.EMILIA_MOBILE_APPROVER_ID;
    const scenario = args.scenario || 'grid';
    if (!apiKey)
        throw new Error('EMILIA_API_KEY is required');
    if (!APPROVER.test(approver || ''))
        throw new Error('--approver must be 3-128 characters of [A-Za-z0-9:_.@-]');
    if (!SCENARIOS.has(scenario))
        throw new Error('--scenario must be grid, treasury, or healthcare');
    const baseURL = new URL(process.env.EMILIA_API_BASE_URL || 'https://www.emiliaprotocol.ai');
    if (baseURL.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(baseURL.hostname)) {
        throw new Error('EMILIA_API_BASE_URL must use HTTPS');
    }
    const pairing = await post(baseURL, apiKey, '/api/v1/mobile/pairings', { approver_id: approver });
    const action = await post(baseURL, apiKey, '/api/v1/mobile/demo/actions', {
        approver_id: approver,
        scenario: scenario,
    });
    const pairingURL = new URL('/mobile/pair', baseURL);
    pairingURL.searchParams.set('code', pairing.pairing_code);
    const result = {
        scenario,
        approver_id: approver,
        pairing_code: pairing.pairing_code,
        pairing_url: pairingURL.toString(),
        pairing_expires_at: pairing.expires_at,
        action_reference: action.action_reference,
        action_expires_at: action.expires_at,
        enabled_platforms: pairing.enabled_platforms,
    };
    if (args.json) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return;
    }
    const qr = await QRCode.toString(result.pairing_url, {
        type: 'terminal',
        small: true,
        errorCorrectionLevel: 'M',
    });
    process.stdout.write(`\nEMILIA APPROVER / LIVE ${scenario.toUpperCase()} CEREMONY\n\n`);
    process.stdout.write('Scan with the phone that will make the protected decision.\n');
    process.stdout.write(qr);
    process.stdout.write(`\nPairing code: ${result.pairing_code}\n`);
    process.stdout.write(`Action:       ${result.action_reference}\n`);
    process.stdout.write(`Approver:     ${result.approver_id}\n`);
    process.stdout.write(`Platforms:    ${result.enabled_platforms.join(', ')}\n`);
    process.stdout.write(`Expires:      ${result.pairing_expires_at}\n\n`);
}
main().catch((error) => {
    process.stderr.write(`mobile demo failed: ${error.message}\n`);
    process.exitCode = 1;
});
