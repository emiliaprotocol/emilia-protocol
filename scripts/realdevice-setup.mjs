#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from realdevice-setup.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Real-device Class A acceptance — the setup half (no finger required here).
//
// Creates a throwaway initiating agent (directly via the service client, so
// it never hits the registration rate limit), mints the $82k receipt over
// HTTP, and opens a signoff. Then prints the two URLs you click in a real
// browser (Safari or Chrome) to do the Touch ID half. Run with the dev
// server up on port 3000:
//
//   npm run dev            # in one terminal (or already running)
//   node scripts/realdevice-setup.mjs
//
// The only thing this script can't do is your fingerprint.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
const BASE = process.env.EP_LOCAL_BASE || 'http://localhost:3000';
const RUN = `${Date.now().toString(36)}`;
// Minimal .env.local loader (no dotenv dep); values are never printed.
for (const line of fs.readFileSync('.env.local', 'utf8').split('\n')) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && !process.env[m[1]])
        process.env[m[1]] = m[2].replace(/^"|"$/g, '');
}
const sha256Hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
async function post(path, body, headers = {}) {
    const res = await fetch(`${BASE}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
    });
    const text = await res.text();
    let json;
    try {
        json = JSON.parse(text);
    }
    catch {
        json = { raw: text };
    }
    return { ok: res.ok, status: res.status, json };
}
async function main() {
    try {
        await fetch(`${BASE}/`, { method: 'GET' });
    }
    catch {
        console.error('\n✗ Cannot reach the dev server at %s. Start it first: npm run dev', BASE);
        process.exit(1);
    }
    if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
        console.error('\n✗ NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.');
        process.exit(1);
    }
    const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
    // 1. Create a throwaway initiating agent directly (mirrors the register
    //    route's entity + api_keys writes — same hashing, so the key
    //    authenticates — but bypasses the IP rate limit).
    const apiKey = `ep_live_${crypto.randomBytes(32).toString('hex')}`;
    const apiKeyHash = sha256Hex(apiKey);
    const entityId = `realdevice-initiator-${RUN}`;
    const { data: entity, error: entErr } = await supabase
        .from('entities')
        .insert({
        entity_id: entityId,
        owner_id: `ep_owner_${crypto.randomUUID()}`,
        display_name: 'Real-device acceptance initiator',
        entity_type: 'agent',
        description: 'Throwaway initiating agent for the Class A real-device signoff test',
        api_key_hash: apiKeyHash,
    })
        .select('id, entity_id')
        .single();
    if (entErr) {
        console.error('\n✗ Entity create failed: %s', entErr.message);
        process.exit(1);
    }
    const { error: keyErr } = await supabase.from('api_keys').insert({
        entity_id: entity.id,
        key_hash: apiKeyHash,
        key_prefix: apiKey.slice(0, 16),
        label: 'realdevice test key',
    });
    if (keyErr) {
        console.error('\n✗ API key create failed: %s', keyErr.message);
        process.exit(1);
    }
    // 2. Mint the $82k receipt — high amount + bank change ⇒ signoff required.
    const mint = await post('/api/v1/trust-receipts', {
        organization_id: `org-realdevice-${RUN}`,
        action_type: 'large_payment_release',
        target_resource_id: `wire/realdevice-${RUN}`,
        amount: 82000,
        currency: 'USD',
        target_changed_fields: ['bank_account'],
        risk_flags: ['new_destination', 'after_hours'],
    }, { Authorization: `Bearer ${apiKey}` });
    if (!mint.ok || !mint.json.signoff_required) {
        console.error('\n✗ Mint failed or signoff not required. status: %s body: %s', mint.status, JSON.stringify(mint.json));
        process.exit(1);
    }
    // 3. Open the signoff.
    const req = await post('/api/v1/signoffs/request', {
        receipt_id: mint.json.receipt_id,
    }, { Authorization: `Bearer ${apiKey}` });
    if (!req.ok) {
        console.error('\n✗ Signoff request failed. status: %s body: %s', req.status, JSON.stringify(req.json));
        process.exit(1);
    }
    const approverId = `ep:approver:realdevice-${RUN}`;
    const signoffUrl = `${BASE}/signoff/${req.json.signoff_id}?approver=${encodeURIComponent(approverId)}`;
    const b = (s) => `\x1b[1m${s}\x1b[0m`;
    const g = (s) => `\x1b[32m${s}\x1b[0m`;
    console.log('\n%s', b('═══ Class A real-device acceptance — your two-touch checklist ═══'));
    console.log('\nUse %s (not the terminal). Touch ID works on http://localhost.', b('Safari or Chrome'));
    console.log('\n%s', b('STEP 1 — Enroll your Touch ID as the approver key'));
    console.log('  Open:        %s', g(`${BASE}/approvers/enroll`));
    console.log('  EP API key:  %s', apiKey);
    console.log('  Approver ID: %s', approverId);
    console.log('  Name:        Real Device Test');
    console.log('  → Click "Create passkey", touch the sensor. Expect: "Enrolled … key class A".');
    console.log('\n%s', b('STEP 2 — Sign the $82,000 wire'));
    console.log('  Open:        %s', g(signoffUrl));
    console.log('  → Review the amount + target, click "Approve & sign", touch the sensor.');
    console.log('    Expect: "Signed and approved — key class A".');
    console.log('\n%s', b('STEP 3 — Prove it verifies offline (back here in the terminal)'));
    console.log('  Run:         %s', g(`node scripts/e2e-offline-verify.mjs ${req.json.signoff_id}`));
    console.log('  → Expect: VALID ✅, forgery rejected ❌, and your real time_to_sign_ms.');
    console.log('\n%s', b('Reference'));
    console.log('  signoff_id:  %s', req.json.signoff_id);
    console.log('  receipt_id:  %s', mint.json.receipt_id);
    console.log('  (Throwaway test entity; the key can do nothing privileged — fine to leave.)\n');
}
main().catch((e) => { console.error(e); process.exit(1); });
