#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from purge-serialized-entities.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Security remediation for the pre-7c5cfcf bug where auth.entity (the full
// entity ROW, including api_key_hash and private_key_encrypted) was stored
// where a string id belonged. Sanitizes those fields back to the entity_id
// string — the value the fixed code now writes — removing the secrets.
//
//   node scripts/purge-serialized-entities.mjs           # dry run (default)
//   node scripts/purge-serialized-entities.mjs --apply    # write changes
//
// Posture:
//  - approver_credentials.attested_by is sanitized in place (not append-only).
//  - audit_events is append-only + evidence-bearing; this script REPORTS any
//    exposure there but does NOT rewrite the log. If any are found, decide
//    deliberately (a sealed redaction event) rather than silently editing.
import fs from 'node:fs';
import { createClient } from '@supabase/supabase-js';
const APPLY = process.argv.includes('--apply');
for (const line of fs.readFileSync('.env.local', 'utf8').split('\n')) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && !process.env[m[1]])
        process.env[m[1]] = m[2].replace(/^"|"$/g, '');
}
if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('✗ NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set (checked .env.local and the environment).');
    process.exit(1);
}
const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
const SECRET_KEYS = ['api_key_hash', 'private_key_encrypted', 'api_key'];
const hasSecret = (v) => !!(v && typeof v === 'object' && SECRET_KEYS.some((k) => k in v));
const idOf = (v) => (v && typeof v === 'object' ? (v.entity_id || v.id || null) : v);
const exposedEntities = new Set();
// ── 1. audit_events — report only (append-only, evidence-bearing) ───────────
const { data: events, error: evErr } = await sb.from('audit_events')
    .select('id, event_type, after_state')
    .in('event_type', [
    'guard.signoff.requested', 'guard.signoff.approved', 'guard.signoff.rejected',
    'guard.trust_receipt.created', 'guard.trust_receipt.consumed',
]);
if (evErr) {
    console.error('audit_events scan failed:', evErr.message);
    process.exit(1);
}
const evBad = [];
for (const e of events || []) {
    const a = e.after_state || {};
    for (const f of ['actor_id', 'initiator_id', 'approver_id']) {
        if (hasSecret(a[f])) {
            evBad.push({ id: e.id, type: e.event_type, field: f });
            exposedEntities.add(idOf(a[f]));
        }
    }
}
console.log(`audit_events: ${evBad.length} row(s) with a serialized entity (REPORT ONLY — append-only log).`);
for (const r of evBad)
    console.log(`  • ${r.type}.${r.field}  (id ${r.id})`);
if (evBad.length) {
    console.log('  → audit_events is append-only + feeds evidence export. Do NOT silently edit.');
    console.log('    Remediate with a deliberate sealed-redaction migration, reviewed separately.');
}
// ── 2. approver_credentials.attested_by — sanitize in place ─────────────────
const { data: creds, error: credErr } = await sb.from('approver_credentials')
    .select('id, approver_id, attested_by');
if (credErr) {
    console.error('approver_credentials scan failed:', credErr.message);
    process.exit(1);
}
const credBad = [];
for (const c of creds || []) {
    let parsed = c.attested_by;
    if (typeof parsed === 'string') {
        try {
            parsed = JSON.parse(parsed);
        }
        catch {
            parsed = c.attested_by;
        }
    }
    if (hasSecret(parsed)) {
        credBad.push({ id: c.id, approver_id: c.approver_id, clean: idOf(parsed) });
        exposedEntities.add(idOf(parsed));
    }
}
console.log(`\napprover_credentials: ${credBad.length} row(s) with a serialized attested_by.`);
for (const r of credBad) {
    console.log(`  • ${r.approver_id}  attested_by → "${r.clean}"  (id ${r.id})`);
    if (APPLY) {
        const { error } = await sb.from('approver_credentials').update({ attested_by: r.clean }).eq('id', r.id);
        console.log(error ? `      ✗ update failed: ${error.message}` : '      ✓ sanitized');
    }
}
// ── 3. Rotation guidance ────────────────────────────────────────────────────
console.log('\n=== entities whose secrets were serialized (rotate if any is REAL) ===');
if (exposedEntities.size === 0) {
    console.log('  none');
}
else {
    for (const id of exposedEntities) {
        const { data: ent } = await sb.from('entities').select('entity_id, entity_type, display_name, created_at').eq('entity_id', id).maybeSingle();
        const tag = /e2e|realdevice|test|throwaway/i.test(id || '') ? 'TEST (likely safe to ignore)' : 'REVIEW — rotate its API key if this is real';
        console.log(`  • ${id}  [${ent?.entity_type || '?'}]  ${tag}`);
    }
}
console.log(APPLY ? '\nApplied.' : '\nDry run — re-run with --apply to sanitize approver_credentials.');
