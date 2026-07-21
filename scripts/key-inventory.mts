#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// API key inventory + integrity audit (read-only).
//
// Part of the key-rotation runbook (docs/KEY-ROTATION-RUNBOOK.md). Answers:
// which keys exist, their age, prefix, owning entity/org, and last-seen — and
// flags integrity anomalies from the migration-113 window when api_keys was
// briefly anon-writable (an attacker could have INSERTed a forged key or
// tampered with rows). Never prints key_hash. Mutates nothing.
//
// Usage: node scripts/key-inventory.mjs   (npm run keys:inventory)
// Needs: NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY (reads .env.local)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClient } from '@supabase/supabase-js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
for (const file of ['.env.local', '.env']) {
  const p = path.join(ROOT, file);
  if (!fs.existsSync(p)) continue;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}
const URL: string | undefined = process.env.NEXT_PUBLIC_SUPABASE_URL;
const KEY: string | undefined = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY;
if (!URL || !KEY) { console.error('FATAL: need NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY'); process.exit(2); }

const days = (iso: string | null | undefined): number | null => iso ? Math.floor((Date.now() - new Date(iso).getTime()) / 86400000) : null;

const main = async (): Promise<void> => {
  const sb = createClient(URL, KEY, { auth: { persistSession: false } });
  const { data: keys, error: ke } = await sb
    .from('api_keys')
    .select('id, entity_id, key_prefix, label, permissions, last_used_at, created_at, revoked_at, invalidated_at');
  if (ke) { console.error('FATAL reading api_keys:', ke.message); process.exit(2); }
  const { data: ents } = await sb.from('entities').select('id, display_name, organization_id, status');
  const entById: Map<any, any> = new Map((ents || []).map((e: any) => [e.id, e]));

  const active = (keys || []).filter((k: any) => !k.revoked_at);
  const revoked = (keys || []).filter((k: any) => k.revoked_at);

  // group active keys per entity (multi-active = the injection/anomaly signal)
  const activeByEntity: Map<any, any[]> = new Map();
  for (const k of active) {
    if (!activeByEntity.has(k.entity_id)) activeByEntity.set(k.entity_id, []);
    (activeByEntity.get(k.entity_id) as any[]).push(k);
  }
  const multiActive = [...activeByEntity.entries()].filter(([, ks]) => ks.length > 1);
  const neverUsedActive = active.filter((k: any) => !k.last_used_at);
  const orphanEntity = (keys || []).filter((k: any) => !entById.has(k.entity_id)); // key for a non-existent entity = red flag

  const byOrg: Map<any, number> = new Map();
  for (const k of active) {
    const org = entById.get(k.entity_id)?.organization_id || '(none)';
    byOrg.set(org, (byOrg.get(org) || 0) + 1);
  }

  console.log(`\nEP API key inventory — ${new Date().toISOString()}`);
  console.log(`Project: ${URL.replace(/^https?:\/\//, '').split('.')[0]}\n`);
  console.log(`  total keys:        ${keys.length}`);
  console.log(`  active:            ${active.length}`);
  console.log(`  revoked:           ${revoked.length}`);
  console.log(`  active never-used: ${neverUsedActive.length}  (dormant — low-blast-radius revoke candidates)`);
  console.log(`  active by org:`);
  for (const [org, n] of [...byOrg.entries()].sort((a, b) => b[1] - a[1])) console.log(`      ${n.toString().padStart(4)}  ${org}`);

  console.log(`\n  INTEGRITY FLAGS (migration-113 anon-write window):`);
  console.log(`    entities with >1 active key: ${multiActive.length}` +
    (multiActive.length ? '  ← inspect: legitimate multi-key, or injected?' : '  ✓'));
  for (const [eid, ks] of multiActive.slice(0, 25)) {
    const e = entById.get(eid);
    console.log(`        entity ${e?.display_name || eid} (${eid}) org=${e?.organization_id || '-'} — ${ks.length} active:`);
    for (const k of ks) console.log(`            ${k.key_prefix}… created=${k.created_at?.slice(0, 10)} (${days(k.created_at)}d) last_used=${k.last_used_at ? k.last_used_at.slice(0, 10) : 'NEVER'} label=${k.label || '-'}`);
  }
  console.log(`    keys for non-existent entity (orphans): ${orphanEntity.length}` + (orphanEntity.length ? '  ← RED FLAG' : '  ✓'));
  for (const k of orphanEntity.slice(0, 25)) console.log(`        ${k.key_prefix}… entity_id=${k.entity_id} created=${k.created_at?.slice(0, 10)}`);

  // age distribution of active keys
  const ages: (number | null)[] = active.map((k: any) => days(k.created_at)).filter((d: any) => d != null);
  (ages as number[]).sort((a, b) => a - b);
  if (ages.length) {
    console.log(`\n  active key age (days): min=${ages[0]} median=${ages[Math.floor(ages.length / 2)]} max=${ages[ages.length - 1]}`);
  }
  console.log('\n  (no key_hash printed; read-only; nothing mutated)\n');

  // machine-readable dump for the operator (not committed; scratchpad)
  const out: Record<string, any> = { generated_at: new Date().toISOString(), totals: { total: (keys || []).length, active: active.length, revoked: revoked.length, neverUsedActive: neverUsedActive.length }, multiActive: multiActive.map(([eid, ks]: any[]) => ({ entity_id: eid, count: ks.length })), orphanEntity: orphanEntity.map((k: any) => ({ id: k.id, entity_id: k.entity_id, key_prefix: k.key_prefix })) };
  const dump: string | undefined = process.env.KEY_INVENTORY_OUT;
  if (dump) { fs.writeFileSync(dump, JSON.stringify(out, null, 2)); console.log(`  wrote ${dump}\n`); }
};
main().catch((e) => { console.error('FATAL:', e); process.exit(2); });
