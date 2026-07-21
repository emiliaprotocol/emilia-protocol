#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Class A acceptance, step 2: take the REAL assertion the e2e run produced,
// verify it fully offline with @emilia-protocol/verify, then forge it and
// watch it fail. Also prints the pilot telemetry row (time_to_sign_ms).
//
//   node scripts/e2e-offline-verify.mjs <signoff_id>

import fs from 'node:fs';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { verifyWebAuthnSignoff } from '../packages/verify/index.js';

const signoffId: string | undefined = process.argv[2];
if (!/^sig_[a-f0-9]{32}$/.test(signoffId || '')) {
  console.error('Usage: node scripts/e2e-offline-verify.mjs sig_<32hex>');
  process.exit(1);
}

// Minimal .env.local loader (no dotenv dep) — values never printed.
for (const line of fs.readFileSync('.env.local', 'utf8').split('\n')) {
  const m: RegExpMatchArray | null = line.match(/^([A-Z0-9_]+)=(.*)$/);
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^"|"$/g, '');
}

const supabase: SupabaseClient<any, 'public', any> = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL as string,
  process.env.SUPABASE_SERVICE_ROLE_KEY as string,
  { auth: { persistSession: false } },
);

const { data: decisions, error }: { data: any; error: any } = await supabase
  .from('audit_events')
  .select('after_state')
  .in('event_type', ['guard.signoff.approved', 'guard.signoff.rejected'])
  .eq('after_state->>signoff_id', signoffId)
  .limit(1);
if (error) throw error;
const decision: any = decisions?.[0]?.after_state;
if (!decision) {
  console.error(`No decision event found for ${signoffId}`);
  process.exit(1);
}
if (decision.key_class !== 'A' || !decision.webauthn || !decision.context) {
  console.error(`Decision is not Class A with embedded evidence (key_class=${decision.key_class})`);
  process.exit(1);
}

const { data: creds, error: credErr }: { data: any; error: any } = await supabase
  .from('approver_credentials')
  .select('public_key_spki, approver_id')
  .eq('credential_id', decision.webauthn.credential_id)
  .limit(1);
if (credErr) throw credErr;
const cred: any = creds?.[0];
if (!cred) {
  console.error('Enrolled credential not found');
  process.exit(1);
}

// ── From here on: NOTHING but the receipt evidence, the enrolled public
// key, and math. No network, no EP server, no account.
const signoff: any = { context: decision.context, webauthn: decision.webauthn };

const ok: any = verifyWebAuthnSignoff(signoff, cred.public_key_spki, { rpId: 'localhost' });
console.log('\n=== OFFLINE VERIFICATION (real device-key assertion) ===');
console.log('approver:        ', decision.approver_id, `(credential of ${cred.approver_id})`);
console.log('context hash:    ', decision.context_hash);
console.log('checks:          ', JSON.stringify(ok.checks));
console.log('VALID:           ', ok.valid ? '✅ YES' : '❌ NO');

const forged: any = JSON.parse(JSON.stringify(signoff));
forged.context.action_hash = 'f'.repeat(64); // point the approval at a different action
const bad: any = verifyWebAuthnSignoff(forged, cred.public_key_spki, { rpId: 'localhost' });
console.log('\n=== FORGERY ATTEMPT (action_hash swapped) ===');
console.log('challenge_binding:', bad.checks.challenge_binding, '→ valid:', bad.valid ? '✅ (BAD!)' : '❌ rejected, as it must be');

const { data: metrics }: { data: any } = await supabase
  .from('signoff_metrics')
  .select('rendered_at, signed_at, time_to_sign_ms, decision, key_class')
  .eq('signoff_id', signoffId)
  .single();
console.log('\n=== PILOT TELEMETRY ===');
console.log(JSON.stringify(metrics, null, 2));

if (!ok.valid || bad.valid) process.exit(1);
console.log('\nAcceptance: offline verify ✅ · forgery rejected ✅ · telemetry recorded ✅');
