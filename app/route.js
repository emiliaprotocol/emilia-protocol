import { readFileSync } from 'fs';
import { join } from 'path';
import { assertServerEnv } from '@/lib/env';

// Validate critical server-only environment variables early. In production
// this will throw and prevent startup; in development it warns.
assertServerEnv({ required: ['SUPABASE_SERVICE_ROLE_KEY'] });

export async function GET() {
  const html = readFileSync(join(process.cwd(), 'public', 'landing.html'), 'utf8');
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
