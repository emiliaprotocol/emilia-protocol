import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

export function getServiceClient() {
  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('Missing Supabase environment variables');
  }
  return createClient(supabaseUrl, supabaseServiceKey);
}

export function generateApiKey() {
  const key = `ep_live_${crypto.randomBytes(32).toString('hex')}`;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return { key, hash, prefix: key.slice(0, 16) };
}

export function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

export async function authenticateRequest(request) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ep_')) {
    return { error: 'Missing or invalid API key. Use: Authorization: Bearer ep_live_...' };
  }

  const apiKey = authHeader.replace('Bearer ', '');
  const keyHash = hashApiKey(apiKey);
  const supabase = getServiceClient();

  const { data: keyRecord } = await supabase
    .from('api_keys')
    .select('entity_id, permissions')
    .eq('key_hash', keyHash)
    .is('revoked_at', null)
    .single();

  if (!keyRecord) {
    return { error: 'Invalid or revoked API key' };
  }

  await supabase
    .from('api_keys')
    .update({ last_used_at: new Date().toISOString() })
    .eq('key_hash', keyHash);

  const { data: entity } = await supabase
    .from('entities')
    .select('*')
    .eq('id', keyRecord.entity_id)
    .single();

  if (!entity || entity.status !== 'active') {
    return { error: 'Entity is inactive or suspended' };
  }

  return { entity, permissions: keyRecord.permissions };
}
