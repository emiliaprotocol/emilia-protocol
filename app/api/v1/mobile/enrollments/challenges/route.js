// SPDX-License-Identifier: Apache-2.0
import { handleMobilePost } from '@/lib/mobile/route.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request) {
  return handleMobilePost(request);
}
