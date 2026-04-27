// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/[signoffId]/reject
//
// Thin route wrapper that delegates to the shared handler in
// lib/guard-signoff.js. Same invariant set as /approve; the only
// difference is the recorded decision.

import { handleSignoffDecision } from '@/lib/guard-signoff';

export async function POST(request, { params }) {
  return handleSignoffDecision(request, params, 'rejected');
}
