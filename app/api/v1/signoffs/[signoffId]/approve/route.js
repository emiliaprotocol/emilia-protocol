// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/[signoffId]/approve
//
// Thin route wrapper that delegates to handleSignoffDecision in
// lib/guard-signoff.js. The shared logic was previously in this file and
// re-imported by the /reject sibling — extracted to lib/ so the import
// graph doesn't depend on sibling route.js modules being importable.

import { handleSignoffDecision } from '@/lib/guard-signoff';

export async function POST(request, { params }) {
  return handleSignoffDecision(request, params, 'approved');
}
