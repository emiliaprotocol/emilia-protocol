// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/[signoffId]/reject
//
// Same invariant set as /approve, just with a 'rejected' decision shape.
// Self-rejection is allowed (initiator can withdraw their own request) but
// any third-party rejection still requires authentication. Sharing the
// implementation keeps approve/reject semantics in lock-step.

import { handleSignoffDecision } from '../approve/route';

export async function POST(request, { params }) {
  return handleSignoffDecision(request, params, 'rejected');
}
