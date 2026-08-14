// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import { AuthorityRecordServiceError } from '@/lib/works/authority-record-service';
import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import { BillingServiceError, createAuthorityMonitoringCheckout } from '@/lib/works/billing-service';
import { isWorksV0Enabled } from '@/lib/works/env';
import { createStripeCheckout } from '@/lib/works/stripe-gateway';
import { ownerBearer } from '../../../_shared';

type Context = { params: Promise<{ recordId: string }> };

function failure(error: unknown) {
  if (error instanceof BillingServiceError || error instanceof AuthorityRecordServiceError) {
    return epProblem(error.status, error.code, error.message);
  }
  return epProblem(500, 'authority_billing_internal_error', 'Monitoring checkout failed.');
}

export async function POST(request: NextRequest, { params }: Context) {
  if (!isWorksV0Enabled()) return epProblem(404, 'not_found', 'Not found');
  const ownerToken = ownerBearer(request);
  if (!ownerToken) return epProblem(404, 'not_found', 'Not found');
  try {
    const { recordId } = await params;
    const result = await createAuthorityMonitoringCheckout({
      recordId,
      ownerToken,
      authorityStore: createSupabaseAuthorityRecordStore(),
      priceId: process.env.STRIPE_PRICE_AUTHORITY_RECORD_MONITOR || '',
      siteOrigin: process.env.NEXT_PUBLIC_APP_URL || process.env.NEXT_PUBLIC_SITE_URL || '',
      createCheckout: createStripeCheckout,
    });
    return Response.json(result, {
      headers: { 'cache-control': 'no-store, max-age=0', 'x-content-type-options': 'nosniff' },
    });
  } catch (error) {
    return failure(error);
  }
}
