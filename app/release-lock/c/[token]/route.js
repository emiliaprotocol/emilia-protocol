// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { exchangeReleaseLockCapability } from '../../api';

export const dynamic = 'force-dynamic';

function redirectWithoutCapability(request, path) {
  const destination = new URL(path, request.url);
  destination.search = '';
  const response = NextResponse.redirect(destination, 303);
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

export async function GET(request, { params }) {
  const { token } = await params;

  try {
    const exchange = await exchangeReleaseLockCapability(token);
    const response = redirectWithoutCapability(request, exchange.clean_path);

    if (exchange.role === 'contractor' || exchange.role === 'customer') {
      response.cookies.set('release_lock_demo_role', exchange.role, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/release-lock',
        maxAge: 60 * 60,
      });
    }

    return response;
  } catch {
    return redirectWithoutCapability(request, '/release-lock/c');
  }
}
