import { NextResponse } from 'next/server';

export async function GET(request) {
  const url = new URL('/landing.html', request.url);
  return NextResponse.rewrite(url);
}
