// SPDX-License-Identifier: Apache-2.0
// POST /api/fire-drill — run the Agent Action Firewall Test on pasted JSON
// (an MCP manifest, OpenAPI spec, or tool list) and return the report. This is
// the web surface over the same scanner that powers `npx @emilia-protocol/fire-drill`.

import { NextResponse } from 'next/server';
import { scan } from '../../../packages/fire-drill/index.js';

export const runtime = 'nodejs';

const MAX_BYTES = 512 * 1024; // a manifest/spec, not a payload

export async function POST(request) {
  let raw;
  try {
    raw = await request.text();
  } catch {
    return NextResponse.json({ error: 'could not read body' }, { status: 400 });
  }
  if (raw.length > MAX_BYTES) {
    return NextResponse.json({ error: 'input too large (max 512KB)' }, { status: 413 });
  }
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: 'input must be valid JSON (MCP manifest, OpenAPI spec, or tool array)' }, { status: 400 });
  }
  try {
    const report = scan(input);
    return NextResponse.json(report);
  } catch (e) {
    return NextResponse.json({ error: e.message }, { status: 422 });
  }
}
