// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { epProblem } from '../errors.js';
import { readLimitedJson, type BodyLimitError, type ReadLimitedJsonOptions } from './body-limit.js';

export type EpJsonResult =
  | { ok: true; value: any }
  | { ok: false; response: NextResponse; error: BodyLimitError };

export async function readEpJson(
  request: Request,
  maxBytes: number,
  options?: ReadLimitedJsonOptions,
): Promise<EpJsonResult> {
  const parsed = await readLimitedJson(request, maxBytes, options);
  if (!parsed.ok) {
    return {
      ok: false,
      response: epProblem(parsed.status, parsed.code, parsed.detail),
      error: parsed,
    };
  }
  return { ok: true, value: parsed.value };
}
