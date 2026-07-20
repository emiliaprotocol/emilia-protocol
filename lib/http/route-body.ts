// SPDX-License-Identifier: Apache-2.0

import { epProblem } from '../errors.js';
import { readLimitedJson } from './body-limit.js';

export async function readEpJson(request, maxBytes, options) {
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
