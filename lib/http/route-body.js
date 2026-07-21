// SPDX-License-Identifier: Apache-2.0

import { epProblem } from '../errors.js';
import { readLimitedJson } from './body-limit.js';

/**
 * @returns {Promise<{ok: false, response: any, error: any, value?: undefined} | {ok: true, value: any, response?: undefined, error?: undefined}>}
 */
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
