// SPDX-License-Identifier: Apache-2.0
import { handleMobileRuntimeRequest } from './runtime.js';
import { mobileProblem } from './response.js';
import { logger } from '@/lib/logger.js';

export async function handleMobilePost(request: Request): Promise<Response> {
  try {
    return await handleMobileRuntimeRequest(request);
  } catch (error) {
    logger.error('[mobile] production runtime unavailable', error);
    return mobileProblem(
      503,
      'refuse_store_unavailable',
      'Mobile authorization service unavailable',
    );
  }
}
