// SPDX-License-Identifier: Apache-2.0
// Generated from agent.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { defineAgent } from 'eve';
// A minimal Eve agent that exposes two irreversible tools (release_funds,
// delete_repo), both gated by EMILIA Receipt-Required. Model resolves through
// Vercel AI Gateway; swap for any gateway model string.
export default defineAgent({
    model: 'openai/gpt-5.4-mini',
});
