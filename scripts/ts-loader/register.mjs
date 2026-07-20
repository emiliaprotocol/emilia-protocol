// SPDX-License-Identifier: Apache-2.0
// Entry point for `node --import ./scripts/ts-loader/register.mjs <script>`.
// Registers the .js->.ts resolution hook (see resolve-ts.mjs) as a module
// customization hook, per Node's documented --import + register() pattern.
import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

register(new URL('./resolve-ts.mjs', import.meta.url));
