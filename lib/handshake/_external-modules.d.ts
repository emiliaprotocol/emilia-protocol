/**
 * Ambient declarations for repo-root `@/lib/*` modules that the handshake code
 * imports across the security-core scope boundary.
 *
 * The `tsconfig.core.json` gate deliberately scopes checkJs to three trees
 * (packages/verify, lib/handshake, packages/gate). The `@/lib/*` targets
 * (lib/actor.js, lib/crypto.js, lib/supabase.js, …) live at the repo root,
 * OUTSIDE that scope, and are intentionally not typed by this pass. Declaring
 * them as opaque ambient modules lets the in-scope handshake files resolve the
 * imports without pulling the entire root `lib/` tree into the type program.
 * This is types-only and changes no runtime behavior.
 *
 * @license Apache-2.0
 */

declare module '@/lib/*';
