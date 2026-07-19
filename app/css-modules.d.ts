/**
 * Ambient module declaration for CSS Modules imports (`*.module.css`) used
 * throughout app/. Next.js ships this declaration in its own
 * `next/types/global.d.ts` (picked up automatically via `next-env.d.ts` in a
 * standard Next.js build), but `tsconfig.app.json`'s `types` field is scoped
 * to `["react", "node"]` only for this checkJs gate, so that ambient
 * declaration isn't reachable from this program. This file restates the
 * same shape locally so CSS Module imports type-check under
 * `tsconfig.app.json` without widening its `types` scope. Types-only, no
 * runtime effect — mirrors Next's own declaration verbatim.
 *
 * @license Apache-2.0
 */

declare module '*.module.css' {
  const classes: { readonly [key: string]: string };
  export default classes;
}

declare module '*.module.scss' {
  const classes: { readonly [key: string]: string };
  export default classes;
}

declare module '*.module.sass' {
  const classes: { readonly [key: string]: string };
  export default classes;
}
