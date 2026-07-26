// SPDX-License-Identifier: Apache-2.0
declare module '*.mjs' {
  export const computeCaid: (
    action: unknown,
    options: unknown,
  ) => { caid?: string; refusals?: string[] };
}

declare module '@emilia-protocol/verify/aeb-adapter-contract' {
  export const digestAeb: (value: unknown) => string;
}
