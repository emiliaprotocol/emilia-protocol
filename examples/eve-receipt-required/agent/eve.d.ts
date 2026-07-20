declare module 'eve' {
  export function defineAgent(config: { model: string }): unknown;
}

declare module 'eve/tools' {
  import type { output, ZodType } from 'zod';

  export function defineTool<TSchema extends ZodType>(definition: {
    description: string;
    inputSchema: TSchema;
    execute(input: output<TSchema>): unknown | Promise<unknown>;
  }): unknown;
}
