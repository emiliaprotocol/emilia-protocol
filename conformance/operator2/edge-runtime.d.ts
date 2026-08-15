declare module "jsr:@supabase/functions-js/edge-runtime.d.ts";

declare namespace Deno {
  function serve(handler: (request: Request) => Response | Promise<Response>): void;
}
