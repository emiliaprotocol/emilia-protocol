declare namespace Deno {
  function serve(handler: (request: Request) => Response | Promise<Response>): void;
}
