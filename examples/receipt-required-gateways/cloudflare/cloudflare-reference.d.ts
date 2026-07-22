// Minimal Durable Object declarations for standalone example type-checking.
// A deployed Worker project should use Cloudflare's current generated types.
interface DurableObjectTransaction {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
}

interface DurableObjectStorage {
  transaction<T>(callback: (transaction: DurableObjectTransaction) => Promise<T>): Promise<T>;
}

interface DurableObjectState {
  storage: DurableObjectStorage;
}

interface DurableObjectStub {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

interface DurableObjectNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): DurableObjectStub;
}
