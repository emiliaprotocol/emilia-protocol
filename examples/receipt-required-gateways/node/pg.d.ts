// Minimal local type surface for this standalone reference. The repository
// intentionally does not take a root @types/pg dependency for one example.
declare module 'pg' {
  export class Pool {
    constructor(options: { connectionString: string; max?: number });
    query(text: string, values?: unknown[]): Promise<{ rowCount: number | null }>;
    end(): Promise<void>;
  }
}
