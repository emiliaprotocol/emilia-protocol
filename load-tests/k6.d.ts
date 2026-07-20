interface K6Response {
  status: number;
  timings: { duration: number };
  json(): any;
}

declare const __ENV: Record<string, string | undefined>;
declare const __VU: number;
declare const __ITER: number;

declare module 'k6' {
  export function check(
    value: unknown,
    checks: Record<string, (value: K6Response) => boolean>,
  ): boolean;
  export function sleep(seconds: number): void;
  export function group<T>(name: string, body: () => T): T;
}

declare module 'k6/metrics' {
  export class Counter {
    readonly name: string;
    constructor(name: string);
    add(value: number): void;
  }
  export class Rate {
    readonly name: string;
    constructor(name: string);
    add(value: number | boolean): void;
  }
  export class Trend {
    readonly name: string;
    constructor(name: string, isTime?: boolean);
    add(value: number): void;
  }
}

declare module 'k6/data' {
  export class SharedArray<T> extends Array<T> {
    constructor(name: string, factory: () => T[]);
  }
}

declare module 'k6/http' {
  const http: {
    get(url: string, params?: object): K6Response;
    post(url: string, body?: string | null, params?: object): K6Response;
  };
  export default http;
}
