// SPDX-License-Identifier: Apache-2.0
//
// Two durable stores, kept deliberately separate because the whole problem
// lives in the gap between them.
//
//   boundary journal  - the MCP server's own record of what it was about to
//                       do. Owned by the boundary. AEB-04 section 5.9 calls
//                       the pre-dispatch entry DISPATCH_PENDING.
//   provider record   - the effecting system's record of what actually
//                       happened. Owned by the provider, signed by the
//                       provider, and carrying a completeness watermark so
//                       that the ABSENCE of an entry can be authoritative
//                       rather than merely unobserved.
//
// The watermark is the honest part. AEB-04 section 5.11 says missing, stale,
// conflicting, unauthenticated or action-mismatched observations MUST leave
// the operation INDETERMINATE. Without a completeness statement, "I do not
// see your payment" is not evidence that it did not happen. With one, it is.
//
// Everything is fsync'd before the caller is told anything, so the injected
// crash cannot lose a write and the demo stays reproducible.

import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { join } from 'node:path';

export interface BoundaryEntry {
  replay_unit: string;
  state: 'DISPATCH_PENDING' | 'EXECUTED' | 'FAILED' | 'INDETERMINATE';
  caid: string;
  operation_id: string;
  authority_instance_digest: string;
  seq_floor: number;
  at: string;
}

export interface ProviderEntry {
  seq: number;
  operation_id: string;
  caid: string;
  amount: string;
  currency: string;
  beneficiary_account: string;
  at: string;
}

export interface ProviderWatermark {
  complete_through_seq: number;
  at: string;
}

/** A signed, point-in-time statement by the provider about one operation id. */
export interface ProviderStatement {
  statement: {
    operation_id: string;
    found: ProviderEntry | null;
    watermark: ProviderWatermark;
  };
  /** Ed25519 over the canonical JSON of `statement`, base64. */
  signature: string;
  public_key_spki_b64: string;
}

function fsyncAppend(path: string, line: string): void {
  appendFileSync(path, line, 'utf8');
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function readJsonl<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  const text = readFileSync(path, 'utf8');
  const out: T[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    out.push(JSON.parse(trimmed) as T);
  }
  return out;
}

/** RFC 8785-shaped enough for this example: sorted keys, no floats emitted. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(',')}}`;
}

export class Stores {
  readonly dir: string;
  readonly boundaryPath: string;
  readonly providerPath: string;
  readonly watermarkPath: string;
  readonly providerKeyPath: string;

  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
    this.boundaryPath = join(dir, 'boundary-journal.jsonl');
    this.providerPath = join(dir, 'provider-record.jsonl');
    this.watermarkPath = join(dir, 'provider-watermark.json');
    this.providerKeyPath = join(dir, 'provider-ed25519.pkcs8.b64');
    if (!existsSync(this.providerKeyPath)) {
      const { privateKey } = generateKeyPairSync('ed25519');
      const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
      writeFileSync(this.providerKeyPath, Buffer.from(pkcs8).toString('base64'), 'utf8');
    }
    if (!existsSync(this.watermarkPath)) {
      writeFileSync(
        this.watermarkPath,
        JSON.stringify({ complete_through_seq: 0, at: new Date(0).toISOString() }),
        'utf8',
      );
    }
  }

  // -- boundary journal -----------------------------------------------------

  boundaryEntries(): BoundaryEntry[] {
    return readJsonl<BoundaryEntry>(this.boundaryPath);
  }

  /** Last recorded state for a replay unit, or null if never seen. */
  latestFor(replayUnit: string): BoundaryEntry | null {
    let found: BoundaryEntry | null = null;
    for (const entry of this.boundaryEntries()) {
      if (entry.replay_unit === replayUnit) found = entry;
    }
    return found;
  }

  appendBoundary(entry: BoundaryEntry): void {
    fsyncAppend(this.boundaryPath, `${JSON.stringify(entry)}\n`);
  }

  // -- provider record ------------------------------------------------------

  providerEntries(): ProviderEntry[] {
    return readJsonl<ProviderEntry>(this.providerPath);
  }

  watermark(): ProviderWatermark {
    return JSON.parse(readFileSync(this.watermarkPath, 'utf8')) as ProviderWatermark;
  }

  /**
   * Apply the effect at the provider. This is the irreversible act. It is
   * durable (fsync) before it returns, and the watermark advances with it so
   * the provider can later answer "I have complete records through seq N".
   */
  applyEffect(input: {
    operation_id: string;
    caid: string;
    amount: string;
    currency: string;
    beneficiary_account: string;
    at: string;
  }): ProviderEntry {
    const seq = this.providerEntries().length + 1;
    const entry: ProviderEntry = { seq, ...input };
    fsyncAppend(this.providerPath, `${JSON.stringify(entry)}\n`);
    writeFileSync(
      this.watermarkPath,
      JSON.stringify({ complete_through_seq: seq, at: input.at }),
      'utf8',
    );
    const fd = openSync(this.watermarkPath, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return entry;
  }

  /**
   * Advance the watermark without an effect. Models the provider closing a
   * window: "nothing else landed up to here". Only this makes an absence
   * authoritative.
   */
  advanceWatermark(at: string): ProviderWatermark {
    const seq = this.providerEntries().length;
    const wm: ProviderWatermark = { complete_through_seq: seq, at };
    writeFileSync(this.watermarkPath, JSON.stringify(wm), 'utf8');
    return wm;
  }

  // -- authenticated provider statement --------------------------------------

  private providerPrivateKey() {
    const der = Buffer.from(readFileSync(this.providerKeyPath, 'utf8'), 'base64');
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  }

  providerPublicKeyB64(): string {
    const pub = createPublicKey(this.providerPrivateKey());
    return Buffer.from(pub.export({ type: 'spki', format: 'der' })).toString('base64');
  }

  /**
   * The provider's signed answer to "did operation X land?". This is what
   * AEB-04 section 5.11 means by authenticating the provider or system of
   * record. The signature is real Ed25519, not a claim that one exists.
   */
  statementFor(operationId: string): ProviderStatement {
    const found = this.providerEntries().find((e) => e.operation_id === operationId) ?? null;
    const statement = { operation_id: operationId, found, watermark: this.watermark() };
    const sig = sign(null, Buffer.from(canonical(statement), 'utf8'), this.providerPrivateKey());
    return {
      statement,
      signature: sig.toString('base64'),
      public_key_spki_b64: this.providerPublicKeyB64(),
    };
  }
}

/**
 * Verify a provider statement against a pinned public key. Returns a refusal
 * with a reason on any failure; never throws on bad input.
 */
export function verifyProviderStatement(
  statement: unknown,
  pinnedPublicKeyB64: string,
): { ok: true; value: ProviderStatement } | { ok: false; refusals: string[] } {
  if (typeof statement !== 'object' || statement === null) {
    return { ok: false, refusals: ['malformed_provider_statement'] };
  }
  const s = statement as Partial<ProviderStatement>;
  if (typeof s.signature !== 'string' || typeof s.public_key_spki_b64 !== 'string' || !s.statement) {
    return { ok: false, refusals: ['malformed_provider_statement'] };
  }
  if (s.public_key_spki_b64 !== pinnedPublicKeyB64) {
    return { ok: false, refusals: ['provider_key_not_pinned'] };
  }
  let ok = false;
  try {
    const pub = createPublicKey({
      key: Buffer.from(pinnedPublicKeyB64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    ok = verify(
      null,
      Buffer.from(canonical(s.statement), 'utf8'),
      pub,
      Buffer.from(s.signature, 'base64'),
    );
  } catch {
    return { ok: false, refusals: ['provider_statement_signature_unverifiable'] };
  }
  if (!ok) return { ok: false, refusals: ['provider_statement_signature_invalid'] };
  return { ok: true, value: s as ProviderStatement };
}

export { canonical as canonicalJson };
