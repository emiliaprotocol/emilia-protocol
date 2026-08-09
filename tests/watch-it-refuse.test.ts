// SPDX-License-Identifier: Apache-2.0
//
// Watch It Refuse — the honesty contract of the public demo surface.
//
//   1. Every archetype's refusal carries real typed reasons from the shipped
//      evaluation code (gate refusal + admissibility verdict + real CAID).
//   2. Malformed input is a typed 4xx, never a crash.
//   3. Flag off -> 404 on the APIs, and the page fails closed via notFound().
//   4. Demo receipts verify under the demo issuer, are rejected under any
//      other trust root, and every minted artifact is demo-marked.
//   5. A consumed demo receipt is refused on replay with the typed reason.
//   6. The OG card endpoint renders a PNG.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { verifyEmiliaReceipt } from '@emilia-protocol/require-receipt';
import { parseCaid } from '../caid/impl/js/caid.mjs';

import {
  DEMO_ISSUER_ID,
  evaluateWatchItRefuse,
  getDemoIssuer,
  mintDemoReceipt,
  validateActionText,
  WirInputError,
} from '../lib/watch-it-refuse/evaluate';
import {
  WIR_ACTION_TYPES,
  buildActionObject,
  classifyActionText,
  parseAmount,
} from '../lib/watch-it-refuse/classify';
import { plainReason } from '../lib/watch-it-refuse/reasons';

import { POST as evaluateRoute } from '../app/api/refuse/evaluate/route';
import { GET as ogRoute } from '../app/api/refuse/og/route';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');

const ARCHETYPE_INPUTS: Record<string, string> = {
  payment: 'Wire $40,000 to this account',
  destructive: 'Delete the prod database',
  communication: 'Email the board my resignation',
  deployment: 'Deploy this build to production',
  physical: 'Unlock the server-room door',
  generic: 'Do the irreversible thing',
};

function postRequest(body: unknown): Request {
  return new Request('https://demo.test/api/refuse/evaluate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

beforeEach(() => {
  vi.stubEnv('WATCH_IT_REFUSE', '1');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('classification is deterministic', () => {
  it('maps each canonical example to its archetype and registry action type', () => {
    for (const [archetype, text] of Object.entries(ARCHETYPE_INPUTS)) {
      expect(classifyActionText(text)).toBe(archetype);
      const action = buildActionObject(archetype as any, text);
      expect(action.action_type).toBe(WIR_ACTION_TYPES[archetype as keyof typeof WIR_ACTION_TYPES]);
    }
  });

  it('parses money amounts deterministically', () => {
    expect(parseAmount('wire $40k to them')).toBe('40000');
    expect(parseAmount('pay $1.5m now')).toBe('1500000');
    expect(parseAmount('transfer 250 dollars')).toBe('250');
    expect(parseAmount('no amount here')).toBe('10000');
  });

  it('same text yields the same action object (stable CAID input)', () => {
    const a = buildActionObject('payment', 'Wire $40,000 to this account');
    const b = buildActionObject('payment', 'Wire $40,000 to this account');
    expect(a).toEqual(b);
  });
});

describe('refusal path — real typed reasons for every archetype', () => {
  for (const [archetype, text] of Object.entries(ARCHETYPE_INPUTS)) {
    it(`${archetype}: refuses with receipt_required + missing_evidence + a real CAID`, async () => {
      const result = await evaluateWatchItRefuse({ text });
      expect(result.demo).toBe(true);
      expect(result.notice).toContain('No action is performed');
      expect(result.classification.archetype).toBe(archetype);

      // Real CAID from the registry implementation.
      expect(result.identity.caid).toBeTruthy();
      const parsed = parseCaid(result.identity.caid);
      expect(parsed.ok).toBe(true);
      expect(parsed.caid.action_type).toBe(result.classification.action_type);
      expect(parsed.caid.suite).toBe('jcs-sha256');

      // Real gate refusal: 428 + typed reason + Receipt-Required challenge.
      expect(result.refusal.allow).toBe(false);
      expect(result.refusal.status).toBe(428);
      expect(result.refusal.reason.code).toBe('receipt_required');
      expect(result.refusal.reason.plain).toBe(plainReason('receipt_required'));
      expect(result.refusal.challenge).toBeTruthy();
      expect(result.refusal.receipt_required_header).toContain('assurance');

      // Real admissibility verdict over the empty bundle.
      expect(result.evidence_check.verdict).toBe('missing_evidence');
      expect(result.evidence_check.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    });
  }
});

describe('approval path — full lifecycle with real one-time consumption', () => {
  it('VERIFIED -> MATCH -> SATISFIED -> AUTHORIZED -> CONSUMED, then replay refused', async () => {
    const result = await evaluateWatchItRefuse({
      text: ARCHETYPE_INPUTS.payment,
      approve: true,
    });
    const stages = result.approval.stages;

    expect(stages.verified.ok).toBe(true);
    expect(stages.match.ok).toBe(true);
    expect(stages.match.caid.valid).toBe(true);
    expect(stages.match.execution_binding.ok).toBe(true);
    expect(stages.satisfied.ok).toBe(true);
    expect(stages.satisfied.assurance.have).toBe('software');
    expect(stages.satisfied.admissibility.verdict).toBe('admissible');
    expect(stages.authorized.allow).toBe(true);
    expect(stages.authorized.status).toBe(200);

    // The replay of the SAME receipt against the SAME gate is refused.
    expect(stages.consumed.consumed).toBe(true);
    expect(stages.consumed.replay_attempt.allow).toBe(false);
    expect(stages.consumed.replay_attempt.status).toBe(428);
    expect(stages.consumed.replay_attempt.reason.code).toBe('replay_refused');
  });

  it('every minted artifact is demo-marked (top-level, signed claim, issuer id)', async () => {
    const result = await evaluateWatchItRefuse({
      text: ARCHETYPE_INPUTS.destructive,
      approve: true,
    });
    const receipt = result.approval.receipt;
    expect(receipt.demo).toBe(true);
    expect(receipt.demo_issuer).toBe(DEMO_ISSUER_ID);
    expect(receipt.payload.demo).toBe(true);
    expect(receipt.payload.issuer).toBe(DEMO_ISSUER_ID);
    expect(receipt.payload.claim.demo).toBe(true);
    expect(receipt.payload.claim.demo_notice).toContain('Not production evidence');
    expect(receipt.payload.receipt_id).toContain(DEMO_ISSUER_ID);
    expect(result.approval.demo).toBe(true);
    expect(result.demo).toBe(true);
  });
});

describe('demo issuer trust boundary', () => {
  it('demo receipts verify ONLY under the demo issuer key, never another root', () => {
    const action = buildActionObject('payment', 'Wire $9k to this account');
    const receipt = mintDemoReceipt(action, 'Wire $9k to this account');
    const issuer = getDemoIssuer();

    const underDemo = verifyEmiliaReceipt(receipt, {
      trustedKeys: [issuer.publicKeyB64u],
      action: 'wire.transfer.1',
      maxAgeSec: 900,
    });
    expect(underDemo.ok).toBe(true);

    // Any other trust root — e.g. a production issuer pin — rejects it.
    const otherKey = crypto.generateKeyPairSync('ed25519')
      .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const underOther = verifyEmiliaReceipt(receipt, {
      trustedKeys: [otherKey],
      action: 'wire.transfer.1',
      maxAgeSec: 900,
    });
    expect(underOther.ok).toBe(false);
    expect(underOther.reason).toBe('untrusted_or_invalid_signature');
  });

  it('stripping the in-claim demo marker breaks the signature', () => {
    const action = buildActionObject('payment', 'Wire $9k to this account');
    const receipt = mintDemoReceipt(action, 'Wire $9k to this account');
    delete receipt.payload.claim.demo;
    delete receipt.payload.claim.demo_notice;
    const issuer = getDemoIssuer();
    const verdict = verifyEmiliaReceipt(receipt, {
      trustedKeys: [issuer.publicKeyB64u],
      action: 'wire.transfer.1',
      maxAgeSec: 900,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe('untrusted_or_invalid_signature');
  });
});

describe('malformed input — typed 4xx, never a crash', () => {
  it('validateActionText refuses junk with typed codes', () => {
    for (const [input, code] of [
      [undefined, 'action_text_required'],
      [42, 'action_text_required'],
      ['a', 'action_text_too_short'],
      ['x'.repeat(500), 'action_text_too_long'],
      ['\ud800 lone surrogate', 'action_text_invalid'],
    ] as const) {
      let thrown: unknown = null;
      try { validateActionText(input); } catch (error) { thrown = error; }
      expect(thrown).toBeInstanceOf(WirInputError);
      expect((thrown as WirInputError).code).toBe(code);
      expect((thrown as WirInputError).status).toBe(400);
    }
  });

  it('API: missing text -> typed 400', async () => {
    const res = await evaluateRoute(postRequest({}) as any);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.type).toContain('action_text_required');
  });

  it('API: unknown keys -> typed 400', async () => {
    const res = await evaluateRoute(postRequest({ text: 'wire $1', extra: true }) as any);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.type).toContain('refuse_input_invalid');
  });

  it('API: non-boolean approve -> typed 400', async () => {
    const res = await evaluateRoute(postRequest({ text: 'wire $1', approve: 'yes' }) as any);
    expect(res.status).toBe(400);
  });

  it('API: invalid JSON body -> typed 4xx', async () => {
    const res = await evaluateRoute(postRequest('{nope') as any);
    expect(res.status).toBe(400);
  });

  it('API: happy path returns the evaluation', async () => {
    const res = await evaluateRoute(postRequest({ text: 'Wire $40,000 to this account' }) as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.demo).toBe(true);
    expect(body.refusal.reason.code).toBe('receipt_required');
  });
});

describe('feature flag off -> 404 everywhere', () => {
  it('evaluate API 404s', async () => {
    vi.stubEnv('WATCH_IT_REFUSE', '');
    const res = await evaluateRoute(postRequest({ text: 'wire $1' }) as any);
    expect(res.status).toBe(404);
  });

  it('OG API 404s', async () => {
    vi.stubEnv('WATCH_IT_REFUSE', '');
    const { NextRequest } = await import('next/server');
    const res = await ogRoute(new NextRequest('https://demo.test/api/refuse/og'));
    expect(res.status).toBe(404);
  });

  it('the page fails closed via notFound() behind the same flag', () => {
    // The page is a server component; asserting its source keeps the gate
    // from being refactored away without this test noticing.
    const src = readFileSync(join(ROOT, 'app/refuse/page.tsx'), 'utf8');
    expect(src).toContain("if (!isWatchItRefuseEnabled()) notFound();");
  });
});

describe('OG card endpoint', () => {
  it('renders a PNG when enabled', async () => {
    const { NextRequest } = await import('next/server');
    const res = await ogRoute(new NextRequest(
      'https://demo.test/api/refuse/og?t=Wire%20%2440%2C000%20to%20this%20account&v=refused',
    ));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('image/png');
    const bytes = new Uint8Array(await res.arrayBuffer());
    // PNG magic number.
    expect(Array.from(bytes.slice(0, 4))).toEqual([0x89, 0x50, 0x4e, 0x47]);
  }, 30000);
});

describe('public-repo hygiene', () => {
  it('the surface never claims to execute anything', async () => {
    const result = await evaluateWatchItRefuse({ text: 'wire $5 to bob', approve: true });
    const serialized = JSON.stringify(result);
    expect(serialized).toContain('No action is performed');
    expect(serialized).not.toMatch(/executed_at/);
  });
});
