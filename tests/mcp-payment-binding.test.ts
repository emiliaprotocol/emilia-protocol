// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { actionForCall, makeGuardedServer, signAction } from '../examples/mcp/_kit.mjs';
import { bindExecutorAction } from '../packages/require-receipt/index.js';

const tool = 'release_payment';
const action = 'payment.release';
const payment = () => ({
  amount_minor: 8200000,
  currency: 'USD',
  vendor: 'Acme Industrial LLC',
  destination: 'acct_new_4471',
});
const receiptFor = (args = payment()) => signAction(actionForCall(tool, action, args));
const serverWithCounter = () => {
  const perform = vi.fn(async (_name, args) => ({ ran: true, ...args }));
  return { perform, call: makeGuardedServer({ tool, perform }) };
};

describe('MCP payment demo binds the complete executor payment', () => {
  it('uses the shared canonical binding, passes the frozen snapshot and consumes once', async () => {
    const args = payment();
    const reordered = { destination: args.destination, vendor: args.vendor, currency: args.currency, amount_minor: args.amount_minor };
    const bound = actionForCall(tool, action, args);
    expect(bound).toBe(bindExecutorAction(action, args));
    expect(actionForCall(tool, action, reordered)).toBe(bound);
    const { call, perform } = serverWithCounter();
    const receipt = receiptFor(args);

    const missing = await call(tool, args);
    expect(missing.status).toBe(428);
    expect(missing.body.required.action).toBe(bound);
    expect(perform).not.toHaveBeenCalled();

    const accepted = await call(tool, args, receipt);
    expect(accepted.status).toBe(200);
    expect(accepted.body).toMatchObject({ ...args, action: bound, ran: true });
    expect(perform).toHaveBeenCalledTimes(1);
    const executed = perform.mock.calls[0][1];
    expect(executed).not.toBe(args);
    expect(Object.isFrozen(executed)).toBe(true);
    expect(executed).toEqual(args);

    const replay = await call(tool, args, receipt);
    expect(replay.body.rejected.reason).toBe('replay_refused');
    expect(perform).toHaveBeenCalledTimes(1);
  });

  for (const [field, value] of Object.entries({
    amount_minor: 8200001,
    currency: 'EUR',
    vendor: 'Different Vendor LLC',
    destination: 'acct_attacker_1234',
  })) {
    it(`refuses a ${field} substitution before consuming a fresh receipt`, async () => {
      const args = payment();
      const receipt = receiptFor(args);
      const { call, perform } = serverWithCounter();
      const result = await call(tool, { ...args, [field]: value }, receipt);
      expect(result.status).toBe(428);
      expect(result.body.rejected.reason).toBe('action_mismatch');
      expect(perform).not.toHaveBeenCalled();
      // Proves this was a binding refusal, not a previously consumed receipt.
      expect((await call(tool, args, receipt)).status).toBe(200);
      expect(perform).toHaveBeenCalledTimes(1);
    });
  }

  for (const field of Object.keys(payment())) {
    it(`refuses missing ${field}, including before a receipt exists`, async () => {
      const args: Record<string, unknown> = payment();
      const receipt = receiptFor();
      delete args[field];
      const { call, perform } = serverWithCounter();
      expect(() => actionForCall(tool, action, args)).toThrow();
      for (const proof of [null, receipt]) {
        const result = await call(tool, args, proof);
        expect(result.status).toBe(428);
        expect(result.body.rejected.reason).toBe('payment_arguments_invalid');
      }
      expect(perform).not.toHaveBeenCalled();
    });
  }

  it.each([
    ['zero amount', { amount_minor: 0 }],
    ['negative amount', { amount_minor: -1 }],
    ['fractional minor units', { amount_minor: 1.25 }],
    ['string amount', { amount_minor: '8200000' }],
    ['unsafe amount', { amount_minor: Number.MAX_SAFE_INTEGER + 1 }],
    ['non-finite amount', { amount_minor: Number.NaN }],
    ['infinite amount', { amount_minor: Number.POSITIVE_INFINITY }],
    ['lowercase currency', { currency: 'usd' }],
    ['missing currency token', { currency: '' }],
    ['wrong currency type', { currency: 840 }],
    ['blank vendor', { vendor: ' ' }],
    ['object destination', { destination: { account: 'attacker' } }],
    ['ambiguous destination whitespace', { destination: ' acct_new_4471' }],
    ['destination control character', { destination: 'acct\nnew' }],
    ['unknown material field', { memo: 'additional instruction' }],
    ['legacy dollar field', { amount_usd: 82000 }],
    ['receipt transport field in material', { __ep: {} }],
  ])('refuses malformed or unknown input: %s', async (_label, changes) => {
    const { call, perform } = serverWithCounter();
    const result = await call(tool, { ...payment(), ...changes }, receiptFor());
    expect(result.status).toBe(428);
    expect(result.body.rejected.reason).toBe('payment_arguments_invalid');
    expect(perform).not.toHaveBeenCalled();
  });

  it('refuses an accessor without evaluating it', async () => {
    const args = payment();
    const getter = vi.fn(() => 'acct_attacker');
    Object.defineProperty(args, 'destination', { get: getter, enumerable: true });
    const { call, perform } = serverWithCounter();
    const result = await call(tool, args, receiptFor());
    expect(result.body.rejected.reason).toBe('payment_arguments_invalid');
    expect(getter).not.toHaveBeenCalled();
    expect(perform).not.toHaveBeenCalled();
  });

  it('refuses non-object, non-plain and hidden or symbol-bearing input', async () => {
    const hidden = payment();
    Object.defineProperty(hidden, 'vendor', { value: hidden.vendor, enumerable: false });
    const symbol = { ...payment(), [Symbol('alternate-destination')]: 'acct_attacker' };
    const inherited = Object.assign(Object.create({ routing: 'attacker' }), payment());
    const { call, perform } = serverWithCounter();
    for (const args of [null, undefined, [], new Date(), hidden, symbol, inherited]) {
      const result = await call(tool, args, receiptFor());
      expect(result.status).toBe(428);
      expect(result.body.rejected.reason).toBe('payment_arguments_invalid');
    }
    expect(perform).not.toHaveBeenCalled();
  });

  it('refuses a Proxy that adds an unknown field only while the snapshot is captured', async () => {
    const material = { ...payment(), memo: 'hidden material instruction' };
    const changingKeys = () => {
      let reads = 0;
      return new Proxy(material, {
        ownKeys: () => ++reads % 3 === 0 ? Object.keys(material) : Object.keys(payment()),
      });
    };
    // A valid signature over the extra field must not make it part of the
    // accepted payment schema. All pre-capture key checks see four fields.
    const receipt = signAction(bindExecutorAction(action, material));
    const { call, perform } = serverWithCounter();
    const result = await call(tool, changingKeys(), receipt);
    expect(result.status).toBe(428);
    expect(result.body.rejected.reason).toBe('payment_arguments_invalid');
    expect(perform).not.toHaveBeenCalled();
    expect(() => actionForCall(tool, action, changingKeys())).toThrow();
  });

  it('refuses a Proxy that hides a required field while the snapshot is captured', async () => {
    let reads = 0;
    const args = new Proxy(payment(), {
      ownKeys: () => ++reads % 3 === 0
        ? Object.keys(payment()).filter((key) => key !== 'vendor')
        : Object.keys(payment()),
    });
    const { call, perform } = serverWithCounter();
    const result = await call(tool, args, receiptFor());
    expect(result.status).toBe(428);
    expect(result.body.rejected.reason).toBe('payment_arguments_invalid');
    expect(perform).not.toHaveBeenCalled();
  });

  for (const [field, value] of Object.entries({
    amount_minor: 8200001,
    currency: 'EUR',
    vendor: 'Changed during reservation',
    destination: 'acct_changed_during_reservation',
  })) {
    it(`refuses ${field} mutation during the asynchronous receipt reservation`, async () => {
      const args = payment();
      const receipt = receiptFor(args);
      const { call, perform } = serverWithCounter();
      const pending = call(tool, args, receipt);
      args[field] = value;
      const result = await pending;
      expect(result.status).toBe(428);
      expect(result.body.rejected.reason).toBe('payment_arguments_changed');
      expect(perform).not.toHaveBeenCalled();
      // The reservation stays consumed on this conservative failure path.
      expect((await call(tool, payment(), receipt)).body.rejected.reason).toBe('replay_refused');
    });
  }

  it('refuses malformed input added during reservation before executor entry', async () => {
    const args: Record<string, unknown> = payment();
    const { call, perform } = serverWithCounter();
    const pending = call(tool, args, receiptFor());
    args.routing_override = 'acct_attacker';
    const result = await pending;
    expect(result.status).toBe(428);
    expect(result.body.rejected.reason).toBe('payment_arguments_changed');
    expect(perform).not.toHaveBeenCalled();
  });

  it('keeps an entered executor on its frozen snapshot if the caller later mutates input', async () => {
    const args = payment();
    let enter: () => void;
    const entered = new Promise<void>((resolve) => { enter = resolve; });
    let finish: () => void;
    const finishExecution = new Promise<void>((resolve) => { finish = resolve; });
    let executed;
    const call = makeGuardedServer({ tool, perform: async (_name, snapshot) => {
      enter();
      await finishExecution;
      executed = snapshot;
      return { ran: true, ...snapshot };
    } });
    const pending = call(tool, args, receiptFor(args));
    await entered;
    args.destination = 'acct_changed_after_entry';
    finish();
    expect((await pending).status).toBe(200);
    expect(executed).toEqual(payment());
    expect(Object.isFrozen(executed)).toBe(true);
  });

  it('refuses an old destination-only receipt', async () => {
    const { call, perform } = serverWithCounter();
    const result = await call(tool, payment(), signAction(`${action}:${payment().destination}`));
    expect(result.body.rejected.reason).toBe('action_mismatch');
    expect(perform).not.toHaveBeenCalled();
  });

  it('prints four fresh-receipt substitution refusals and explicit simulation limits', () => {
    const script = fileURLToPath(new URL('../examples/mcp/payment-server.mjs', import.meta.url));
    const output = execFileSync(process.execPath, [script], { env: { ...process.env, FAST: '1' }, encoding: 'utf8' });
    expect(output.match(/\(action_mismatch\)/g)).toHaveLength(4);
    for (const field of Object.keys(payment())) expect(output).toContain(`substitute ${field} with a fresh, unused receipt`);
    expect(output).toContain('generated demo keys, in-memory consumption, mock executor');
    expect(output).toContain('No funds move; no real human or device ceremony is performed');
    expect(output).toContain('replay_refused');
    expect(output).toContain('mock tool performed');
  });
});
