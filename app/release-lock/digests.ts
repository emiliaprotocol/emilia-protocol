// SPDX-License-Identifier: Apache-2.0

import { canonicalize as canonicalizeProtocol } from '../../lib/canonical-json.js';

export function canonicalize(value: unknown): string {
  return canonicalizeProtocol(value);
}

export async function sha256Digest(value: string | Record<string, unknown>): Promise<string> {
  const bytes = new TextEncoder().encode(
    typeof value === 'string' ? value : canonicalize(value),
  );
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => (
    byte.toString(16).padStart(2, '0')
  )).join('')}`;
}

interface BuildActionMirrorBindingsParams {
  lock: any;
  ceremony: string;
  questions: any[];
  answers: Record<string, string>;
}

export async function buildActionMirrorBindings({
  lock,
  ceremony,
  questions,
  answers,
}: BuildActionMirrorBindingsParams): Promise<any> {
  const promptSet = questions.map(({ id, field, prompt, options }) => ({
    id,
    field,
    prompt,
    options,
  }));
  const answerSet = questions.map(({ id }) => ({
    id,
    answer: answers[id],
  }));

  return {
    ceremony,
    action_digest: lock.ceremonies[ceremony].digest,
    prompt_set_digest: await sha256Digest({ ceremony, prompts: promptSet }),
    answer_digest: await sha256Digest({ ceremony, answers: answerSet }),
  };
}

export function shortDigest(value: unknown, start: number = 12, end: number = 8): string {
  if (!value || String(value).length <= start + end + 3) return String(value) || 'not available';
  const valueStr = String(value);
  return `${valueStr.slice(0, start)}...${valueStr.slice(-end)}`;
}
