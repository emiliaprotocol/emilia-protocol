// SPDX-License-Identifier: Apache-2.0

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(',')}]`;

  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`);
  return `{${entries.join(',')}}`;
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
