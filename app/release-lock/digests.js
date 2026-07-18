// SPDX-License-Identifier: Apache-2.0

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(',')}]`;

  const entries = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
  return `{${entries.join(',')}}`;
}

export async function sha256Digest(value) {
  const bytes = new TextEncoder().encode(
    typeof value === 'string' ? value : canonicalize(value),
  );
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => (
    byte.toString(16).padStart(2, '0')
  )).join('')}`;
}

export async function buildActionMirrorBindings({
  lock,
  ceremony,
  questions,
  answers,
}) {
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

export function shortDigest(value, start = 12, end = 8) {
  if (!value || value.length <= start + end + 3) return value || 'not available';
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}
