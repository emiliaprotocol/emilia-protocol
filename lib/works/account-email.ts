// SPDX-License-Identifier: Apache-2.0

const RESEND_URL = 'https://api.resend.com/emails';
const FROM = process.env.WORKS_FROM_EMAIL || 'EMILIA Works <works@emiliaprotocol.ai>';

export async function sendWorksAccountCodeEmail({
  to,
  code,
}: {
  to: string;
  code: string;
}): Promise<{ delivered: boolean }> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return { delivered: false };
  try {
    const response = await fetch(RESEND_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        from: FROM,
        to,
        subject: 'Your EMILIA Works sign-in code',
        text: [
          'Use this code to finish signing in to EMILIA Works:',
          '',
          code,
          '',
          'The code expires in 10 minutes and works once. If you did not request it, you can ignore this email.',
        ].join('\n'),
      }),
      signal: AbortSignal.timeout(8_000),
    });
    return { delivered: response.ok };
  } catch {
    return { delivered: false };
  }
}
