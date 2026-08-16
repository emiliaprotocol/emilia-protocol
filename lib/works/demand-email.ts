// SPDX-License-Identifier: Apache-2.0

const RESEND_URL = 'https://api.resend.com/emails';
const FROM = process.env.WORKS_FROM_EMAIL || 'EMILIA Works <works@emiliaprotocol.ai>';

export async function sendAuthorityDemandVerificationEmail({
  to,
  verifyUrl,
  recordId,
}: {
  to: string;
  verifyUrl: string;
  recordId: string;
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
        subject: 'Confirm your Authority Record request',
        text: [
          'Confirm that you requested information about this EMILIA Authority Record.',
          '',
          verifyUrl,
          '',
          `Record: ${recordId}`,
          'The link expires in 24 hours. This confirms interest only. It is not a purchase or endorsement.',
        ].join('\n'),
      }),
      signal: AbortSignal.timeout(8_000),
    });
    return { delivered: response.ok };
  } catch {
    return { delivered: false };
  }
}
