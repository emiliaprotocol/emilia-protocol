// SPDX-License-Identifier: Apache-2.0

/**
 * Call the public receipt-required demo without letting transport failures lock
 * the client state machine. Every outcome resolves to the same result shape so
 * callers can always clear their busy state.
 */

interface PostDemoResponse {
  status: number;
  data: Record<string, any>;
  receiptRequired: string | null;
}

export async function postReceiptRequiredDemo(body: Record<string, any>, fetchImpl: typeof fetch = fetch): Promise<PostDemoResponse> {
  try {
    const response = await fetchImpl('/api/demo/require-receipt', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

    let data: Record<string, any>;
    try {
      data = await response.json();
    } catch {
      data = {
        title: 'non-JSON response',
        error: `gate returned ${response.status}`,
      };
    }

    return {
      status: response.status,
      data,
      receiptRequired: response.headers.get('receipt-required'),
    };
  } catch (error) {
    return {
      status: 0,
      data: {
        title: 'network error',
        error: String((error as any)?.message || error),
      },
      receiptRequired: null,
    };
  }
}

export default postReceiptRequiredDemo;
