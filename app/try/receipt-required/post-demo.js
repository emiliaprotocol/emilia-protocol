// SPDX-License-Identifier: Apache-2.0

/**
 * Call the public receipt-required demo without letting transport failures lock
 * the client state machine. Every outcome resolves to the same result shape so
 * callers can always clear their busy state.
 */
export async function postReceiptRequiredDemo(body, fetchImpl = fetch) {
  try {
    const response = await fetchImpl('/api/demo/require-receipt', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

    let data;
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
        error: String(error?.message || error),
      },
      receiptRequired: null,
    };
  }
}

export default postReceiptRequiredDemo;
