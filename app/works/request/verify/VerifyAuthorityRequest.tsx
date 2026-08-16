'use client';

// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';

export default function VerifyAuthorityRequest() {
  const [message, setMessage] = useState('Verifying your request…');

  useEffect(() => {
    const token = window.location.hash.slice(1);
    history.replaceState(null, '', window.location.pathname);
    if (!/^ardv1_[0-9a-f]{64}$/.test(token)) {
      queueMicrotask(() => setMessage('This verification link is unavailable.'));
      return;
    }
    void fetch('/api/works/authority-records/requests/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    }).then((response) => {
      setMessage(response.ok
        ? 'Your request is verified. Thank you.'
        : 'This verification link is unavailable.');
    }).catch(() => setMessage('Verification is temporarily unavailable.'));
  }, []);

  return <p>{message}</p>;
}
