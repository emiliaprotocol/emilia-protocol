// SPDX-License-Identifier: Apache-2.0
'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import AccountForm from './account/AccountForm';

type Account = { displayName: string; claimsVerified: false; emailNotifications: boolean };
async function readWorksAccount(): Promise<Account | null> {
  const response = await fetch('/api/works/account/session', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  const body: unknown = await response.json();
  if (!response.ok || !body || typeof body !== 'object') throw new Error('Account access could not be checked.');
  const value = body as { authenticated?: unknown; account?: Account };
  if (value.authenticated === false) return null;
  if (value.authenticated === true && typeof value.account?.displayName === 'string'
      && value.account.displayName.length <= 200 && value.account.claimsVerified === false
      && typeof value.account.emailNotifications === 'boolean') return value.account;
  throw new Error('Account access could not be checked.');
}
export function useWorksAccount() {
  const [account, setAccount] = useState<Account | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const sequence = useRef({ generation: 0 });
  const refresh = useCallback(async () => {
    const requestState = sequence.current;
    const current = ++requestState.generation;
    try {
      const value = await readWorksAccount();
      if (current !== requestState.generation) return;
      setAccount(value);
      setError('');
    } catch { if (current === requestState.generation) { setAccount(null); setError('Account access could not be checked. Try again before publishing.'); } }
    finally { if (current === requestState.generation) setLoading(false); }
  }, [sequence]);
  useEffect(() => {
    const requestState = sequence.current;
    const current = ++requestState.generation;
    void readWorksAccount().then(value => {
      if (current !== requestState.generation) return;
      setAccount(value); setError(''); setLoading(false);
    }, () => {
      if (current !== requestState.generation) return;
      setAccount(null); setError('Account access could not be checked. Try again before publishing.'); setLoading(false);
    });
    return () => { requestState.generation++; };
  }, [sequence]);
  const onAuthenticated = useCallback((value: Account) => {
    sequence.current.generation++; setAccount(value); setLoading(false); setError('');
  }, [sequence]);
  return { account, loading, error, refresh, onAuthenticated };
}

/** Render outside the host publication form: email verification has its own
 * form, while the job or listing draft stays in the parent page's memory. */
export default function WorksAccountAccess({ access }: { access: ReturnType<typeof useWorksAccount> }) {
  return <section aria-label="Your marketplace account" style={{ margin: '24px 0', fontSize: 18, lineHeight: 1.6 }}>
    {access.loading ? <p role="status">Checking your account…</p> : access.account ? <p>
      Signed in as <strong>{access.account.displayName}</strong>. <Link href="/works/workspace">Your workspace</Link>
    </p> : <>
      <details><summary style={{ cursor: 'pointer', padding: '12px 0', fontWeight: 600 }}>Create a free account or sign in with email</summary>
        <p>Your draft stays here while you confirm your email. No API key needed.</p>
        <AccountForm onAuthenticated={access.onAuthenticated} />
      </details>
      {access.error ? <p role="status">{access.error} <button type="button" onClick={() => void access.refresh()}>Check again</button></p> : null}
    </>}
  </section>;
}
