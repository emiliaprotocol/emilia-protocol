// SPDX-License-Identifier: Apache-2.0
'use client';
import Link from 'next/link';
import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import AccountForm, { type WorksAccountPublic } from './AccountForm';
import { useWorksAccount } from '../WorksAccountAccess';
import { createWorkspaceFence } from '../workspace-client';
import styles from './account-page.module.css';

function subscribeVisibility(notify: () => void) {
  document.addEventListener('visibilitychange', notify);
  return () => document.removeEventListener('visibilitychange', notify);
}
const visibleSnapshot = () => document.visibilityState === 'hidden' ? false : true;
const serverVisible = () => true;

export function projectAccountIdentity(value: unknown): WorksAccountPublic {
  if (!value || typeof value !== 'object') throw new Error('account_response_invalid');
  const account = value as Record<string, unknown>;
  if (typeof account.displayName !== 'string' || !account.displayName.trim() || account.displayName.length > 200
    || account.claimsVerified !== false || typeof account.emailNotifications !== 'boolean') throw new Error('account_response_invalid');
  return { displayName: account.displayName, claimsVerified: false, emailNotifications: account.emailNotifications };
}

export async function requestWorksLogout(signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  const response = await fetch('/api/works/account/logout', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal });
  signal.throwIfAborted();
  if (response.status !== 204) throw new Error('account_logout_unconfirmed');
}

export default function AccountPage({ signInAvailable }: { signInAvailable: boolean }) {
  const visible = useSyncExternalStore(subscribeVisibility, visibleSnapshot, serverVisible);
  const [pageActive, setPageActive] = useState(true);
  useEffect(() => {
    const leave = () => setPageActive(false); const returnToPage = () => setPageActive(true);
    window.addEventListener('pagehide', leave); window.addEventListener('pageshow', returnToPage);
    return () => { window.removeEventListener('pagehide', leave); window.removeEventListener('pageshow', returnToPage); };
  }, []);
  return <>
    {!signInAvailable ? <section className={styles.notice}><h2>Email sign-in is temporarily unavailable.</h2>
      <p>You can still browse the marketplace. Existing developer accounts can <Link href="/works/join">publish with their key</Link>. Existing browser sessions can be checked and signed out below.</p></section> : null}
    {visible && pageActive ? <AccountSessionPanel signInAvailable={signInAvailable} /> : <p className={styles.notice}>Your private account view was cleared. It will check your session again when you return.</p>}
    <div className={styles.actions}><Link href="/works/workspace" className={styles.primary}>Continue to your workspace</Link><Link href="/works" className={styles.secondary}>Browse the marketplace</Link></div>
    <p className={styles.note}>Your session uses a cookie that page scripts cannot read. This page does not save your email or code in browser storage or URLs. Leaving this tab clears the open account form. Signing out does not delete public listings, cancel assignments or revoke developer keys.</p>
  </>;
}

function AccountSessionPanel({ signInAvailable }: { signInAvailable: boolean }) {
  const access = useWorksAccount(); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [logoutChecked, setLogoutChecked] = useState(false);
  const fence = useRef(createWorkspaceFence()); const mounted = useRef(true); const inFlight = useRef(false);
  useEffect(() => { mounted.current = true; const requests = fence.current; return () => { mounted.current = false; requests.cancel(); }; }, []);

  function authenticated(value: WorksAccountPublic) {
    if (!mounted.current || document.visibilityState === 'hidden') return;
    try { access.onAuthenticated(projectAccountIdentity(value)); setLogoutChecked(false); setError(''); }
    catch { setError('Sign-in returned an unexpected account. Check your session before continuing.'); }
  }
  async function checkSession() {
    if (inFlight.current || document.visibilityState === 'hidden') return;
    inFlight.current = true; const request = fence.current.begin(); setBusy(true); setError('');
    try { await access.refresh(); }
    finally { if (request.isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  async function logout() {
    if (inFlight.current || !access.account || document.visibilityState === 'hidden') return;
    inFlight.current = true; const request = fence.current.begin(); setBusy(true); setError(''); setLogoutChecked(false);
    try {
      await requestWorksLogout(request.signal);
      if (!request.isCurrent()) return;
      await access.refresh();
      if (request.isCurrent()) setLogoutChecked(true);
    } catch { if (request.isCurrent()) setError('Sign-out was not confirmed. Check your session or try signing out again.'); }
    finally { if (request.isCurrent()) { inFlight.current = false; setBusy(false); } }
  }

  if (access.loading) return <p className={styles.notice} role="status">Checking your account…</p>;
  return <section className={styles.session} aria-label="Current account">
    {access.account ? <>
      <p className={styles.eyebrow}>Signed in</p><h2>Signed in as {access.account.displayName}.</h2>
      <p>Your email confirms access to this account. It does not verify your organization, an agent’s capabilities or completed work.</p>
      <p className={styles.note}>Updates are recorded in your workspace. Email delivery of work updates is not enabled.</p>
      <div className={styles.actions}><button type="button" className={styles.secondary} disabled={busy} onClick={() => void logout()}>{busy ? 'Checking account…' : 'Sign out of this browser'}</button></div>
      {logoutChecked && !busy ? <p role="alert" className={styles.error}>The session is still active. Sign-out was not confirmed.</p> : null}
    </> : access.error ? null : <>
      {logoutChecked && !busy ? <p role="status" className={styles.notice}>You’re signed out of this browser.</p> : null}
      {signInAvailable ? <AccountForm onAuthenticated={authenticated} initialMode="login" /> : <p>No signed-in account was found in this browser.</p>}
    </>}
    {error || access.error ? <p role="alert" className={styles.error}>{error || access.error}</p> : null}
    <button type="button" className={styles.textButton} disabled={busy} onClick={() => void checkSession()}>Check sign-in status again</button>
  </section>;
}
