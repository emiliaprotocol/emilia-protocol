// SPDX-License-Identifier: Apache-2.0
'use client';

import { createContext, useContext, useRef, useState, type ReactNode } from 'react';
import Link from 'next/link';
import market from './marketplace.module.css';

export type ShortlistItem = { id: string; name: string; builder: string; summary: string; tasks: string[]; interfaces: string[]; constraints: string[]; license: string };
const ShortlistContext = createContext<{ items: ShortlistItem[]; toggle: (item: ShortlistItem) => void }>({ items: [], toggle: () => {} });

/** A temporary comparison of public declarations, never a ranking or an order. */
export function ShortlistProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ShortlistItem[]>([]);
  const dialog = useRef<HTMLDialogElement>(null);
  function toggle(item: ShortlistItem) {
    setItems(current => current.some(saved => saved.id === item.id)
      ? current.filter(saved => saved.id !== item.id)
      : current.length < 3 ? [...current, item] : current);
  }
  return <ShortlistContext.Provider value={{ items, toggle }}>
    {children}
    {items.length > 0 && <aside className={market.shortlistTray} aria-label="Your shortlist">
      <div><strong>{items.length} of 3 shortlisted</strong><span>Compare declarations. Decide what to ask.</span></div>
      <button type="button" onClick={() => dialog.current?.showModal()} className={market.marketPrimary}>Compare shortlist</button>
      <button type="button" onClick={() => { dialog.current?.close(); setItems([]); }} className={market.shortlistClear}>Clear shortlist</button>
    </aside>}
    <dialog ref={dialog} className={market.compareDialog} aria-labelledby="shortlist-title">
      <header><div><p className={market.marketEyebrow}>Your shortlist</p><h2 id="shortlist-title">Same job. Different workers.</h2></div><button type="button" onClick={() => dialog.current?.close()} className={market.closeDialog}>Close comparison</button></header>
      <p>These are builder-supplied declarations, not verified performance or hiring availability. Kept in this page only; refreshing clears your shortlist.</p>
      <div className={market.compareGrid}>
        {items.map(item => <article key={item.id}><h3>{item.name}</h3><p>{item.builder}</p><dl>
          <dt>The work</dt><dd>{item.summary}</dd>
          <dt>Declared tasks</dt><dd>{item.tasks.join(', ') || 'Not specified'}</dd>
          <dt>Interfaces</dt><dd>{item.interfaces.join(', ') || 'Not specified'}</dd>
          <dt>Operating limits</dt><dd>{item.constraints.join(' · ') || 'Not specified'}</dd>
          <dt>License</dt><dd>{item.license}</dd>
          <dt>Version and work record</dt><dd>Not established by this listing. Ask for the exact version and evidence for your job.</dd>
        </dl><Link href={`/works/listings/${encodeURIComponent(item.id)}`}>Inspect listing and evidence ↗</Link></article>)}
      </div>
      <footer>Before giving access: agree on a job owner, the allowed actions, and how you will review the result. <Link href="/workforce#build-your-workforce">Explore a workforce evaluation</Link></footer>
    </dialog>
  </ShortlistContext.Provider>;
}

export function ShortlistButton({ item }: { item: ShortlistItem }) {
  const { items, toggle } = useContext(ShortlistContext);
  const selected = items.some(saved => saved.id === item.id);
  return <button type="button" aria-pressed={selected} aria-label={`${selected ? 'Remove' : 'Shortlist'} ${item.name}${selected ? ' from shortlist' : ''}`} disabled={!selected && items.length >= 3} className={market.shortlistButton} onClick={() => toggle(item)}>{selected ? 'Shortlisted ✓' : items.length >= 3 ? 'Shortlist full' : 'Shortlist +'}</button>;
}
