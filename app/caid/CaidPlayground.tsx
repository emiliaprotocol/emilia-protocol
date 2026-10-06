// SPDX-License-Identifier: Apache-2.0
'use client';

import { useEffect, useRef, useState } from 'react';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';

import styles from './caid.module.css';
import {
  BASELINE_CAID_INPUT,
  type CaidComparison,
  type CaidDemoInput,
} from './types';

type CaidPlaygroundProps = {
  initialComparison: CaidComparison;
};

const AMOUNT_MUTATION: CaidDemoInput = {
  ...BASELINE_CAID_INPUT,
  amount: '82500.00',
};

const DESTINATION_MUTATION: CaidDemoInput = {
  ...BASELINE_CAID_INPUT,
  destinationReference: 'Globex Parts / settlement / account 9981',
};

function Identifier({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(children);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className={styles.identifier}>
      <code>{children}</code>
      <button type="button" onClick={copy} aria-label="Copy identifier">
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

export default function CaidPlayground({ initialComparison }: CaidPlaygroundProps) {
  const [input, setInput] = useState<CaidDemoInput>({ ...BASELINE_CAID_INPUT });
  const [comparison, setComparison] = useState(initialComparison);
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const requestController = useRef<AbortController | null>(null);

  useEffect(() => () => requestController.current?.abort(), []);

  async function compare(nextInput: CaidDemoInput): Promise<void> {
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setInput(nextInput);
    setDirty(false);
    setLoading(true);
    setError('');
    try {
      const response = await fetch('/api/caid', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(nextInput),
        signal: controller.signal,
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error || 'The comparison failed');
      setComparison(body as CaidComparison);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      setError(caught instanceof Error ? caught.message : 'The comparison failed');
    } finally {
      if (requestController.current === controller) setLoading(false);
    }
  }

  const statusTitle = comparison.matchesApprovedAction
    ? 'Matches the approved action'
    : 'Does not match the approved action';
  const statusDetail = comparison.matchesApprovedAction
    ? 'The exact typed content recomputes to the same identifier.'
    : `Material field${comparison.changedFields.length === 1 ? '' : 's'} changed: ${comparison.changedFields.join(', ')}.`;

  return (
    <div className={styles.page}>
      <SiteNav activePage="Developers" />

      <main>
        <section className={styles.hero}>
          <div className={styles.kicker}>Canonical Action Identifier</div>
          <h1>
            <span>One exact action.</span>{' '}
            <span>One portable identifier.</span>
          </h1>
          <p>
            Change what matters and the identifier changes. Keep the exact typed action,
            and any conforming system can recompute the same <code>canactid:</code> value.
          </p>
          <div className={styles.heroProof} aria-label="CAID behavior summary">
            <span>same typed content</span>
            <i aria-hidden="true" />
            <strong>same identifier</strong>
          </div>
        </section>

        <section className={styles.lab} aria-labelledby="lab-heading">
          <div className={styles.labIntro}>
            <div>
              <span className={styles.sectionLabel}>Live reference computation</span>
              <h2 id="lab-heading">Move one material fact. Watch the match break.</h2>
            </div>
            <p>
              The approved record below is an $82,000 payment to Acme. Compare it unchanged,
              then change the amount or destination. The page uses the repository&apos;s reference
              implementation and active <code>payment.release.1</code> definition.
            </p>
          </div>

          <div className={styles.workbench}>
            <form
              className={styles.controls}
              onSubmit={(event) => {
                event.preventDefault();
                void compare(input);
              }}
            >
              <div className={styles.approvedStamp}>
                <span>Approved record</span>
                <strong>Payment instruction pi-demo-1042</strong>
                <small>USD · Acme Supply · exact-action baseline</small>
              </div>

              <label htmlFor="caid-amount">
                <span>Amount</span>
                <div className={styles.inputFrame}>
                  <b aria-hidden="true">$</b>
                  <input
                    id="caid-amount"
                    name="amount"
                    value={input.amount}
                    inputMode="decimal"
                    autoComplete="off"
                    onChange={(event) => {
                      setInput((current) => ({ ...current, amount: event.target.value }));
                      setDirty(true);
                    }}
                  />
                  <em>USD</em>
                </div>
              </label>

              <label htmlFor="caid-destination">
                <span>Destination reference</span>
                <input
                  id="caid-destination"
                  name="destination"
                  className={styles.textInput}
                  value={input.destinationReference}
                  autoComplete="off"
                  maxLength={256}
                  onChange={(event) => {
                    setInput((current) => ({ ...current, destinationReference: event.target.value }));
                    setDirty(true);
                  }}
                />
                <small>
                  Demo rule: SHA-256 of the exact UTF-8 text entered here. Production issuers must
                  state their own account normalization rule.
                </small>
              </label>

              <button className={styles.compareButton} type="submit" disabled={loading || !dirty}>
                {loading ? 'Computing…' : dirty ? 'Compare this action' : 'Action compared'}
              </button>

              <div className={styles.mutations} aria-label="Example mutations">
                <span>Try a material change</span>
                <button type="button" onClick={() => void compare(AMOUNT_MUTATION)} disabled={loading}>
                  Change the amount
                </button>
                <button type="button" onClick={() => void compare(DESTINATION_MUTATION)} disabled={loading}>
                  Change the destination
                </button>
                <button
                  type="button"
                  className={styles.resetButton}
                  onClick={() => void compare({ ...BASELINE_CAID_INPUT })}
                  disabled={loading}
                >
                  Restore approved action
                </button>
              </div>
            </form>

            <div className={styles.result} aria-live="polite" aria-busy={loading}>
              <div className={`${styles.verdict} ${comparison.matchesApprovedAction ? styles.match : styles.mismatch}`}>
                <div className={styles.verdictGlyph} aria-hidden="true">
                  {comparison.matchesApprovedAction ? '✓' : '≠'}
                </div>
                <div>
                  <span>Exact-action comparison</span>
                  <h3>{statusTitle}</h3>
                  <p>{statusDetail}</p>
                </div>
              </div>

              {error ? <div className={styles.error} role="alert">{error}</div> : null}

              <div className={styles.identifierPair}>
                <div>
                  <span>Approved identifier</span>
                  <Identifier>{comparison.approvedCaid}</Identifier>
                </div>
                <div>
                  <span>Proposed identifier</span>
                  <Identifier>{comparison.proposedCaid}</Identifier>
                </div>
              </div>

              <div className={styles.repeatCheck}>
                <span>Same action, same identifier</span>
                <strong>{comparison.recomputedCaid === comparison.approvedCaid ? 'Confirmed' : 'Failed'}</strong>
              </div>

              <details className={styles.actionDetail}>
                <summary>See the typed action used for this identifier</summary>
                <pre>{JSON.stringify(comparison.canonicalAction, null, 2)}</pre>
              </details>
            </div>
          </div>
        </section>

        <section className={styles.meaning} aria-labelledby="meaning-heading">
          <div>
            <span className={styles.sectionLabel}>The boundary matters</span>
            <h2 id="meaning-heading">It tells systems what action they are talking about.</h2>
            <p>
              CAID is content correlation. It gives independently produced records a precise way
              to refer to the same material action without making a bigger claim.
            </p>
          </div>
          <ul>
            <li><strong>It does not authorize an action.</strong> Authority still comes from the relying party&apos;s policy and evidence.</li>
            <li><strong>It does not prove execution.</strong> The executor must report the outcome separately.</li>
            <li><strong>It does not prevent replay.</strong> Use an operation ID, nonce, and atomic consumption for that.</li>
            <li><strong>It is not an idempotency key.</strong> Identical action content may legitimately occur more than once.</li>
            <li><strong>It is not a URL to fetch.</strong> A <code>canactid:</code> URI is not dereferenceable.</li>
          </ul>
        </section>

        <section className={styles.status} aria-labelledby="status-heading">
          <div className={styles.registryMark} aria-hidden="true">IANA</div>
          <div>
            <span className={styles.sectionLabel}>Registry status</span>
            <h2 id="status-heading">A registered name, with a deliberately narrow claim.</h2>
            <p>
              The <code>canactid</code> URI scheme is provisionally registered in IANA&apos;s URI Schemes
              registry and references CAID-05. CAID remains an individual Internet-Draft. The
              registration is not IETF adoption, endorsement, or permanent status.
            </p>
            <div className={styles.statusLinks}>
              <a href="https://www.iana.org/assignments/uri-schemes/prov/canactid" target="_blank" rel="noreferrer">
                IANA registry entry
              </a>
              <a href="https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/" target="_blank" rel="noreferrer">
                Read CAID-05
              </a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/caid" target="_blank" rel="noreferrer">
                Reference code and vectors
              </a>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
