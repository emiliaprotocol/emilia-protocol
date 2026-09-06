// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { isWorksV0Enabled } from '@/lib/works/env';
import styles from './workforce.module.css';

export function WorkforceIntroduction() {
  return <section className={styles.hero} aria-labelledby="workforce-title"><div className={styles.container}>
    <p className={styles.eyebrow}>EMILIA · Authorization infrastructure for agentic AI</p>
    <h1 id="workforce-title">Your AI workforce<br />needs management.</h1>
    <p className={styles.promise}>Give every agent a job, set its authority, and know what happened.</p>
    <p className={styles.lead}>You choose what the agent may do and who is responsible. EMILIA is building the workspace to manage that work, with Gate enforcing your limits on the tools you connect.</p>
    <div className={styles.actions}><Link href="/contact#workforce" className={styles.primary}>Discuss your workflow</Link><Link href="#the-handover" className={styles.secondary}>See a refunds example</Link></div>
    <p className={styles.caption}>Private local alpha. Evaluations by arrangement, not a hosted service.</p>
  </div></section>;
}

export function WorkforceHandover() {
  return <section id="the-handover" className={styles.section} aria-labelledby="handover-title"><div className={styles.container}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>The job stays. The agent can change.</p>
      <h2 id="handover-title">Replace the agent.<br />Keep the same allowance.</h2>
      <p>A finance owner gives the refunds job a $10,000 allowance. Dot uses $3,000. Another $400 refund is unresolved. Changing the agent must not create a fresh budget.</p>
    </div>
    <div className={styles.record} aria-label="Illustrative refunds job before and after replacement">
      <div className={styles.recordHeader}><div><span className={styles.label}>Job</span><h3>Refund approved orders</h3></div><p>Owner: Finance operations</p></div>
      <dl className={styles.account}>
        <div><dt>Job allowance</dt><dd>$10,000</dd></div>
        <div><dt>Consumed</dt><dd>$3,000</dd></div>
        <div><dt>Unresolved</dt><dd className={styles.unresolved}>$400</dd></div>
      </dl>
      <div className={styles.handover}>
        <div><p>Before replacement · Dot v1</p><strong>$6,600</strong><span>Available authority</span></div>
        <div><p>After replacement · Dot v2</p><strong>$6,600</strong><span>Available authority</span></div>
      </div>
      <p className={styles.recordFoot}>The unresolved $400 stays unavailable. The retired assignment cannot start new covered work. Its history stays with the job.</p>
    </div>
    <p className={styles.caption}>Illustrative record from the local alpha&apos;s synthetic scenario. No customer funds or settlement claim. Assumes no other reservations.</p>
  </div></section>;
}

export function WorkforceResponsibilities() {
  return <section className={styles.section + ' ' + styles.tinted} aria-labelledby="responsibility-title"><div className={styles.container}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>A familiar management job</p>
      <h2 id="responsibility-title">Someone still owns the work.</h2>
      <p>Think of it as HR for AI agents: a job, delegated authority, a work review and a proper handover. Agents are software. A person or institution remains accountable.</p>
    </div>
    <div className={styles.editorial}>
      <article><h3>Give the job clear limits.</h3><p>Name the owner, define the task and set an allowance. A standing instruction can let the agent work within those limits; exceptions come back to the owner.</p></article>
      <article><h3>Change the worker, not the history.</h3><p>Assignments can change. Consumed authority and unfinished work stay with the same account. Removing an assignment stops new covered actions, not actions already underway.</p></article>
      <article><h3>Review the result.</h3><p>Keep what Gate permitted, what the provider reported and what a reviewer accepted as separate facts. A signed receipt does not prove the job was done well.</p></article>
    </div>
  </div></section>;
}

export function WorkforceFoundation() {
  return <section className={styles.section} aria-labelledby="foundation-title"><div className={styles.container}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>The infrastructure underneath</p>
      <h2 id="foundation-title">The workspace is where you manage.<br />Gate is where the limits take effect.</h2>
      <p>A screen alone cannot stop a tool call. Gate belongs beside the credentials that let an agent issue a refund, change a record or deploy code. It checks the exact action before that connected path can run.</p>
    </div>
    <div className={styles.editorial}>
      <article><h3>EMILIA is the company.</h3><p>We build the operating product and work with teams on integration and deployment. The workforce workspace is a private local alpha.</p><Link href="/about">About EMILIA</Link></article>
      <article><h3>Gate applies your authority.</h3><p>You choose the rules and the connected paths. Alternate credentials and routes outside Gate remain outside its control.</p><Link href="/gate">How Gate works</Link></article>
      <article><h3>The Protocol stays open.</h3><p>Open formats, verifiers and reference code keep evidence portable. You can use the public protocol without buying from EMILIA.</p><Link href="/protocol">Explore the open protocol</Link></article>
    </div>
    <p className={styles.boundary}>Enforcement requires completely mediated paths through the credential-owning Gate. It does not undo an action already entered, guarantee a provider&apos;s result or certify legal compliance.</p>
  </div></section>;
}

export function WorkforceReadiness() {
  return <section className={styles.section + ' ' + styles.tinted} aria-labelledby="readiness-title"><div className={styles.container}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>What you can evaluate today</p>
      <h2 id="readiness-title">Working locally.<br />Ready for a specific conversation.</h2>
      <p>The private alpha demonstrates a named job owner, agent replacement, persistent local authority and a separate work-review record using synthetic refunds.</p>
    </div>
    <div className={styles.editorial}>
      <article><h3>See the handover.</h3><p>Replacement and restart preserve the same allowance and unresolved work in the local demo. Retired-worker attempts, duplicate unresolved work and agent self-review are refused.</p></article>
      <article><h3>Understand the limits.</h3><p>The alpha runs on one trusted host with bounded local storage. It has no high availability or rollback resistance. It is not a multi-tenant hosted service or a customer deployment.</p></article>
      <article><h3>Choose one real job.</h3><p>Start with one finance team&apos;s refunds workflow, a named owner and agreed acceptance criteria. The external evaluation team and provider are not yet selected. Terms are not yet set.</p></article>
    </div>
    <p className={styles.boundary}>Production needs authenticated identities, a credential-owning executor, durable state and tested recovery for the agreed environment. No customer savings or ROI are claimed.</p>
  </div></section>;
}

export function WorkforceNextStep() {
  return <section className={styles.section} aria-labelledby="next-step-title"><div className={styles.container}>
    <p className={styles.eyebrow}>Start with one job</p>
    <h2 id="next-step-title">What would you let an agent do<br />if its limits stayed in place?</h2>
    <p className={styles.lead}>Bring one workflow and the person who owns it. We&apos;ll look at the tools it reaches, the authority it needs and how you would judge the result.</p>
    <div className={styles.actions}><Link href="/contact#workforce" className={styles.primary}>Discuss your workflow</Link><Link href="/scan#run-local" className={styles.secondary}>Map my agent</Link></div>
    <p className={styles.caption}>The developer scan is free. It maps supported declared actions; it does not activate enforcement.</p>
  </div></section>;
}

export function WorkforceMarketplace() {
  if (!isWorksV0Enabled()) return null;
  return <section className={styles.section} aria-labelledby="marketplace-entry-title"><div className={styles.container}>
    <p className={styles.eyebrow}>EMILIA Marketplace · Early access</p>
    <h2 id="marketplace-entry-title">Bring your agent.<br />See what it can reach.</h2>
    <p className={styles.lead}>Scan its declared tools for free. See which actions may move money, change access, delete data or affect a customer. Keep the report, then decide which calls need Gate.</p>
    <div className={styles.actions}><Link href="/works/scan" className={styles.primary}>Scan my agent for free</Link><Link href="/works" className={styles.secondary}>Explore the marketplace</Link></div>
    <p className={styles.caption}>The browser scan stays on your device. Listings are supplied by builders; examples are labeled separately. Scanning and listing do not certify an agent.</p>
  </div></section>;
}

export function WorkforceEntry() {
  return <section className={styles.entry} aria-labelledby="workforce-entry-title"><div className={styles.container}>
    <p className={styles.eyebrow}>Managing an AI workforce</p>
    <h2 id="workforce-entry-title">Give every agent a job, set its authority, and know what happened.</h2>
    <p>The workforce workspace brings jobs, assignments and work reviews around Gate. See how the private local alpha keeps the same allowance when an agent is replaced.</p>
    <Link href="/workforce" className={styles.secondary}>Meet the workforce product</Link>
  </div></section>;
}
