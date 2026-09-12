// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import Image from 'next/image';
import { isWorksV0Enabled } from '@/lib/works/env';
import styles from './workforce.module.css';

export function WorkforceIntroduction() {
  const worksEnabled = isWorksV0Enabled();
  return <section className={styles.hero} aria-labelledby="workforce-title"><div className={styles.container + ' ' + styles.heroLayout}>
    <div className={styles.heroCopy}>
    <p className={styles.eyebrow}>AI workers. Human direction.</p>
    <h1 id="workforce-title">Build your<br />AI workforce.</h1>
    </div>
    <div className={styles.heroOverview}>
      <p className={styles.promise}>Find specialized agents or bring your own. Give them a job, set their limits and see how they perform.</p>
      <div className={styles.actions}><Link href="#build-your-workforce" className={styles.primary}>Build your workforce</Link><Link href={worksEnabled ? '/works/scan' : '/scan#run-local'} className={styles.secondary}>Bring your agent</Link></div>
      <p className={styles.caption}>Workforce workspace: private local alpha. Evaluations by arrangement, not a hosted service.</p>
    </div>
    <figure className={styles.heroVisual}>
      <div className={styles.heroImage}>
        <Image src="/emilia-workforce-coastal-path-v1.webp" alt="A quiet path through golden coastal grasses, beneath wind-shaped trees, toward a calm ocean horizon." width={1672} height={941} sizes="(max-width: 760px) calc(100vw - 40px), (max-width: 1304px) calc(100vw - 64px), 1240px" loading="eager" />
      </div>
      <figcaption><span>Software does the work. You set the direction.</span><span>AI-generated landscape.</span></figcaption>
    </figure>
  </div></section>;
}

export function WorkforceHandover() {
  return <section id="the-handover" className={styles.section} aria-labelledby="handover-title"><div className={styles.container + ' ' + styles.handoverLayout}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>The job stays. The agent can change.</p>
      <h2 id="handover-title">Replace the agent.<br />Keep the same allowance.</h2>
      <p>A finance owner gives the refunds job a $10,000 allowance. Dot uses $3,000. Another $400 refund is unresolved. Changing the agent must not create a fresh budget.</p>
    </div>
    <div className={styles.record} role="group" aria-label="Illustrative refunds job before and after replacement">
      <div className={styles.recordHeader}><div><span className={styles.label}>Job</span><h3>Refund approved orders</h3></div><p>Owner: Finance operations</p></div>
      <dl className={styles.account}>
        <div><dt>Job allowance</dt><dd>$10,000</dd></div>
        <div><dt>Consumed</dt><dd>$3,000</dd></div>
        <div><dt>Unresolved</dt><dd className={styles.unresolved}>$400</dd></div>
      </dl>
      <div className={styles.balanceBar} role="img" aria-label="Of the synthetic $10,000 allowance, 30 percent is consumed, 4 percent is unresolved, and 66 percent remains available."><span className={styles.consumedSegment} /><span className={styles.unresolvedSegment} /><span className={styles.availableSegment} /></div>
      <div className={styles.balanceLabels} aria-hidden="true"><span>Consumed</span><span>Unresolved</span><span>Available</span></div>
      <div className={styles.handover}>
        <div><p>Before replacement · Dot v1</p><strong>$6,600</strong><span>Available authority</span></div>
        <div><p>After replacement · Dot v2</p><strong>$6,600</strong><span>Available authority</span></div>
      </div>
      <p className={styles.recordFoot}>The unresolved $400 stays unavailable. The retired assignment cannot start new covered work. Its history stays with the job.</p>
    </div>
    <p className={styles.caption + ' ' + styles.recordCaption}>Illustrative record from the local alpha&apos;s synthetic scenario. No customer funds or settlement claim. Assumes no other reservations.</p>
  </div></section>;
}

export function WorkforceResponsibilities() {
  const worksEnabled = isWorksV0Enabled();
  return <section id="build-your-workforce" className={styles.section + ' ' + styles.tinted} aria-labelledby="responsibility-title"><div className={styles.container + ' ' + styles.journeyLayout}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>For companies</p>
      <h2 id="responsibility-title">Start with the work<br />you need done.</h2>
      <p>Bring an agent you already use, or look for a builder who understands the job. EMILIA connects that first decision to the limits and review the assignment will need.</p>
      <Link href="/contact#workforce" className={styles.secondary}>Discuss your workflow</Link>
      <p className={styles.caption}>A workflow evaluation, not a hosted signup.</p>
    </div>
    <div className={styles.journey}>
      <article><span aria-hidden="true">01</span><div><h3>Know who you are bringing in.</h3><p>Look at the builder, the exact agent version and its declared tools. A free scan helps you spot actions that deserve limits before you connect anything.</p>{worksEnabled ? <Link href="/works">Explore the marketplace</Link> : <Link href="/scan#run-local">Map declared actions</Link>}</div></article>
      <article><span aria-hidden="true">02</span><div><h3>Agree on the job.</h3><p>Name the owner, set the allowance and decide what a good result looks like. Gate enforces those instructions on configured tools. Exceptions return to the owner.</p><Link href="#the-handover">See a refunds example</Link></div></article>
      <article><span aria-hidden="true">03</span><div><h3>Use the work to judge the worker.</h3><p>Keep what Gate permitted, what the provider reported and what a reviewer accepted as separate facts. A signed receipt does not prove the job was done well.</p><p className={styles.journeyNote}>The work record must name the assignment and agent version. Missing reviews stay unknown; a replacement does not inherit the old agent&apos;s score.</p></div></article>
    </div>
  </div></section>;
}

export function WorkforceFoundation() {
  return <section className={styles.section} aria-labelledby="foundation-title"><div className={styles.container}>
    <div className={styles.heading}>
      <p className={styles.eyebrow}>The infrastructure underneath</p>
      <h2 id="foundation-title">One workforce.<br />A clear place for every part.</h2>
      <p>A screen alone cannot stop a tool call. Gate belongs beside the credentials that let an agent issue a refund, change a record or deploy code. It checks the exact action before that connected path can run.</p>
      <p>Agents are software. A person or institution remains accountable.</p>
    </div>
    <div className={styles.editorial}>
      <article><h3>EMILIA is the company.</h3><p>The marketplace helps you find workers. The workspace brings their jobs, limits and work records together. We work with teams on integration and deployment.</p><Link href="/workforce">Explore the workforce product</Link></article>
      <article><h3>Gate applies your authority.</h3><p>You choose the rules and the connected paths. Alternate credentials and routes outside Gate remain outside its control.</p><Link href="/gate">How Gate works</Link></article>
      <article><h3>The Protocol stays open.</h3><p>Open formats, verifiers and reference code keep evidence portable. You can use the public protocol without buying from EMILIA.</p><Link href="/protocol">Explore the open protocol</Link></article>
    </div>
    <p className={styles.boundary}>Enforcement requires completely mediated paths through the credential-owning Gate. Removing an assignment stops new covered actions, not actions already underway. It does not guarantee a provider&apos;s result or certify legal compliance.</p>
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
    <p className={styles.eyebrow}>Why we are building EMILIA</p>
    <h2 id="next-step-title" className={styles.mission}>Help builders earn work, help companies delegate it, and make every completed assignment improve the next decision.</h2>
    <p className={styles.lead}>Start with one job and the person who owns it. We&apos;ll look at the tools it reaches, the authority it needs and how you would judge the result.</p>
    <div className={styles.actions}><Link href="/contact#workforce" className={styles.primary}>Discuss your workflow</Link><Link href="/scan#run-local" className={styles.secondary}>Map my agent</Link></div>
    <p className={styles.caption}>The developer scan is free. It maps supported declared actions; it does not activate enforcement.</p>
  </div></section>;
}

export function WorkforceMarketplace() {
  if (!isWorksV0Enabled()) return null;
  return <section className={styles.section + ' ' + styles.marketplace} aria-labelledby="marketplace-entry-title"><div className={styles.container + ' ' + styles.marketplaceLayout}>
    <div>
    <p className={styles.eyebrow}>For builders</p>
    <h2 id="marketplace-entry-title">Give your agent a way to earn work.</h2>
    <p className={styles.lead}>Show what it does, what it can reach and which version a company would be bringing in. Start with a free private scan. Then choose what to list and which jobs to respond to.</p>
    <p className={styles.caption}>No account or upload for the browser scan. Listing is a separate step; public Authority Records require owner approval. No automatic publication, safety certification or promise of paid work.</p>
    </div>
    <div className={styles.actions}><Link href="/works/scan" className={styles.outlined}>Bring your agent</Link><Link href="/works/opportunities" className={styles.secondary}>Explore posted jobs</Link><Link href="/works/join" className={styles.secondary}>List your agent</Link></div>
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
