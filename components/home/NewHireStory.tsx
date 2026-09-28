// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import Image from 'next/image';
import { Barlow_Condensed, Newsreader } from 'next/font/google';
import proofStats from '@/lib/proof-stats.json';
import styles from './newhire.module.css';

const display = Barlow_Condensed({ subsets: ['latin'], weight: ['600', '700'], variable: '--nh-display', display: 'swap' });
const serif = Newsreader({ subsets: ['latin'], weight: ['400', '500'], style: ['normal', 'italic'], variable: '--nh-serif', display: 'swap' });

const WIDE = '100vw';
const HALF = '(max-width: 900px) 100vw, 50vw';

export function NewHireStory(): React.ReactElement {
  return (
    <div className={`${styles.story} ${display.variable} ${serif.variable}`}>
      <section className={styles.hero} aria-labelledby="newhire-title">
        <Image className={styles.bleed} src="/home-newhire-cover-v1.webp" alt="Toll gates at dusk under orange lamps, with the light trails of traffic passing through." fill priority sizes={WIDE} />
        <div className={styles.heroPanel}>
          <p className={styles.kicker}>EMILIA</p>
          <h1 id="newhire-title">Hire the AI.<br />Keep your rules.</h1>
          <p className={styles.heroLead}>EMILIA gives AI the rules every new hire gets, and checks them at a gate the AI can&apos;t go around.</p>
          <div className={styles.actions}>
            <Link href="/try" className={styles.primary}>Try it with Face ID</Link>
            <Link href="/gate" className={styles.secondary}>How the gate works</Link>
          </div>
          <p className={styles.caption}>The live demo: approve an AI&apos;s payment with Face ID, then watch a forged amount fail the check.</p>
        </div>
      </section>

      <section className={`${styles.split} ${styles.bone}`} aria-labelledby="rosa-title">
        <div className={styles.media}><Image src="/home-newhire-kitchen-v1.webp" alt="A woman seen from behind, working on a laptop at a kitchen table by a sunny window." fill sizes={HALF} /></div>
        <div className={styles.copy}>
          <p className={styles.kicker}>A short story about AI at work</p>
          <h2 id="rosa-title">Rosa pays the bills</h2>
          <p>For 22 years she has paid the bills at her family&apos;s flooring company, and trained everyone who touches the money.</p>
          <p className={styles.note}>An illustrative story with AI-generated images. Rosa, her company and every amount in it are made up. The trouble she meets is real.</p>
        </div>
      </section>

      <section className={`${styles.split} ${styles.reverse} ${styles.bone}`} aria-labelledby="rules-title">
        <div className={styles.media}><Image src="/home-newhire-ledger-v1.webp" alt="An open ledger, a pen and an ink stamp on a dark wooden desk under a lamp." fill sizes={HALF} /></div>
        <div className={styles.copy}>
          <p className={styles.kicker}>Rosa&apos;s rules</p>
          <h2 id="rules-title">Every new hire<br />gets rules</h2>
          <ol className={styles.rules}>
            <li>Pay approved bills up to $10,000</li>
            <li>Anything bigger waits for Rosa&apos;s yes</li>
            <li>Pay suppliers at their usual account</li>
            <li>Write everything down</li>
          </ol>
          <p>This year the new hire is an AI. It reads the bills and pays them, even at 2 a.m. And like any new hire, it can be fooled.</p>
        </div>
      </section>

      <section className={styles.statement} aria-labelledby="email-title">
        <Image className={styles.bleed} src="/home-newhire-openlane-v1.webp" alt="An empty toll lane at night with truck light trails passing in the next lane." fill sizes={WIDE} />
        <div className={styles.statementPanel}>
          <p className={styles.kicker}>Tuesday, 2:14 a.m.</p>
          <h2 id="email-title">&ldquo;We&apos;ve changed banks&rdquo;</h2>
          <p>Please send this month&apos;s $8,400 to our new account. The bill is real. The account belongs to a scammer. It is under the $10,000 limit, so a check on the amount alone would wave it through.</p>
        </div>
      </section>

      <section className={`${styles.band} ${styles.asphalt}`} aria-labelledby="stake-title">
        <div className={styles.bandInner}>
          <div>
            <p className={styles.kicker}>This part is real</p>
            <h2 id="stake-title">People already<br />fall for this</h2>
          </div>
          <div className={styles.bigNumber}>
            <strong>$3B</strong>
            <p>reported lost to business email compromise in 2025.</p>
            <p className={styles.note}>FBI Internet Crime Complaint Center, <a href="https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf">2025 Annual Report</a>: $3,046,598,558.</p>
          </div>
        </div>
      </section>

      <section className={styles.statement} aria-labelledby="asleep-title">
        <Image className={styles.bleed} src="/home-newhire-barrier-v1.webp" alt="A red and white barrier arm across a wet road at night, lit by one orange lamp." fill sizes={WIDE} />
        <div className={styles.statementPanel}>
          <p className={styles.kicker}>Rosa is asleep</p>
          <h2 id="asleep-title">She can&apos;t watch<br />it all night</h2>
          <p>A good scam can talk an AI out of its instructions. So Rosa&apos;s rules sit at a gate it can&apos;t talk its way past.</p>
        </div>
      </section>

      <section className={`${styles.band} ${styles.bone}`} aria-labelledby="gate-title">
        <div className={styles.bandStack}>
          <p className={styles.kicker}>Meet EMILIA</p>
          <h2 id="gate-title">EMILIA is the gate</h2>
          <div className={styles.flow} role="group" aria-label="The AI asks for one exact payment. The EMILIA Gate checks it against the rules. Within the rules it goes through. Outside them it stops, with a reason.">
            <div className={styles.node}><span>The AI asks</span><p>This amount, to this account.</p></div>
            <div className={`${styles.node} ${styles.gateNode}`}><span>EMILIA Gate</span><p>Checks the rules.</p></div>
            <div className={styles.outcomes}>
              <div className={styles.node}><span>Within the rules</span><p>Goes through.</p></div>
              <div className={`${styles.node} ${styles.stopNode}`}><span>Outside them</span><p>Stops, with a reason.</p></div>
            </div>
          </div>
          <p className={styles.wide}>The AI doesn&apos;t pay anyone directly. It asks, and the gate checks that exact payment: the amount, and the account it is going to. The gate takes those details from the company&apos;s own records, never from the AI&apos;s say-so. A bigger payment can wait for a person to approve that one payment.</p>
        </div>
      </section>

      <section className={`${styles.split} ${styles.asphalt}`} aria-labelledby="keys-title">
        <div className={styles.media}><Image src="/home-newhire-signalbox-v1.webp" alt="Inside a signal box at dusk: a row of levers, a desk lamp and a logbook, with rail tracks outside the window." fill sizes={HALF} /></div>
        <div className={styles.copy}>
          <p className={styles.kicker}>No way around</p>
          <h2 id="keys-title">The new hire never<br />holds the keys</h2>
          <p>The gate holds the bank login. The AI can ask, but it can&apos;t go around the gate or raise its own limit. If the bank goes quiet in the middle of a payment, the gate marks it unfinished, so it can&apos;t be blindly sent twice. The money never passes through the gate. It stays in the bank.</p>
          <p className={styles.note}>This covers the payment paths a company connects through EMILIA.</p>
        </div>
      </section>

      <section className={`${styles.band} ${styles.bone}`} aria-labelledby="stopped-title">
        <div className={styles.bandStack}>
          <p className={styles.kicker}>2:14 a.m., at the gate</p>
          <h2 id="stopped-title">Same bill.<br />Wrong account.</h2>
          <div className={styles.contrast}>
            <div className={styles.allowed}><span>Rosa&apos;s rules allow</span><strong>$8,400</strong><p>to the supplier&apos;s usual account</p></div>
            <div className={styles.bar} aria-hidden="true" />
            <div className={styles.asked}><span>The AI asked</span><strong>$8,400</strong><p>to a new account</p><em>Stopped: not the usual account.</em></div>
          </div>
        </div>
      </section>

      <section className={`${styles.split} ${styles.reverse} ${styles.bone}`} aria-labelledby="homework-title">
        <div className={styles.media}><Image src="/home-newhire-seal-v1.webp" alt="A geometric seal embossed into thick white paper." fill sizes={HALF} /></div>
        <div className={styles.copy}>
          <p className={styles.kicker}>The next morning</p>
          <h2 id="homework-title">Nobody grades their<br />own homework</h2>
          <p>Rosa reads why the payment stopped and calls the supplier on the number she has had for years. They never changed banks.</p>
          <p>Every yes and no is written down. Each payment the gate allows gets a signed receipt her accountant can check on their own computer, even offline, without asking the AI company.</p>
          <p className={styles.note}>A check shows a receipt is genuine and unchanged. Which signers to trust stays the accountant&apos;s call.</p>
          <Link href="/verify" className={styles.textLink}>Check a receipt in your browser</Link>
        </div>
      </section>

      <section className={`${styles.band} ${styles.asphalt}`} aria-labelledby="blueprint-title">
        <div className={styles.bandInner}>
          <div>
            <p className={styles.kicker}>The business</p>
            <h2 id="blueprint-title">Free blueprint.<br />Running it is our job.</h2>
          </div>
          <div className={styles.blueprint}>
            <p>The EMILIA protocol and a reference Gate are open source under the Apache-2.0 license. Anyone can read how the gate works and build on it, because a gate you are asked to trust should be one you can inspect. Our business is operating the gate for companies and connecting it to the systems they already use, scoped for each deployment.</p>
            <p className={styles.note}>The public repository records {Number(proofStats.tests.total).toLocaleString('en-US')} automated tests, {proofStats.conformance.vectors} conformance vectors and {proofStats.securityCase.claims} executable security claims. Those are engineering results, not customer adoption or proof of a complete deployment. No customer savings or ROI are claimed.</p>
            <div className={styles.links}>
              <Link href="/proof">Inspect the proof</Link>
              <Link href="/protocol">Read the protocol</Link>
              <Link href="/products">See the supporting tools</Link>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.statement} aria-labelledby="close-title">
        <Image className={styles.bleed} src="/home-newhire-dawnroad-v1.webp" alt="An open toll gate at sunrise with an empty road running toward misty hills." fill sizes={WIDE} />
        <div className={styles.statementPanel}>
          <p className={styles.kicker}>Where we&apos;re headed</p>
          <h2 id="close-title">A gate wherever<br />AI does real work</h2>
          <p>We start with supplier payments at the finance teams of larger companies. The aim is a gate like this wherever AI does real work for a business, earned one company at a time.</p>
          <div className={styles.actions}>
            <Link href="/try" className={styles.primary}>Try it with Face ID</Link>
            <Link href="/contact" className={styles.secondary}>Talk to us</Link>
          </div>
          <p className={styles.caption}>Also from EMILIA: the <Link href="/workforce">AI workforce alpha</Link>, a private local preview.</p>
        </div>
      </section>
    </div>
  );
}
