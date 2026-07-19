'use client';

// SPDX-License-Identifier: Apache-2.0
import Image from 'next/image';
import Link from 'next/link';
import {
  Activity,
  BadgeDollarSign,
  ChevronLeft,
  ChevronRight,
  FileCheck2,
  Gauge,
  Pause,
  Play,
  Send,
  ShieldCheck,
  Smartphone,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import styles from './demo.module.css';

const SLIDE_COUNT = 6;
const SLIDE_DURATION_MS = 5000;

function Boundary() {
  return (
    <div className={styles.boundary}>
      <span>Reference simulation</span>
      <span>Real cryptographic verification</span>
      <span>No physical grid event</span>
    </div>
  );
}

function SlideLabel({ number, children }) {
  return (
    <div className={styles.slideLabel}>
      <span>{String(number).padStart(2, '0')}</span>
      <strong>{children}</strong>
    </div>
  );
}

function ScreenshotFrame({ src, alt, className = '' }) {
  return (
    <div className={`${styles.screenshotFrame} ${className}`}>
      <Image src={src} alt={alt} fill priority sizes="(max-width: 760px) 100vw, 70vw" />
    </div>
  );
}

export default function GraceScreenshotStory() {
  const [active, setActive] = useState(0);
  const [playing, setPlaying] = useState(true);

  const move = useCallback((offset) => {
    setActive((current) => (current + offset + SLIDE_COUNT) % SLIDE_COUNT);
  }, []);

  useEffect(() => {
    if (!playing) return undefined;
    const timer = window.setTimeout(() => move(1), SLIDE_DURATION_MS);
    return () => window.clearTimeout(timer);
  }, [active, move, playing]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === 'ArrowRight') move(1);
      if (event.key === 'ArrowLeft') move(-1);
      if (event.key === ' ') {
        event.preventDefault();
        setPlaying((value) => !value);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [move]);

  const slides = [
    <section className={`${styles.slide} ${styles.opening}`} key="opening">
      <div className={styles.openingCopy}>
        <SlideLabel number={1}>THE REQUEST</SlideLabel>
        <h1>18 MW should never move on an AI&apos;s word alone.</h1>
        <p>
          GRACE turns an autonomous curtailment request into one bounded action that two
          accountable humans must approve before execution.
        </p>
        <div className={styles.openingFacts}>
          <div><strong>18.000</strong><span>MW ordered</span></div>
          <div><strong>2</strong><span>Class-A approvers</span></div>
          <div><strong>90</strong><span>minute window</span></div>
        </div>
      </div>
      <div className={styles.phoneHero}>
        <Image
          src="/grace-demo/mobile-approval.png"
          alt="EMILIA Approver showing the exact 18 MW grid curtailment action"
          fill
          priority
          sizes="(max-width: 760px) 66vw, 30vw"
        />
      </div>
      <Boundary />
    </section>,

    <section className={`${styles.slide} ${styles.ceremony}`} key="ceremony">
      <div className={styles.ceremonyCopy}>
        <SlideLabel number={2}>THE CEREMONY</SlideLabel>
        <h2>The same action. Two independent approvals.</h2>
        <p>
          Each handshake is fresh, device-bound, exact-action-bound, and checked against a
          relying-party-pinned roster. The initiator cannot approve its own request.
        </p>
        <div className={styles.digestJoin}>
          <ShieldCheck aria-hidden="true" size={23} />
          <span>Both signatures bind the same action digest</span>
        </div>
      </div>
      <div className={styles.phonePair}>
        <div>
          <span className={styles.personLabel}>Grid operator / 01</span>
          <ScreenshotFrame src="/grace-demo/mobile-approval.png" alt="First Class-A mobile approval" className={styles.phoneCrop} />
        </div>
        <div>
          <span className={styles.personLabel}>Facility duty officer / 02</span>
          <ScreenshotFrame src="/grace-demo/mobile-approval.png" alt="Second Class-A mobile approval" className={styles.phoneCrop} />
        </div>
      </div>
      <Boundary />
    </section>,

    <section className={`${styles.slide} ${styles.control}`} key="control">
      <div className={styles.topCopy}>
        <SlideLabel number={3}>THE CONTROL CHAIN</SlideLabel>
        <h2>Permission closes before power moves.</h2>
        <p>Six transitions. Every boundary signed or independently checked.</p>
      </div>
      <ScreenshotFrame
        src="/grace-demo/control-room.png"
        alt="GRACE control room showing authorize, verify, dispatch, measure, record, and settle"
        className={styles.wideCapture}
      />
      <Boundary />
    </section>,

    <section className={`${styles.slide} ${styles.effect}`} key="effect">
      <div className={styles.effectCopy}>
        <SlideLabel number={4}>THE PHYSICAL EFFECT</SlideLabel>
        <h2>64.000 <span>to</span> 46.072 MW</h2>
        <p>
          An independent meter reports 17.847 MW delivered. The settlement rule is pinned
          outside the meter, and Action State binds the authorization, dispatch, and measurement.
        </p>
        <div className={styles.effectStats}>
          <div><strong>99.2%</strong><span>delivered</span></div>
          <div><strong>1x</strong><span>settlement consumption</span></div>
        </div>
      </div>
      <ScreenshotFrame
        src="/grace-demo/measured-effect.png"
        alt="Measured facility load and the signed evidence packet"
        className={styles.effectCapture}
      />
      <Boundary />
    </section>,

    <section className={`${styles.slide} ${styles.hostile}`} key="hostile">
      <div className={styles.topCopy}>
        <SlideLabel number={5}>THE HOSTILE RUN</SlideLabel>
        <h2>The happy path is not the test. These are.</h2>
        <p>The same implementation that produces the proof must refuse its mutations.</p>
      </div>
      <ScreenshotFrame
        src="/grace-demo/refused-attacks.png"
        alt="GRACE refusing replay, action substitution, and meter rule smuggling"
        className={styles.attackCapture}
      />
      <div className={styles.mobileAttacks}>
        <ScreenshotFrame src="/grace-demo/attack-replay.png" alt="Replay attack refused" className={styles.mobileAttackShot} />
        <ScreenshotFrame src="/grace-demo/attack-substitution.png" alt="Action substitution refused" className={styles.mobileAttackShot} />
        <ScreenshotFrame src="/grace-demo/attack-meter-rule.png" alt="Meter rule smuggling refused" className={styles.mobileAttackShot} />
      </div>
      <div className={styles.refusalStrip}>
        <span>Replay refused</span>
        <span>Action substitution refused</span>
        <span>Meter-rule smuggling refused</span>
      </div>
      <Boundary />
    </section>,

    <section className={`${styles.slide} ${styles.closing}`} key="closing">
      <div className={styles.closingMark}>GRACE</div>
      <SlideLabel number={6}>THE RELIANCE RECORD</SlideLabel>
      <h2>From human permission to physical consequence.</h2>
      <div className={styles.chain}>
        {(/** @type {Array<[import('react').ComponentType<any>, string]>} */ ([
          [Smartphone, 'Approve'],
          [ShieldCheck, 'Verify'],
          [Send, 'Dispatch'],
          [Gauge, 'Measure'],
          [FileCheck2, 'Record'],
          [BadgeDollarSign, 'Settle'],
        ])).map(([Icon, label]) => (
          <div className={styles.chainNode} key={label}>
            <Icon aria-hidden="true" size={25} />
            <span>{label}</span>
          </div>
        ))}
      </div>
      <p className={styles.closingCopy}>
        A reference control layer for consequential machine actions, built on EMILIA authorization,
        COSA-compatible dispatch evidence, and Action State records.
      </p>
      <Link className={styles.liveLink} href="/grace/live">
        <Activity aria-hidden="true" size={18} />
        Open the live reference run
      </Link>
      <Boundary />
    </section>,
  ];

  return (
    <main className={styles.story} aria-label="GRACE screenshot demonstration">
      <div className={styles.brand}>EMILIA / GRACE</div>
      <Link href="/grace/live" className={styles.closeButton} aria-label="Close presentation" title="Close presentation">
        <X aria-hidden="true" size={21} />
      </Link>

      <div className={styles.slides}>
        {slides.map((slide, index) => (
          <div className={index === active ? styles.activeSlide : styles.inactiveSlide} key={index} aria-hidden={index !== active}>
            {slide}
          </div>
        ))}
      </div>

      <div className={styles.controls}>
        <button type="button" onClick={() => move(-1)} aria-label="Previous frame" title="Previous frame">
          <ChevronLeft aria-hidden="true" size={21} />
        </button>
        <button type="button" onClick={() => setPlaying((value) => !value)} aria-label={playing ? 'Pause presentation' : 'Play presentation'} title={playing ? 'Pause presentation' : 'Play presentation'}>
          {playing ? <Pause aria-hidden="true" size={18} /> : <Play aria-hidden="true" size={18} />}
        </button>
        <div className={styles.dots} aria-label={`Frame ${active + 1} of ${SLIDE_COUNT}`}>
          {Array.from({ length: SLIDE_COUNT }, (_, index) => (
            <button
              type="button"
              className={index === active ? styles.activeDot : ''}
              aria-label={`Open frame ${index + 1}`}
              title={`Frame ${index + 1}`}
              onClick={() => setActive(index)}
              key={index}
            />
          ))}
        </div>
        <button type="button" onClick={() => move(1)} aria-label="Next frame" title="Next frame">
          <ChevronRight aria-hidden="true" size={21} />
        </button>
      </div>
    </main>
  );
}
