// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import { PROTECTION_PRESETS } from '@emilia-protocol/gate/protection-plan';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import ProtectionBuilder from './ProtectionBuilder';
import styles from './protect.module.css';

export const metadata: Metadata = {
  title: 'Choose What AI Must Ask Before Doing | EMILIA',
  description: 'Build a local EMILIA Consequence Firewall protection plan for money movement, file deletion, access changes, production code, sensitive data, and machine commands.',
};

export default function ProtectPage(): React.ReactElement {
  const presets = PROTECTION_PRESETS.map((preset) => ({
    id: preset.id,
    label: preset.label,
    consequence: preset.consequence,
    action_type: preset.action_type,
    assurance_floor: preset.assurance_floor,
    connector: preset.connector,
  }));

  return (
    <div className={styles.shell}>
      <SiteNav />
      <main>
        <section className={styles.hero}>
          <div className={styles.eyebrow}>EMILIA CONSEQUENCE FIREWALL / PERSONAL PREVIEW</div>
          <h1>Choose what AI must never do silently.</h1>
          <p className={styles.lede}>
            Pick the consequences that should require your authority before an AI agent,
            automation, or connected app can cross the boundary.
          </p>
          <div className={styles.promise}>
            <span>01</span> You choose the consequences.
            <span>02</span> EMILIA compiles the rules.
            <span>03</span> Verified connectors enforce them.
          </div>
        </section>

        <ProtectionBuilder presets={presets} />

        <section className={styles.truth}>
          <div>
            <span className={styles.eyebrow}>WHAT “PROTECTED” MEANS</span>
            <h2>A green check must be earned.</h2>
          </div>
          <p>
            Choosing a protection creates configuration. It does not control your bank,
            filesystem, cloud account, or equipment by itself. EMILIA says an action is
            protected only after you pin the rule, its owning connector is installed, and
            an active refusal test passes.
          </p>
        </section>

        <section className={styles.steps}>
          <article><span>SELECTED</span><h3>You chose the consequence</h3><p>The rule is an unsigned draft. Selection alone grants no authority and covers no execution path.</p></article>
          <article><span>PINNED + CONNECTED</span><h3>You approved the rule and connected its owner</h3><p>Gate sits before the actual money, file, code, data, access, or machine mutation.</p></article>
          <article><span>PROTECTED</span><h3>A refusal probe passed</h3><p>A receiptless test was refused at the boundary. Only then may the action show as protected.</p></article>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
