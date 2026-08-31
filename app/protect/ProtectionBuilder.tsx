'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  ArrowDownToLine,
  Bot,
  Check,
  ChevronRight,
  CircleDollarSign,
  Code2,
  DatabaseZap,
  FileX2,
  KeyRound,
  LoaderCircle,
  ShieldCheck,
  Unplug,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import gatePackage from '../../packages/gate/package.json';
import styles from './protect.module.css';

type Preset = {
  id: string;
  label: string;
  consequence: string;
  action_type: string;
  assurance_floor: 'class_a' | 'quorum';
  connector: { required: true; kind: string; label: string };
};

const ICONS: Record<string, React.ComponentType<{ size?: number; 'aria-hidden'?: boolean }>> = {
  'spend-money': CircleDollarSign,
  'delete-files': FileX2,
  'change-access': KeyRound,
  'publish-code': Code2,
  'send-sensitive-data': DatabaseZap,
  'control-machines': Bot,
};

function safePlanId(label: string): string {
  const base = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'personal';
  return `${base}-${Date.now().toString(36)}`;
}

export default function ProtectionBuilder({ presets }: { presets: Preset[] }): React.ReactElement {
  const [selected, setSelected] = useState<string[]>([]);
  const [ownerLabel, setOwnerLabel] = useState('My devices');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [plan, setPlan] = useState<any>(null);

  const selectedPresets = useMemo(
    () => presets.filter((preset) => selected.includes(preset.id)),
    [presets, selected],
  );

  function toggle(id: string): void {
    setPlan(null);
    setError('');
    setSelected((current) => current.includes(id)
      ? current.filter((entry) => entry !== id)
      : [...current, id]);
  }

  async function build(): Promise<void> {
    if (selected.length === 0 || busy) return;
    setBusy(true);
    setError('');
    try {
      const response = await fetch('/api/v1/protection-plans', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          plan_id: safePlanId(ownerLabel),
          owner_label: ownerLabel || 'My devices',
          selections: selected.map((presetId) => ({ preset_id: presetId })),
        }),
      });
      const body = await response.json();
      if (!response.ok || !body.plan) throw new Error(body.error || 'plan_build_failed');
      setPlan(body.plan);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'plan_build_failed');
    } finally {
      setBusy(false);
    }
  }

  function download(): void {
    if (!plan) return;
    const href = URL.createObjectURL(new Blob([`${JSON.stringify(plan, null, 2)}\n`], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.download = `${plan.plan_id}.emilia-protection-plan.json`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  return (
    <section className={styles.builder} aria-label="Build a protection plan">
      <div className={styles.builderHeader}>
        <div><span className={styles.eyebrow}>STEP 1 / CHOOSE CONSEQUENCES</span><h2>What should require authority?</h2></div>
        <strong>{selected.length} selected</strong>
      </div>

      <div className={styles.presetGrid}>
        {presets.map((preset) => {
          const Icon = ICONS[preset.id] || ShieldCheck;
          const isSelected = selected.includes(preset.id);
          return (
            <button
              type="button"
              key={preset.id}
              className={`${styles.preset} ${isSelected ? styles.presetSelected : ''}`}
              aria-pressed={isSelected}
              onClick={() => toggle(preset.id)}
            >
              <span className={styles.presetIcon}><Icon size={23} aria-hidden /></span>
              <span className={styles.presetCopy}><strong>{preset.label}</strong><small>{preset.consequence}</small></span>
              <span className={styles.selectMark}>{isSelected ? <Check size={16} aria-hidden /> : 'Add'}</span>
              <span className={styles.connector}><Unplug size={13} aria-hidden />{preset.connector.label}</span>
            </button>
          );
        })}
      </div>

      <div className={styles.planBar}>
        <label>
          <span>Name this protection plan</span>
          <input value={ownerLabel} maxLength={160} onChange={(event) => { setOwnerLabel(event.target.value); setPlan(null); }} />
        </label>
        <button type="button" className={styles.buildButton} onClick={build} disabled={selected.length === 0 || busy}>
          {busy ? <LoaderCircle className={styles.spin} size={17} aria-hidden /> : <ShieldCheck size={17} aria-hidden />}
          Build my plan
          <ChevronRight size={17} aria-hidden />
        </button>
      </div>

      {error ? <p className={styles.error} role="alert">Plan could not be built: {error}</p> : null}

      {plan ? (
        <section className={styles.result} aria-live="polite">
          <div className={styles.resultHead}>
            <div><span className={styles.eyebrow}>LOCAL DRAFT CREATED / NOT YET ACTIVE</span><h2>Your draft is ready to review and connect.</h2></div>
            <button type="button" onClick={download}><ArrowDownToLine size={16} aria-hidden />Download plan</button>
          </div>
          <div className={styles.resultRows}>
            {selectedPresets.map((preset) => (
              <div key={preset.id}>
                <span><Check size={14} aria-hidden />Selected</span>
                <strong>{preset.label}</strong>
                <small>Next: {preset.connector.label}</small>
                <em>Connector required</em>
              </div>
            ))}
          </div>
          <p><Unplug size={16} aria-hidden />This unsigned draft does not claim your systems are protected. Pin it as owner authority, install each owning connector, and verify its refusal probe first.</p>
          <div className={styles.activation}>
            <span className={styles.eyebrow}>STEP 2 / SIGN LOCALLY</span>
            <h3>Activate the plan with your own key.</h3>
            <p>EMILIA never receives the private key. The Gate utility signs the exact plan on your machine and writes a customer-owned activation artifact.</p>
            <code>npx --package @emilia-protocol/gate@{gatePackage.version} ep-protect activate {plan.plan_id}.emilia-protection-plan.json --private-key owner.pem --tenant my-tenant --gateway my-mcp-gateway --authorizer my-owner --key-id owner-key-1 --out activation.json</code>
            <div className={styles.activationLinks}>
              <a href="https://www.npmjs.com/package/@emilia-protocol/gate" target="_blank" rel="noopener noreferrer">Install EMILIA Gate</a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/customer-owned-mcp-gateway" target="_blank" rel="noopener noreferrer">Run the customer-owned MCP gateway</a>
            </div>
            <small>Active protection begins only after the gateway verifies this activation, owns the protected tool path, and passes the refusal probe.</small>
          </div>
        </section>
      ) : null}
    </section>
  );
}
