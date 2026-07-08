// SPDX-License-Identifier: Apache-2.0
/**
 * Acceptance preflight (EP-RELIANCE-GAP-REPORT-v1) test suite.
 *
 * What is asserted, and why it matters:
 *   - DETERMINISM: two builds over the same inputs are byte-identical, keys
 *     sorted, no wall-clock reads (the report is only reproducible evidence if
 *     anyone can rebuild the same bytes offline);
 *   - VERDICT FIDELITY: kernel_verdict is exactly what evaluateReliance
 *     returns, never reinterpreted or invented;
 *   - FAIL-CLOSED FOREIGN ARTIFACTS: an artifact type with no registered
 *     verifier is unverifiable presence, never satisfaction;
 *   - REFUSAL WITHOUT EVALUATION TIME: no opts.now and no packet.evaluated_at
 *     refuses with a reason instead of silently reading the clock;
 *   - THE DEMO: the five relying-party profiles over the one synthetic
 *     specialty-PA packet produce the documented, meaningfully different
 *     verdicts;
 *   - EXIT CODES: the CLI exits 0 on rely / all-rely, 2 on any do_not_rely_*,
 *     1 on operational error, driven through child_process on the real
 *     example fixtures.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildRelianceGapReport,
  buildMultiPartyRelianceGapReport,
  RELIANCE_GAP_REPORT_VERSION,
  RELIANCE_GAP_MULTI_VERSION,
  RELIANCE_GAP_LIMITATIONS,
} from '../packages/verify/reliance-gap.js';
import { evaluateReliance, RELIANCE_VERDICTS } from '../packages/verify/reliance.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'packages', 'verify', 'cli.js');
const EXAMPLE_DIR = join(ROOT, 'examples', 'reliance-gap');
const PACKET_PATH = join(EXAMPLE_DIR, 'specialty-pa-packet.json');
const PROFILES_DIR = join(EXAMPLE_DIR, 'profiles');

const loadJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const packet = () => loadJson(PACKET_PATH);
const profile = (name) => loadJson(join(PROFILES_DIR, name));

// The documented demo outcome: same transaction, five parties, five pinned
// profiles, one portable evidence packet, five meaningfully different verdicts.
const EXPECTED_VERDICTS = {
  'pharmacy.json': 'rely',
  'payer-pbm.json': 'rely',
  'prescriber-ehr.json': 'do_not_rely_quorum_unsatisfied',
  'medicaid-auditor.json': 'do_not_rely_stale_revocation',
  'hub-vendor.json': 'do_not_rely_policy_mismatch',
};

/** Assemble the same kernel input the report builder assembles, independently. */
function kernelInputFor(pkt, prof) {
  const slot = (type) => pkt.evidence.find((e) => e.type === type)?.artifact;
  return [{
    action: pkt.action,
    receipt: slot('receipt'),
    authority_proof: slot('authority_proof'),
    revocation_state: slot('revocation_state'),
    consumption: slot('consumption'),
    relying_party_profile: prof,
    now: Date.parse(pkt.evaluated_at),
  }, {
    approverKeys: pkt.context.approver_keys,
    logPublicKey: pkt.context.log_public_key,
    rpId: pkt.context.rp_id,
  }];
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI, 'reliance-gap', ...args], { cwd: ROOT, encoding: 'utf8' });
}

describe('report determinism', () => {
  it('two builds over the same inputs are byte-identical', () => {
    const a = JSON.stringify(buildRelianceGapReport(packet(), profile('pharmacy.json')));
    const b = JSON.stringify(buildRelianceGapReport(packet(), profile('pharmacy.json')));
    expect(a).toBe(b);
  });

  it('emits sorted keys at every level', () => {
    const report = buildRelianceGapReport(packet(), profile('pharmacy.json'));
    const assertSorted = (value, path) => {
      if (Array.isArray(value)) return value.forEach((v, i) => assertSorted(v, `${path}[${i}]`));
      if (value !== null && typeof value === 'object') {
        const keys = Object.keys(value);
        expect(keys, `keys unsorted at ${path}`).toEqual([...keys].sort());
        for (const k of keys) assertSorted(value[k], `${path}.${k}`);
      }
    };
    assertSorted(report, 'report');
  });

  it('two multi-party builds are byte-identical', () => {
    const profiles = () => readdirSync(PROFILES_DIR).sort()
      .map((name) => ({ label: name, profile: profile(name) }));
    const a = JSON.stringify(buildMultiPartyRelianceGapReport(packet(), profiles()));
    const b = JSON.stringify(buildMultiPartyRelianceGapReport(packet(), profiles()));
    expect(a).toBe(b);
  });

  it('two CLI runs produce byte-identical stdout', () => {
    const args = [PACKET_PATH, '--profile', join(PROFILES_DIR, 'pharmacy.json')];
    const a = runCli(args);
    const b = runCli(args);
    expect(a.stdout.length).toBeGreaterThan(0);
    expect(a.stdout).toBe(b.stdout);
  });
});

describe('verdict pass-through fidelity', () => {
  it('kernel_verdict never diverges from evaluateReliance, for every demo profile', () => {
    for (const name of Object.keys(EXPECTED_VERDICTS)) {
      const pkt = packet();
      const prof = profile(name);
      const report = buildRelianceGapReport(pkt, prof);
      const [input, opts] = kernelInputFor(pkt, prof);
      const kernel = evaluateReliance(input, opts);
      expect(report.kernel_verdict, name).toBe(kernel.verdict);
      expect(report.kernel_reasons, name).toEqual(kernel.reasons);
      expect(RELIANCE_VERDICTS, name).toContain(report.kernel_verdict);
    }
  });

  it('stays faithful when evidence is stripped (authority proof removed)', () => {
    const pkt = packet();
    pkt.evidence = pkt.evidence.filter((e) => e.type !== 'authority_proof');
    const prof = profile('pharmacy.json');
    const report = buildRelianceGapReport(pkt, prof);
    const [input, opts] = kernelInputFor(pkt, prof);
    expect(report.kernel_verdict).toBe(evaluateReliance(input, opts).verdict);
    expect(report.kernel_verdict).toBe('do_not_rely_authority_missing');
    // The statically-absent leg is enumerated in missing_evidence too.
    expect(report.missing_evidence.map((g) => g.requirement)).toContain('authority_proof');
  });
});

describe('foreign artifacts fail closed', () => {
  it('records unknown types as unverifiable presence and never counts them as evidence', () => {
    const pkt = packet();
    // Replace ALL evidence with foreign artifacts, one of which impersonates
    // a legacy fax exhibit. Nothing fills a kernel slot.
    pkt.evidence = [
      { '@type': 'x-legacy-fax', pages: 2 },
      { '@type': 'x-pdf-exhibit', uri: 'file://synthetic' },
    ];
    const report = buildRelianceGapReport(pkt, profile('pharmacy.json'));
    expect(report.evidence_inventory.every((e) => e.status === 'unverifiable_present')).toBe(true);
    // No receipt slot filled: the kernel refuses as unsigned.
    expect(report.kernel_verdict).toBe('do_not_rely_unsigned');
    const requirements = report.missing_evidence.map((g) => g.requirement);
    expect(requirements).toContain('verifiable_evidence_only:x-legacy-fax');
    expect(requirements).toContain('verifiable_evidence_only:x-pdf-exhibit');
    // Every required leg is reported missing; the foreign artifacts satisfied none.
    expect(requirements).toContain('receipt');
    expect(requirements).toContain('authority_proof');
    expect(requirements).toContain('revocation_freshness');
    expect(requirements).toContain('unconsumed_authorization');
  });

  it('an envelope declaring an unregistered type never fills a slot', () => {
    const pkt = packet();
    pkt.evidence = [{ type: 'x-attestation-of-goodness', artifact: { anything: true } }];
    const report = buildRelianceGapReport(pkt, profile('payer-pbm.json'));
    expect(report.evidence_inventory[0].status).toBe('unverifiable_present');
    expect(report.kernel_verdict).toBe('do_not_rely_unsigned');
  });

  it('a rely report still surfaces the foreign artifact as a gap (demo packet)', () => {
    const report = buildRelianceGapReport(packet(), profile('pharmacy.json'));
    expect(report.kernel_verdict).toBe('rely');
    expect(report.missing_evidence.map((g) => g.requirement))
      .toContain('verifiable_evidence_only:x-demo-fax-confirmation');
  });
});

describe('evaluation time', () => {
  it('refuses with a reason when neither opts.now nor packet.evaluated_at is supplied', () => {
    const pkt = packet();
    delete pkt.evaluated_at;
    const report = buildRelianceGapReport(pkt, profile('pharmacy.json'));
    expect(report.refused).toBe(true);
    expect(report.refusal_reason).toMatch(/evaluation time/);
    expect(report.kernel_verdict).toBeUndefined();
  });

  it('opts.now overrides packet.evaluated_at', () => {
    const pkt = packet();
    // Two hours later: the pharmacy's 3600s revocation bound is now blown.
    const report = buildRelianceGapReport(pkt, profile('pharmacy.json'), { now: '2026-07-08T17:00:00Z' });
    expect(report.kernel_verdict).toBe('do_not_rely_stale_revocation');
    expect(report.evaluated_at).toBe('2026-07-08T17:00:00.000Z');
  });

  it('refuses an unparseable evaluation time', () => {
    const report = buildRelianceGapReport(packet(), profile('pharmacy.json'), { now: 'not-a-time' });
    expect(report.refused).toBe(true);
  });
});

describe('the five-party demo', () => {
  it('produces the documented verdicts: two rely, three distinct refusals', () => {
    const profiles = readdirSync(PROFILES_DIR).sort()
      .map((name) => ({ label: name, profile: profile(name) }));
    const report = buildMultiPartyRelianceGapReport(packet(), profiles);
    expect(report['@type']).toBe(RELIANCE_GAP_MULTI_VERSION);
    expect(report.profiles_evaluated).toBe(5);
    expect(report.all_rely).toBe(false);
    const verdictByProfile = Object.fromEntries(report.summary.map((s) => [s.profile, s.verdict]));
    expect(verdictByProfile).toEqual(EXPECTED_VERDICTS);
    const relies = report.summary.filter((s) => s.verdict === 'rely');
    const refusals = report.summary.filter((s) => s.verdict !== 'rely');
    expect(relies.length).toBeGreaterThanOrEqual(2);
    expect(new Set(refusals.map((s) => s.verdict)).size).toBeGreaterThanOrEqual(2);
  });

  it('every single-profile report carries the closed limitations list and both digests', () => {
    for (const name of Object.keys(EXPECTED_VERDICTS)) {
      const report = buildRelianceGapReport(packet(), profile(name));
      expect(report['@type']).toBe(RELIANCE_GAP_REPORT_VERSION);
      expect(report.limitations).toEqual([...RELIANCE_GAP_LIMITATIONS]);
      expect(report.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(report.profile.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(report.profile.id).toBe(profile(name).profile_id);
      expect(report.reproduce.command).toContain('reliance-gap');
      // The control mapping stays auditor-readable: closed status vocabulary.
      for (const row of report.control_mapping) {
        expect(['satisfied', 'missing', 'not_required', 'not_evaluated']).toContain(row.status);
      }
    }
  });
});

describe('CLI exit-code semantics (child_process on the example fixtures)', () => {
  it('exits 0 on rely and prints the report JSON on stdout', () => {
    const r = runCli([PACKET_PATH, '--profile', join(PROFILES_DIR, 'pharmacy.json')]);
    expect(r.status).toBe(0);
    const report = JSON.parse(r.stdout);
    expect(report.kernel_verdict).toBe('rely');
  });

  it('exits 2 on a do_not_rely verdict', () => {
    const r = runCli([PACKET_PATH, '--profile', join(PROFILES_DIR, 'prescriber-ehr.json')]);
    expect(r.status).toBe(2);
    expect(JSON.parse(r.stdout).kernel_verdict).toBe('do_not_rely_quorum_unsatisfied');
  });

  it('exits 2 in multi mode when any profile refuses, with the documented summary', () => {
    const r = runCli([PACKET_PATH, '--profiles', PROFILES_DIR]);
    expect(r.status).toBe(2);
    const report = JSON.parse(r.stdout);
    const verdictByProfile = Object.fromEntries(report.summary.map((s) => [s.profile, s.verdict]));
    expect(verdictByProfile).toEqual(EXPECTED_VERDICTS);
  });

  it('exits 1 on an unreadable packet (operational error)', () => {
    const r = runCli([join(EXAMPLE_DIR, 'no-such-packet.json'), '--profile', join(PROFILES_DIR, 'pharmacy.json')]);
    expect(r.status).toBe(1);
  });

  it('exits 1 when no evaluation time is available (refusal, not a verdict)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'reliance-gap-'));
    const pkt = packet();
    delete pkt.evaluated_at;
    const p = join(dir, 'packet-no-time.json');
    writeFileSync(p, JSON.stringify(pkt));
    const r = runCli([p, '--profile', join(PROFILES_DIR, 'pharmacy.json')]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/evaluation time/);
    // Supplying --now heals it without touching the packet.
    const healed = runCli([p, '--profile', join(PROFILES_DIR, 'pharmacy.json'), '--now', '2026-07-08T15:00:00Z']);
    expect(healed.status).toBe(0);
  });

  it('writes the report to --out and keeps the human summary on stdout', () => {
    const dir = mkdtempSync(join(tmpdir(), 'reliance-gap-'));
    const out = join(dir, 'report.json');
    const r = runCli([PACKET_PATH, '--profile', join(PROFILES_DIR, 'pharmacy.json'), '--out', out]);
    expect(r.status).toBe(0);
    expect(JSON.parse(readFileSync(out, 'utf8')).kernel_verdict).toBe('rely');
    expect(r.stdout).toMatch(/RELY/);
  });
});
