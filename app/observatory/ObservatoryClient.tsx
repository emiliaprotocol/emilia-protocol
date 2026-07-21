'use client';

import type React from 'react';
import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronUp,
  CircleHelp,
  Clock3,
  Database,
  ExternalLink,
  FileCheck2,
  GitCompare,
  Minus,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react';

interface ValueMeta {
  label: string;
  icon: React.ComponentType<Record<string, unknown>>;
}

const VALUE_META: Record<string, ValueMeta> = {
  yes: { label: 'Defined', icon: Check },
  partial: { label: 'Partial', icon: Minus },
  no: { label: 'Not defined', icon: X },
  unknown: { label: 'Unknown', icon: CircleHelp },
};

interface TabItem {
  id: string;
  label: string;
  icon: React.ComponentType<Record<string, unknown>>;
}

const TABS: TabItem[] = [
  { id: 'matrix', label: 'Guarantee map', icon: ShieldCheck },
  { id: 'movement', label: 'Movement', icon: Clock3 },
  { id: 'frontiers', label: 'Open frontiers', icon: GitCompare },
  { id: 'recon', label: 'Recon index', icon: Database },
];

function formatDate(value: string): string {
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }).format(new Date(value));
}

function statusLabel(value: string): string {
  return value.replaceAll('_', ' ');
}

interface SourceLinkProps {
  href: string;
  children?: React.ReactNode;
}

function SourceLink({ href, children = 'Open source' }: SourceLinkProps): React.ReactElement {
  return (
    <a className="obs-source-link" href={href} target="_blank" rel="noopener noreferrer">
      {children}<ExternalLink size={13} aria-hidden="true" />
    </a>
  );
}

interface Guarantee {
  value: string;
  rationale: string;
}

interface Dimension {
  id: string;
  label: string;
  short_label: string;
  question: string;
}

interface Source {
  id: string;
  short_name: string;
  title: string;
  revision: string;
  layer: string;
  venue: string;
  source_url: string;
  defines: string;
  quote: { text: string; locator: string };
  evidence_lock: { quote_sha256: string };
  operative_status: string;
  operative_basis: string;
  relation: string;
  limits: string;
  guarantees: Record<string, Guarantee>;
}

interface GuaranteeCellProps {
  guarantee: Guarantee;
  dimension: Dimension;
}

function GuaranteeCell({ guarantee, dimension }: GuaranteeCellProps): React.ReactElement {
  const meta = VALUE_META[guarantee.value];
  const Icon = meta.icon;
  return (
    <td className={`obs-guarantee obs-guarantee--${guarantee.value}`} title={`${dimension.label}: ${meta.label}. ${guarantee.rationale}`}>
      <span className="obs-guarantee-mark" aria-hidden="true"><Icon size={15} strokeWidth={2.2} /></span>
      <span className="obs-sr-only">{dimension.label}: {meta.label}</span>
    </td>
  );
}

interface SearchControlProps {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  label: string;
}

function SearchControl({ value, onChange, placeholder, label }: SearchControlProps): React.ReactElement {
  return (
    <label className="obs-search">
      <span className="obs-sr-only">{label}</span>
      <Search size={16} aria-hidden="true" />
      <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />
    </label>
  );
}

interface SourceDetailProps {
  source: Source;
  dimensions: Dimension[];
}

function SourceDetail({ source, dimensions }: SourceDetailProps): React.ReactElement {
  return (
    <section className="obs-source-detail" aria-label={`Evidence for ${source.short_name}`}>
      <div className="obs-detail-heading">
        <div>
          <div className="obs-kicker">Source-locked evidence</div>
          <h3>{source.title}</h3>
          <p>{source.defines}</p>
        </div>
        <SourceLink href={source.source_url}>Open exact revision</SourceLink>
      </div>

      <blockquote>
        <p>"{source.quote.text}"</p>
        <footer>{source.quote.locator} · sha256:{source.evidence_lock.quote_sha256.slice(0, 16)}</footer>
      </blockquote>

      <div className="obs-detail-grid">
        <div>
          <span>Operative status</span>
          <strong>{statusLabel(source.operative_status)}</strong>
          <p>{source.operative_basis}</p>
        </div>
        <div>
          <span>Boundary</span>
          <strong>{statusLabel(source.relation)}</strong>
          <p>{source.limits}</p>
        </div>
      </div>

      <div className="obs-rationale-list">
        {dimensions.map((dimension) => {
          const guarantee = source.guarantees[dimension.id];
          const meta = VALUE_META[guarantee.value];
          const Icon = meta.icon;
          return (
            <div key={dimension.id} className="obs-rationale-row">
              <span className={`obs-inline-mark obs-inline-mark--${guarantee.value}`}><Icon size={14} aria-hidden="true" />{meta.label}</span>
              <strong>{dimension.label}</strong>
              <p>{guarantee.rationale}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

interface SnapshotData {
  sources: Source[];
  dimensions: Dimension[];
  events: Event[];
  frontiers: Frontier[];
  recon: ReconData;
  metrics: Metrics;
  operative_conflicts: OperativeConflict[];
  as_of: string;
  snapshot_sha256: string;
}

interface Event {
  id: string;
  date: string;
  venue: string;
  title: string;
  description: string;
  status: string;
  truth_boundary: string;
  evidence: string;
  source_ids?: string[];
}

interface Frontier {
  id: string;
  priority: number;
  title: string;
  status: string;
  problem: string;
  deliverable: string;
  verdicts: string[];
  acceptance_tests: string[];
}

interface ReconData {
  claim_boundary: string;
  metrics: ReconMetrics;
  corpus_sha256: string;
}

interface ReconMetrics {
  declared_agent_reads: number;
  recovered_structured_reports: number;
  unrecovered_reports: number;
  workflow_files_scanned: number;
}

interface Metrics {
  primary_sources_verified: number;
  guarantee_dimensions: number;
  recovered_structured_reports: number;
  declared_agent_reads: number;
  open_frontiers: number;
}

interface OperativeConflict {
  finding: string;
  consequence: string;
}

interface GuaranteeMapProps {
  snapshot: SnapshotData;
}

function GuaranteeMap({ snapshot }: GuaranteeMapProps): React.ReactElement {
  const [query, setQuery] = useState<string>('');
  const [layer, setLayer] = useState<string>('all');
  const [selectedId, setSelectedId] = useState<string>('wimse-condition-bounded');
  const layers = useMemo(() => [...new Set(snapshot.sources.map((source) => source.layer))].sort(), [snapshot.sources]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return snapshot.sources.filter((source) => {
      const matchesLayer = layer === 'all' || source.layer === layer;
      const haystack = `${source.short_name} ${source.title} ${source.venue} ${source.layer} ${source.revision}`.toLowerCase();
      return matchesLayer && (!needle || haystack.includes(needle));
    });
  }, [snapshot.sources, query, layer]);
  const selected = selectedId ? filtered.find((source) => source.id === selectedId) || null : null;

  return (
    <div className="obs-view">
      <div className="obs-view-heading">
        <div>
          <div className="obs-kicker">Publication-grade comparison</div>
          <h2>Guarantees, not labels</h2>
          <p>Every cell has a source-locked rationale. "Unknown" means the evidence is insufficient, not that the feature is absent.</p>
        </div>
        <div className="obs-legend" aria-label="Guarantee legend">
          {Object.entries(VALUE_META).map(([value, meta]) => {
            const Icon = meta.icon;
            return <span key={value} className={`obs-inline-mark obs-inline-mark--${value}`}><Icon size={13} aria-hidden="true" />{meta.label}</span>;
          })}
        </div>
      </div>

      <div className="obs-controls">
        <SearchControl value={query} onChange={setQuery} label="Search verified sources" placeholder="Search source, revision, layer…" />
        <label className="obs-select">
          <span className="obs-sr-only">Filter by layer</span>
          <select value={layer} onChange={(event) => setLayer(event.target.value)}>
            <option value="all">All layers</option>
            {layers.map((item) => <option key={item} value={item}>{statusLabel(item)}</option>)}
          </select>
          <ChevronDown size={15} aria-hidden="true" />
        </label>
        <span className="obs-result-count">{filtered.length} source{filtered.length === 1 ? '' : 's'}</span>
      </div>

      <div className="obs-table-wrap">
        <table className="obs-matrix">
          <thead>
            <tr>
              <th className="obs-source-column">Source</th>
              <th className="obs-layer-column">Layer</th>
              {snapshot.dimensions.map((dimension) => (
                <th key={dimension.id} title={dimension.question}>{dimension.short_label}</th>
              ))}
              <th className="obs-expand-column"><span className="obs-sr-only">Details</span></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((source) => {
              const expanded = selected?.id === source.id;
              return (
                <tr key={source.id} data-selected={expanded ? 'true' : undefined}>
                  <td className="obs-source-column">
                      <button type="button" className="obs-source-button" onClick={() => setSelectedId(expanded ? '' : source.id)} aria-expanded={expanded}>
                      <strong>{source.short_name}</strong>
                      <span>{source.revision}</span>
                    </button>
                  </td>
                  <td className="obs-layer-column">{statusLabel(source.layer)}</td>
                  {snapshot.dimensions.map((dimension) => (
                    <GuaranteeCell key={dimension.id} dimension={dimension} guarantee={source.guarantees[dimension.id]} />
                  ))}
                  <td className="obs-expand-column">
                    <button type="button" className="obs-icon-button" onClick={() => setSelectedId(expanded ? '' : source.id)} aria-label={`${expanded ? 'Close' : 'Inspect'} ${source.short_name}`}>
                      {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {selected ? <SourceDetail source={selected} dimensions={snapshot.dimensions} /> : <p className="obs-empty">No verified source matches those filters.</p>}
    </div>
  );
}

interface MovementProps {
  snapshot: SnapshotData;
}

function Movement({ snapshot }: MovementProps): React.ReactElement {
  const sourceById = new Map(snapshot.sources.map((source) => [source.id, source]));
  return (
    <div className="obs-view">
      <div className="obs-view-heading">
        <div>
          <div className="obs-kicker">Revision-aware event log</div>
          <h2>What actually moved</h2>
          <p>Events are phrased at their narrowest defensible level. Submission, scheduling, adoption, and publication are different states.</p>
        </div>
      </div>
      <div className="obs-timeline">
        {snapshot.events.map((event) => {
          const pending = event.status === 'pending_public_archive';
          return (
            <article key={event.id} className="obs-event" data-pending={pending ? 'true' : undefined}>
              <div className="obs-event-date">{formatDate(event.date)}</div>
              <div className="obs-event-marker"><span /></div>
              <div className="obs-event-copy">
                <div className="obs-event-meta">
                  <span>{event.venue}</span>
                  <span className={`obs-status obs-status--${pending ? 'pending' : 'verified'}`}>{pending ? 'Archive pending' : 'Publicly verified'}</span>
                </div>
                <h3>{event.title}</h3>
                <p>{event.description}</p>
                <div className="obs-boundary"><AlertTriangle size={15} aria-hidden="true" /><span>{event.truth_boundary}</span></div>
                <div className="obs-event-links">
                  {/^https:\/\//.test(event.evidence) && <SourceLink href={event.evidence}>Event evidence</SourceLink>}
                  {(event.source_ids || []).map((id) => sourceById.get(id)).filter(Boolean).map((source) => (
                    <SourceLink key={source!.id} href={source!.source_url}>{source!.short_name}</SourceLink>
                  ))}
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}

interface FrontiersProps {
  snapshot: SnapshotData;
}

function Frontiers({ snapshot }: FrontiersProps): React.ReactElement {
  return (
    <div className="obs-view">
      <div className="obs-view-heading">
        <div>
          <div className="obs-kicker">Source-derived build register</div>
          <h2>Where the map still breaks</h2>
          <p>These are testable missing layers, not declarations of empty territory. Each frontier names the artifact and the conditions that would make it real.</p>
        </div>
      </div>
      <div className="obs-frontiers">
        {[...snapshot.frontiers].sort((a, b) => a.priority - b.priority).map((frontier) => (
          <article key={frontier.id} className="obs-frontier">
            <div className="obs-frontier-index">0{frontier.priority}</div>
            <div className="obs-frontier-main">
              <div className="obs-frontier-titleline">
                <h3>{frontier.title}</h3>
                <span className="obs-status obs-status--frontier">{statusLabel(frontier.status)}</span>
              </div>
              <p className="obs-frontier-problem">{frontier.problem}</p>
              <div className="obs-deliverable"><ArrowRight size={17} aria-hidden="true" /><p><strong>Build:</strong> {frontier.deliverable}</p></div>
              <div className="obs-verdicts" aria-label="Closed verdicts">
                {frontier.verdicts.map((verdict) => <code key={verdict}>{verdict}</code>)}
              </div>
              <div className="obs-acceptance">
                <span>Acceptance contract</span>
                {frontier.acceptance_tests.map((test) => <p key={test}><Check size={14} aria-hidden="true" />{test}</p>)}
              </div>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

interface ReconIndexProps {
  snapshot: SnapshotData;
}

function ReconIndex({ snapshot }: ReconIndexProps): React.ReactElement {
  const m = snapshot.recon.metrics;
  return (
    <div className="obs-view">
      <div className="obs-view-heading">
        <div>
          <div className="obs-kicker">Discovery corpus</div>
          <h2>The sweep, in aggregate</h2>
          <p>{snapshot.recon.claim_boundary}</p>
        </div>
      </div>
      <div className="obs-recon-warning">
        <Database size={19} aria-hidden="true" />
        <p><strong>{m.recovered_structured_reports} of {m.declared_agent_reads}</strong> declared reads were recovered. The per-artifact index is held privately and is never published; an effort is named publicly only after it is promoted into the source-locked matrix with an exact revision, excerpt, and curator rationale.</p>
      </div>
      <div className="obs-stat-row" role="list">
        <div className="obs-stat" role="listitem"><strong>{m.declared_agent_reads}</strong><span>declared reads</span></div>
        <div className="obs-stat" role="listitem"><strong>{m.recovered_structured_reports}</strong><span>recovered</span></div>
        <div className="obs-stat" role="listitem"><strong>{m.unrecovered_reports}</strong><span>unrecovered</span></div>
        <div className="obs-stat" role="listitem"><strong>{m.workflow_files_scanned}</strong><span>workflow files scanned</span></div>
      </div>
      <p className="obs-muted obs-recon-digest">Private corpus digest sha256:{snapshot.recon.corpus_sha256}</p>
    </div>
  );
}

interface ObservatoryClientProps {
  snapshot: SnapshotData;
}

export default function ObservatoryClient({ snapshot }: ObservatoryClientProps): React.ReactElement {
  const [tab, setTab] = useState<string>('matrix');
  const request = snapshot.events.find((event) => event.id === 'wimse-agenda-request-emilia-composition');
  const conflict = snapshot.operative_conflicts[0];

  return (
    <main className="obs-page">
      <header className="obs-header">
        <div className="obs-shell">
          <div className="obs-header-grid">
            <div>
              <div className="obs-kicker">EMILIA Standards Observatory</div>
              <h1>Know what the standards actually say.</h1>
              <p>Revision-aware cartography for workload identity, agent authorization, human evidence, receipts, and relying-party acceptance.</p>
            </div>
            <div className="obs-snapshot">
              <FileCheck2 size={18} aria-hidden="true" />
              <div><span>Source-locked snapshot</span><strong>{formatDate(snapshot.as_of)}</strong><code>sha256:{snapshot.snapshot_sha256.slice(0, 18)}</code></div>
            </div>
          </div>
          <div className="obs-metrics" aria-label="Observatory coverage">
            <div><strong>{snapshot.metrics.primary_sources_verified}</strong><span>primary sources verified</span></div>
            <div><strong>{snapshot.metrics.guarantee_dimensions}</strong><span>guarantees compared</span></div>
            <div><strong>{snapshot.metrics.recovered_structured_reports}/{snapshot.metrics.declared_agent_reads}</strong><span>recon reports recovered</span></div>
            <div><strong>{snapshot.metrics.open_frontiers}</strong><span>testable frontiers</span></div>
          </div>
        </div>
      </header>

      <section className="obs-movement-signal">
        <div className="obs-shell obs-signal-grid">
          <div className="obs-live-mark"><span />Movement</div>
          <div>
            <h2>{request?.title}</h2>
            <p>{request?.description}</p>
          </div>
          <div className="obs-signal-state"><Clock3 size={15} aria-hidden="true" /><span>Archive pending</span><small>Request, not acceptance</small></div>
        </div>
      </section>

      <section className="obs-conflict-band">
        <div className="obs-shell obs-conflict-inner">
          <GitCompare size={17} aria-hidden="true" />
          <p><strong>Operative-version correction:</strong> {conflict.finding} {conflict.consequence}</p>
        </div>
      </section>

      <div className="obs-tabs-wrap">
        <div className="obs-shell">
          <div className="obs-tabs" role="tablist" aria-label="Observatory views">
            {TABS.map((item) => {
              const Icon = item.icon;
              const active = tab === item.id;
              return (
                <button key={item.id} type="button" role="tab" aria-selected={active} className={active ? 'is-active' : ''} onClick={() => setTab(item.id)}>
                  <Icon size={16} aria-hidden="true" />{item.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <section className="obs-content">
        <div className="obs-shell">
          {tab === 'matrix' && <GuaranteeMap snapshot={snapshot} />}
          {tab === 'movement' && <Movement snapshot={snapshot} />}
          {tab === 'frontiers' && <Frontiers snapshot={snapshot} />}
          {tab === 'recon' && <ReconIndex snapshot={snapshot} />}
        </div>
      </section>
    </main>
  );
}
