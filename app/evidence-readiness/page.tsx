"use client";

import { useMemo, useState } from "react";
import SiteNav from "@/components/SiteNav";
import SiteFooter from "@/components/SiteFooter";
import { color, font, styles, cta } from "@/lib/tokens";

type EvidenceRun = {
  receipt_id: string;
  created_at: string | null;
  action_type: string | null;
  action_hash: string | null;
  caid: string | null;
  status: string | null;
  decision: string | null;
  policy_id: string | null;
  authority_verdict: string | null;
  enforcement_mode: string | null;
  adapter: string | null;
  amount: number | null;
  currency: string | null;
  signoff_required: boolean;
};

type EvidenceReadinessResponse = {
  schema: "emilia.evidence-readiness.v1";
  tenant_id: string;
  environment: "production";
  source: "audit_events.guard_trust_receipts";
  returned: number;
  limit: number;
  truncated: boolean;
  date_range: { from: string | null; to: string | null };
  runs: EvidenceRun[];
  generated_at: string;
  claim_boundary: string;
};

const STATUS_COLOR: Record<string, string> = {
  READY: color.green,
  SATISFIED: color.green,
  REVIEW: "#B45309",
  INDETERMINATE: "#B45309",
  BLOCKED: color.red,
  UNSATISFIED: color.red,
};

function displayStatus(run: EvidenceRun) {
  const status = String(run?.status || "UNMAPPED").toUpperCase();
  return status.replaceAll("_", " ");
}

function countStatus(runs: EvidenceRun[], statuses: string[]) {
  return runs.filter((run) =>
    statuses.includes(String(run.status || "").toUpperCase()),
  ).length;
}

function isEvidenceReadinessResponse(value: unknown): value is EvidenceReadinessResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<EvidenceReadinessResponse>;
  return candidate.schema === "emilia.evidence-readiness.v1"
    && typeof candidate.tenant_id === "string"
    && candidate.environment === "production"
    && Number.isFinite(candidate.returned)
    && Array.isArray(candidate.runs);
}

export default function EvidenceReadinessPage() {
  const [apiKey, setApiKey] = useState("");
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [response, setResponse] = useState<EvidenceReadinessResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState("ALL");

  const runs = useMemo(() => response?.runs || [], [response]);
  const visibleRuns = useMemo(() => {
    if (filter === "ALL") return runs;
    return runs.filter((run) => displayStatus(run) === filter);
  }, [filter, runs]);
  const selected =
    runs.find((run) => run.receipt_id === selectedId) || visibleRuns[0] || null;

  async function connect() {
    const key = apiKey.trim();
    if (!key) {
      setError(
        "Enter a tenant-scoped EMILIA Cloud API key. It is held in memory only.",
      );
      return;
    }
    setLoading(true);
    setConnected(false);
    setError("");
    setApiKey("");
    try {
      const res = await fetch("/api/cloud/evidence-readiness/runs?limit=100", {
        headers: { Authorization: `Bearer ${key}` },
        cache: "no-store",
      });
      const data: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        const problem = data && typeof data === "object" && !Array.isArray(data)
          ? data as { detail?: unknown; error?: unknown }
          : {};
        throw new Error(
          String(problem.detail || problem.error || `Request failed (${res.status})`),
        );
      }
      if (!isEvidenceReadinessResponse(data)) {
        throw new Error("Evidence service returned an invalid response.");
      }
      setResponse(data);
      setConnected(true);
      setSelectedId(data.runs[0]?.receipt_id || null);
    } catch (err) {
      setResponse(null);
      setError(
        err instanceof Error ? err.message : "Could not load tenant evidence.",
      );
    } finally {
      setLoading(false);
    }
  }

  function exportPackage() {
    if (!selected || !response) return;
    const payload = {
      schema: "emilia.evidence-readiness.package.v1",
      tenant_id: response.tenant_id,
      generated_at: new Date().toISOString(),
      source: response.source,
      claim_boundary: response.claim_boundary,
      run: selected,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${selected.receipt_id || "evidence-run"}-event-snapshot.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={styles.page}>
      <SiteNav />
      <main>
        <section
          style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 42 }}
        >
          <div style={styles.eyebrow}>
            PRODUCT · AUTHENTICATED TENANT WORKSPACE
          </div>
          <h1 style={{ ...styles.h1Large, maxWidth: 860 }}>
            Evidence readiness for agent runs.
          </h1>
          <p style={{ ...styles.body, maxWidth: 750, fontSize: 19 }}>
            Connect a production-scoped EMILIA Cloud key and inspect bounded,
            tenant-scoped trust-receipt lifecycle records: action, policy,
            authority verdict, decision, and status.
          </p>
          <div
            style={{
              ...styles.card,
              marginTop: 28,
              borderLeft: `4px solid ${color.gold}`,
              maxWidth: 820,
            }}
          >
            <div style={{ ...styles.cardTitle, marginBottom: 4 }}>
              No bundled demo data
            </div>
            <div style={styles.cardBody}>
              This workspace reads records stored for the authenticated tenant.
              Records may include customer-created tests and do not independently
              prove an asserted external effect. The API key is cleared after
              each request and is never written to local storage.
            </div>
          </div>
        </section>

        <section
          style={{ ...styles.sectionWide, paddingTop: 16, paddingBottom: 36 }}
        >
          <div style={styles.card}>
            <div style={styles.eyebrow}>CONNECT</div>
            <label style={styles.label} htmlFor="cloud-api-key">
              Tenant Cloud API key
            </label>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <input
                id="cloud-api-key"
                type="password"
                autoComplete="off"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="ept_live_…"
                style={{ ...styles.input, flex: "1 1 360px" }}
              />
              <button
                onClick={connect}
                disabled={loading}
                style={{ ...cta.primary, opacity: loading ? 0.6 : 1 }}
              >
                {loading ? "Loading…" : "Load tenant evidence"}
              </button>
            </div>
            {error && (
              <div
                role="alert"
                style={{ ...styles.cardBody, color: color.red, marginTop: 12 }}
              >
                {error}
              </div>
            )}
            {connected && response && (
              <div
                role="status"
                style={{
                  ...styles.cardBody,
                  color: color.green,
                  marginTop: 12,
                }}
              >
                Connected to tenant {response.tenant_id}. {response.returned}{" "}
                bounded receipt records loaded{response.truncated ? " (more may exist)" : ""}.
              </div>
            )}
          </div>
        </section>

        {response && (
          <>
            <section
              style={{
                ...styles.sectionWide,
                paddingTop: 0,
                paddingBottom: 36,
              }}
            >
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: 12,
                }}
              >
                {[
                  [String(response.returned ?? runs.length), "records loaded"],
                  [
                    String(countStatus(runs, ["READY", "SATISFIED"])),
                    "READY/SATISFIED labels",
                  ],
                  [
                    String(runs.filter((run) => run.signoff_required).length),
                    "signoff-required records",
                  ],
                  [
                    String(runs.filter((run) => Boolean(run.caid)).length),
                    "records carrying CAID",
                  ],
                ].map(([value, label]) => (
                  <div key={label} style={{ ...styles.card, padding: 18 }}>
                    <div
                      style={{
                        fontFamily: font.mono,
                        fontSize: 28,
                        color: color.t1,
                      }}
                    >
                      {value}
                    </div>
                    <div style={{ ...styles.cardBody, marginTop: 3 }}>
                      {label}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section
              id="runs"
              style={{ ...styles.sectionWide, paddingTop: 28 }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "end",
                  justifyContent: "space-between",
                  gap: 16,
                  flexWrap: "wrap",
                }}
              >
                <div>
                  <div style={styles.eyebrow}>RUN REVIEW</div>
                  <h2 style={styles.h2}>
                    Inspect what was recorded before relying on it.
                  </h2>
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {[
                    "ALL",
                    "READY",
                    "SATISFIED",
                    "INDETERMINATE",
                    "BLOCKED",
                  ].map((item) => (
                    <button
                      key={item}
                      onClick={() => setFilter(item)}
                      style={{
                        ...cta.ghost,
                        color: filter === item ? color.t1 : color.t3,
                        border: `1px solid ${filter === item ? color.t1 : color.border}`,
                        background:
                          filter === item ? color.cardHover : color.card,
                      }}
                    >
                      {item}
                    </button>
                  ))}
                </div>
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "minmax(0, 1.05fr) minmax(0, 1fr)",
                  gap: 18,
                  marginTop: 24,
                }}
              >
                <div
                  style={{ display: "grid", gap: 10, alignContent: "start" }}
                >
                  {visibleRuns.length === 0 && (
                    <div style={styles.card}>
                      <div style={styles.cardBody}>
                        No events match this filter.
                      </div>
                    </div>
                  )}
                  {visibleRuns.map((run) => (
                    <button
                      key={run.receipt_id}
                      onClick={() => setSelectedId(run.receipt_id)}
                      style={{
                        ...styles.card,
                        padding: 18,
                        textAlign: "left",
                        cursor: "pointer",
                        border: `1px solid ${selected?.receipt_id === run.receipt_id ? color.t1 : color.border}`,
                        background:
                          selected?.receipt_id === run.receipt_id
                            ? color.cardHover
                            : color.card,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          gap: 12,
                        }}
                      >
                        <span
                          style={{
                            fontFamily: font.mono,
                            fontSize: 11,
                            color: color.t3,
                          }}
                        >
                          {run.receipt_id}
                        </span>
                        <span
                          style={{
                            fontFamily: font.mono,
                            fontSize: 11,
                            color:
                              STATUS_COLOR[
                                String(run.status || "").toUpperCase()
                              ] || color.t3,
                          }}
                        >
                          {displayStatus(run)}
                        </span>
                      </div>
                      <div style={{ ...styles.cardTitle, marginTop: 10 }}>
                        {run.action_type || "Unclassified action"}
                      </div>
                      <div style={{ ...styles.cardBody, marginTop: 3 }}>
                        {run.policy_id || "policy not recorded"} ·{" "}
                        {run.authority_verdict || "authority verdict unavailable"}
                      </div>
                      <div
                        style={{
                          fontFamily: font.mono,
                          fontSize: 11,
                          color: color.t3,
                          marginTop: 12,
                        }}
                      >
                        {run.caid || "CAID not present in this event"}
                      </div>
                    </button>
                  ))}
                </div>
                <div
                  style={{ ...styles.card, padding: 24, alignSelf: "start" }}
                >
                  {selected ? (
                    <>
                      <div style={styles.eyebrow}>SELECTED EVENT</div>
                      <h3 style={{ ...styles.h2, marginBottom: 8 }}>
                        {selected.action_type || "Unclassified action"}
                      </h3>
                      <dl
                        style={{
                          display: "grid",
                          gridTemplateColumns: "auto 1fr",
                          gap: "9px 16px",
                          margin: 0,
                          fontSize: 14,
                        }}
                      >
                        <dt style={{ color: color.t3 }}>Decision</dt>
                        <dd style={{ margin: 0, fontFamily: font.mono }}>
                          {selected.decision || "not recorded"}
                        </dd>
                        <dt style={{ color: color.t3 }}>Status</dt>
                        <dd style={{ margin: 0, fontFamily: font.mono }}>
                          {selected.status || "not recorded"}
                        </dd>
                        <dt style={{ color: color.t3 }}>CAID</dt>
                        <dd
                          style={{
                            margin: 0,
                            fontFamily: font.mono,
                            overflowWrap: "anywhere",
                          }}
                        >
                          {selected.caid || "not recorded"}
                        </dd>
                        <dt style={{ color: color.t3 }}>Policy</dt>
                        <dd style={{ margin: 0, fontFamily: font.mono }}>
                          {selected.policy_id || "not recorded"}
                        </dd>
                        <dt style={{ color: color.t3 }}>Action hash</dt>
                        <dd style={{ margin: 0, fontFamily: font.mono, overflowWrap: "anywhere" }}>
                          {selected.action_hash || "not recorded"}
                        </dd>
                      </dl>
                      <button
                        onClick={exportPackage}
                        style={{ ...cta.primary, marginTop: 24 }}
                      >
                        Export normalized event snapshot
                      </button>
                    </>
                  ) : (
                    <div style={styles.cardBody}>
                      Select an event to inspect it.
                    </div>
                  )}
                </div>
              </div>
            </section>
          </>
        )}
      </main>
      <SiteFooter />
    </div>
  );
}
