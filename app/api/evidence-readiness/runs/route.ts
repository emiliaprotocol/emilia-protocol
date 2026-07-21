import { NextResponse } from "next/server";
import { authenticateCloudRequest } from "@/lib/cloud/auth";
import { requirePermission } from "@/lib/cloud/authorize";
import { queryEvents, verifyIntegrity } from "@/lib/cloud/event-explorer";
import { epProblem, EP_ERRORS } from "@/lib/errors";
import { logger } from "@/lib/logger.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type EventRecord = {
  event_id?: unknown;
  source_table?: unknown;
  created_at?: unknown;
  event_type?: unknown;
  actor_entity_ref?: unknown;
  detail?: unknown;
};

type EventQueryFilters = {
  tenant_id: string;
  limit: number;
  offset: number;
  date_from?: string;
  date_to?: string;
};

function text(value: unknown): string | null {
  return typeof value === "string"
    ? value
    : value == null
      ? null
      : String(value);
}

function normalizeRun(event: EventRecord) {
  const detail: Record<string, unknown> =
    event.detail && typeof event.detail === "object" && !Array.isArray(event.detail)
      ? event.detail as Record<string, unknown>
      : {};
  return {
    event_id: text(event.event_id) ?? "unknown-event",
    source_table: text(event.source_table),
    created_at: text(event.created_at),
    action: text(
      detail.action || detail.action_type || detail.method || event.event_type,
    ),
    agent: text(detail.agent_id || detail.actor || event.actor_entity_ref),
    authority: text(detail.authority_scope || detail.authority || detail.scope),
    caid: text(detail.caid || detail.canonical_action_id || detail.action_id),
    status: text(
      detail.status ||
        detail.lifecycle_state ||
        detail.outcome ||
        event.event_type,
    ),
    decision: text(detail.decision || detail.evidence_verdict),
    outcome: text(detail.outcome || detail.effect_status),
    evidence: Array.isArray(detail.evidence) ? detail.evidence : [],
    obligations: Array.isArray(detail.obligations) ? detail.obligations : [],
    detail,
  };
}

export async function GET(request: Request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, "read");

    const url = new URL(request.url);
    const limit = Math.min(
      Math.max(
        Number.parseInt(url.searchParams.get("limit") || "100", 10) || 100,
        1,
      ),
      500,
    );
    const offset = Math.max(
      Number.parseInt(url.searchParams.get("offset") || "0", 10) || 0,
      0,
    );
    const dateFrom = url.searchParams.get("date_from");
    const dateTo = url.searchParams.get("date_to");
    const filters: EventQueryFilters = { tenant_id: auth.tenantId, limit, offset };
    if (dateFrom) filters.date_from = dateFrom;
    if (dateTo) filters.date_to = dateTo;

    const [eventResult, integrity] = await Promise.all([
      queryEvents(filters),
      verifyIntegrity({
        tenant_id: auth.tenantId,
        from: dateFrom || undefined,
        to: dateTo || undefined,
      }),
    ]);

    return NextResponse.json(
      {
        schema: "emilia.evidence-readiness.v1",
        tenant_id: auth.tenantId,
        total: eventResult.total,
        offset,
        limit,
        integrity,
        runs: eventResult.events.map((event: EventRecord) => normalizeRun(event)),
        generated_at: new Date().toISOString(),
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "CloudAuthorizationError")
      return epProblem(403, "forbidden", err.message);
    logger.error("[evidence-readiness/runs] Error:", err);
    return EP_ERRORS.INTERNAL();
  }
}
