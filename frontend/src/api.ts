// Types mirror Crux's triage queue JSON (GET /api/findings).
// Every string in here can originate from a scanned target: treat it as
// attacker-controlled and only ever render it as React text.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Verdict = "TRUE_POSITIVE" | "ABSTAIN" | "LIKELY_FALSE_POSITIVE";

export interface Finding {
  id?: string;
  tool?: string;
  rule_id: string;
  severity: Severity;
  title: string;
  message?: string;
  url?: string;
  file?: string;
  line?: number;
  category?: "DAST" | "SAST" | "SCA";
  cwe?: string;
  code?: string;
}

export interface TriageItem {
  finding: Finding;
  verdict: Verdict;
  confidence: number;
  fp_likelihood: number;
  rationale?: string;
  remediation?: string;
  triager?: string;
  duplicates?: string[];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

/** Same-origin relative path only: the Vite dev proxy / Rust backend serve it. */
export async function getFindings(): Promise<TriageItem[]> {
  const res = await fetch("/api/findings");
  if (!res.ok) {
    throw new Error(`GET /api/findings failed: ${res.status}`);
  }
  const body: unknown = await res.json();
  if (!Array.isArray(body)) {
    throw new Error("GET /api/findings returned an unexpected payload");
  }
  // One malformed row must not crash rendering: keep only rows with an object `finding`.
  return body.filter((it) => isObject(it) && isObject(it.finding)) as unknown as TriageItem[];
}

// A pending human-approval gate (GET /api/gates). Like findings, every string
// can originate from a scanned target: render as React text only.
export interface Gate {
  id: string;
  title: string;
  why: string;
  command: string;
  target: string;
  in_scope: boolean;
  // Proposer metadata (optional; absent on older gates). Render as text only.
  detect_only?: boolean;
  expected_evidence?: string;
  why_it_might_fail?: string;
}

export type GateDecision = "approve" | "deny";

/** Thrown by decideGate on a non-2xx response so callers can branch on status. */
export class GateDecisionError extends Error {
  readonly status: number;
  constructor(status: number) {
    super(`POST /api/gates decision failed: ${status}`);
    this.name = "GateDecisionError";
    this.status = status;
  }
}

export async function getGates(): Promise<Gate[]> {
  const res = await fetch("/api/gates");
  if (!res.ok) {
    throw new Error(`GET /api/gates failed: ${res.status}`);
  }
  const body: unknown = await res.json();
  if (!Array.isArray(body)) {
    throw new Error("GET /api/gates returned an unexpected payload");
  }
  const seen = new Set<string>();
  const gates: Gate[] = [];
  for (const it of body) {
    if (!isObject(it) || typeof it.id !== "string" || it.id === "" || seen.has(it.id)) continue;
    seen.add(it.id);
    gates.push(it as unknown as Gate);
  }
  return gates;
}

/**
 * Records a human decision in the audit log. It never runs the command.
 * The backend's request guard requires `X-Ascent: 1` on every POST (CSRF).
 */
export async function decideGate(id: string, decision: GateDecision): Promise<void> {
  const res = await fetch(`/api/gates/${encodeURIComponent(id)}/${decision}`, {
    method: "POST",
    headers: { "X-Ascent": "1" },
  });
  if (!res.ok) {
    throw new GateDecisionError(res.status);
  }
}

// GET /api/report: the markdown report ("" when none exists yet). The text can
// contain scanned-target data (titles, URLs): the Report screen must never
// render it as raw HTML.
export async function getReport(): Promise<string> {
  const res = await fetch("/api/report");
  if (!res.ok) {
    throw new Error(`GET /api/report failed: ${res.status}`);
  }
  const body: unknown = await res.json();
  const md = (body as { markdown?: unknown } | null)?.markdown;
  if (typeof md !== "string") {
    throw new Error("GET /api/report returned an unexpected payload");
  }
  return md;
}

// GET /api/audit: hash-chained log. Two entry kinds share one list. Strings
// may be attacker-influenced: render as React text only.
export interface TriageAuditEntry {
  ts?: string;
  finding_id?: string;
  finding_hash?: string;
  triager?: string;
  verdict?: string;
  confidence?: number;
  fp_likelihood?: number;
  type?: undefined;
  prev_hash?: string;
  entry_hash?: string;
}

export interface GateAuditEntry {
  ts?: string;
  type: "gate_decision";
  gate_id?: string;
  decision?: "approved" | "denied";
  prev_hash?: string;
  entry_hash?: string;
}

export type AuditEntry = TriageAuditEntry | GateAuditEntry;

export interface AuditLog {
  entries: AuditEntry[];
  chain_ok: boolean;
}

export async function getAudit(): Promise<AuditLog> {
  const res = await fetch("/api/audit");
  if (!res.ok) {
    throw new Error(`GET /api/audit failed: ${res.status}`);
  }
  const body = (await res.json()) as Partial<AuditLog> | null;
  if (!body || !Array.isArray(body.entries) || typeof body.chain_ok !== "boolean") {
    throw new Error("GET /api/audit returned an unexpected payload");
  }
  return { entries: body.entries.filter(isObject) as AuditEntry[], chain_ok: body.chain_ok };
}

// GET /api/engagement: the parsed engagement file, or null when none is loaded.
export interface Engagement {
  name?: string;
}

export async function getEngagement(): Promise<Engagement | null> {
  const res = await fetch("/api/engagement");
  if (!res.ok) {
    throw new Error(`GET /api/engagement failed: ${res.status}`);
  }
  const body: unknown = await res.json();
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return null;
  }
  return body as Engagement;
}
