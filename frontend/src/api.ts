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

export interface GateEvaluationAuditEntry {
  ts?: string;
  type: "gate_evaluation";
  decision?: string;
  exit_code?: number;
  policy_hash?: string;
  prev_hash?: string;
  entry_hash?: string;
}

export interface GateExecutionAuditEntry {
  ts?: string;
  type: "gate_execution";
  gate_id?: string;
  outcome?: string;
  prev_hash?: string;
  entry_hash?: string;
}

export type AuditEntry =
  | TriageAuditEntry
  | GateAuditEntry
  | GateEvaluationAuditEntry
  | GateExecutionAuditEntry;

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

// POST /api/engagements: define a new scan. This only writes a validated scope
// file; it never starts a scan. The backend requires `X-Ascent: 1` (CSRF) and
// validates every target with the same scope parser the pipeline enforces.
export interface NewScanInput {
  name: string;
  targets: string[];
  source?: string;
  dast_profile?: "passive" | "standard" | "active";
  /** Header NAME only; the value lives in the env var named by `auth_env`. */
  auth_header?: string;
  auth_env?: string;
}

export interface CreatedEngagement {
  ok: true;
  name: string;
  path: string;
  scope: { hosts: string[]; cidrs: string[]; urls: string[] };
  source: string;
  dast: { profile: string; auth_header: string };
  run_command: string;
}

/** Thrown on a non-2xx create so the screen can show the message and rejected list. */
export class CreateEngagementError extends Error {
  readonly status: number;
  readonly rejected?: string[];
  readonly field?: string;
  constructor(status: number, message: string, extra?: { rejected?: string[]; field?: string }) {
    super(message);
    this.name = "CreateEngagementError";
    this.status = status;
    this.rejected = extra?.rejected;
    this.field = extra?.field;
  }
}

export async function createEngagement(input: NewScanInput): Promise<CreatedEngagement> {
  const res = await fetch("/api/engagements", {
    method: "POST",
    headers: { "X-Ascent": "1", "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const b = isObject(body) ? body : {};
    const message = typeof b.error === "string" ? b.error : `create failed: ${res.status}`;
    const rejected = Array.isArray(b.rejected)
      ? b.rejected.filter((x): x is string => typeof x === "string")
      : undefined;
    const field = typeof b.field === "string" ? b.field : undefined;
    throw new CreateEngagementError(res.status, message, { rejected, field });
  }
  if (!isObject(body) || body.ok !== true) {
    throw new CreateEngagementError(res.status, "create returned an unexpected payload");
  }
  return body as unknown as CreatedEngagement;
}

// GET /api/gate: the last policy verdict (out/gate.json), or null when no
// policy has been evaluated. Strings can originate from scanned targets:
// render as React text only.
export type GateDecisionKind = "PASS" | "CONDITIONAL" | "FAIL" | "INCOMPLETE";

export interface GateEntryView {
  fingerprint: string;
  rule_id: string;
  severity: string;
  category: string;
  title: string;
  locus: string;
  reason: string;
}

export interface GateReport {
  policy: { name: string; hash: string };
  decision: GateDecisionKind;
  exit_code: number;
  complete: boolean;
  dry_run?: boolean;
  failed_tools?: string[];
  // Analysers that were not installed; one covering a policy category makes the run INCOMPLETE.
  skipped_tools?: string[];
  counts: { evaluated: number; failed: number; warned: number; demoted_fp: number };
  failed: GateEntryView[];
  warned: GateEntryView[];
  evaluated_at?: string;
}

const DECISIONS: readonly string[] = ["PASS", "CONDITIONAL", "FAIL", "INCOMPLETE"];

export async function getGate(): Promise<GateReport | null> {
  const res = await fetch("/api/gate");
  if (!res.ok) {
    throw new Error(`GET /api/gate failed: ${res.status}`);
  }
  const body: unknown = await res.json();
  if (body === null) return null;
  if (!isObject(body) || typeof body.decision !== "string" || !DECISIONS.includes(body.decision)) {
    throw new Error("GET /api/gate returned an unexpected payload");
  }
  const list = (v: unknown) => (Array.isArray(v) ? v.filter(isObject) : []) as unknown as GateEntryView[];
  const policy = isObject(body.policy) ? body.policy : {};
  const counts = isObject(body.counts) ? body.counts : {};
  const num = (v: unknown) => (typeof v === "number" ? v : 0);
  const strings = (v: unknown) => (Array.isArray(v) ? v.filter((t): t is string => typeof t === "string") : []);
  return {
    policy: {
      name: typeof policy.name === "string" ? policy.name : "",
      hash: typeof policy.hash === "string" ? policy.hash : "",
    },
    decision: body.decision as GateDecisionKind,
    exit_code: num(body.exit_code),
    complete: body.complete === true,
    dry_run: body.dry_run === true,
    failed_tools: strings(body.failed_tools),
    skipped_tools: strings(body.skipped_tools),
    counts: {
      evaluated: num(counts.evaluated),
      failed: num(counts.failed),
      warned: num(counts.warned),
      demoted_fp: num(counts.demoted_fp),
    },
    failed: list(body.failed),
    warned: list(body.warned),
    evaluated_at: typeof body.evaluated_at === "string" ? body.evaluated_at : undefined,
  };
}
