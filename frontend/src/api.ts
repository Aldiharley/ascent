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
  return body as TriageItem[];
}
