import type { ReactNode } from "react";
import type { AuditEntry } from "../api";
import { IconHand, IconPlayCircle, IconSearch, IconShieldCheck } from "./icons";

export type AuditDensity = "page" | "compact";

const HASH_CHARS = 12;

export type AuditKind = "triage" | "decision" | "policy" | "run";
type Kind = AuditKind;

// Glyph and tint per entry kind. A fixed table: nothing here is read from the entry.
const KINDS: Record<Kind, { cls: string; icon: ReactNode }> = {
  triage: { cls: "audit-node--triage", icon: <IconSearch /> },
  decision: { cls: "audit-node--decision", icon: <IconHand /> },
  policy: { cls: "audit-node--policy", icon: <IconShieldCheck /> },
  run: { cls: "audit-node--run", icon: <IconPlayCircle /> },
};

const BY_TYPE: Record<string, Kind> = {
  gate_decision: "decision",
  gate_evaluation: "policy",
  gate_execution: "run",
};

/** Which kind of entry this is; the Audit type filter counts with the same rule the rows draw by. */
export function kindOf(entry: AuditEntry): AuditKind {
  const t = entry.type;
  // Any other (or unknown) type is a triage entry, as before.
  return typeof t === "string" && Object.hasOwn(BY_TYPE, t) ? BY_TYPE[t] : "triage";
}

function describe(entry: AuditEntry, kind: Kind): { title: string; detail: string } {
  const e = entry as Record<string, unknown> as {
    gate_id?: string;
    decision?: string;
    outcome?: string;
    exit_code?: number;
    finding_id?: string;
    verdict?: string;
    confidence?: number;
  };
  switch (kind) {
    case "decision":
      return { title: "Human decision", detail: `gate ${e.gate_id ?? "?"} → ${e.decision ?? "?"}` };
    case "policy":
      return { title: "Policy gate", detail: `${e.decision ?? "?"} (exit ${e.exit_code ?? "?"})` };
    case "run":
      return { title: "Verification run", detail: `gate ${e.gate_id ?? "?"} → ${e.outcome ?? "?"}` };
    default: {
      const conf = typeof e.confidence === "number" ? ` (${e.confidence.toFixed(2)})` : "";
      return { title: "Triage", detail: `finding ${e.finding_id ?? "?"} → ${e.verdict ?? "?"}${conf}` };
    }
  }
}

/**
 * One hash-chained audit entry: a tinted glyph disc, "Title · detail", then the raw timestamp and
 * the 12-character hash. Shared by the Audit timeline (`page`) and the Overview card (`compact`).
 * Every field is scanned or logged text, rendered only as React text.
 */
export function AuditEntryRow({ entry, density = "page" }: { entry: AuditEntry; density?: AuditDensity }) {
  const kind = kindOf(entry);
  const { title, detail } = describe(entry, kind);
  const hash = entry.entry_hash ? entry.entry_hash.slice(0, HASH_CHARS) : "";
  const d = density === "compact" ? "compact" : "page";
  return (
    <div className={`audit-row audit-row--${d}`}>
      <span className={`audit-node ${KINDS[kind].cls}`} aria-hidden="true">
        {KINDS[kind].icon}
      </span>
      <div className="audit-body">
        <div className="audit-line">
          <b>{title}</b> · {detail}
        </div>
        <div className="audit-meta">
          <span className="audit-ts">{entry.ts ?? ""}</span>
          {hash ? <span className="audit-hash">{hash}</span> : null}
        </div>
      </div>
    </div>
  );
}
