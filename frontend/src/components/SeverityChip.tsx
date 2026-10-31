import type { Severity } from "../api";

// Fixed lookup keyed by the severity enum: class names and labels never come from data.
// An unrecognised severity fails safe to the INFO tier.
const TIERS: Record<Severity, { label: Severity; tier: string }> = {
  CRITICAL: { label: "CRITICAL", tier: "crit" },
  HIGH: { label: "HIGH", tier: "high" },
  MEDIUM: { label: "MEDIUM", tier: "med" },
  LOW: { label: "LOW", tier: "low" },
  INFO: { label: "INFO", tier: "info" },
};

function tierOf(severity: Severity) {
  return Object.hasOwn(TIERS, severity) ? TIERS[severity] : TIERS.INFO;
}

/** Square-ish uppercase chip, so it reads differently from the round verdict pills. */
export function SeverityChip({ severity }: { severity: Severity }) {
  const t = tierOf(severity);
  return <span className={`sev-chip sev-chip--${t.tier}`}>{t.label}</span>;
}

/** Coloured bar at the left edge of a row; the parent must be `position:relative`. */
export function SeverityStripe({ severity }: { severity: Severity }) {
  return <span className={`stripe stripe--${tierOf(severity).tier}`} aria-hidden="true" />;
}
