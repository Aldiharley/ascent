import type { Severity } from "../api";

// INFO shares the lowest visual tier (the mockup has no separate style for it).
const TIERS: Record<Severity, { stripe: string; badge: string }> = {
  CRITICAL: { stripe: "s-crit", badge: "crit" },
  HIGH: { stripe: "s-high", badge: "high" },
  MEDIUM: { stripe: "s-med", badge: "med" },
  LOW: { stripe: "s-low", badge: "low" },
  INFO: { stripe: "s-low", badge: "low" },
};

function tier(severity: Severity) {
  return TIERS[severity] ?? TIERS.INFO;
}

export function SeverityStripe({ severity }: { severity: Severity }) {
  return <span className={`stripe ${tier(severity).stripe}`} aria-hidden="true" />;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev ${tier(severity).badge}`}>{severity}</span>;
}
