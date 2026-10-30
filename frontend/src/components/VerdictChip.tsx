import type { Verdict } from "../api";

const VERDICTS: Record<Verdict, { label: string; cls: string }> = {
  TRUE_POSITIVE: { label: "True positive", cls: "vchip--tp" },
  ABSTAIN: { label: "Needs human", cls: "vchip--hu" },
  LIKELY_FALSE_POSITIVE: { label: "Likely noise", cls: "vchip--fp" },
};

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  // Unknown verdicts fail safe to "needs human"; class names never come from data.
  const v = Object.hasOwn(VERDICTS, verdict) ? VERDICTS[verdict] : VERDICTS.ABSTAIN;
  return <span className={`vchip ${v.cls}`}>{v.label}</span>;
}
