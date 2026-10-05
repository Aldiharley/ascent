import type { Verdict } from "../api";

const VERDICTS: Record<Verdict, { label: string; cls: string }> = {
  TRUE_POSITIVE: { label: "True positive", cls: "v-tp" },
  ABSTAIN: { label: "Needs human", cls: "v-hu" },
  LIKELY_FALSE_POSITIVE: { label: "Likely noise", cls: "v-fp" },
};

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  // Unknown verdicts fail safe to "needs human"; class names never come from data.
  const v = VERDICTS[verdict] ?? VERDICTS.ABSTAIN;
  return <span className={`verdict ${v.cls}`}>{v.label}</span>;
}
