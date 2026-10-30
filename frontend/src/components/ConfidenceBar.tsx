import type { Verdict } from "../api";

// Fill colour per verdict is a stylesheet class (spec 4.3.9); unknown verdicts read as needs-human.
const FILL: Record<Verdict, string> = {
  TRUE_POSITIVE: "conf-fill--tp",
  ABSTAIN: "conf-fill--hu",
  LIKELY_FALSE_POSITIVE: "conf-fill--fp",
};

export function ConfidenceBar({ confidence, verdict }: { confidence: number; verdict: Verdict }) {
  const c = Number.isFinite(confidence) ? Math.min(1, Math.max(0, confidence)) : 0;
  const fill = Object.hasOwn(FILL, verdict) ? FILL[verdict] : FILL.ABSTAIN;
  return (
    <div className="conf">
      <span className="conf-track">
        <i className={`conf-fill ${fill}`} style={{ width: `${Math.round(c * 100)}%` }} />
      </span>
      <b className="conf-val">{c.toFixed(2)}</b>
    </div>
  );
}
