import type { CSSProperties } from "react";
import type { Verdict } from "../api";

// Mockup colours: default teal gradient for true positives, amber for
// needs-human, grey for noise.
const FILL: Partial<Record<Verdict, string>> = {
  ABSTAIN: "linear-gradient(90deg,#e0a400,#f2c14e)",
  LIKELY_FALSE_POSITIVE: "linear-gradient(90deg,#8a99ad,#b7c2d1)",
};

export function ConfidenceBar({ confidence, verdict }: { confidence: number; verdict: Verdict }) {
  const c = Number.isFinite(confidence) ? Math.min(1, Math.max(0, confidence)) : 0;
  const style: CSSProperties = { width: `${Math.round(c * 100)}%`, background: FILL[verdict] };
  return (
    <div className="conf">
      <span className="bar">
        <i style={style} />
      </span>
      <b>{c.toFixed(2)}</b>
    </div>
  );
}
