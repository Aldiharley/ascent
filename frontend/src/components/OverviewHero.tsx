import { useId } from "react";
import type { GateDecisionKind } from "../api";
import { greeting } from "../data/greeting";
import { Button } from "./Button";
import { IconTarget } from "./icons";
import type { NavId } from "./Shell";

/** What the hero knows about the engagement. Only a named one is ever quoted. */
export type HeroEngagement =
  | { kind: "loading" }
  | { kind: "error" }
  | { kind: "none" }
  | { kind: "named"; name: string };

/**
 * Facts for the summary line. A field is `undefined` until its data has loaded (or if it failed),
 * and the line is built from the loaded ones only. `decision: null` means "loaded, no verdict yet".
 */
export interface HeroSummary {
  needsReview?: number;
  pending?: number;
  decision?: GateDecisionKind | null;
}

export interface OverviewHeroProps {
  engagement: HeroEngagement;
  summary?: HeroSummary;
  onNavigate: (id: NavId) => void;
  /** Clock override for tests; the greeting uses local time. */
  now?: Date;
}

const WAVE = "M0 120 C 80 90 160 150 260 118 S 420 80 520 110 V 184 H 0 Z";

const DECISIONS: Record<GateDecisionKind, string> = {
  PASS: "PASS",
  CONDITIONAL: "CONDITIONAL",
  FAIL: "FAIL",
  INCOMPLETE: "INCOMPLETE",
};

/** Summary parts, joined with " · ". Never includes a finding title or any scanned text. */
function summaryLine(s: HeroSummary): string {
  const parts: string[] = [];
  if (typeof s.needsReview === "number" && s.needsReview > 0) parts.push(`${s.needsReview} need your review`);
  if (typeof s.pending === "number" && s.pending > 0) {
    parts.push(s.pending === 1 ? "1 approval pending" : `${s.pending} approvals pending`);
  }
  if (s.decision) {
    parts.push(`policy ${Object.hasOwn(DECISIONS, s.decision) ? DECISIONS[s.decision] : DECISIONS.INCOMPLETE}`);
  }
  if (parts.length === 0 && s.needsReview === 0 && s.pending === 0 && s.decision === null) {
    return "All quiet. Nothing needs you right now.";
  }
  return parts.join(" · ");
}

/** Overview banner: the watchdog, a time-of-day greeting, what is being watched, and the next step. */
export function OverviewHero({ engagement, summary = {}, onNavigate, now }: OverviewHeroProps) {
  const uid = useId().replace(/:/g, "");
  const line = summaryLine(summary);
  const pending = typeof summary.pending === "number" ? summary.pending : 0;

  return (
    <section className="hero" aria-label="Welcome">
      <span className="mascot mascot--hero mascot--float" aria-hidden="true" />
      <div className="hero-waves-wrap" aria-hidden="true">
        <svg className="hero-waves" viewBox="0 0 520 184" preserveAspectRatio="none" focusable="false">
          <defs>
            <pattern id={`${uid}-knit`} width="4" height="4" patternUnits="userSpaceOnUse">
              <line x1="0" y1="0.5" x2="4" y2="0.5" style={{ stroke: "var(--white)" }} strokeWidth="1" strokeOpacity=".06" />
            </pattern>
          </defs>
          <path d={WAVE} style={{ fill: "var(--slate-500)" }} opacity=".35" />
          <path d={WAVE} fill={`url(#${uid}-knit)`} />
          <path d={WAVE} transform="translate(0 22)" style={{ fill: "var(--teal-500)" }} opacity=".28" />
          <path d={WAVE} transform="translate(0 44)" style={{ fill: "var(--slate-300)" }} opacity=".22" />
        </svg>
      </div>

      <div className="hero-text">
        <p className="hero-greet">{greeting(now)}</p>
        {engagement.kind === "named" ? (
          <p className="hero-eng" title={engagement.name}>
            Watching <b>{engagement.name}</b>
          </p>
        ) : engagement.kind === "none" ? (
          <p className="hero-eng">Define a scope to get started.</p>
        ) : null}
        {line ? <p className="hero-sum">{line}</p> : null}
        <div className="hero-cta">
          <Button variant="primary" onClick={() => onNavigate("newscan")}>
            <IconTarget /> Define a new scan
          </Button>
          {pending > 0 ? (
            <Button variant="ghost-dark" onClick={() => onNavigate("gates")}>
              Review approvals
            </Button>
          ) : null}
        </div>
      </div>
    </section>
  );
}
