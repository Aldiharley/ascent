import { useId, useState } from "react";
import type { CSSProperties } from "react";
import type { TriageItem } from "../api";
import { verdictCounts } from "../data/findingStats";
import { SegmentedControl } from "./SegmentedControl";

export type DonutMode = "verdict" | "category";

export interface MixSegment {
  /** Fixed label from the tables below, never scanned text. */
  label: string;
  value: number;
  /** CSS custom property that carries the segment colour. */
  color: string;
}

const VERDICT_ROWS = [
  { verdict: "TRUE_POSITIVE", label: "True positive", color: "--v-tp" },
  { verdict: "ABSTAIN", label: "Needs human", color: "--v-hu" },
  { verdict: "LIKELY_FALSE_POSITIVE", label: "Likely noise", color: "--v-fp" },
] as const;

const CATEGORY_ROWS = [
  { category: "DAST", label: "DAST", color: "--cat-dast" },
  { category: "SAST", label: "SAST", color: "--cat-sast" },
  { category: "SCA", label: "SCA", color: "--cat-sca" },
] as const;

/** Findings per verdict. An unknown verdict is counted as "Needs human", like `VerdictChip`. */
export function verdictMix(items: readonly TriageItem[]): MixSegment[] {
  const c = verdictCounts(items);
  const counts = [c.tp, c.hu, c.fp];
  return VERDICT_ROWS.map((r, i) => ({ label: r.label, value: counts[i], color: r.color }));
}

/** Findings per category; a missing or unknown category is "Uncategorised". */
export function categoryMix(items: readonly TriageItem[]): MixSegment[] {
  const counts = [0, 0, 0, 0];
  for (const it of items) {
    const i = CATEGORY_ROWS.findIndex((r) => r.category === it.finding?.category);
    counts[i === -1 ? 3 : i] += 1;
  }
  return [
    ...CATEGORY_ROWS.map((r, i) => ({ label: r.label, value: counts[i], color: r.color })),
    { label: "Uncategorised", value: counts[3], color: "--cat-none" },
  ];
}

const R = 72;
const C = 2 * Math.PI * R;
const CIRC_VAR = "--donut-circ";

/** "Verdict mix" / "Category mix" card: a clay donut with a legend of counts and percents. */
export function DonutCard({ items }: { items: readonly TriageItem[] }) {
  const [mode, setMode] = useState<DonutMode>("verdict");
  const uid = useId().replace(/:/g, "");
  const title = mode === "verdict" ? "Verdict mix" : "Category mix";
  const segments = mode === "verdict" ? verdictMix(items) : categoryMix(items);
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const drawn = segments.filter((s) => s.value > 0);
  const gap = drawn.length >= 2 ? 3 : 0;
  const name = `${title}: ${segments.map((s) => `${s.label} ${s.value}`).join(", ")}`;

  let before = 0;
  const arcs = drawn.map((s) => {
    const arc = {
      key: s.label,
      color: s.color,
      dash: Math.max((C * s.value) / total - gap, 0),
      offset: -((C * before) / total),
    };
    before += s.value;
    return arc;
  });

  return (
    <section className="card chart-card" aria-labelledby={`${uid}-title`}>
      <div className="card-head">
        <h2 className="card-title" id={`${uid}-title`}>
          {title}
        </h2>
        <SegmentedControl<DonutMode>
          label="Group findings by"
          value={mode}
          onChange={setMode}
          options={[
            { value: "verdict", label: "Verdict" },
            { value: "category", label: "Category" },
          ]}
        />
      </div>
      <div className="donut-wrap">
        <svg viewBox="0 0 200 200" role="img" aria-label={name}>
          <defs>
            <radialGradient id={`${uid}-disc`} cx="50%" cy="40%" r="65%">
              <stop offset="0" style={{ stopColor: "var(--white)" }} />
              <stop offset="1" style={{ stopColor: "var(--paper-100)" }} />
            </radialGradient>
          </defs>
          <circle
            className="donut-track"
            cx="100"
            cy="100"
            r={R}
            fill="none"
            strokeWidth="28"
            style={{ stroke: "var(--slate-100)" }}
          />
          <g className="donut-segs">
            {arcs.map((a) => (
              <circle
                key={a.key}
                className="donut-seg"
                cx="100"
                cy="100"
                r={R}
                fill="none"
                strokeWidth="28"
                strokeLinecap="butt"
                strokeDasharray={`${Number(a.dash.toFixed(3))} ${Number(C.toFixed(3))}`}
                strokeDashoffset={Number(a.offset.toFixed(3))}
                transform="rotate(-90 100 100)"
                // --donut-circ is where the draw-in animation starts from (the full circumference)
                style={{ stroke: `var(${a.color})`, [CIRC_VAR]: Number(C.toFixed(3)) } as CSSProperties}
              />
            ))}
          </g>
          <circle
            cx="100"
            cy="100"
            r="58"
            fill={`url(#${uid}-disc)`}
            strokeWidth="1"
            style={{ stroke: "var(--border-soft)" }}
          />
          <text className="donut-total" x="100" y="104" textAnchor="middle">
            {total}
          </text>
          <text className="donut-caption" x="100" y="126" textAnchor="middle">
            findings
          </text>
        </svg>
        <div className="legend">
          {segments.map((s) => (
            <div className="legend-row" key={s.label}>
              <span className="legend-dot" aria-hidden="true" style={{ background: `var(${s.color})` }} />
              <span className="legend-label">{s.label}</span>
              <span className="legend-count">{s.value}</span>
              <span className="legend-pct">{total === 0 ? 0 : Math.round((s.value / total) * 100)}%</span>
            </div>
          ))}
          {total === 0 ? <p className="chart-empty">No findings yet</p> : null}
        </div>
      </div>
    </section>
  );
}
