import { useId, useState } from "react";
import type { CSSProperties } from "react";
import type { Severity, TriageItem } from "../api";
import { SegmentedControl } from "./SegmentedControl";

export type SeverityMode = "all" | "confirmed";

// Fixed order and labels. Keys are the severity enum, so nothing here comes from scanned data.
const TIERS: readonly { sev: Severity; label: string; fill: string }[] = [
  { sev: "CRITICAL", label: "Critical", fill: "--sev-crit" },
  { sev: "HIGH", label: "High", fill: "--sev-high" },
  { sev: "MEDIUM", label: "Medium", fill: "--sev-med" },
  { sev: "LOW", label: "Low", fill: "--sev-low" },
  { sev: "INFO", label: "Info", fill: "--sev-info" },
];

/** Smallest of 1, 2, 5, 10, 20, 50, 100, ... that is at or above `x`. */
export function niceStep(x: number): number {
  if (!Number.isFinite(x) || x <= 1) return 1;
  for (let mag = 1; ; mag *= 10) {
    for (const m of [1, 2, 5]) if (m * mag >= x) return m * mag;
  }
}

/** Findings per severity tier. A severity outside the enum counts as Info, like `SeverityChip`. */
export function severityCounts(items: readonly TriageItem[], mode: SeverityMode): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const it of items) {
    if (mode === "confirmed" && it.verdict !== "TRUE_POSITIVE") continue;
    const sev = it.finding?.severity;
    counts[typeof sev === "string" && Object.hasOwn(counts, sev) ? sev : "INFO"] += 1;
  }
  return counts;
}

// Plot geometry (spec 4.2.1).
const X0 = 44;
const PLOT_W = 464;
const Y_TOP = 20;
const Y_BASE = 196;
const PLOT_H = Y_BASE - Y_TOP;
const BAR_W = 44;

/** Two decimals, no float noise (`68.4`, not `68.39999999999999`). */
const n = (v: number) => Number(v.toFixed(2));

/** Bar with a rounded top and a flat base. */
function barPath(x: number, h: number): string {
  const r = Math.min(10, BAR_W / 2, h);
  const top = Y_BASE - h;
  return `M${n(x)},${Y_BASE} V${n(top + r)} Q${n(x)},${n(top)} ${n(x + r)},${n(top)} H${n(x + BAR_W - r)} Q${n(x + BAR_W)},${n(top)} ${n(x + BAR_W)},${n(top + r)} V${Y_BASE} Z`;
}

/** "Findings by severity" card: a five-bar chart with an All / Confirmed switch. */
export function SeverityBarChart({ items }: { items: readonly TriageItem[] }) {
  const [mode, setMode] = useState<SeverityMode>("all");
  const uid = useId().replace(/:/g, "");
  const counts = severityCounts(items, mode);
  const max = Math.max(1, ...TIERS.map((t) => counts[t.sev]));
  const step = niceStep(max / 4);
  const yMax = step * 4;
  const band = PLOT_W / TIERS.length;
  const total = TIERS.reduce((sum, t) => sum + counts[t.sev], 0);
  const name = `${mode === "confirmed" ? "Confirmed findings" : "Findings"} by severity: ${TIERS.map(
    (t) => `${t.label} ${counts[t.sev]}`,
  ).join(", ")}`;

  return (
    <section className="card chart-card" aria-labelledby={`${uid}-title`}>
      <div className="card-head">
        <h2 className="card-title" id={`${uid}-title`}>
          Findings by severity
        </h2>
        <SegmentedControl<SeverityMode>
          label="Findings shown"
          value={mode}
          onChange={setMode}
          options={[
            { value: "all", label: "All" },
            { value: "confirmed", label: "Confirmed" },
          ]}
        />
      </div>
      <svg className="bar-svg" viewBox="0 0 520 240" role="img" aria-label={name}>
        <defs>
          {TIERS.map((t) => (
            <linearGradient key={t.sev} id={`${uid}-g-${t.sev}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" style={{ stopColor: `color-mix(in srgb, var(${t.fill}) 78%, white)` }} />
              <stop offset=".35" style={{ stopColor: `var(${t.fill})` }} />
              <stop offset="1" style={{ stopColor: `var(${t.fill})` }} />
            </linearGradient>
          ))}
          <filter id={`${uid}-blur`} x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" />
          </filter>
        </defs>

        {[0, 1, 2, 3, 4].map((i) => {
          const y = Y_BASE - (PLOT_H * i) / 4;
          return (
            <g key={i}>
              <line className="grid-line" x1={X0} x2={X0 + PLOT_W} y1={y} y2={y} />
              <text className="axis-text tick-text" x={36} y={y + 4} textAnchor="end">
                {step * i}
              </text>
            </g>
          );
        })}

        {TIERS.map((t, i) => {
          const count = counts[t.sev];
          const x = X0 + band * i + (band - BAR_W) / 2;
          const h = (PLOT_H * count) / yMax;
          return (
            <g key={t.sev}>
              {count > 0 ? (
                <>
                  <path
                    d={barPath(x, h)}
                    transform="translate(0 4)"
                    fill="rgba(20,35,50,.12)"
                    filter={`url(#${uid}-blur)`}
                  />
                  <path
                    className="bar-rect"
                    d={barPath(x, h)}
                    fill={`url(#${uid}-g-${t.sev})`}
                    style={{ "--i": i } as CSSProperties}
                  />
                </>
              ) : (
                <rect
                  className="bar-stub"
                  x={n(x)}
                  y={Y_BASE - 4}
                  width={BAR_W}
                  height={4}
                  rx={2}
                  style={{ fill: "var(--slate-200)" }}
                />
              )}
              <text
                className="val-text"
                x={n(x + BAR_W / 2)}
                y={n(Y_BASE - h - 8)}
                textAnchor="middle"
              >
                {count}
              </text>
              <text className="axis-text x-text" x={n(x + BAR_W / 2)} y={218} textAnchor="middle">
                {t.label}
              </text>
            </g>
          );
        })}
      </svg>
      {total === 0 ? <p className="chart-empty">No findings yet</p> : null}
    </section>
  );
}
