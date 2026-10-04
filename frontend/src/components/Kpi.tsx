import type { CSSProperties } from "react";

export interface KpiProps {
  label: string;
  value: number;
  sub: string;
  /** Ring fill, 0-100. */
  percent: number;
  /** Ring inner text. */
  ringText: string;
  /** CSS colour (a design token such as `var(--crit)`). */
  color: string;
}

export function Kpi({ label, value, sub, percent, ringText, color }: KpiProps) {
  const p = Number.isFinite(percent) ? Math.min(100, Math.max(0, percent)) : 0;
  const style = { "--p": p, "--c": color } as CSSProperties;
  return (
    <div className="kpi glass">
      <div className="ring" style={style} aria-hidden="true">
        <i>{ringText}</i>
      </div>
      <div>
        <div className="n">{value}</div>
        <div className="l">{label}</div>
        <div className="sub">{sub}</div>
      </div>
    </div>
  );
}
