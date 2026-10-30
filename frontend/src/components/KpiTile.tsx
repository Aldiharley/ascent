import type { ReactNode } from "react";
import { IconBadge } from "./IconBadge";
import type { BadgeTone } from "./IconBadge";

export type KpiTone = "teal" | "bluegrey" | "ice" | "lav";

// Fixed tables: the tint class and the badge tone are never taken from caller-supplied strings.
const TONES: Record<KpiTone, { cls: string; badge: BadgeTone }> = {
  teal: { cls: "kpi--teal", badge: "teal" },
  bluegrey: { cls: "kpi--bluegrey", badge: "bluegrey" },
  ice: { cls: "kpi--ice", badge: "ice" },
  lav: { cls: "kpi--lav", badge: "lav" },
};

export interface KpiTileProps {
  label: string;
  value: number;
  sub: string;
  tone: KpiTone;
  icon: ReactNode;
  /** Toggle state; exposed as `aria-pressed` on interactive tiles only. */
  pressed?: boolean;
  /** Makes the tile a real `<button>`. Without it the tile is a plain, non-interactive `<div>`. */
  onClick?: () => void;
  compact?: boolean;
}

/** Pastel statistic tile (spec 4.1). Keeps the `.kpi`, `.l`, `.n` and `.sub` class names. */
export function KpiTile({ label, value, sub, tone, icon, pressed, onClick, compact }: KpiTileProps) {
  const t = Object.hasOwn(TONES, tone) ? TONES[tone] : TONES.teal;
  const className = `kpi ${t.cls}${compact ? " kpi--compact" : ""}`;
  const body = (
    <>
      <IconBadge tone={t.badge}>{icon}</IconBadge>
      <span className="l">{label}</span>
      <span className="n">{value}</span>
      <span className="sub">{sub}</span>
    </>
  );
  if (onClick) {
    return (
      <button
        type="button"
        className={className}
        aria-pressed={pressed === undefined ? undefined : pressed}
        onClick={onClick}
      >
        {body}
      </button>
    );
  }
  return <div className={className}>{body}</div>;
}
