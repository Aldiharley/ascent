import type { ReactNode } from "react";

export type BadgeTone = "teal" | "bluegrey" | "ice" | "lav" | "sand" | "coral";
export type BadgeSize = "sm" | "md" | "lg";

// Class names come from these fixed tables, never from caller-supplied strings.
const TONES: Record<BadgeTone, string> = {
  teal: "ibadge--teal",
  bluegrey: "ibadge--bluegrey",
  ice: "ibadge--ice",
  lav: "ibadge--lav",
  sand: "ibadge--sand",
  coral: "ibadge--coral",
};

const SIZES: Record<BadgeSize, string> = { sm: " ibadge--sm", md: "", lg: " ibadge--lg" };

/** Clay icon badge: a rounded square holding a white line glyph. Always decorative. */
export function IconBadge({
  tone = "teal",
  size = "md",
  children,
}: {
  tone?: BadgeTone;
  size?: BadgeSize;
  children: ReactNode;
}) {
  const t = Object.hasOwn(TONES, tone) ? TONES[tone] : TONES.teal;
  const s = Object.hasOwn(SIZES, size) ? SIZES[size] : "";
  return (
    <span className={`ibadge ${t}${s}`} aria-hidden="true">
      {children}
    </span>
  );
}
