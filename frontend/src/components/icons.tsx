import type { ReactNode } from "react";

/**
 * Line glyphs for the console. Every glyph is a 24x24, stroke-only, round-capped svg that
 * inherits `currentColor` and is `aria-hidden`: the label next to it carries the meaning.
 * Size and stroke width are normally set by the surrounding component's CSS (`.ibadge svg`,
 * `.btn svg`, ...); the props only override the defaults.
 */
export interface IconProps {
  size?: number;
  strokeWidth?: number;
  className?: string;
}

function glyph(name: string, body: ReactNode) {
  function Glyph({ size, strokeWidth = 2, className }: IconProps) {
    return (
      <svg
        viewBox="0 0 24 24"
        width={size}
        height={size}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        focusable="false"
        className={className}
      >
        {body}
      </svg>
    );
  }
  Glyph.displayName = name;
  return Glyph;
}

/** 2x2 rounded squares (Overview). */
export const IconGrid = glyph(
  "IconGrid",
  <>
    <rect x="3.5" y="3.5" width="7" height="7" rx="2" />
    <rect x="13.5" y="3.5" width="7" height="7" rx="2" />
    <rect x="3.5" y="13.5" width="7" height="7" rx="2" />
    <rect x="13.5" y="13.5" width="7" height="7" rx="2" />
  </>,
);

/** Crosshair circle (New scan). */
export const IconTarget = glyph(
  "IconTarget",
  <>
    <circle cx="12" cy="12" r="7.5" />
    <path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4" />
    <circle cx="12" cy="12" r="1.2" />
  </>,
);

/** Magnifier with three list lines inside the lens (Findings). */
export const IconSearchLines = glyph(
  "IconSearchLines",
  <>
    <circle cx="10.5" cy="10.5" r="7" />
    <path d="m21 21-5.1-5.1" />
    <path d="M7.5 8.5h6M7.5 10.5h6M7.5 12.5h3.5" />
  </>,
);

/** Plain magnifier (the top-bar search field). */
export const IconSearch = glyph(
  "IconSearch",
  <>
    <circle cx="10.5" cy="10.5" r="7" />
    <path d="m21 21-5.1-5.1" />
  </>,
);

/** Shield with a tick (Approval gates, policy gate). */
export const IconShieldCheck = glyph(
  "IconShieldCheck",
  <>
    <path d="M12 3 4.5 6v5.6c0 4.6 3.1 8 7.5 9.4 4.4-1.4 7.5-4.8 7.5-9.4V6z" />
    <path d="m8.8 12.2 2.4 2.4 4.2-4.7" />
  </>,
);

/** Document with a folded corner (Report). */
export const IconDocument = glyph(
  "IconDocument",
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5" />
    <path d="M9 13h6M9 17h6" />
  </>,
);

/** Two chain links (Audit). */
export const IconChain = glyph(
  "IconChain",
  <>
    <rect x="2.5" y="8.5" width="12" height="7" rx="3.5" />
    <rect x="9.5" y="8.5" width="12" height="7" rx="3.5" />
  </>,
);

/** Radar sweep: circle, arc, sweep line and dot (Findings KPI). */
export const IconRadar = glyph(
  "IconRadar",
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M16.5 12A4.5 4.5 0 0 0 12 7.5" />
    <path d="m12 12 5.5-5.5" />
    <circle cx="12" cy="12" r="1" />
  </>,
);

/** Target rings with a tick (True positive KPI). */
export const IconCrosshairCheck = glyph(
  "IconCrosshairCheck",
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="m8.3 12.3 2.6 2.6 4.8-5.3" />
  </>,
);

/** Raised hand (Needs human KPI). */
export const IconHand = glyph(
  "IconHand",
  <>
    <path d="M8 12V6.2a1.5 1.5 0 0 1 3 0V11" />
    <path d="M11 10.5V4.7a1.5 1.5 0 0 1 3 0V11" />
    <path d="M14 10.8V6.2a1.5 1.5 0 0 1 3 0V13" />
    <path d="M8 12.2 6.6 10.8a1.5 1.5 0 0 0-2.2 2L8.2 18A5 5 0 0 0 12.2 21H12.5a4.5 4.5 0 0 0 4.5-4.5V13" />
  </>,
);

/** Funnel with a slash through it (Likely noise KPI). */
export const IconFunnelSlash = glyph(
  "IconFunnelSlash",
  <>
    <path d="M3.5 5h17l-6.5 8v6l-4-2v-4z" />
    <path d="m3 3 18 18" />
  </>,
);

/** Circular arrows (Refresh). */
export const IconRefresh = glyph(
  "IconRefresh",
  <>
    <path d="M20 11a8 8 0 0 0-14.3-4.5L4 8.5" />
    <path d="M4 4v4.5h4.5" />
    <path d="M4 13a8 8 0 0 0 14.3 4.5l1.7-2" />
    <path d="M20 20v-4.5h-4.5" />
  </>,
);

/** Bell (pending approvals). */
export const IconBell = glyph(
  "IconBell",
  <>
    <path d="M6 9a6 6 0 0 1 12 0c0 6 2.5 7.5 2.5 7.5h-17S6 15 6 9z" />
    <path d="M10 20a2 2 0 0 0 4 0" />
  </>,
);

/** Padlock (authenticated scanning). */
export const IconLock = glyph(
  "IconLock",
  <>
    <rect x="5" y="11" width="14" height="10" rx="2.5" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  </>,
);

/** Circled "i". */
export const IconInfo = glyph(
  "IconInfo",
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5.5M12 7.8v.01" />
  </>,
);

/** Warning triangle. */
export const IconAlertTriangle = glyph(
  "IconAlertTriangle",
  <>
    <path d="M10.3 4 2.8 17a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0z" />
    <path d="M12 9.5v4M12 17v.01" />
  </>,
);

/** Circled "!" (errors). */
export const IconAlertCircle = glyph(
  "IconAlertCircle",
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7.5v5.5M12 16.5v.01" />
  </>,
);

/** Check mark. */
export const IconTick = glyph("IconTick", <path d="m5 12.5 4.5 4.5L19 7" />);

/** Close "x". */
export const IconX = glyph("IconX", <path d="M6 6l12 12M18 6 6 18" />);

/** Play inside a circle. */
export const IconPlayCircle = glyph(
  "IconPlayCircle",
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M10.5 8.8v6.4l5.3-3.2z" />
  </>,
);

/** Clipboard. */
export const IconClipboard = glyph(
  "IconClipboard",
  <>
    <rect x="5" y="4.5" width="14" height="17" rx="2.5" />
    <rect x="9" y="2.5" width="6" height="4" rx="1.5" />
    <path d="M9 11.5h6M9 15.5h4" />
  </>,
);

/** Two overlapping sheets (copy). */
export const IconCopy = glyph(
  "IconCopy",
  <>
    <rect x="8.5" y="8.5" width="12" height="12" rx="2.5" />
    <path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5" />
  </>,
);

/** Down chevron. */
export const IconChevronDown = glyph("IconChevronDown", <path d="m6 9 6 6 6-6" />);
