import type { ReactNode } from "react";

export type NavId = "overview" | "findings" | "gates" | "report" | "audit";

interface NavItem {
  id: NavId;
  label: string;
  icon: ReactNode;
}

// Icons ported verbatim from design/dashboard-mockup.html.
const svgProps = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  "aria-hidden": true,
} as const;

const NAV: NavItem[] = [
  {
    id: "overview",
    label: "Overview",
    icon: (
      <svg {...svgProps}>
        <rect x="3" y="3" width="7" height="7" rx="2" />
        <rect x="14" y="3" width="7" height="7" rx="2" />
        <rect x="3" y="14" width="7" height="7" rx="2" />
        <rect x="14" y="14" width="7" height="7" rx="2" />
      </svg>
    ),
  },
  {
    id: "findings",
    label: "Findings",
    icon: (
      <svg {...svgProps}>
        <path d="M4 6h16M4 12h16M4 18h10" />
      </svg>
    ),
  },
  {
    id: "gates",
    label: "Approval gates",
    icon: (
      <svg {...svgProps}>
        <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
  },
  {
    id: "report",
    label: "Report",
    icon: (
      <svg {...svgProps}>
        <path d="M7 3h7l5 5v13H7z" />
        <path d="M14 3v5h5M10 13h6M10 17h6" />
      </svg>
    ),
  },
  {
    id: "audit",
    label: "Audit",
    icon: (
      <svg {...svgProps}>
        <path d="M12 8v5l3 2" />
        <circle cx="12" cy="12" r="9" />
      </svg>
    ),
  },
];

export interface ShellProps {
  children?: ReactNode;
  /** Optional right-hand rail (approval gate + audit feed). Omit for a 2-column shell. */
  aside?: ReactNode;
  /** Currently active nav item. */
  active?: NavId;
  /** Called when a rail button is clicked. Navigation is wired up later. */
  onNavigate?: (id: NavId) => void;
  /** Engagement status shown in the topbar pill. */
  status?: string;
}

const DEFAULT_STATUS = "no engagement loaded";

export function Shell({
  children,
  aside,
  active = "overview",
  onNavigate,
  status = DEFAULT_STATUS,
}: ShellProps) {
  const idle = status === DEFAULT_STATUS;
  return (
    <>
      <div className="field" aria-hidden="true">
        <div className="blob b1" />
        <div className="blob b2" />
        <div className="blob b3" />
      </div>

      <div className={aside ? "app" : "app no-side"}>
        <nav className="rail glass" aria-label="Primary">
          <div className="logo" aria-hidden="true">
            A
          </div>
          <div className="nav">
            {NAV.map((item) => (
              <button
                key={item.id}
                type="button"
                className={item.id === active ? "on" : undefined}
                aria-label={item.label}
                aria-current={item.id === active ? "page" : undefined}
                title={item.label}
                onClick={() => onNavigate?.(item.id)}
              >
                {item.icon}
              </button>
            ))}
          </div>
        </nav>

        <main className="main">
          <header className="topbar glass">
            <h1 className="sr-only">Ascent Console</h1>
            <div className="eng">
              <span className={idle ? "dot idle" : "dot"} aria-hidden="true" /> {status}
            </div>
          </header>
          {children}
        </main>

        {aside ? <aside className="side">{aside}</aside> : null}
      </div>
    </>
  );
}
