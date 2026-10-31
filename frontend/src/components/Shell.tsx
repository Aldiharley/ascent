import { useEffect, useRef, useState } from "react";
import type { ComponentType, FormEvent, KeyboardEvent, ReactNode } from "react";
import {
  IconBell,
  IconChain,
  IconDocument,
  IconGrid,
  IconRefresh,
  IconSearch,
  IconSearchLines,
  IconShieldCheck,
  IconTarget,
} from "./icons";
import type { IconProps } from "./icons";
import { SidebarPolicyCard } from "./SidebarPolicyCard";
import type { ShellPolicy } from "./SidebarPolicyCard";

export type { ShellPolicy };

export type NavId = "overview" | "newscan" | "findings" | "gates" | "report" | "audit";

interface NavItem {
  id: NavId;
  /** Accessible name of the nav button (exact, never changes between breakpoints). */
  label: string;
  /** Visible label in the phone tab bar; always contained in `label` (WCAG 2.5.3). */
  short: string;
  /** Page title shown in the top bar. */
  title: string;
  Icon: ComponentType<IconProps>;
}

const NAV: NavItem[] = [
  { id: "overview", label: "Overview", short: "Overview", title: "Overview", Icon: IconGrid },
  { id: "newscan", label: "New scan", short: "Scan", title: "New scan", Icon: IconTarget },
  { id: "findings", label: "Findings", short: "Findings", title: "Findings", Icon: IconSearchLines },
  { id: "gates", label: "Approval gates", short: "Gates", title: "Approval gates", Icon: IconShieldCheck },
  { id: "report", label: "Report", short: "Report", title: "Report", Icon: IconDocument },
  { id: "audit", label: "Audit", short: "Audit", title: "Audit log", Icon: IconChain },
];

const TITLES = Object.fromEntries(NAV.map((n) => [n.id, n.title])) as Record<NavId, string>;

/** Page title of a screen; an unknown id falls back to Overview. */
export function navTitle(id: NavId): string {
  return Object.hasOwn(TITLES, id) ? TITLES[id] : TITLES.overview;
}

const POLICY_TITLE_ID = "policy-gate-title";

/** Screens whose content the search field filters live; elsewhere Enter opens Findings. */
const LIVE_SEARCH: readonly NavId[] = ["findings", "overview"];

export interface ShellProps {
  children?: ReactNode;
  /** Currently active nav item. */
  active?: NavId;
  /** Called when a nav button, the bell or "View verdict" asks for another screen. */
  onNavigate?: (id: NavId) => void;
  /** Engagement status shown in the sidebar chip. */
  status?: string;
  /** Page title; defaults to the title of `active`. */
  title?: string;
  /** Pending approval gates; undefined = unknown (no badge, count-free bell name). */
  pendingGates?: number;
  /** Policy verdict: undefined = not loaded (no card), null = not evaluated. */
  policy?: ShellPolicy | null;
  query?: string;
  onQueryChange?: (query: string) => void;
  /** Enter in the search field. */
  onSearchSubmit?: () => void;
  onRefresh?: () => void;
  /** Some data is being (re)fetched: the refresh icon spins. */
  refreshing?: boolean;
}

const DEFAULT_STATUS = "no engagement loaded";

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

export function Shell({
  children,
  active = "overview",
  onNavigate,
  status = DEFAULT_STATUS,
  title,
  pendingGates,
  policy,
  query,
  onQueryChange,
  onSearchSubmit,
  onRefresh,
  refreshing = false,
}: ShellProps) {
  const idle = status === DEFAULT_STATUS;
  const heading = title ?? navTitle(active);

  // ---- search ----
  const [localQuery, setLocalQuery] = useState("");
  const q = query ?? localQuery;
  const inputRef = useRef<HTMLInputElement>(null);
  const [searchFocused, setSearchFocused] = useState(false);
  const showHint = searchFocused && !LIVE_SEARCH.includes(active);

  function changeQuery(next: string) {
    setLocalQuery(next);
    onQueryChange?.(next);
  }

  function onSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Escape") changeQuery("");
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    onSearchSubmit?.();
  }

  // "/" focuses search unless focus is already in a text field.
  useEffect(() => {
    function onKey(e: globalThis.KeyboardEvent) {
      // Not a keystroke some other handler already took (a widget's own "/" shortcut).
      if (e.key !== "/" || e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target;
      if (t instanceof HTMLElement && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName))) {
        return;
      }
      e.preventDefault();
      inputRef.current?.focus();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // ---- policy mini-card ----
  // "View verdict": go to Overview, then focus the policy card heading once it exists (its data may
  // still be loading), so keyboard and screen-reader users land on it.
  const [verdictRequest, setVerdictRequest] = useState(0);
  useEffect(() => {
    if (verdictRequest === 0) return;
    let tries = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    function attempt() {
      const el = document.getElementById(POLICY_TITLE_ID);
      if (el) {
        el.focus({ preventScroll: true });
        el.scrollIntoView?.({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
        return;
      }
      if (++tries < 20) timer = setTimeout(attempt, 50);
    }
    attempt();
    return () => clearTimeout(timer);
  }, [verdictRequest]);

  function viewVerdict() {
    onNavigate?.("overview");
    setVerdictRequest((n) => n + 1);
  }

  const pending = typeof pendingGates === "number" && pendingGates > 0 ? pendingGates : 0;
  const bellName = typeof pendingGates === "number" ? `Pending approvals: ${pendingGates}` : "Pending approvals";

  return (
    <div className="app">
      <a className="skip" href="#main">
        Skip to content
      </a>

      <nav className="sidebar" aria-label="Primary">
        <div className="sb-id">
          <span className="avatar mascot mascot--avatar" aria-hidden="true" />
          <p className="sb-word">Ascent</p>
          <div className="sb-chip" title={status}>
            <span className={idle ? "dot idle" : "dot"} aria-hidden="true" />
            <span className="sb-chip-text">{status}</span>
          </div>
        </div>

        <ul className="sb-nav" role="list">
          {NAV.map(({ id, label, short, Icon }) => (
            <li key={id}>
              <button
                type="button"
                aria-label={label}
                aria-current={id === active ? "page" : undefined}
                onClick={() => onNavigate?.(id)}
              >
                <Icon />
                <span className="nav-label">{label}</span>
                <span className="nav-short" aria-hidden="true">
                  {short}
                </span>
                {id === "gates" && pending > 0 ? (
                  <span className="nav-badge" aria-hidden="true">
                    {pending > 99 ? "99+" : pending}
                  </span>
                ) : null}
              </button>
            </li>
          ))}
        </ul>

        <div className="sb-spacer" />

        {policy !== undefined ? <SidebarPolicyCard policy={policy} onViewVerdict={viewVerdict} /> : null}
      </nav>

      <div className="main">
        <header className="topbar">
          <h1 className="page-title">
            <span className="sr-only">Ascent Console: </span>
            {heading}
          </h1>

          <form role="search" className={q ? "search has-value" : "search"} onSubmit={onSubmit}>
            <IconSearch />
            <input
              ref={inputRef}
              type="search"
              aria-label="Search findings"
              placeholder="Search findings, rules, CWEs, paths…"
              autoComplete="off"
              value={q}
              onChange={(e) => changeQuery(e.target.value)}
              onKeyDown={onSearchKeyDown}
              onFocus={() => setSearchFocused(true)}
              onBlur={() => setSearchFocused(false)}
            />
            <kbd aria-hidden="true">/</kbd>
            <div role="status" className="search-live">
              {showHint ? <span className="search-hint">Press Enter to search findings</span> : null}
            </div>
          </form>

          <button
            type="button"
            className="icon-btn"
            aria-label="Refresh data"
            aria-busy={refreshing ? true : undefined}
            onClick={() => onRefresh?.()}
          >
            <IconRefresh />
          </button>
          <button type="button" className="icon-btn" aria-label={bellName} onClick={() => onNavigate?.("gates")}>
            <IconBell />
            {pending > 0 ? (
              <span className="icon-btn-badge" aria-hidden="true">
                {pending > 99 ? "99+" : pending}
              </span>
            ) : null}
          </button>
        </header>

        <main id="main" tabIndex={-1}>
          <div className="screen">{children}</div>
        </main>
      </div>
    </div>
  );
}
