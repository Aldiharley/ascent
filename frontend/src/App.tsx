import { useCallback, useRef, useState } from "react";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Shell, navTitle } from "./components/Shell";
import type { NavId, ShellPolicy } from "./components/Shell";
import { usePendingGates as usePendingGatesResource } from "./data/gates";
import { RESOURCE_KEYS, useResource } from "./data/resources";
import type { ResourceKey } from "./data/resources";
import type { Verdict } from "./api";
import { Audit } from "./screens/Audit";
import { Findings } from "./screens/Findings";
import { Gates } from "./screens/Gates";
import { NewScan } from "./screens/NewScan";
import { Overview } from "./screens/Overview";
import { Report } from "./screens/Report";

const NO_ENGAGEMENT = "no engagement loaded";

type Versions = Record<ResourceKey, number>;

const INITIAL_VERSIONS = Object.fromEntries(RESOURCE_KEYS.map((k) => [k, 0])) as Versions;

/** Sidebar status text; anything but a named engagement is the neutral fallback.
 *  Refetches whenever `version` changes (e.g. after a new scan is created). While a refetch is in
 *  flight, or if it fails, the last known text stays, so the chip neither flickers nor loses a
 *  name it already showed. */
function useEngagementStatus(version: number): { status: string; loading: boolean } {
  const res = useResource("engagement", version);
  const last = useRef(NO_ENGAGEMENT);
  if (res.status === "ready") {
    const name = typeof res.data?.name === "string" ? res.data.name.trim() : "";
    last.current = name ? `engagement: ${name}` : NO_ENGAGEMENT;
  }
  // On an error the last known text stays; before any name was loaded it is still the neutral
  // fallback, so a failing first fetch reads "no engagement loaded".
  return { status: last.current, loading: res.status === "loading" };
}

/** Number of pending approval gates for the nav badge and the bell. Unknown (undefined) until the
 *  first load; a refetch or a failure keeps the last known count so the badge does not flicker.
 *  It reads the same pending list as the Approval gates views (decided gates already subtracted), so
 *  the badge, the bell, the hero and the cards always show one number. */
function usePendingGates(version: number): { count: number | undefined; loading: boolean } {
  const res = usePendingGatesResource(version);
  const last = useRef<number | undefined>(undefined);
  if (res.status === "ready") last.current = Array.isArray(res.data) ? res.data.length : undefined;
  return { count: last.current, loading: res.status === "loading" };
}

/** Policy verdict for the sidebar card: undefined = not loaded or failed (no card), null = no
 *  verdict yet. Read-only: nothing here evaluates a policy. */
function usePolicy(version: number): { policy: ShellPolicy | null | undefined; loading: boolean } {
  const res = useResource("gate", version);
  const last = useRef<ShellPolicy | null | undefined>(undefined);
  if (res.status === "ready") {
    const g = res.data;
    last.current = g
      ? {
          decision: g.decision,
          exit_code: typeof g.exit_code === "number" ? g.exit_code : 0,
          policy: typeof g.policy?.name === "string" ? g.policy.name : "",
        }
      : null;
  } else if (res.status === "error") {
    last.current = undefined;
  }
  return { policy: last.current, loading: res.status === "loading" };
}

export default function App() {
  const [active, setActive] = useState<NavId>("overview");
  // One version counter per shared resource (see data/resources.ts). Bumping a key makes every
  // reader of it refetch: a recorded gate decision bumps gates + audit, a created scan bumps all
  // the data the new engagement affects, and Refresh bumps everything.
  const [versions, setVersions] = useState<Versions>(INITIAL_VERSIONS);
  const bump = useCallback((...keys: ResourceKey[]) => {
    setVersions((v) => {
      const next = { ...v };
      for (const k of keys) next[k] += 1;
      return next;
    });
  }, []);
  // The search query lives here so it survives navigation (Findings and Overview filter by it).
  const [query, setQuery] = useState("");
  // The verdict the Findings table is narrowed to (set by the Overview KPI tiles); kept across
  // navigation like the query.
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "ALL">("ALL");

  const engagement = useEngagementStatus(versions.engagement);
  const pending = usePendingGates(versions.gates);
  const policy = usePolicy(versions.gate);

  const shell = {
    active,
    onNavigate: setActive,
    status: engagement.status,
    title: navTitle(active),
    pendingGates: pending.count,
    policy: policy.policy,
    query,
    onQueryChange: setQuery,
    // Enter in the search box always lands on Findings (a no-op there).
    onSearchSubmit: () => setActive("findings"),
    onRefresh: () => bump(...RESOURCE_KEYS),
    refreshing: engagement.loading || pending.loading || policy.loading,
  };
  const onDecided = () => bump("gates", "audit");
  // "Clear filters" on Findings: the verdict toggle and the search box both go back to empty.
  const clearFilters = () => {
    setVerdictFilter("ALL");
    setQuery("");
  };

  switch (active) {
    case "newscan":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="newscan">
            <NewScan onCreated={() => bump(...RESOURCE_KEYS)} />
          </ErrorBoundary>
        </Shell>
      );
    case "findings":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="findings">
            <Findings
              version={versions.findings}
              verdictFilter={verdictFilter}
              onVerdictFilterChange={setVerdictFilter}
              query={query}
              onClearFilters={clearFilters}
              onNavigate={setActive}
            />
          </ErrorBoundary>
        </Shell>
      );
    case "gates":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="gates">
            <Gates version={versions.gates} onDecided={onDecided} />
          </ErrorBoundary>
        </Shell>
      );
    case "report":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="report">
            <Report version={versions.report} />
          </ErrorBoundary>
        </Shell>
      );
    case "audit":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="audit">
            <Audit version={versions.audit} />
          </ErrorBoundary>
        </Shell>
      );
    default:
      return (
        <Shell {...shell}>
          <ErrorBoundary key="overview">
            <Overview
              versions={versions}
              query={query}
              onClearQuery={() => setQuery("")}
              onNavigate={setActive}
              onOpenFindings={(filter) => {
                setVerdictFilter(filter);
                setActive("findings");
              }}
              onDecided={onDecided}
            />
          </ErrorBoundary>
        </Shell>
      );
  }
}
