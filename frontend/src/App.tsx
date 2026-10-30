import { useCallback, useRef, useState } from "react";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { PolicyGate } from "./components/PolicyGate";
import { Shell } from "./components/Shell";
import type { NavId } from "./components/Shell";
import { RESOURCE_KEYS, useResource } from "./data/resources";
import type { ResourceKey } from "./data/resources";
import { Audit } from "./screens/Audit";
import { Findings } from "./screens/Findings";
import { Gates } from "./screens/Gates";
import { NewScan } from "./screens/NewScan";
import { Report } from "./screens/Report";

const NO_ENGAGEMENT = "no engagement loaded";

type Versions = Record<ResourceKey, number>;

const INITIAL_VERSIONS = Object.fromEntries(RESOURCE_KEYS.map((k) => [k, 0])) as Versions;

/** Topbar status text; anything but a named engagement is the neutral fallback.
 *  Refetches whenever `version` changes (e.g. after a new scan is created). While a refetch is in
 *  flight the last known text stays, so the chip does not flicker. */
function useEngagementStatus(version: number): string {
  const res = useResource("engagement", version);
  const last = useRef(NO_ENGAGEMENT);
  if (res.status === "ready") {
    const name = typeof res.data?.name === "string" ? res.data.name.trim() : "";
    last.current = name ? `engagement: ${name}` : NO_ENGAGEMENT;
  } else if (res.status === "error") {
    last.current = NO_ENGAGEMENT;
  }
  return last.current;
}

export default function App() {
  const [active, setActive] = useState<NavId>("overview");
  // One version counter per shared resource (see data/resources.ts). Bumping a key makes every
  // reader of it refetch: a recorded gate decision bumps gates + audit, a created scan bumps all
  // the data the new engagement affects.
  const [versions, setVersions] = useState<Versions>(INITIAL_VERSIONS);
  const bump = useCallback((...keys: ResourceKey[]) => {
    setVersions((v) => {
      const next = { ...v };
      for (const k of keys) next[k] += 1;
      return next;
    });
  }, []);
  const status = useEngagementStatus(versions.engagement);

  const shell = { active, onNavigate: setActive, status };

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
            <Findings />
          </ErrorBoundary>
        </Shell>
      );
    case "gates":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="gates">
            <Gates />
          </ErrorBoundary>
        </Shell>
      );
    case "report":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="report">
            <Report />
          </ErrorBoundary>
        </Shell>
      );
    case "audit":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="audit">
            <Audit />
          </ErrorBoundary>
        </Shell>
      );
    default:
      return (
        <Shell
          {...shell}
          aside={
            <>
              <ErrorBoundary key="overview-gates">
                <Gates onDecided={() => bump("gates", "audit")} />
              </ErrorBoundary>
              <ErrorBoundary key="overview-audit">
                <Audit key={versions.audit} />
              </ErrorBoundary>
            </>
          }
        >
          <ErrorBoundary key="overview-gate">
            <PolicyGate />
          </ErrorBoundary>
          <ErrorBoundary key="overview-findings">
            <Findings />
          </ErrorBoundary>
        </Shell>
      );
  }
}
