import { useEffect, useState } from "react";
import { getEngagement } from "./api";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Shell } from "./components/Shell";
import type { NavId } from "./components/Shell";
import { Audit } from "./screens/Audit";
import { Findings } from "./screens/Findings";
import { Gates } from "./screens/Gates";
import { NewScan } from "./screens/NewScan";
import { Report } from "./screens/Report";

const NO_ENGAGEMENT = "no engagement loaded";

/** Topbar status text; anything but a named engagement is the neutral fallback.
 *  Refetches whenever `version` changes (e.g. after a new scan is created). */
function useEngagementStatus(version: number): string {
  const [status, setStatus] = useState(NO_ENGAGEMENT);
  useEffect(() => {
    let live = true;
    getEngagement().then(
      (eng) => {
        const name = typeof eng?.name === "string" ? eng.name.trim() : "";
        if (live) setStatus(name ? `engagement: ${name}` : NO_ENGAGEMENT);
      },
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [version]);
  return status;
}

export default function App() {
  const [active, setActive] = useState<NavId>("overview");
  // Bumped when a gate decision is recorded so the Overview audit feed refetches.
  const [auditVersion, setAuditVersion] = useState(0);
  // Bumped when a new scan is created so the topbar engagement name refetches.
  const [engVersion, setEngVersion] = useState(0);
  const status = useEngagementStatus(engVersion);

  const shell = { active, onNavigate: setActive, status };

  switch (active) {
    case "newscan":
      return (
        <Shell {...shell}>
          <ErrorBoundary key="newscan">
            <NewScan onCreated={() => setEngVersion((v) => v + 1)} />
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
                <Gates onDecided={() => setAuditVersion((v) => v + 1)} />
              </ErrorBoundary>
              <ErrorBoundary key="overview-audit">
                <Audit key={auditVersion} />
              </ErrorBoundary>
            </>
          }
        >
          <ErrorBoundary key="overview-findings">
            <Findings />
          </ErrorBoundary>
        </Shell>
      );
  }
}
