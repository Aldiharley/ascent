import { useEffect, useState } from "react";
import { getEngagement } from "./api";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Shell } from "./components/Shell";
import type { NavId } from "./components/Shell";
import { Audit } from "./screens/Audit";
import { Findings } from "./screens/Findings";
import { Gates } from "./screens/Gates";
import { Report } from "./screens/Report";

const NO_ENGAGEMENT = "no engagement loaded";

/** Topbar status text; anything but a named engagement is the neutral fallback. */
function useEngagementStatus(): string {
  const [status, setStatus] = useState(NO_ENGAGEMENT);
  useEffect(() => {
    let live = true;
    getEngagement().then(
      (eng) => {
        const name = typeof eng?.name === "string" ? eng.name.trim() : "";
        if (live && name) setStatus(`engagement: ${name}`);
      },
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, []);
  return status;
}

export default function App() {
  const [active, setActive] = useState<NavId>("overview");
  // Bumped when a gate decision is recorded so the Overview audit feed refetches.
  const [auditVersion, setAuditVersion] = useState(0);
  const status = useEngagementStatus();

  const shell = { active, onNavigate: setActive, status };

  switch (active) {
    case "findings":
      return (
        <Shell {...shell}>
          <ErrorBoundary>
            <Findings />
          </ErrorBoundary>
        </Shell>
      );
    case "gates":
      return (
        <Shell {...shell}>
          <ErrorBoundary>
            <Gates />
          </ErrorBoundary>
        </Shell>
      );
    case "report":
      return (
        <Shell {...shell}>
          <ErrorBoundary>
            <Report />
          </ErrorBoundary>
        </Shell>
      );
    case "audit":
      return (
        <Shell {...shell}>
          <ErrorBoundary>
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
              <ErrorBoundary>
                <Gates onDecided={() => setAuditVersion((v) => v + 1)} />
              </ErrorBoundary>
              <ErrorBoundary>
                <Audit key={auditVersion} />
              </ErrorBoundary>
            </>
          }
        >
          <ErrorBoundary>
            <Findings />
          </ErrorBoundary>
        </Shell>
      );
  }
}
