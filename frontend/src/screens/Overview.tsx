import type { Verdict } from "../api";
import { DonutCard } from "../components/DonutCard";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { OverviewHero } from "../components/OverviewHero";
import type { HeroEngagement, HeroSummary } from "../components/OverviewHero";
import { PolicyGate } from "../components/PolicyGate";
import type { NavId } from "../components/Shell";
import { SeverityBarChart } from "../components/SeverityBarChart";
import { verdictCounts } from "../data/findingStats";
import { useStaleResource } from "../data/resources";
import type { Resource, ResourceKey, ResourceMap } from "../data/resources";
import { Gates } from "./Gates";
import { ChartSlot, KpiRow, RecentAuditCard, ReportBanner, TopFindingsCard } from "./overviewCards";

export interface OverviewProps {
  /** Per-resource version counters from `App`; a bump swaps that data in place. */
  versions: Record<ResourceKey, number>;
  /** The top-bar search text: "Top findings" filters by it. */
  query: string;
  onClearQuery: () => void;
  onNavigate: (id: NavId) => void;
  /** A KPI tile was pressed: open Findings narrowed to this verdict ("ALL" = unfiltered). */
  onOpenFindings: (filter: Verdict | "ALL") => void;
  /** A gate decision was recorded here, so `App` refreshes the bell, the badge and the audit log. */
  onDecided: () => void;
}

function heroEngagement(res: Resource<ResourceMap["engagement"]>): HeroEngagement {
  if (res.status === "loading") return { kind: "loading" };
  if (res.status === "error") return { kind: "error" };
  const name = typeof res.data?.name === "string" ? res.data.name.trim() : "";
  return name ? { kind: "named", name } : { kind: "none" };
}

/**
 * The Overview screen (spec 3.1): a 12-column grid of cards. Each card sits in its own error
 * boundary so one malformed payload fails one card. Findings are read once here and handed to the
 * KPI row, both charts and the "Top findings" list, so a Retry refreshes all of them together.
 */
export function Overview({ versions, query, onClearQuery, onNavigate, onOpenFindings, onDecided }: OverviewProps) {
  const findings = useStaleResource("findings", versions.findings);
  const gates = useStaleResource("gates", versions.gates);
  const gate = useStaleResource("gate", versions.gate);
  const engagement = useStaleResource("engagement", versions.engagement);

  const summary: HeroSummary = {
    needsReview: findings.status === "ready" ? verdictCounts(findings.data).hu : undefined,
    pending: gates.status === "ready" ? gates.data.length : undefined,
    decision: gate.status === "ready" ? (gate.data ? gate.data.decision : null) : undefined,
  };

  return (
    <div className="grid">
      <div className="col-12">
        <ErrorBoundary>
          <OverviewHero engagement={heroEngagement(engagement)} summary={summary} onNavigate={onNavigate} />
        </ErrorBoundary>
      </div>

      <div className="col-12">
        <ErrorBoundary>
          <KpiRow res={findings} onOpen={onOpenFindings} />
        </ErrorBoundary>
      </div>

      <div className="col-12">
        <ErrorBoundary>
          <PolicyGate version={versions.gate} />
        </ErrorBoundary>
      </div>

      <div className="col-7">
        <ErrorBoundary>
          <ChartSlot res={findings}>{(items) => <SeverityBarChart items={items} />}</ChartSlot>
        </ErrorBoundary>
      </div>
      <div className="col-5">
        <ErrorBoundary>
          <ChartSlot res={findings}>{(items) => <DonutCard items={items} />}</ChartSlot>
        </ErrorBoundary>
      </div>

      <div className="col-4">
        <ErrorBoundary>
          <TopFindingsCard
            res={findings}
            query={query}
            onClearQuery={onClearQuery}
            onSeeAll={() => onNavigate("findings")}
          />
        </ErrorBoundary>
      </div>
      <div className="col-4">
        <ErrorBoundary>
          <Gates variant="compact" version={versions.gates} onDecided={onDecided} onSeeAll={() => onNavigate("gates")} />
        </ErrorBoundary>
      </div>
      <div className="col-4 col-last">
        <ErrorBoundary>
          <RecentAuditCard version={versions.audit} onSeeAll={() => onNavigate("audit")} />
        </ErrorBoundary>
      </div>

      <div className="col-12">
        <ErrorBoundary>
          <ReportBanner
            version={versions.report}
            onOpenReport={() => onNavigate("report")}
            onNewScan={() => onNavigate("newscan")}
          />
        </ErrorBoundary>
      </div>
    </div>
  );
}
