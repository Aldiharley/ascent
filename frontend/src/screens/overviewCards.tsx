import type { ReactNode } from "react";
import type { TriageItem, Verdict } from "../api";
import { AuditEntryRow } from "../components/AuditEntryRow";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { IconBadge } from "../components/IconBadge";
import { IconCrosshairCheck, IconDocument, IconFunnelSlash, IconHand, IconRadar } from "../components/icons";
import { KpiTile } from "../components/KpiTile";
import { ListCard } from "../components/ListCard";
import { SeverityChip } from "../components/SeverityChip";
import { Skeleton } from "../components/Skeleton";
import { VerdictChip } from "../components/VerdictChip";
import { percent, scannerCount, verdictCounts } from "../data/findingStats";
import { useStaleResource } from "../data/resources";
import type { Resource } from "../data/resources";
import { matchFinding } from "../data/search";
import { orderFindings } from "./Findings";

const BACKEND_HINT = "check that the Ascent backend is running";

/** Load-failure card: fixed text only (a response body can carry scanned data) and a Retry. */
function ErrorCard({ title, onRetry }: { title: string; onRetry: () => void }) {
  return (
    <section className="card">
      <ErrorState title={title} detail={BACKEND_HINT} onRetry={onRetry} />
    </section>
  );
}

/** Skeleton card: announced as a status, with a visible caption (spec 4.12). */
function LoadingCard({ caption, rows = 3, h = 56 }: { caption: string; rows?: number; h?: number }) {
  return (
    <section className="card list-card" role="status">
      <div className="skeleton-stack">
        <Skeleton h={22} w="45%" />
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} h={h} r={16} />
        ))}
      </div>
      <p className="loading-caption">{caption}</p>
    </section>
  );
}

// ---- KPI row (3.1.2) ----

const SKELETON_TONES = ["teal", "bluegrey", "ice", "lav"] as const;

export function KpiRow({
  res,
  onOpen,
}: {
  res: Resource<TriageItem[]>;
  onOpen: (filter: Verdict | "ALL") => void;
}) {
  if (res.status === "loading") {
    return (
      <div className="kpi-row" role="status">
        <span className="sr-only">Loading findings…</span>
        {SKELETON_TONES.map((tone) => (
          <div key={tone} className={`kpi kpi--${tone}`} aria-hidden="true">
            <Skeleton h={48} w={48} r={16} />
            <Skeleton h={16} w="50%" />
            <Skeleton h={34} w="35%" />
            <Skeleton h={14} w="75%" />
          </div>
        ))}
      </div>
    );
  }
  if (res.status === "error") return <ErrorCard title="Could not load findings" onRetry={res.retry} />;

  const items = res.data;
  const c = verdictCounts(items);
  const scanners = scannerCount(items);
  const sub0 =
    scanners > 0 ? `from ${scanners} ${scanners === 1 ? "scanner" : "scanners"}` : "triaged by Crux";
  return (
    <div className="kpi-row">
      <KpiTile label="Findings" value={c.total} sub={sub0} tone="teal" icon={<IconRadar />} onClick={() => onOpen("ALL")} />
      <KpiTile
        label="True positive"
        value={c.tp}
        sub={`${percent(c.tp, c.total)}% · confirmed by triage`}
        tone="bluegrey"
        icon={<IconCrosshairCheck />}
        onClick={() => onOpen("TRUE_POSITIVE")}
      />
      <KpiTile
        label="Needs human"
        value={c.hu}
        sub={`${percent(c.hu, c.total)}% · awaiting your review`}
        tone="ice"
        icon={<IconHand />}
        onClick={() => onOpen("ABSTAIN")}
      />
      <KpiTile
        label="Likely noise"
        value={c.fp}
        sub={`${percent(c.fp, c.total)}% · cut by Crux`}
        tone="lav"
        icon={<IconFunnelSlash />}
        onClick={() => onOpen("LIKELY_FALSE_POSITIVE")}
      />
    </div>
  );
}

// ---- chart slot: skeleton / error / the chart itself ----

export function ChartSlot({
  res,
  children,
}: {
  res: Resource<TriageItem[]>;
  children: (items: TriageItem[]) => ReactNode;
}) {
  if (res.status === "loading") {
    return (
      <section className="card chart-card" role="status">
        <Skeleton h={22} w="40%" />
        <div className="skeleton-stack">
          <Skeleton h={240} r={20} />
        </div>
        <p className="loading-caption">Loading findings…</p>
      </section>
    );
  }
  if (res.status === "error") return <ErrorCard title="Could not load findings" onRetry={res.retry} />;
  return <>{children(res.data)}</>;
}

// ---- Top findings (3.1.5.1) ----

const TOP_LIMIT = 5;

export function TopFindingsCard({
  res,
  query,
  onClearQuery,
  onSeeAll,
}: {
  res: Resource<TriageItem[]>;
  query: string;
  onClearQuery: () => void;
  onSeeAll: () => void;
}) {
  if (res.status === "loading") return <LoadingCard caption="Loading findings…" />;
  if (res.status === "error") return <ErrorCard title="Could not load findings" onRetry={res.retry} />;

  const q = query.trim();
  const ordered = orderFindings(res.data);
  const matches = q ? ordered.filter((it) => matchFinding(it, q)) : ordered;
  const shown = matches.slice(0, TOP_LIMIT);
  const count = q ? `${matches.length} of ${ordered.length} match` : `${ordered.length} triaged`;

  return (
    <ListCard title="Top findings" count={count} seeAll={{ label: "findings", onClick: onSeeAll }}>
      {ordered.length === 0 ? (
        <EmptyState title="No findings yet" />
      ) : shown.length === 0 ? (
        <EmptyState
          title={`No findings match “${q}”`}
          action={
            <Button variant="text" onClick={onClearQuery}>
              Clear search
            </Button>
          }
        />
      ) : (
        <ul className="list-plain" role="list">
          {shown.map((it, i) => (
            <li className="list-row" key={it.finding.id ?? i}>
              <SeverityChip severity={it.finding.severity} />
              <div className="row-main">
                <div className="row-title" title={it.finding.title}>
                  {it.finding.title}
                </div>
                <div className="row-meta">{it.finding.rule_id}</div>
              </div>
              <VerdictChip verdict={it.verdict} />
            </li>
          ))}
        </ul>
      )}
    </ListCard>
  );
}

// ---- Recent audit (3.1.5.3) ----

const AUDIT_LIMIT = 5;

export function RecentAuditCard({ version, onSeeAll }: { version: number; onSeeAll: () => void }) {
  const res = useStaleResource("audit", version);
  if (res.status === "loading") return <LoadingCard caption="Loading audit log…" />;
  if (res.status === "error") return <ErrorCard title="Could not load the audit log" onRetry={res.retry} />;

  const { entries, chain_ok } = res.data;
  const recent = entries.slice(-AUDIT_LIMIT).reverse();
  return (
    <ListCard
      title="Recent audit"
      seeAll={{ label: "audit entries", onClick: onSeeAll }}
      headExtra={
        chain_ok ? (
          <div className="chain chain-ok" role="status">
            Hash chain OK
          </div>
        ) : (
          <div className="chain chain-fail" role="alert">
            Hash chain FAIL: log may have been tampered with
          </div>
        )
      }
    >
      {recent.length === 0 ? (
        <EmptyState title="No audit entries yet" />
      ) : (
        <div className="feed feed--compact">
          {recent.map((e, i) => (
            <AuditEntryRow key={e.entry_hash ?? i} entry={e} density="compact" />
          ))}
        </div>
      )}
    </ListCard>
  );
}

// ---- Report banner (3.1.6) ----

export function ReportBanner({
  version,
  onOpenReport,
  onNewScan,
}: {
  version: number;
  onOpenReport: () => void;
  onNewScan: () => void;
}) {
  const res = useStaleResource("report", version);
  // A failed report fetch is the Report screen's problem: the banner simply is not drawn.
  if (res.status === "error") return null;
  if (res.status === "loading") {
    return (
      <section className="banner banner--loading" role="status">
        <Skeleton h={28} w="40%" />
        <span className="sr-only">Loading report…</span>
      </section>
    );
  }
  const has = res.data.trim() !== "";
  return (
    <section className="banner" aria-label="Report">
      <IconBadge tone="sand" size="lg">
        <IconDocument />
      </IconBadge>
      <div className="banner-text">
        {has ? (
          <>
            <h2 className="banner-title">Your report is ready</h2>
            <p className="banner-sub">Findings, the policy verdict and DAST coverage in one markdown report.</p>
          </>
        ) : (
          <>
            <h2 className="banner-title">No report yet</h2>
            <p className="banner-sub">
              Run <code>ascent run</code> on a defined scope and the report lands here.
            </p>
          </>
        )}
      </div>
      {has ? (
        <Button variant="primary" onClick={onOpenReport}>
          Open report
        </Button>
      ) : (
        <Button variant="primary" onClick={onNewScan}>
          Define a new scan
        </Button>
      )}
    </section>
  );
}
