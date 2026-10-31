import { useId } from "react";
import type { TriageItem, Verdict } from "../api";
import { Button } from "../components/Button";
import { ConfidenceBar } from "../components/ConfidenceBar";
import { EmptyState } from "../components/EmptyState";
import type { NavId } from "../components/Shell";
import { SeverityChip, SeverityStripe } from "../components/SeverityChip";
import { ErrorCard, LoadingCard } from "../components/StateCards";
import { VerdictChip } from "../components/VerdictChip";
import { VerdictTiles } from "../components/VerdictTiles";
import type { VerdictFilter } from "../components/VerdictTiles";
import { classifyVerdict, matchesVerdict } from "../data/findingStats";
import { useStaleResource } from "../data/resources";
import { findingLocus, matchFinding } from "../data/search";

const VERDICT_RANK: Record<Verdict, number> = {
  TRUE_POSITIVE: 0,
  ABSTAIN: 1,
  LIKELY_FALSE_POSITIVE: 2,
};

/** True positives first, then needs-human, then noise; higher confidence first. */
export function orderFindings(items: readonly TriageItem[]): TriageItem[] {
  // The same classification as the tiles and the filter, so an unknown verdict sorts as needs-human.
  const rank = (it: TriageItem) => VERDICT_RANK[classifyVerdict(it.verdict)];
  return [...items].sort((a, b) => rank(a) - rank(b) || (b.confidence ?? 0) - (a.confidence ?? 0));
}

export interface FindingsProps {
  /** Bump to refetch; the previous rows stay on screen until the new ones arrive. */
  version?: number;
  /** Which verdict the table is narrowed to. Anything but one of the three verdicts means "ALL". */
  verdictFilter?: VerdictFilter;
  /**
   * Makes the tiles filter toggles; called with the new filter ("ALL" when the pressed tile is
   * pressed again). Without it the tiles are plain statistics: no inert buttons.
   */
  onVerdictFilterChange?: (filter: VerdictFilter) => void;
  /** The top-bar search text; every term must match a finding (see `matchFinding`). */
  query?: string;
  /** Resets the verdict filter and the search text. Without it no "Clear filters" button is drawn. */
  onClearFilters?: () => void;
  /** Lets the empty state offer "Define a new scan". */
  onNavigate?: (id: NavId) => void;
}

export function Findings({
  version = 0,
  verdictFilter = "ALL",
  onVerdictFilterChange,
  query = "",
  onClearFilters,
  onNavigate,
}: FindingsProps = {}) {
  const state = useStaleResource("findings", version);
  const titleId = useId();

  if (state.status === "loading") return <LoadingCard caption="Loading findings…" />;
  if (state.status === "error") {
    return (
      <ErrorCard title="Could not load findings" detail="Check that the Ascent backend is running." onRetry={state.retry} />
    );
  }

  const items = orderFindings(state.data);
  const total = items.length;
  // Only the three verdict values narrow the table; anything else (including inherited keys) is ALL.
  const filter: VerdictFilter = Object.hasOwn(VERDICT_RANK, verdictFilter) ? verdictFilter : "ALL";
  const q = query.trim();
  const rows = items.filter((it) => matchesVerdict(it, filter) && (q === "" || matchFinding(it, q)));
  const filtered = filter !== "ALL" || q !== "";

  const clear = onClearFilters ? (
    <Button variant="text" onClick={onClearFilters}>
      Clear filters
    </Button>
  ) : null;

  return (
    <div className="stack">
      <VerdictTiles
        items={items}
        compact
        filter={filter}
        onSelect={
          onVerdictFilterChange
            ? (target) => onVerdictFilterChange(target === filter ? "ALL" : target)
            : undefined
        }
      />

      <section className="card" aria-labelledby={titleId}>
        <div className="card-head">
          <h2 className="card-title" id={titleId}>
            Findings
          </h2>
          <span className="count">{total} triaged</span>
          {filtered && total > 0 ? <span className="count">{rows.length} shown</span> : null}
          {/* With no matching rows the message below carries the one reset, so it is not repeated here. */}
          {filtered && rows.length > 0 ? clear : null}
        </div>
        {total === 0 ? (
          <EmptyState
            size={160}
            title="No findings yet"
            action={
              onNavigate ? (
                <Button variant="primary" onClick={() => onNavigate("newscan")}>
                  Define a new scan
                </Button>
              ) : undefined
            }
          >
            Define a scan, run it, and triaged findings land here.
          </EmptyState>
        ) : rows.length === 0 ? (
          <EmptyState title="No findings match these filters" action={clear} />
        ) : (
          <div className="tbl">
            <table>
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Verdict</th>
                  <th>Location</th>
                  <th>Mapping</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item, i) => {
                  const f = item.finding;
                  return (
                    <tr key={f.id ?? i}>
                      <td>
                        <SeverityStripe severity={f.severity} />
                        <div className="fname">{f.title}</div>
                        <div className="frule">{f.rule_id}</div>
                      </td>
                      <td data-label="Severity">
                        <SeverityChip severity={f.severity} />
                      </td>
                      <td data-label="Confidence">
                        <ConfidenceBar confidence={item.confidence} verdict={item.verdict} />
                      </td>
                      <td data-label="Verdict">
                        <VerdictChip verdict={item.verdict} />
                      </td>
                      <td data-label="Location">
                        <span className="loc">{findingLocus(item) || "—"}</span>
                      </td>
                      <td data-label="Mapping">
                        <div className="tags">
                          {f.cwe ? <span className="tag">{f.cwe}</span> : null}
                          {f.category ? <span className="tag">{f.category}</span> : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
