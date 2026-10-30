import type { TriageItem, Verdict } from "../api";
import { Button } from "../components/Button";
import { ConfidenceBar } from "../components/ConfidenceBar";
import { Kpi } from "../components/Kpi";
import { SeverityChip, SeverityStripe } from "../components/SeverityChip";
import { VerdictChip } from "../components/VerdictChip";
import { useStaleResource } from "../data/resources";
import { findingLocus } from "../data/search";

const VERDICT_RANK: Record<Verdict, number> = {
  TRUE_POSITIVE: 0,
  ABSTAIN: 1,
  LIKELY_FALSE_POSITIVE: 2,
};

function rank(v: Verdict): number {
  return Object.hasOwn(VERDICT_RANK, v) ? VERDICT_RANK[v] : 1;
}

/** True positives first, then needs-human, then noise; higher confidence first. */
export function orderFindings(items: readonly TriageItem[]): TriageItem[] {
  return [...items].sort(
    (a, b) => rank(a.verdict) - rank(b.verdict) || (b.confidence ?? 0) - (a.confidence ?? 0),
  );
}

function pct(n: number, total: number): number {
  return total === 0 ? 0 : Math.round((n / total) * 100);
}

const VERDICT_LABEL: Record<Verdict, string> = {
  TRUE_POSITIVE: "True positive",
  ABSTAIN: "Needs human",
  LIKELY_FALSE_POSITIVE: "Likely noise",
};

export interface FindingsProps {
  /** Bump to refetch; the previous rows stay on screen until the new ones arrive. */
  version?: number;
  /** Narrow the table to one verdict (the Overview KPI tiles set this). Anything else is "ALL". */
  verdictFilter?: Verdict | "ALL";
  /** Lifts the verdict filter. Without it a narrowed table is labelled but has no button. */
  onClearFilter?: () => void;
}

export function Findings({ version = 0, verdictFilter = "ALL", onClearFilter }: FindingsProps = {}) {
  const state = useStaleResource("findings", version);

  if (state.status === "loading") {
    return (
      <section className="panel glass" role="status">
        <div className="phead">
          <span className="ptitle">Loading findings…</span>
        </div>
      </section>
    );
  }

  if (state.status === "error") {
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load findings</span>
          <span className="count">check that the Ascent backend is running</span>
        </div>
      </section>
    );
  }

  const items = orderFindings(state.data);
  const total = items.length;
  const tp = items.filter((i) => i.verdict === "TRUE_POSITIVE").length;
  const hu = items.filter((i) => i.verdict === "ABSTAIN").length;
  const fp = items.filter((i) => i.verdict === "LIKELY_FALSE_POSITIVE").length;
  // Only the three verdict values narrow the table; anything else (including inherited keys) is ALL.
  const narrow = Object.hasOwn(VERDICT_RANK, verdictFilter) ? (verdictFilter as Verdict) : null;
  const rows = narrow ? items.filter((i) => i.verdict === narrow) : items;

  return (
    <>
      <section className="kpis">
        <Kpi label="Findings" value={total} sub="triaged by Crux" percent={100} ringText={String(total)} color="var(--accent)" />
        <Kpi label="True positive" value={tp} sub="confirmed by triage" percent={pct(tp, total)} ringText={`${pct(tp, total)}%`} color="var(--crit)" />
        <Kpi label="Needs human" value={hu} sub="awaiting your review" percent={pct(hu, total)} ringText={`${pct(hu, total)}%`} color="var(--med)" />
        <Kpi label="Likely noise" value={fp} sub="cut by Crux" percent={pct(fp, total)} ringText={`${pct(fp, total)}%`} color="var(--faint)" />
      </section>

      <section className="panel glass">
        <div className="phead">
          <span className="ptitle">Findings</span>
          <span className="count">{total} triaged</span>
          {narrow ? <span className="count">Showing only: {VERDICT_LABEL[narrow]}</span> : null}
          {narrow && onClearFilter ? (
            <Button variant="text" onClick={onClearFilter}>
              Show all
            </Button>
          ) : null}
        </div>
        {total === 0 ? (
          <div className="phead">
            <span className="sub">No findings yet</span>
          </div>
        ) : rows.length === 0 ? (
          <div className="phead">
            <span className="sub">No findings match this filter</span>
          </div>
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
                      <td>
                        <SeverityChip severity={f.severity} />
                      </td>
                      <td>
                        <ConfidenceBar confidence={item.confidence} verdict={item.verdict} />
                      </td>
                      <td>
                        <VerdictChip verdict={item.verdict} />
                      </td>
                      <td>
                        <span className="loc">{findingLocus(item) || "—"}</span>
                      </td>
                      <td>
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
    </>
  );
}
