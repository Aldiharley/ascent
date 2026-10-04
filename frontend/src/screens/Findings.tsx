import { useEffect, useState } from "react";
import { getFindings } from "../api";
import type { TriageItem, Verdict } from "../api";
import { ConfidenceBar } from "../components/ConfidenceBar";
import { Kpi } from "../components/Kpi";
import { SeverityBadge, SeverityStripe } from "../components/SeverityStripe";
import { VerdictChip } from "../components/VerdictChip";

const VERDICT_RANK: Record<Verdict, number> = {
  TRUE_POSITIVE: 0,
  ABSTAIN: 1,
  LIKELY_FALSE_POSITIVE: 2,
};

function rank(v: Verdict): number {
  return VERDICT_RANK[v] ?? 1;
}

/** True positives first, then needs-human, then noise; higher confidence first. */
function order(items: TriageItem[]): TriageItem[] {
  return [...items].sort(
    (a, b) => rank(a.verdict) - rank(b.verdict) || (b.confidence ?? 0) - (a.confidence ?? 0),
  );
}

function locus(item: TriageItem): string {
  const { url, file, line } = item.finding;
  if (url) return url;
  if (file) return line ? `${file}:${line}` : file;
  return "—";
}

function pct(n: number, total: number): number {
  return total === 0 ? 0 : Math.round((n / total) * 100);
}

type State =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; items: TriageItem[] };

export function Findings() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let live = true;
    getFindings().then(
      (items) => live && setState({ status: "ready", items }),
      () => live && setState({ status: "error" }),
    );
    return () => {
      live = false;
    };
  }, []);

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

  const items = order(state.items);
  const total = items.length;
  const tp = items.filter((i) => i.verdict === "TRUE_POSITIVE").length;
  const hu = items.filter((i) => i.verdict === "ABSTAIN").length;
  const fp = items.filter((i) => i.verdict === "LIKELY_FALSE_POSITIVE").length;

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
        </div>
        {total === 0 ? (
          <div className="phead">
            <span className="sub">No findings yet</span>
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
                {items.map((item, i) => {
                  const f = item.finding;
                  return (
                    <tr key={f.id ?? i}>
                      <td>
                        <SeverityStripe severity={f.severity} />
                        <div className="fname">{f.title}</div>
                        <div className="frule">{f.rule_id}</div>
                      </td>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td>
                        <ConfidenceBar confidence={item.confidence} verdict={item.verdict} />
                      </td>
                      <td>
                        <VerdictChip verdict={item.verdict} />
                      </td>
                      <td>
                        <span className="loc">{locus(item)}</span>
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
