import { useEffect, useState } from "react";
import { getGate } from "../api";
import type { GateDecisionKind, GateReport } from "../api";

type State = { status: "loading" } | { status: "error" } | { status: "ready"; gate: GateReport | null };

const LABEL: Record<GateDecisionKind, string> = {
  PASS: "Policy passed",
  CONDITIONAL: "Passed with warnings",
  FAIL: "Policy failed",
  INCOMPLETE: "Scan incomplete — cannot pass",
};

/** Read-only view of out/gate.json. It never evaluates a policy or starts a run. */
export function PolicyGate() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let live = true;
    getGate().then(
      (gate) => live && setState({ status: "ready", gate }),
      () => live && setState({ status: "error" }),
    );
    return () => {
      live = false;
    };
  }, []);

  if (state.status === "loading") {
    return (
      <section className="panel glass policy" role="status">
        <div className="phead">
          <span className="ptitle">Loading policy gate…</span>
        </div>
      </section>
    );
  }
  if (state.status === "error") {
    return (
      <section className="panel glass policy" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load the policy gate</span>
        </div>
      </section>
    );
  }
  const g = state.gate;
  if (g === null) {
    return (
      <section className="panel glass policy">
        <div className="phead">
          <span className="ptitle" id="policy-gate-title" tabIndex={-1}>
            Policy gate
          </span>
          <span className="verdict-pill v-none">NOT EVALUATED</span>
        </div>
        <div className="policy-body">
          <div className="note" style={{ textAlign: "left" }}>
            No policy verdict yet. Add <code>--policy ascent-policy.yaml</code> to <code>ascent run</code>, or run{" "}
            <code>ascent gate --policy ascent-policy.yaml</code>, to get a PASS / FAIL verdict and a CI exit code.
          </div>
        </div>
      </section>
    );
  }
  const shown = g.failed.length > 0 ? g.failed : g.warned;
  return (
    <section className={`panel glass policy policy-${g.decision.toLowerCase()}`}>
      <div className="phead">
        <span className="ptitle" id="policy-gate-title" tabIndex={-1}>
          Policy gate
        </span>
        <span className={`verdict-pill v-${g.decision.toLowerCase()}`}>{g.decision}</span>
        <span className="count">exit {g.exit_code}</span>
        <span className="policy-meta">
          policy {g.policy.name} · {g.policy.hash.slice(0, 12)}
        </span>
      </div>
      <div className="policy-body">
        <div className="policy-headline">{LABEL[g.decision]}</div>
        <div className="policy-counts">
          <span><b>{g.counts.failed}</b> failing</span>
          <span><b>{g.counts.warned}</b> warnings</span>
          <span><b>{g.counts.demoted_fp}</b> demoted likely-FP</span>
          <span><b>{g.counts.evaluated}</b> evaluated</span>
        </div>
        {g.decision === "INCOMPLETE" && (
          <div className="policy-why">
            {g.dry_run ? "This was a dry run: no scanners ran. " : ""}
            {g.failed_tools && g.failed_tools.length > 0 ? `Scanners that failed: ${g.failed_tools.join(", ")}. ` : ""}
            {g.skipped_tools && g.skipped_tools.length > 0 ? `Analysers not installed: ${g.skipped_tools.join(", ")}. ` : ""}
            An incomplete scan never passes the gate.
          </div>
        )}
        {shown.length > 0 && (
          <ul className="policy-list">
            {shown.slice(0, 5).map((e) => (
              <li key={e.fingerprint}>
                <span className={`sev ${sevClass(e.severity)}`}>{e.severity}</span>
                <span className="policy-title">{e.title}</span>
                <span className="loc">{e.locus}</span>
                <span className="policy-reason">{e.reason}</span>
              </li>
            ))}
          </ul>
        )}
        <div className="note" style={{ textAlign: "left" }}>
          Read-only verdict from out/gate.json{g.evaluated_at ? `, evaluated ${g.evaluated_at}` : ""}. It is chained into the audit log.
        </div>
      </div>
    </section>
  );
}

function sevClass(sev: string): string {
  switch (sev) {
    case "CRITICAL":
      return "crit";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "med";
    default:
      return "low";
  }
}
