import { useEffect, useState } from "react";
import { getAudit } from "../api";
import type { AuditEntry, AuditLog } from "../api";

type State =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; log: AuditLog };

const HASH_CHARS = 12;

function shortHash(h: string | undefined): string {
  return h ? h.slice(0, HASH_CHARS) : "";
}

function EntryRow({ entry }: { entry: AuditEntry }) {
  const hash = shortHash(entry.entry_hash);
  if (entry.type === "gate_decision") {
    return (
      <div className="ev">
        <span className="tick human" aria-hidden="true" />
        <div className="m">
          <b>Human decision</b> · gate {entry.gate_id ?? "?"} → {entry.decision ?? "?"}
          <div className="h">{entry.ts ?? ""}</div>
          {hash ? <div className="h">{hash}</div> : null}
        </div>
      </div>
    );
  }
  const conf = typeof entry.confidence === "number" ? ` (${entry.confidence.toFixed(2)})` : "";
  return (
    <div className="ev">
      <span className="tick" aria-hidden="true" />
      <div className="m">
        <b>Triage</b> · finding {entry.finding_id ?? "?"} → {entry.verdict ?? "?"}
        {conf}
        <div className="h">{entry.ts ?? ""}</div>
        {hash ? <div className="h">{hash}</div> : null}
      </div>
    </div>
  );
}

export function Audit() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let live = true;
    getAudit().then(
      (log) => live && setState({ status: "ready", log }),
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
          <span className="ptitle">Loading audit log…</span>
        </div>
      </section>
    );
  }

  if (state.status === "error") {
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load the audit log</span>
          <span className="count">check that the Ascent backend is running</span>
        </div>
      </section>
    );
  }

  const { entries, chain_ok } = state.log;

  return (
    <section className="audit glass">
      <h3>Audit log</h3>
      {chain_ok ? (
        <div className="chain chain-ok" role="status">
          Hash chain OK
        </div>
      ) : (
        <div className="chain chain-fail" role="alert">
          Hash chain FAIL: log may have been tampered with
        </div>
      )}
      {entries.length === 0 ? (
        <div className="note">No audit entries yet</div>
      ) : (
        <div className="feed">
          {entries.map((e, i) => (
            <EntryRow key={e.entry_hash ?? i} entry={e} />
          ))}
        </div>
      )}
    </section>
  );
}
