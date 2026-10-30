import { AuditEntryRow } from "../components/AuditEntryRow";
import { useStaleResource } from "../data/resources";

export interface AuditProps {
  /** Bump to refetch; the previous entries stay on screen until the new ones arrive. */
  version?: number;
}

export function Audit({ version = 0 }: AuditProps = {}) {
  const res = useStaleResource("audit", version);

  if (res.status === "loading") {
    return (
      <section className="panel glass" role="status">
        <div className="phead">
          <span className="ptitle">Loading audit log…</span>
        </div>
      </section>
    );
  }

  if (res.status === "error") {
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load the audit log</span>
          <span className="count">check that the Ascent backend is running</span>
        </div>
      </section>
    );
  }

  const { entries, chain_ok } = res.data;

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
        <div className="feed feed--page">
          {entries.map((e, i) => (
            <AuditEntryRow key={e.entry_hash ?? i} entry={e} />
          ))}
        </div>
      )}
    </section>
  );
}
