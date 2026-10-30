import { useState } from "react";
import { AuditEntryRow, kindOf } from "../components/AuditEntryRow";
import type { AuditKind } from "../components/AuditEntryRow";
import { EmptyState } from "../components/EmptyState";
import { IconBadge } from "../components/IconBadge";
import { IconChain } from "../components/icons";
import { SegmentedControl } from "../components/SegmentedControl";
import { ErrorCard, LoadingCard } from "../components/StateCards";
import { useStaleResource } from "../data/resources";

export interface AuditProps {
  /** Bump to refetch; the previous entries stay on screen until the new ones arrive. */
  version?: number;
}

type TypeFilter = "all" | AuditKind;

// Filter labels name the kind of record, not the row titles ("Triage", "Human decision", "Policy
// gate", "Verification run"), so a text query for a row title matches exactly one place.
const FILTERS: { value: AuditKind; label: string }[] = [
  { value: "triage", label: "Verdicts" },
  { value: "decision", label: "Decisions" },
  { value: "policy", label: "Policy" },
  { value: "run", label: "Runs" },
];

export function Audit({ version = 0 }: AuditProps = {}) {
  const res = useStaleResource("audit", version);
  const [filter, setFilter] = useState<TypeFilter>("all");

  if (res.status === "loading") return <LoadingCard caption="Loading audit log…" rows={5} />;
  if (res.status === "error") return <ErrorCard title="Could not load the audit log" onRetry={res.retry} />;

  const { entries, chain_ok } = res.data;
  const kinds = entries.map(kindOf);
  const counts: Record<AuditKind, number> = { triage: 0, decision: 0, policy: 0, run: 0 };
  for (const k of kinds) counts[k] += 1;
  // A refresh can empty the selected type; fall back to All rather than show an empty list.
  const active: TypeFilter = filter !== "all" && counts[filter] > 0 ? filter : "all";
  const shown = entries
    .map((entry, i) => ({ entry, i }))
    .filter(({ i }) => active === "all" || kinds[i] === active);

  return (
    <div className="stack">
      <section className="card chain-card">
        <IconBadge tone={chain_ok ? "teal" : "coral"} size="lg">
          <IconChain />
        </IconBadge>
        {chain_ok ? (
          <div className="chain chain-ok" role="status">
            Hash chain OK
          </div>
        ) : (
          <div className="chain chain-fail" role="alert">
            Hash chain FAIL: log may have been tampered with
          </div>
        )}
        <span className="chain-count">{entries.length === 1 ? "1 entry" : `${entries.length} entries`}</span>
      </section>

      <section className="card" aria-labelledby="audit-timeline-title">
        <div className="card-head">
          <h2 className="card-title" id="audit-timeline-title">
            Timeline
          </h2>
          {entries.length > 0 && (
            <SegmentedControl<TypeFilter>
              label="Show"
              value={active}
              onChange={setFilter}
              options={[
                { value: "all", label: `All ${entries.length}` },
                ...FILTERS.map((f) => ({
                  value: f.value,
                  label: `${f.label} ${counts[f.value]}`,
                  disabled: counts[f.value] === 0,
                })),
              ]}
            />
          )}
        </div>
        {entries.length === 0 ? (
          <EmptyState size={120} title="No audit entries yet" />
        ) : (
          // Scrollable, so it must be reachable by keyboard.
          <div className="feed feed--page" role="region" aria-label="Audit timeline" tabIndex={0}>
            {shown.map(({ entry, i }) => (
              <AuditEntryRow key={entry.entry_hash ?? i} entry={entry} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
