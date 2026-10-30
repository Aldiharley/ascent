import type { ReactNode } from "react";
import type { GateDecisionKind, GateEntryView, Severity } from "../api";
import { useStaleResource } from "../data/resources";
import { ErrorState } from "./ErrorState";
import { IconBadge } from "./IconBadge";
import type { BadgeTone } from "./IconBadge";
import {
  IconAlertCircle,
  IconEllipsis,
  IconInfo,
  IconLock,
  IconShieldDots,
  IconTick,
  IconX,
} from "./icons";
import { SeverityChip } from "./SeverityChip";
import { Skeleton } from "./Skeleton";
import { VerdictPill } from "./VerdictPill";

// Everything below is keyed by the decision enum: the headline, tint class, badge tone and glyph are
// never taken from API text. An unrecognised decision fails safe to INCOMPLETE.
const DECISIONS: Record<GateDecisionKind, { headline: string; cls: string; tone: BadgeTone; icon: ReactNode }> = {
  PASS: { headline: "Policy passed", cls: "policy--pass", tone: "teal", icon: <IconTick /> },
  CONDITIONAL: {
    headline: "Passed with warnings",
    cls: "policy--conditional",
    tone: "sand",
    icon: <IconAlertCircle />,
  },
  FAIL: { headline: "Policy failed", cls: "policy--fail", tone: "coral", icon: <IconX /> },
  INCOMPLETE: {
    headline: "Scan incomplete — cannot pass",
    cls: "policy--incomplete",
    tone: "bluegrey",
    icon: <IconEllipsis />,
  },
};

export interface PolicyGateProps {
  /** Bump to refetch; the previous verdict stays on screen until the new one arrives. */
  version?: number;
}

/** Read-only view of out/gate.json. It never evaluates a policy or starts a run. */
export function PolicyGate({ version = 0 }: PolicyGateProps = {}) {
  const res = useStaleResource("gate", version);

  if (res.status === "loading") {
    return (
      <section className="card policy" role="status">
        <div className="skeleton-stack">
          <Skeleton h={160} r={20} />
        </div>
        <p className="loading-caption">Loading policy gate…</p>
      </section>
    );
  }
  if (res.status === "error") {
    return (
      <section className="card policy">
        <ErrorState title="Could not load the policy gate" onRetry={res.retry} />
      </section>
    );
  }

  const g = res.data;
  if (g === null) {
    return (
      <section className="card policy policy--none" aria-labelledby="policy-gate-title">
        <div className="policy-head">
          <IconBadge tone="bluegrey" size="lg">
            <IconShieldDots />
          </IconBadge>
          <div className="policy-title-col">
            <h2 className="card-title" id="policy-gate-title" tabIndex={-1}>
              Policy gate
            </h2>
          </div>
          <div className="policy-meta-col">
            <VerdictPill decision={null} />
          </div>
        </div>
        <div className="policy-why">
          <IconInfo />
          <span>
            No policy verdict yet. Add <code>--policy ascent-policy.yaml</code> to <code>ascent run</code>, or run{" "}
            <code>ascent gate --policy ascent-policy.yaml</code>, to get a PASS / FAIL verdict and a CI exit code.
          </span>
        </div>
      </section>
    );
  }

  const d = Object.hasOwn(DECISIONS, g.decision) ? DECISIONS[g.decision] : DECISIONS.INCOMPLETE;
  const shown: GateEntryView[] = (g.failed.length > 0 ? g.failed : g.warned).slice(0, 5);
  return (
    <section className={`card policy ${d.cls}`} aria-labelledby="policy-gate-title">
      <div className="policy-head">
        <IconBadge tone={d.tone} size="lg">
          {d.icon}
        </IconBadge>
        <div className="policy-title-col">
          <h2 className="card-title" id="policy-gate-title" tabIndex={-1}>
            Policy gate
          </h2>
          <p className="policy-headline">{d.headline}</p>
        </div>
        <div className="policy-meta-col">
          <VerdictPill decision={g.decision} />
          <span className="tag">exit {g.exit_code}</span>
          <span className="policy-meta">
            policy {g.policy.name} · {g.policy.hash.slice(0, 12)}
          </span>
        </div>
      </div>

      <div className="stat-row">
        <div className="stat">
          <b>{g.counts.failed}</b> failing
        </div>
        <div className="stat">
          <b>{g.counts.warned}</b> warnings
        </div>
        <div className="stat">
          <b>{g.counts.demoted_fp}</b> demoted likely-FP
        </div>
        <div className="stat">
          <b>{g.counts.evaluated}</b> evaluated
        </div>
      </div>

      {g.decision === "INCOMPLETE" && (
        <div className="policy-why">
          <IconInfo />
          <span>
            {g.dry_run ? "This was a dry run: no scanners ran. " : ""}
            {g.failed_tools && g.failed_tools.length > 0 ? `Scanners that failed: ${g.failed_tools.join(", ")}. ` : ""}
            {g.skipped_tools && g.skipped_tools.length > 0 ? `Analysers not installed: ${g.skipped_tools.join(", ")}. ` : ""}
            An incomplete scan never passes the gate.
          </span>
        </div>
      )}

      {shown.length > 0 && (
        <ul className="policy-list" role="list">
          {shown.map((e) => (
            <li key={e.fingerprint}>
              <SeverityChip severity={e.severity as Severity} />
              <span className="policy-title">{e.title}</span>
              <span className="loc">{e.locus}</span>
              <span className="policy-reason">{e.reason}</span>
            </li>
          ))}
        </ul>
      )}

      <p className="policy-note">
        <IconLock size={16} /> Read-only verdict from out/gate.json{g.evaluated_at ? `, evaluated ${g.evaluated_at}` : ""}. It
        is chained into the audit log.
      </p>
    </section>
  );
}
