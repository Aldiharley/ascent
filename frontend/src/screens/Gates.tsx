import { useEffect, useRef, useState } from "react";
import { GateDecisionError, decideGate } from "../api";
import type { Gate, GateDecision } from "../api";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { GateCard } from "../components/GateCard";
import { ListCard } from "../components/ListCard";
import { Skeleton } from "../components/Skeleton";
import { ToastStack, useToasts } from "../components/Toast";
import { useStaleResource } from "../data/resources";

export interface GatesProps {
  /** Called after a decision is recorded (or found already recorded), so sibling views can refresh. */
  onDecided?: () => void;
  /** `page` is the Approval gates screen; `compact` is the Overview "Approval required" list card. */
  variant?: "page" | "compact";
  /** Bump to refetch the list; the cards and toasts stay on screen until the new list arrives. */
  version?: number;
  /** The compact card's "See all" and "N more" controls. Omitted: no such controls are drawn. */
  onSeeAll?: () => void;
}

/** How many gates the compact card shows before it links to the rest. */
const COMPACT_LIMIT = 3;

export function Gates({ onDecided, variant = "page", version = 0, onSeeAll }: GatesProps = {}) {
  const res = useStaleResource("gates", version);
  // Gates decided in this view, hidden at once and kept hidden even if a refetch still lists them.
  const [removed, setRemoved] = useState<ReadonlySet<string>>(new Set());
  const [deciding, setDeciding] = useState<ReadonlyMap<string, GateDecision>>(new Map());
  const { toasts, notify, dismiss } = useToasts();
  const inFlight = useRef<Set<string>>(new Set());
  const live = useRef(true);

  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);

  function setDecidingFor(id: string, decision: GateDecision | null) {
    setDeciding((prev) => {
      const next = new Map(prev);
      if (decision) next.set(id, decision);
      else next.delete(id);
      return next;
    });
  }

  function removeGate(id: string) {
    setRemoved((prev) => new Set(prev).add(id));
  }

  async function decide(gate: Gate, decision: GateDecision) {
    if (inFlight.current.has(gate.id) || deciding.has(gate.id)) return;
    inFlight.current.add(gate.id);
    setDecidingFor(gate.id, decision);
    const verb = decision === "approve" ? "Approved" : "Denied";
    try {
      await decideGate(gate.id, decision);
      if (!live.current) return;
      removeGate(gate.id);
      onDecided?.();
      notify({
        kind: "ok",
        title: `${verb}: recorded in the audit log`,
        detail: `${gate.title}. This action does not run the command.`,
      });
    } catch (e) {
      if (!live.current) return;
      if (e instanceof GateDecisionError && e.status === 409) {
        removeGate(gate.id);
        onDecided?.();
        notify({
          kind: "info",
          title: "Already decided",
          detail: `${gate.title} is no longer pending, so it was removed from the list.`,
        });
      } else {
        notify({
          kind: "error",
          title: "Decision not recorded",
          detail: `${gate.title}: could not record the decision. Try again.`,
        });
      }
    } finally {
      inFlight.current.delete(gate.id);
      if (live.current) setDecidingFor(gate.id, null);
    }
  }

  const compact = variant === "compact";

  if (res.status === "loading") {
    if (compact) {
      return (
        <section className="card list-card" role="status">
          <div className="skeleton-stack">
            <Skeleton h={22} w="45%" />
            <Skeleton h={96} r={20} />
            <Skeleton h={96} r={20} />
          </div>
          <p className="loading-caption">Loading approval gates…</p>
        </section>
      );
    }
    return (
      <section className="panel glass" role="status">
        <div className="phead">
          <span className="ptitle">Loading approval gates…</span>
        </div>
      </section>
    );
  }

  if (res.status === "error") {
    if (compact) {
      return (
        <section className="card list-card">
          <ErrorState
            title="Could not load approval gates"
            detail="check that the Ascent backend is running"
            onRetry={res.retry}
          />
        </section>
      );
    }
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load approval gates</span>
          <span className="count">check that the Ascent backend is running</span>
          <Button variant="secondary" size="sm" onClick={res.retry}>
            Retry
          </Button>
        </div>
      </section>
    );
  }

  const gates = res.data.filter((g) => !removed.has(g.id));
  const card = (g: Gate) => (
    <GateCard
      key={g.id}
      gate={g}
      variant={variant}
      deciding={deciding.get(g.id)}
      onDecide={(d) => decide(g, d)}
    />
  );

  if (compact) {
    const shown = gates.slice(0, COMPACT_LIMIT);
    const more = gates.length - shown.length;
    return (
      <>
        <ListCard
          title="Approval required"
          count={`${gates.length} pending`}
          seeAll={onSeeAll ? { label: "approval gates", onClick: onSeeAll } : undefined}
        >
          {gates.length === 0 ? (
            <EmptyState title="No actions awaiting approval" />
          ) : (
            <div className="gate-list">{shown.map(card)}</div>
          )}
          {more > 0 ? (
            onSeeAll ? (
              <div className="list-more">
                <Button variant="text" onClick={onSeeAll}>
                  {more} more in Approval gates
                </Button>
              </div>
            ) : (
              <p className="list-more">{more} more in Approval gates</p>
            )
          ) : null}
        </ListCard>
        <ToastStack toasts={toasts} onDismiss={dismiss} />
      </>
    );
  }

  return (
    <>
      <section className="gate glass">
        <h3>
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" />
          </svg>{" "}
          Approval required{" "}
          <span className="pill" style={{ marginLeft: "auto" }}>
            {gates.length} pending
          </span>
        </h3>
        {gates.length === 0 ? <div className="note">No actions awaiting approval</div> : gates.map(card)}
      </section>

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </>
  );
}
