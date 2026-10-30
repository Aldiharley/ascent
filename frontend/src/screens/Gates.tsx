import { useEffect, useId, useRef, useState } from "react";
import { GateDecisionError, decideGate } from "../api";
import type { Gate, GateDecision } from "../api";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { GateCard } from "../components/GateCard";
import { IconBadge } from "../components/IconBadge";
import { IconShieldCheck } from "../components/icons";
import { ListCard } from "../components/ListCard";
import { Skeleton } from "../components/Skeleton";
import { ErrorCard, LoadingCard } from "../components/StateCards";
import { ToastStack, useToasts } from "../components/Toast";
import { markGateDecided, usePendingGates } from "../data/gates";

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

type Outcome = "recorded" | "already" | "failed";

async function postDecision(id: string, decision: GateDecision): Promise<Outcome> {
  try {
    await decideGate(id, decision);
    return "recorded";
  } catch (e) {
    return e instanceof GateDecisionError && e.status === 409 ? "already" : "failed";
  }
}

export function Gates({ onDecided, variant = "page", version = 0, onSeeAll }: GatesProps = {}) {
  // The gates still pending, from the one source every view of them shares (see data/gates.ts):
  // a decision recorded here is hidden from the bell, the hero and the other card at the same time.
  const res = usePendingGates(version);
  const [deciding, setDeciding] = useState<ReadonlyMap<string, GateDecision>>(new Map());
  const { toasts, notify, dismiss } = useToasts();
  const inFlight = useRef<Set<string>>(new Set());
  const live = useRef(true);
  const introId = useId();

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

  async function decide(gate: Gate, decision: GateDecision) {
    if (inFlight.current.has(gate.id) || deciding.has(gate.id)) return;
    inFlight.current.add(gate.id);
    setDecidingFor(gate.id, decision);
    const verb = decision === "approve" ? "Approved" : "Denied";
    try {
      const outcome = await postDecision(gate.id, decision);
      // Recorded (or already recorded): the audit log and the pending list have changed, whether or
      // not this view is still on screen, so tell everyone before anything that needs a mounted view.
      if (outcome !== "failed") {
        markGateDecided(gate.id);
        onDecided?.();
      }
      if (!live.current) return;
      if (outcome === "recorded") {
        notify({
          kind: "ok",
          title: `${verb}: recorded in the audit log`,
          detail: `${gate.title}. This action does not run the command.`,
        });
      } else if (outcome === "already") {
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
    if (compact) return <LoadingCard caption="Loading approval gates…" rows={2} h={96} />;
    return (
      <div role="status">
        <div className="gate-grid">
          {[0, 1].map((i) => (
            <div className="card" key={i}>
              <div className="skeleton-stack">
                <Skeleton h={40} w="60%" r={14} />
                <Skeleton h={16} />
                <Skeleton h={64} r={14} />
                <Skeleton h={44} r={999} />
              </div>
            </div>
          ))}
        </div>
        <p className="loading-caption">Loading approval gates…</p>
      </div>
    );
  }

  if (res.status === "error") {
    return <ErrorCard title="Could not load approval gates" onRetry={res.retry} />;
  }

  const gates = res.data;
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
      <div className="stack">
        <section className="card intro-strip" aria-labelledby={introId}>
          <IconBadge tone="ice">
            <IconShieldCheck />
          </IconBadge>
          <div className="intro-text">
            <div className="intro-head">
              <h2 className="card-title" id={introId}>
                Approval required
              </h2>
              <span className="count">{gates.length} pending</span>
            </div>
            <p className="intro-sub">
              Detect-only verification gates. Approving records your consent in the hash-chained audit log. It never
              runs anything from this console.
            </p>
          </div>
        </section>

        {gates.length === 0 ? (
          <section className="card">
            <EmptyState size={180} title="No actions awaiting approval">
              When triage proposes a verification step, it waits here for you.
            </EmptyState>
          </section>
        ) : (
          <div className="gate-grid">{gates.map(card)}</div>
        )}
      </div>

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </>
  );
}
