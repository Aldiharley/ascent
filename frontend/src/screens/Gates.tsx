import { useEffect, useRef, useState } from "react";
import { GateDecisionError, decideGate, getGates } from "../api";
import type { Gate, GateDecision } from "../api";

type State =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; gates: Gate[] };

interface ToastMsg {
  kind: "ok" | "info" | "error";
  title: string;
  detail: string;
}

interface ToastItem extends ToastMsg {
  key: number;
}

const TOAST_MS = 5000;
const MAX_TOASTS = 4;

export interface GatesProps {
  /** Called after a decision is recorded (or found already recorded), so a sibling audit view can refresh. */
  onDecided?: () => void;
}

export function Gates({ onDecided }: GatesProps = {}) {
  const [state, setState] = useState<State>({ status: "loading" });
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timers = useRef<Set<ReturnType<typeof setTimeout>>>(new Set());
  const inFlight = useRef<Set<string>>(new Set());
  const nextKey = useRef(0);
  const live = useRef(true);

  function load() {
    setState({ status: "loading" });
    getGates().then(
      (gates) => live.current && setState({ status: "ready", gates }),
      () => live.current && setState({ status: "error" }),
    );
  }

  useEffect(() => {
    live.current = true;
    load();
    const pending = timers.current;
    return () => {
      live.current = false;
      pending.forEach(clearTimeout);
      pending.clear();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function notify(msg: ToastMsg) {
    const key = nextKey.current++;
    setToasts((prev) => [...prev, { ...msg, key }].slice(-MAX_TOASTS));
    const t = setTimeout(() => {
      timers.current.delete(t);
      setToasts((prev) => prev.filter((x) => x.key !== key));
    }, TOAST_MS);
    timers.current.add(t);
  }

  function setBusyFor(id: string, on: boolean) {
    setBusy((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function removeGate(id: string) {
    setState((s) =>
      s.status === "ready" ? { status: "ready", gates: s.gates.filter((g) => g.id !== id) } : s,
    );
  }

  async function decide(gate: Gate, decision: GateDecision) {
    if (inFlight.current.has(gate.id) || busy.has(gate.id)) return;
    inFlight.current.add(gate.id);
    setBusyFor(gate.id, true);
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
      if (live.current) setBusyFor(gate.id, false);
    }
  }

  if (state.status === "loading") {
    return (
      <section className="panel glass" role="status">
        <div className="phead">
          <span className="ptitle">Loading approval gates…</span>
        </div>
      </section>
    );
  }

  if (state.status === "error") {
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load approval gates</span>
          <span className="count">check that the Ascent backend is running</span>
          <button type="button" className="deny" onClick={load}>
            Retry
          </button>
        </div>
      </section>
    );
  }

  const { gates } = state;

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
        {gates.length === 0 ? (
          <div className="note">No actions awaiting approval</div>
        ) : (
          gates.map((g) => {
            const inScope = g.in_scope === true;
            const working = busy.has(g.id);
            return (
              <div className="gcard" key={g.id}>
                <div className="t">{g.title}</div>
                <div className="why">{g.why}</div>
                <div className="why">
                  Target: <span className="loc">{g.target}</span>
                </div>
                <div className="cmd">{g.command}</div>
                {inScope ? (
                  <div className="scope-ok">
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                      <path d="M20 6 9 17l-5-5" />
                    </svg>{" "}
                    In scope
                  </div>
                ) : (
                  <div className="scope-bad">Out of scope: approval is blocked</div>
                )}
                <div className="acts">
                  <button className="approve" disabled={!inScope || working} onClick={() => decide(g, "approve")}>
                    Approve
                  </button>
                  <button className="deny" disabled={working} onClick={() => decide(g, "deny")}>
                    Deny
                  </button>
                </div>
                <div className="note">
                  Every decision is written to the audit log. Approving records consent; it does not run the command.
                </div>
              </div>
            );
          })
        )}
      </section>

      <div className="toast-stack">
        <div aria-live="polite" role="status" className="toast-region">
          {toasts.filter((t) => t.kind !== "error").map((t) => (
            <ToastView key={t.key} toast={t} />
          ))}
        </div>
        <div aria-live="assertive" role="alert" className="toast-region">
          {toasts.filter((t) => t.kind === "error").map((t) => (
            <ToastView key={t.key} toast={t} />
          ))}
        </div>
      </div>
    </>
  );
}

const TOAST_ICON: Record<ToastMsg["kind"], string> = { ok: "✓", info: "i", error: "!" };

function ToastView({ toast }: { toast: ToastMsg }) {
  return (
    <div className={`toast glass gate-toast${toast.kind === "error" ? " toast-error" : ""}`}>
      <div className="ic" aria-hidden="true">
        {TOAST_ICON[toast.kind]}
      </div>
      <div className="m">
        <b>{toast.title}</b>
        <div>{toast.detail}</div>
      </div>
    </div>
  );
}
