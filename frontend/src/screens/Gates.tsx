import { useEffect, useRef, useState } from "react";
import { GateDecisionError, decideGate, getGates } from "../api";
import type { Gate, GateDecision } from "../api";

type State =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; gates: Gate[] };

interface ToastMsg {
  kind: "ok" | "error";
  title: string;
  detail: string;
}

const TOAST_MS = 5000;

export function Gates() {
  const [state, setState] = useState<State>({ status: "loading" });
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
  const [toast, setToast] = useState<ToastMsg | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const live = useRef(true);

  useEffect(() => {
    live.current = true;
    getGates().then(
      (gates) => live.current && setState({ status: "ready", gates }),
      () => live.current && setState({ status: "error" }),
    );
    return () => {
      live.current = false;
      clearTimeout(timer.current);
    };
  }, []);

  function notify(msg: ToastMsg) {
    clearTimeout(timer.current);
    setToast(msg);
    timer.current = setTimeout(() => setToast(null), TOAST_MS);
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
    if (busy.has(gate.id)) return;
    setBusyFor(gate.id, true);
    const verb = decision === "approve" ? "Approved" : "Denied";
    try {
      await decideGate(gate.id, decision);
      if (!live.current) return;
      removeGate(gate.id);
      notify({
        kind: "ok",
        title: `${verb}: recorded in the audit log`,
        detail: `${gate.title}. This action does not run the command.`,
      });
    } catch (e) {
      if (!live.current) return;
      if (e instanceof GateDecisionError && e.status === 409) {
        removeGate(gate.id);
        notify({
          kind: "ok",
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

      {toast ? (
        <div
          className={`toast glass gate-toast${toast.kind === "error" ? " toast-error" : ""}`}
          role={toast.kind === "error" ? "alert" : "status"}
        >
          <div className="ic" aria-hidden="true">
            {toast.kind === "error" ? "!" : "✓"}
          </div>
          <div className="m">
            <b>{toast.title}</b>
            <div>{toast.detail}</div>
          </div>
        </div>
      ) : null}
    </>
  );
}
