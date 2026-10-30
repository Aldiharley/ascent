import type { GateDecisionKind } from "../api";

const DECISIONS: Record<GateDecisionKind, { text: string; cls: string }> = {
  PASS: { text: "PASS", cls: "vpill--pass" },
  CONDITIONAL: { text: "CONDITIONAL", cls: "vpill--cond" },
  FAIL: { text: "FAIL", cls: "vpill--fail" },
  INCOMPLETE: { text: "INCOMPLETE", cls: "vpill--inc" },
};

const NOT_EVALUATED = { text: "NOT EVALUATED", cls: "vpill--none" };

/**
 * Policy decision pill. `null`/`undefined` means no verdict exists yet ("NOT EVALUATED"); an
 * unrecognised decision fails safe to INCOMPLETE. Text and class come from the fixed table only.
 */
export function VerdictPill({ decision }: { decision?: GateDecisionKind | null }) {
  if (decision === null || decision === undefined) {
    return <span className={`vpill ${NOT_EVALUATED.cls}`}>{NOT_EVALUATED.text}</span>;
  }
  const d = Object.hasOwn(DECISIONS, decision) ? DECISIONS[decision] : DECISIONS.INCOMPLETE;
  return <span className={`vpill ${d.cls}`}>{d.text}</span>;
}
