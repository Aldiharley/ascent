import { useId } from "react";
import type { Gate, GateDecision } from "../api";
import { Button } from "./Button";
import { IconBadge } from "./IconBadge";
import { IconInfo, IconShieldCheck, IconTick } from "./icons";

export type GateCardVariant = "page" | "compact";

export const CONSENT_NOTE =
  "Every decision is written to the audit log. Approving records consent; it does not run the command.";

/**
 * One pending approval gate (spec 4.5). Every string comes from the proposer and may carry scanned
 * data, so all of it is React text. The full command is always shown, in both variants: consent
 * means seeing exactly what would run. Approving records consent and never runs anything.
 */
export function GateCard({
  gate,
  variant = "page",
  deciding,
  onDecide,
}: {
  gate: Gate;
  variant?: GateCardVariant;
  /** The decision currently being recorded for this gate, if any (shows a spinner on that button). */
  deciding?: GateDecision;
  onDecide: (decision: GateDecision) => void;
}) {
  const titleId = useId();
  const compact = variant === "compact";
  const inScope = gate.in_scope === true;
  const working = deciding !== undefined;

  const evidence =
    typeof gate.expected_evidence === "string" && gate.expected_evidence !== "" ? (
      <div className="why">
        <b>Expected evidence:</b> <span>{gate.expected_evidence}</span>
      </div>
    ) : null;
  const failure =
    typeof gate.why_it_might_fail === "string" && gate.why_it_might_fail !== "" ? (
      <div className="why">
        <b>Why it might fail:</b> <span>{gate.why_it_might_fail}</span>
      </div>
    ) : null;

  return (
    <article className={compact ? "gcard gcard--compact" : "gcard"} aria-labelledby={titleId}>
      <header className="gcard-head">
        <IconBadge tone="ice" size="sm">
          <IconShieldCheck />
        </IconBadge>
        <h3 className="gcard-title" id={titleId}>
          {gate.title}
        </h3>
        {gate.detect_only === true && <span className="badge-detect">DETECT-ONLY</span>}
      </header>
      <p className="why">{gate.why}</p>
      <div className="gcard-target">
        <span className="gcard-label">Target:</span> <span className="tag tag--wrap">{gate.target}</span>
      </div>
      <div className="cmd">{gate.command}</div>
      {compact ? (
        evidence || failure ? (
          <details className="gdetails">
            <summary>More context</summary>
            {evidence}
            {failure}
          </details>
        ) : null
      ) : (
        <>
          {evidence}
          {failure}
        </>
      )}
      {inScope ? (
        <span className="scope-ok">
          <IconTick size={14} strokeWidth={2.6} /> In scope
        </span>
      ) : (
        <span className="scope-bad">Out of scope: approval is blocked</span>
      )}
      <div className="acts">
        <Button
          variant="primary"
          className="approve"
          disabled={!inScope || working}
          busy={deciding === "approve"}
          onClick={() => onDecide("approve")}
        >
          Approve
        </Button>
        <Button
          variant="danger"
          className="deny"
          disabled={working}
          busy={deciding === "deny"}
          onClick={() => onDecide("deny")}
        >
          Deny
        </Button>
      </div>
      <p className="note">
        <IconInfo size={16} /> {CONSENT_NOTE}
      </p>
    </article>
  );
}
