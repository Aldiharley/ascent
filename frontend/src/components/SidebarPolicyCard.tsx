import { useEffect, useRef, useState } from "react";
import type { GateDecisionKind } from "../api";
import { Button } from "./Button";
import { IconBadge } from "./IconBadge";
import type { BadgeTone } from "./IconBadge";
import { IconShieldCheck } from "./icons";
import { VerdictPill } from "./VerdictPill";

export interface ShellPolicy {
  decision: GateDecisionKind;
  exit_code: number;
  policy: string;
}

// Policy card badge tone per decision. Fixed table: the tone is never taken from API text.
const POLICY_TONES: Record<GateDecisionKind, BadgeTone> = {
  PASS: "teal",
  CONDITIONAL: "sand",
  FAIL: "coral",
  INCOMPLETE: "bluegrey",
};

const POLICY_FLAG = "--policy ascent-policy.yaml";
const COPIED_MS = 1500;
const BLOCKED_MS = 4000;

/**
 * The sidebar's read-only policy verdict (spec 2.2.4), drawn only once /api/gate has loaded. At
 * desktop width it is a card; on the 88px icon rail the CSS collapses it to its one round button
 * (`.sb-card-rail`), so both controls live here and share one "Copied" announcement.
 *
 * Nothing here evaluates a policy: "View verdict" navigates, "Copy --policy flag" copies text.
 */
export function SidebarPolicyCard({
  policy,
  onViewVerdict,
}: {
  /** The verdict, or null when no policy has been evaluated. */
  policy: ShellPolicy | null;
  onViewVerdict: () => void;
}) {
  const [copy, setCopy] = useState<"idle" | "copied" | "blocked">("idle");
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(copyTimer.current), []);

  async function copyFlag() {
    clearTimeout(copyTimer.current);
    try {
      await navigator.clipboard.writeText(POLICY_FLAG);
      setCopy("copied");
      copyTimer.current = setTimeout(() => setCopy("idle"), COPIED_MS);
    } catch {
      // The browser refused the clipboard: say so and name the flag, never claim a copy.
      setCopy("blocked");
      copyTimer.current = setTimeout(() => setCopy("idle"), BLOCKED_MS);
    }
  }

  const decision: GateDecisionKind | null = policy
    ? Object.hasOwn(POLICY_TONES, policy.decision)
      ? policy.decision
      : "INCOMPLETE"
    : null;
  const tone: BadgeTone = decision ? POLICY_TONES[decision] : "bluegrey";
  const policyLine = policy ? (policy.policy ? `exit ${policy.exit_code} · ${policy.policy}` : `exit ${policy.exit_code}`) : "";

  return (
    <>
      <section className="sb-card">
        <IconBadge tone={tone}>
          <IconShieldCheck />
        </IconBadge>
        <h2 className="sb-card-title">Policy gate</h2>
        {policy ? (
          <>
            <VerdictPill decision={decision} />
            <p className="sb-card-line" title={policyLine}>
              {policyLine}
            </p>
            <Button variant="ghost-dark" size="sm" onClick={onViewVerdict}>
              View verdict
            </Button>
          </>
        ) : (
          <>
            <p className="sb-card-strong">No verdict yet</p>
            <p className="sb-card-note">
              Add --policy to <code>ascent run</code> for a CI exit code.
            </p>
            <Button variant="ghost-dark" size="sm" onClick={copyFlag}>
              {copy === "copied" ? "Copied" : copy === "blocked" ? "Copy blocked" : "Copy --policy flag"}
            </Button>
          </>
        )}
        {/* Icon rail (1024-1279px): the card collapses to this one round button. */}
        <button
          type="button"
          className="sb-card-rail"
          aria-label={`Policy gate: ${decision ?? "not evaluated"}`}
          onClick={policy ? onViewVerdict : copyFlag}
        >
          <IconBadge tone={tone} size="lg">
            <IconShieldCheck />
          </IconBadge>
        </button>
      </section>
      {/* Outside the card, which the rail hides: the rail button's name never changes, so a copy
          there would otherwise be silent. Always mounted, so the text appearing is announced. */}
      <div role="status" className="sb-card-live sr-only">
        {copy === "copied" ? "Copied --policy flag to the clipboard" : ""}
        {copy === "blocked" ? `Couldn't copy. Add ${POLICY_FLAG} to ascent run.` : ""}
      </div>
    </>
  );
}
