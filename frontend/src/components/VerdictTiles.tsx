import type { TriageItem, Verdict } from "../api";
import { percent, scannerCount, verdictCounts } from "../data/findingStats";
import { IconCrosshairCheck, IconFunnelSlash, IconHand, IconRadar } from "./icons";
import { KpiTile } from "./KpiTile";

export type VerdictFilter = Verdict | "ALL";

/**
 * The four finding tiles (Findings, True positive, Needs human, Likely noise), shared by the
 * Overview and the Findings screen so their numbers and wording cannot drift apart. Every count
 * comes from `verdictCounts`, the same classification the Findings filter uses.
 *
 * Without `onSelect` the tiles are plain statistics. With it they are buttons that report the tile's
 * verdict; give `filter` as well and they become toggles (`aria-pressed`, the pressed one is the
 * active filter, and "Findings" is pressed while nothing is narrowed).
 */
export function VerdictTiles({
  items,
  filter,
  onSelect,
  compact,
}: {
  items: readonly TriageItem[];
  filter?: VerdictFilter;
  onSelect?: (target: VerdictFilter) => void;
  compact?: boolean;
}) {
  const c = verdictCounts(items);
  const scanners = scannerCount(items);
  const totalSub = scanners > 0 ? `from ${scanners} ${scanners === 1 ? "scanner" : "scanners"}` : "triaged by Crux";
  const tile = (target: VerdictFilter) => ({
    pressed: filter === undefined ? undefined : filter === target,
    onClick: onSelect ? () => onSelect(target) : undefined,
    compact,
  });
  return (
    <div className="kpi-row">
      <KpiTile label="Findings" value={c.total} sub={totalSub} tone="teal" icon={<IconRadar />} {...tile("ALL")} />
      <KpiTile
        label="True positive"
        value={c.tp}
        sub={`${percent(c.tp, c.total)}% · confirmed by triage`}
        tone="bluegrey"
        icon={<IconCrosshairCheck />}
        {...tile("TRUE_POSITIVE")}
      />
      <KpiTile
        label="Needs human"
        value={c.hu}
        sub={`${percent(c.hu, c.total)}% · awaiting your review`}
        tone="ice"
        icon={<IconHand />}
        {...tile("ABSTAIN")}
      />
      <KpiTile
        label="Likely noise"
        value={c.fp}
        sub={`${percent(c.fp, c.total)}% · cut by Crux`}
        tone="lav"
        icon={<IconFunnelSlash />}
        {...tile("LIKELY_FALSE_POSITIVE")}
      />
    </div>
  );
}
