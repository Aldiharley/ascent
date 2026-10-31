import type { TriageItem, Verdict } from "../api";

export interface VerdictCounts {
  total: number;
  tp: number;
  hu: number;
  fp: number;
}

/**
 * The one place a verdict is classified. A value outside the enum (a newer backend, a corrupt
 * payload, an inherited key like "constructor") is "needs human": the same fail-safe as
 * `VerdictChip`, so the tiles, the donut, the filter and the table can never disagree.
 */
export function classifyVerdict(verdict: unknown): Verdict {
  return verdict === "TRUE_POSITIVE" || verdict === "LIKELY_FALSE_POSITIVE" ? verdict : "ABSTAIN";
}

/** Does `item` belong to the verdict bucket the filter names? "ALL" (or anything unknown) keeps every item. */
export function matchesVerdict(item: TriageItem, filter: Verdict | "ALL"): boolean {
  if (filter !== "TRUE_POSITIVE" && filter !== "ABSTAIN" && filter !== "LIKELY_FALSE_POSITIVE") return true;
  return classifyVerdict(item.verdict) === filter;
}

/** Findings per verdict bucket (see `classifyVerdict`), so the four numbers always add up. */
export function verdictCounts(items: readonly TriageItem[]): VerdictCounts {
  let tp = 0;
  let hu = 0;
  let fp = 0;
  for (const it of items) {
    const v = classifyVerdict(it.verdict);
    if (v === "TRUE_POSITIVE") tp += 1;
    else if (v === "LIKELY_FALSE_POSITIVE") fp += 1;
    else hu += 1;
  }
  return { total: items.length, tp, hu, fp };
}

/** Rounded share of `total`; 0 when there is nothing to share. */
export function percent(n: number, total: number): number {
  return total === 0 ? 0 : Math.round((n / total) * 100);
}

/** Distinct scanners that reported a finding (findings with no usable `tool` are ignored). */
export function scannerCount(items: readonly TriageItem[]): number {
  const tools = new Set<string>();
  for (const it of items) {
    const tool = it.finding?.tool;
    if (typeof tool === "string" && tool !== "") tools.add(tool);
  }
  return tools.size;
}
