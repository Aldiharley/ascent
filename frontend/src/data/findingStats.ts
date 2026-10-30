import type { TriageItem } from "../api";

export interface VerdictCounts {
  total: number;
  tp: number;
  hu: number;
  fp: number;
}

/**
 * Findings per verdict. A verdict outside the enum counts as "needs human" (the same fail-safe as
 * `VerdictChip`), so the four numbers always add up and match the verdict donut.
 */
export function verdictCounts(items: readonly TriageItem[]): VerdictCounts {
  let tp = 0;
  let fp = 0;
  for (const it of items) {
    if (it.verdict === "TRUE_POSITIVE") tp += 1;
    else if (it.verdict === "LIKELY_FALSE_POSITIVE") fp += 1;
  }
  return { total: items.length, tp, hu: items.length - tp - fp, fp };
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
