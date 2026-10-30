import { expect, test } from "vitest";
import type { TriageItem } from "../api";
import { percent, scannerCount, verdictCounts } from "./findingStats";

function it(verdict: string, tool?: unknown): TriageItem {
  return { finding: { rule_id: "r", severity: "HIGH", title: "t", tool }, verdict, confidence: 1, fp_likelihood: 0 } as unknown as TriageItem;
}

test("verdictCounts buckets by verdict; an unknown verdict counts as needs-human", () => {
  const items = [it("TRUE_POSITIVE"), it("TRUE_POSITIVE"), it("ABSTAIN"), it("LIKELY_FALSE_POSITIVE"), it("bogus"), it("constructor")];
  expect(verdictCounts(items)).toEqual({ total: 6, tp: 2, hu: 3, fp: 1 });
});

test("verdictCounts of nothing is all zeros", () => {
  expect(verdictCounts([])).toEqual({ total: 0, tp: 0, hu: 0, fp: 0 });
});

test("percent is a rounded share, 0 when the total is 0", () => {
  expect(percent(1, 3)).toBe(33);
  expect(percent(2, 3)).toBe(67);
  expect(percent(0, 0)).toBe(0);
  expect(percent(5, 5)).toBe(100);
});

test("scannerCount is the number of distinct non-empty string tools", () => {
  expect(scannerCount([it("ABSTAIN", "nuclei"), it("ABSTAIN", "nuclei"), it("ABSTAIN", "opengrep")])).toBe(2);
  expect(scannerCount([it("ABSTAIN"), it("ABSTAIN", ""), it("ABSTAIN", 7), it("ABSTAIN", null)])).toBe(0);
  expect(scannerCount([])).toBe(0);
});
