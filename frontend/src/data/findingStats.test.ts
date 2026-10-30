import { expect, test } from "vitest";
import type { TriageItem } from "../api";
import { classifyVerdict, matchesVerdict, percent, scannerCount, verdictCounts } from "./findingStats";

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

test("classifyVerdict maps anything outside the enum to needs-human", () => {
  expect(classifyVerdict("TRUE_POSITIVE")).toBe("TRUE_POSITIVE");
  expect(classifyVerdict("LIKELY_FALSE_POSITIVE")).toBe("LIKELY_FALSE_POSITIVE");
  expect(classifyVerdict("ABSTAIN")).toBe("ABSTAIN");
  for (const odd of ["bogus", "constructor", "__proto__", "", undefined, null, 7]) {
    expect(classifyVerdict(odd as never), String(odd)).toBe("ABSTAIN");
  }
});

test("matchesVerdict uses the same classification as verdictCounts, so a tile and its filter agree", () => {
  const items = [it("TRUE_POSITIVE"), it("ABSTAIN"), it("LIKELY_FALSE_POSITIVE"), it("bogus"), it("constructor")];
  const c = verdictCounts(items);
  expect(items.filter((i) => matchesVerdict(i, "TRUE_POSITIVE"))).toHaveLength(c.tp);
  expect(items.filter((i) => matchesVerdict(i, "ABSTAIN"))).toHaveLength(c.hu);
  expect(items.filter((i) => matchesVerdict(i, "LIKELY_FALSE_POSITIVE"))).toHaveLength(c.fp);
  expect(items.filter((i) => matchesVerdict(i, "ALL"))).toHaveLength(c.total);
  expect(c.hu).toBe(3); // the two unknown verdicts are counted, and listed, as needs-human
});

test("matchesVerdict treats a filter outside the enum as ALL", () => {
  expect(matchesVerdict(it("TRUE_POSITIVE"), "constructor" as never)).toBe(true);
  expect(matchesVerdict(it("TRUE_POSITIVE"), undefined as never)).toBe(true);
});
