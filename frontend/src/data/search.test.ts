import { describe, expect, test } from "vitest";
import type { TriageItem } from "../api";
import { findingLocus, matchFinding } from "./search";

function item(over: Partial<TriageItem["finding"]> = {}): TriageItem {
  return {
    finding: {
      rule_id: "ssrf-1",
      severity: "HIGH",
      title: "SSRF in fetch",
      url: "http://lab/x",
      cwe: "CWE-918",
      category: "DAST",
      tool: "nuclei",
      ...over,
    },
    verdict: "TRUE_POSITIVE",
    confidence: 0.9,
    fp_likelihood: 0.1,
  };
}

describe("matchFinding", () => {
  test("an empty or whitespace-only query matches everything", () => {
    expect(matchFinding(item(), "")).toBe(true);
    expect(matchFinding(item(), "   \t ")).toBe(true);
  });

  test("matches title, rule id, locus, cwe, category and tool, case-insensitively", () => {
    expect(matchFinding(item(), "ssrf in")).toBe(true);
    expect(matchFinding(item(), "SSRF-1")).toBe(true);
    expect(matchFinding(item(), "lab/x")).toBe(true);
    expect(matchFinding(item(), "cwe-918")).toBe(true);
    expect(matchFinding(item(), "dast")).toBe(true);
    expect(matchFinding(item(), "NUCLEI")).toBe(true);
  });

  test("every whitespace-separated term must match, in any order, possibly across fields", () => {
    expect(matchFinding(item(), "nuclei ssrf")).toBe(true);
    expect(matchFinding(item(), "  cwe-918   lab ")).toBe(true);
    expect(matchFinding(item(), "ssrf sqli")).toBe(false);
  });

  test("a non-matching query is false", () => {
    expect(matchFinding(item(), "sqli")).toBe(false);
  });

  test("file:line is part of the locus when there is no url", () => {
    const it = item({ url: undefined, file: "src/app.py", line: 42 });
    expect(matchFinding(it, "app.py:42")).toBe(true);
    expect(matchFinding(it, "app.py:43")).toBe(false);
  });

  test("severity, message and verdict are not searched", () => {
    const it = item({ message: "secret-body" });
    expect(matchFinding(it, "high")).toBe(false);
    expect(matchFinding(it, "secret-body")).toBe(false);
    expect(matchFinding(it, "true_positive")).toBe(false);
  });

  test("missing and non-string fields never throw and never match", () => {
    const weird = {
      finding: { rule_id: 7, severity: "LOW", title: null, cwe: { a: 1 } },
      verdict: "ABSTAIN",
      confidence: 0,
      fp_likelihood: 0,
    } as unknown as TriageItem;
    expect(() => matchFinding(weird, "x")).not.toThrow();
    expect(matchFinding(weird, "x")).toBe(false);
    expect(matchFinding(weird, "")).toBe(true);
    expect(matchFinding({} as TriageItem, "x")).toBe(false);
  });

  test("regex metacharacters in the query are plain text", () => {
    expect(matchFinding(item({ title: "a.b(c" }), "a.b(c")).toBe(true);
    expect(matchFinding(item({ title: "axb" }), "a.b")).toBe(false);
    expect(matchFinding(item(), ".*")).toBe(false);
  });
});

describe("findingLocus", () => {
  test("prefers the url, then file:line, then file, then empty", () => {
    expect(findingLocus(item())).toBe("http://lab/x");
    expect(findingLocus(item({ url: undefined, file: "a.py", line: 3 }))).toBe("a.py:3");
    expect(findingLocus(item({ url: undefined, file: "a.py" }))).toBe("a.py");
    expect(findingLocus(item({ url: undefined }))).toBe("");
  });
});
