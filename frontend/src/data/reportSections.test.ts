import { expect, test } from "vitest";
import { sectionIds, sectionLabel } from "./reportSections";

test("ids are r- plus the lower-cased heading with runs of non-alphanumerics as one dash", () => {
  expect(sectionIds(["Summary", "DAST coverage", "  Top 10: OWASP / CWE  ", "Über-Fund"])).toEqual([
    "r-summary",
    "r-dast-coverage",
    "r-top-10-owasp-cwe",
    "r-ber-fund",
  ]);
});

test("repeated headings are de-duplicated with -2, -3 and never collide with a literal heading", () => {
  expect(sectionIds(["A", "A", "A", "A 2", "a-2"])).toEqual(["r-a", "r-a-2", "r-a-3", "r-a-2-2", "r-a-2-3"]);
  const ids = sectionIds(["x", "x 2", "x", "x"]);
  expect(new Set(ids).size).toBe(ids.length);
});

test("a heading with nothing to slug still gets a valid id", () => {
  expect(sectionIds(["!!!", "", "???"])).toEqual(["r-section", "r-section-2", "r-section-3"]);
});

test("hostile text can only produce [a-z0-9-]", () => {
  for (const id of sectionIds(['<img src=x onerror=alert(1)>', '"><script>', "constructor", "__proto__", "javascript:alert(1)"])) {
    expect(id).toMatch(/^r-[a-z0-9-]+$/);
  }
});

test("the label is the trimmed, single-spaced heading text, or a numbered fallback", () => {
  expect(sectionLabel("  DAST \n  coverage ", 0)).toBe("DAST coverage");
  expect(sectionLabel("   ", 2)).toBe("Section 3");
});
