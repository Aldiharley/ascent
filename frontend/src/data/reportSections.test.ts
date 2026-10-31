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

test("the slug is capped at 64 characters, with no dangling dash, and still de-duplicated", () => {
  const long = "word ".repeat(40); // 200 characters of heading
  const [one] = sectionIds([long]);
  expect(one.slice("r-".length).length).toBeLessThanOrEqual(64);
  expect(one).not.toMatch(/-$/);
  // The cut can land on a dash: the id never ends with one.
  const [cut] = sectionIds(["a".repeat(63) + " tail"]);
  expect(cut).toBe("r-" + "a".repeat(63));
  // Two headings that only differ after the cut collide on the capped slug, so they get -2.
  const [a, b, c] = sectionIds(["x".repeat(70) + " one", "x".repeat(70) + " two", "x".repeat(70) + " three"]);
  expect(new Set([a, b, c]).size).toBe(3);
  expect(b).toBe(`${a}-2`);
  expect(c).toBe(`${a}-3`);
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
