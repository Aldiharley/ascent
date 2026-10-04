import { render, screen, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { Findings } from "./Findings";

type Verdict = "TRUE_POSITIVE" | "ABSTAIN" | "LIKELY_FALSE_POSITIVE";

function item(over: {
  finding?: Record<string, unknown>;
  verdict?: Verdict;
  confidence?: number;
}) {
  return {
    finding: {
      id: "f-1",
      tool: "nuclei",
      rule_id: "rule/x",
      severity: "HIGH",
      title: "A finding",
      message: "m",
      url: "/somewhere",
      file: "",
      line: 0,
      category: "DAST",
      cwe: "",
      code: "",
      ...over.finding,
    },
    verdict: over.verdict ?? "TRUE_POSITIVE",
    confidence: over.confidence ?? 0.9,
    fp_likelihood: 0.1,
    rationale: "r",
    remediation: "fix",
    triager: "mock",
    duplicates: [],
  };
}

function mockJson(body: unknown, init?: ResponseInit) {
  return vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(new Response(JSON.stringify(body), init));
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("renders a finding row and KPI", async () => {
  const spy = mockJson([
    {
      finding: { title: "SQL injection", rule_id: "sqli", severity: "CRITICAL", url: "/login", cwe: "CWE-89" },
      verdict: "TRUE_POSITIVE",
      confidence: 0.95,
      fp_likelihood: 0.05,
      rationale: "r",
      remediation: "fix",
    },
  ]);
  render(<Findings />);
  expect(await screen.findByText("SQL injection")).toBeInTheDocument();
  // "True positive" appears in both the KPI label and the row chip.
  const table = screen.getByRole("table");
  expect(within(table).getByText(/True positive/i)).toBeInTheDocument();
  expect(screen.getAllByText(/True positive/i)).toHaveLength(2);
  expect(within(table).getByText("CRITICAL")).toBeInTheDocument();
  expect(within(table).getByText("/login")).toBeInTheDocument();
  expect(within(table).getByText("CWE-89")).toBeInTheDocument();
  expect(within(table).getByText("0.95")).toBeInTheDocument();
  // Only the same-origin relative path is ever fetched.
  expect(spy).toHaveBeenCalledTimes(1);
  expect(spy.mock.calls[0][0]).toBe("/api/findings");
});

function kpi(label: string): HTMLElement {
  const el = screen.getByText(label, { selector: ".kpi .l" }).closest(".kpi");
  if (!el) throw new Error(`no KPI for ${label}`);
  return el as HTMLElement;
}

test("KPI counts are computed by verdict, plus total", async () => {
  mockJson([
    item({ finding: { id: "a", title: "One" }, verdict: "TRUE_POSITIVE" }),
    item({ finding: { id: "b", title: "Two" }, verdict: "ABSTAIN", confidence: 0.4 }),
    item({ finding: { id: "c", title: "Three" }, verdict: "LIKELY_FALSE_POSITIVE", confidence: 0.7 }),
  ]);
  render(<Findings />);
  await screen.findByText("One");
  expect(within(kpi("Findings")).getByText("3", { selector: ".n" })).toBeInTheDocument();
  expect(within(kpi("True positive")).getByText("1", { selector: ".n" })).toBeInTheDocument();
  expect(within(kpi("Needs human")).getByText("1", { selector: ".n" })).toBeInTheDocument();
  expect(within(kpi("Likely noise")).getByText("1", { selector: ".n" })).toBeInTheDocument();
  const table = screen.getByRole("table");
  expect(within(table).getByText("Needs human")).toBeInTheDocument();
  expect(within(table).getByText("Likely noise")).toBeInTheDocument();
});

test("orders true positives first, then by confidence", async () => {
  mockJson([
    item({ finding: { id: "a", title: "Noise" }, verdict: "LIKELY_FALSE_POSITIVE", confidence: 0.99 }),
    item({ finding: { id: "b", title: "TP low" }, verdict: "TRUE_POSITIVE", confidence: 0.6 }),
    item({ finding: { id: "c", title: "TP high" }, verdict: "TRUE_POSITIVE", confidence: 0.95 }),
    item({ finding: { id: "d", title: "Human" }, verdict: "ABSTAIN", confidence: 0.4 }),
  ]);
  render(<Findings />);
  await screen.findByText("Noise");
  const names = within(screen.getByRole("table"))
    .getAllByText(/^(Noise|TP low|TP high|Human)$/)
    .map((n) => n.textContent);
  expect(names).toEqual(["TP high", "TP low", "Human", "Noise"]);
});

test("falls back to file:line locus when url is empty", async () => {
  mockJson([
    item({ finding: { title: "Hardcoded secret", url: "", file: "src/auth.rs", line: 42, category: "SAST", cwe: "CWE-798" } }),
  ]);
  render(<Findings />);
  expect(await screen.findByText("src/auth.rs:42")).toBeInTheDocument();
  expect(screen.getByText("CWE-798")).toBeInTheDocument();
  expect(screen.getByText("SAST")).toBeInTheDocument();
});

test("shows an error state when the API returns 500", async () => {
  mockJson({ error: "boom" }, { status: 500 });
  render(<Findings />);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(/could not load findings/i);
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});

test("shows an error state when the fetch rejects", async () => {
  vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("network down"));
  render(<Findings />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not load findings/i);
});

test("shows a loading state before the response arrives", async () => {
  mockJson([]);
  render(<Findings />);
  expect(screen.getByRole("status")).toHaveTextContent(/loading/i);
  expect(await screen.findByText("No findings yet")).toBeInTheDocument();
});

test("shows an empty state for []", async () => {
  mockJson([]);
  render(<Findings />);
  expect(await screen.findByText("No findings yet")).toBeInTheDocument();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(within(kpi("Findings")).getByText("0", { selector: ".n" })).toBeInTheDocument();
});

test("renders attacker-controlled titles as literal text (no HTML injection)", async () => {
  const evil = "<img src=x onerror=alert(1)>";
  mockJson([item({ finding: { title: evil, url: "<script>alert(2)</script>" } })]);
  const { container } = render(<Findings />);
  expect(await screen.findByText(evil)).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("a[href], [src]")).toBeNull();
});
