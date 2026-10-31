import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, test, vi } from "vitest";
import type { Verdict } from "../api";
import type { NavId } from "../components/Shell";
import { Findings } from "./Findings";

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


// ---- KPI filter toggles, query, empty and no-match states (spec 3.3) ----

const three = () => [
  item({ finding: { id: "a", title: "Real one", rule_id: "rule/real", url: "/real" }, verdict: "TRUE_POSITIVE" }),
  item({ finding: { id: "b", title: "Maybe two", rule_id: "rule/maybe", url: "/maybe" }, verdict: "ABSTAIN", confidence: 0.4 }),
  item({ finding: { id: "c", title: "Noise three", rule_id: "rule/noise", url: "/noise" }, verdict: "LIKELY_FALSE_POSITIVE", confidence: 0.7 }),
];

/** What `App` does: owns the verdict filter and the search text and hands them down. */
function Harness({
  initial = "ALL",
  initialQuery = "",
  onNavigate,
}: {
  initial?: Verdict | "ALL";
  initialQuery?: string;
  onNavigate?: (id: NavId) => void;
}) {
  const [filter, setFilter] = useState<Verdict | "ALL">(initial);
  const [query, setQuery] = useState(initialQuery);
  return (
    <>
      <input aria-label="q" value={query} onChange={(e) => setQuery(e.target.value)} />
      <Findings
        verdictFilter={filter}
        onVerdictFilterChange={setFilter}
        query={query}
        onClearFilters={() => {
          setFilter("ALL");
          setQuery("");
        }}
        onNavigate={onNavigate}
      />
    </>
  );
}

function tile(label: string): HTMLElement {
  return kpi(label);
}

function rowTitles(): string[] {
  const table = screen.queryByRole("table");
  if (!table) return [];
  return within(table)
    .getAllByRole("row")
    .slice(1)
    .map((r) => r.querySelector(".fname")?.textContent ?? "");
}

test("the tiles are filter toggles: real buttons with aria-pressed, Findings pressed while nothing is narrowed", async () => {
  mockJson(three());
  render(<Harness />);
  await screen.findByText("Real one");
  for (const l of ["Findings", "True positive", "Needs human", "Likely noise"]) {
    expect(tile(l).tagName).toBe("BUTTON");
  }
  expect(tile("Findings")).toHaveAttribute("aria-pressed", "true");
  expect(tile("True positive")).toHaveAttribute("aria-pressed", "false");
  expect(tile("Needs human")).toHaveAttribute("aria-pressed", "false");
  expect(tile("Likely noise")).toHaveAttribute("aria-pressed", "false");
  // The compact tile variant is used here.
  expect(tile("Findings")).toHaveClass("kpi--compact");
});

test("clicking a tile filters the rows, presses it, and says how many are shown", async () => {
  mockJson(three());
  render(<Harness />);
  await screen.findByText("Real one");
  expect(rowTitles()).toEqual(["Real one", "Maybe two", "Noise three"]);
  fireEvent.click(tile("Needs human"));
  expect(rowTitles()).toEqual(["Maybe two"]);
  expect(tile("Needs human")).toHaveAttribute("aria-pressed", "true");
  expect(tile("Findings")).toHaveAttribute("aria-pressed", "false");
  expect(screen.getByText("3 triaged")).toBeInTheDocument();
  expect(screen.getByText("1 shown")).toBeInTheDocument();
  // The tile counts are totals, they do not shrink with the filter.
  expect(within(tile("Findings")).getByText("3", { selector: ".n" })).toBeInTheDocument();
  fireEvent.click(tile("Likely noise"));
  expect(rowTitles()).toEqual(["Noise three"]);
  expect(tile("Needs human")).toHaveAttribute("aria-pressed", "false");
});

test("the filter state is not announced with extra 'True positive' text", async () => {
  mockJson([item({ finding: { id: "a", title: "Only" }, verdict: "TRUE_POSITIVE" })]);
  render(<Harness initial="TRUE_POSITIVE" />);
  await screen.findByText("Only");
  expect(screen.getAllByText(/True positive/i)).toHaveLength(2); // the tile label and the row chip
  expect(screen.queryByText(/Showing only/i)).toBeNull();
});

test("clicking the pressed tile again, or the Findings tile, shows everything", async () => {
  mockJson(three());
  render(<Harness />);
  await screen.findByText("Real one");
  fireEvent.click(tile("True positive"));
  expect(rowTitles()).toEqual(["Real one"]);
  fireEvent.click(tile("True positive"));
  expect(rowTitles()).toHaveLength(3);
  expect(tile("Findings")).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(tile("Likely noise"));
  expect(rowTitles()).toEqual(["Noise three"]);
  fireEvent.click(tile("Findings"));
  expect(rowTitles()).toHaveLength(3);
});

test("the tile reports its verdict (or ALL) to the parent, which owns the filter", async () => {
  mockJson(three());
  const onChange = vi.fn();
  const { rerender } = render(<Findings verdictFilter="ALL" onVerdictFilterChange={onChange} />);
  await screen.findByText("Real one");
  fireEvent.click(tile("Needs human"));
  expect(onChange).toHaveBeenLastCalledWith("ABSTAIN");
  rerender(<Findings verdictFilter="ABSTAIN" onVerdictFilterChange={onChange} />);
  fireEvent.click(tile("Needs human"));
  expect(onChange).toHaveBeenLastCalledWith("ALL");
  fireEvent.click(tile("Findings"));
  expect(onChange).toHaveBeenLastCalledWith("ALL");
});

test("without a handler the tiles are plain statistics, not inert buttons", async () => {
  mockJson(three());
  const { container } = render(<Findings />);
  await screen.findByText("Real one");
  expect(container.querySelectorAll(".kpi-row .kpi")).toHaveLength(4);
  expect(container.querySelector(".kpi-row button")).toBeNull();
  expect(container.querySelector("[aria-pressed]")).toBeNull();
});

test("a verdict filter given from outside (an Overview tile) narrows the rows but not the tile counts", async () => {
  mockJson(three());
  render(<Findings verdictFilter="ABSTAIN" />);
  await screen.findByText("Maybe two");
  expect(rowTitles()).toEqual(["Maybe two"]);
  expect(within(tile("Findings")).getByText("3", { selector: ".n" })).toBeInTheDocument();
  expect(screen.getByText("1 shown")).toBeInTheDocument();
});

test("an unknown filter value is treated as ALL", async () => {
  mockJson(three());
  render(<Findings verdictFilter={"constructor" as never} />);
  await screen.findByText("Real one");
  expect(rowTitles()).toHaveLength(3);
  expect(screen.queryByText(/shown/)).toBeNull();
});

test("tile counts and the filter use one classification: an unknown verdict is Needs human in both", async () => {
  mockJson([
    ...three(),
    item({ finding: { id: "d", title: "Odd verdict" }, verdict: "SOMETHING_NEW" as never }),
    item({ finding: { id: "e", title: "Proto verdict" }, verdict: "constructor" as never }),
  ]);
  render(<Harness />);
  await screen.findByText("Real one");
  // 1 Needs human + 2 unknown = 3, the VerdictChip also reads them as Needs human.
  expect(within(tile("Needs human")).getByText("3", { selector: ".n" })).toBeInTheDocument();
  for (const [label, expected] of [
    ["True positive", 1],
    ["Needs human", 3],
    ["Likely noise", 1],
    ["Findings", 5],
  ] as const) {
    fireEvent.click(tile(label));
    const tileCount = Number(tile(label).querySelector(".n")?.textContent);
    expect(tileCount, label).toBe(expected);
    expect(rowTitles(), label).toHaveLength(tileCount);
  }
  fireEvent.click(tile("Needs human"));
  expect(rowTitles().sort()).toEqual(["Maybe two", "Odd verdict", "Proto verdict"]);
});

test("the query filters rows by title, rule id and location, case-insensitively", async () => {
  mockJson(three());
  render(<Findings query="  MAYBE " />);
  await screen.findByText("Maybe two");
  expect(rowTitles()).toEqual(["Maybe two"]);
  expect(screen.getByText("1 shown")).toBeInTheDocument();
});

test("the query matches rule id and location, and every term must match", async () => {
  mockJson(three());
  const { rerender } = render(<Findings query="rule/noise" />);
  await screen.findByText("Noise three");
  expect(rowTitles()).toEqual(["Noise three"]);
  rerender(<Findings query="/real" />);
  expect(rowTitles()).toEqual(["Real one"]);
  rerender(<Findings query="real noise" />);
  expect(rowTitles()).toEqual([]);
});

test("the query and a verdict filter combine; the tiles stay totals", async () => {
  mockJson([...three(), item({ finding: { id: "d", title: "Maybe four", url: "/four" }, verdict: "ABSTAIN", confidence: 0.3 })]);
  const { rerender } = render(<Findings query="maybe" verdictFilter="LIKELY_FALSE_POSITIVE" />);
  await screen.findByText("No findings match these filters");
  rerender(<Findings query="maybe" verdictFilter="ABSTAIN" />);
  expect(rowTitles().sort()).toEqual(["Maybe four", "Maybe two"]);
  expect(within(tile("Findings")).getByText("4", { selector: ".n" })).toBeInTheDocument();
  expect(screen.getByText("2 shown")).toBeInTheDocument();
});

test("a query is never treated as a pattern", async () => {
  mockJson(three());
  render(<Findings query=".*" />);
  expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
});

test("no match: a message and Clear filters, which resets the verdict filter and the search", async () => {
  mockJson(three());
  render(<Harness initial="TRUE_POSITIVE" initialQuery="zzz" />);
  expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  expect(screen.queryByRole("table")).toBeNull();
  // One reset, in the message: the header does not repeat it while the message is showing.
  const buttons = screen.getAllByRole("button", { name: "Clear filters" });
  expect(buttons).toHaveLength(1);
  expect(buttons[0].closest(".empty-state")).not.toBeNull();
  fireEvent.click(buttons[0]);
  expect(rowTitles()).toEqual(["Real one", "Maybe two", "Noise three"]);
  expect(screen.getByLabelText("q")).toHaveValue("");
  expect(tile("Findings")).toHaveAttribute("aria-pressed", "true");
  expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
});

test("Clear filters is offered in the header whenever a filter or a query is active, and only then", async () => {
  mockJson(three());
  const onClearFilters = vi.fn();
  const { rerender } = render(<Findings onClearFilters={onClearFilters} />);
  await screen.findByText("Real one");
  expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
  expect(screen.queryByText(/shown/)).toBeNull();
  rerender(<Findings verdictFilter="TRUE_POSITIVE" onClearFilters={onClearFilters} />);
  fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
  expect(onClearFilters).toHaveBeenCalledTimes(1);
  rerender(<Findings query="real" onClearFilters={onClearFilters} />);
  expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  // A whitespace-only query is not a filter.
  rerender(<Findings query="   " onClearFilters={onClearFilters} />);
  expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
});

test("without a handler a filtered table draws no inert Clear filters button", async () => {
  mockJson(three());
  render(<Findings verdictFilter="TRUE_POSITIVE" />);
  await screen.findByText("Real one");
  expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
});

test("a filter with no matching rows says so instead of showing an empty table", async () => {
  mockJson([item({ finding: { id: "a", title: "Real one" }, verdict: "TRUE_POSITIVE" })]);
  render(<Findings verdictFilter="LIKELY_FALSE_POSITIVE" />);
  expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.getByText("0 shown")).toBeInTheDocument();
});

test("the empty state offers to define a scan, only when it can navigate", async () => {
  mockJson([]);
  const onNavigate = vi.fn();
  const { container } = render(<Findings onNavigate={onNavigate} />);
  expect(await screen.findByText("No findings yet")).toBeInTheDocument();
  expect(screen.getByText("Define a scan, run it, and triaged findings land here.")).toBeInTheDocument();
  expect((container.querySelector(".mascot") as HTMLElement).style.width).toBe("160px");
  fireEvent.click(screen.getByRole("button", { name: "Define a new scan" }));
  expect(onNavigate).toHaveBeenCalledWith("newscan");
});

test("the empty state has no button when nothing can navigate", async () => {
  mockJson([]);
  render(<Findings />);
  await screen.findByText("No findings yet");
  expect(screen.queryByRole("button", { name: "Define a new scan" })).toBeNull();
});

test("a query over no findings at all is still the plain empty state", async () => {
  mockJson([]);
  render(<Findings query="anything" />);
  expect(await screen.findByText("No findings yet")).toBeInTheDocument();
  expect(screen.queryByText("No findings match these filters")).toBeNull();
});

test("the loading state is a skeleton card announced as a status with a visible caption", async () => {
  vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise<Response>(() => {}));
  const { container } = render(<Findings />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading findings…");
  expect(container.querySelectorAll(".skeleton").length).toBeGreaterThanOrEqual(3);
});

test("the error state is a single alert with the fixed copy and a working Retry", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: "<b>leaky detail</b>" }), { status: 500 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(three())));
  render(<Findings />);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load findings");
  expect(alert).toHaveTextContent("Check that the Ascent backend is running.");
  expect(alert).not.toHaveTextContent("leaky");
  expect(screen.getAllByRole("alert")).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("Real one")).toBeInTheDocument();
});

test("the table keeps real table semantics and fixed data-label cells for the mobile cards", async () => {
  mockJson(three());
  render(<Findings />);
  await screen.findByText("Real one");
  const table = screen.getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
    "Finding",
    "Severity",
    "Confidence",
    "Verdict",
    "Location",
    "Mapping",
  ]);
  const cells = within(within(table).getAllByRole("row")[1]).getAllByRole("cell");
  expect(cells.map((c) => c.getAttribute("data-label"))).toEqual([null, "Severity", "Confidence", "Verdict", "Location", "Mapping"]);
});

test("rows do nothing on click, so they carry no click handler or button semantics", async () => {
  mockJson(three());
  render(<Findings />);
  await screen.findByText("Real one");
  const row = within(screen.getByRole("table")).getAllByRole("row")[1];
  expect(row).not.toHaveAttribute("tabindex");
  expect(row).not.toHaveAttribute("onclick");
  expect(within(screen.getByRole("table")).queryByRole("button")).toBeNull();
});

test("the section is labelled by its Findings heading with the triaged count", async () => {
  mockJson(three());
  render(<Findings />);
  await screen.findByText("Real one");
  const heading = screen.getByRole("heading", { level: 2, name: "Findings" });
  expect(screen.getByRole("region", { name: "Findings" })).toContainElement(heading);
  expect(screen.getByText("3 triaged")).toBeInTheDocument();
});

test("a new version refetches and swaps the rows in place", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify([item({ finding: { id: "a", title: "Old row" } })])))
    .mockResolvedValueOnce(new Response(JSON.stringify([item({ finding: { id: "b", title: "New row" } })])));
  const { rerender } = render(<Findings version={0} />);
  await screen.findByText("Old row");
  rerender(<Findings version={1} />);
  expect(screen.getByText("Old row")).toBeInTheDocument(); // no loading flash
  expect(await screen.findByText("New row")).toBeInTheDocument();
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
