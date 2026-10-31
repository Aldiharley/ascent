import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { RESOURCE_KEYS } from "../data/resources";
import type { ResourceKey } from "../data/resources";
import { Overview } from "./Overview";
import type { OverviewProps } from "./Overview";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function finding(id: string, over: Record<string, unknown> = {}, verdict = "TRUE_POSITIVE", confidence = 0.9) {
  return {
    finding: { id, rule_id: `rule-${id}`, severity: "HIGH", title: `Title ${id}`, url: `http://lab/${id}`, tool: "nuclei", category: "DAST", ...over },
    verdict,
    confidence,
    fp_likelihood: 0.1,
  };
}

const gate = { id: "g1", title: "Confirm SSRF", why: "w", command: "nuclei ...", target: "/x", in_scope: true };

type Routes = Record<string, () => Response | Promise<Response>>;

function mockApi(overrides: Routes = {}) {
  const routes: Routes = {
    "/api/findings": () => json([finding("a")]),
    "/api/gates": () => json([gate]),
    "/api/audit": () => json({ entries: [], chain_ok: true }),
    "/api/gate": () => json(null),
    "/api/report": () => json({ markdown: "## Report body" }),
    "/api/engagement": () => json({ name: "ascent-local-lab" }),
    ...overrides,
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const route = routes[String(input)];
    if (!route) throw new Error(`unmocked fetch: ${String(input)}`);
    return route();
  });
}

const zeroVersions = Object.fromEntries(RESOURCE_KEYS.map((k) => [k, 0])) as Record<ResourceKey, number>;

function overview(over: Partial<OverviewProps> = {}) {
  const props: OverviewProps = {
    versions: zeroVersions,
    query: "",
    onClearQuery: vi.fn(),
    onNavigate: vi.fn(),
    onOpenFindings: vi.fn(),
    onDecided: vi.fn(),
    ...over,
  };
  const r = render(<Overview {...props} />);
  return { ...r, props };
}

function card(title: string): HTMLElement {
  return screen.getByRole("heading", { level: 2, name: title }).closest("section") as HTMLElement;
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ---- layout and composition ----

test("lays out hero, KPI row, policy card, charts, three list cards and the banner", async () => {
  mockApi();
  const { container } = overview();
  expect(await screen.findByText("Title a")).toBeInTheDocument();
  expect(container.querySelector(".hero")).not.toBeNull();
  expect(container.querySelectorAll(".kpi-row .kpi")).toHaveLength(4);
  expect(await screen.findByRole("heading", { level: 2, name: "Policy gate" })).toHaveAttribute("id", "policy-gate-title");
  expect(screen.getByRole("heading", { level: 2, name: "Findings by severity" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 2, name: "Verdict mix" })).toBeInTheDocument();
  for (const t of ["Top findings", "Approval required", "Recent audit"]) {
    expect(screen.getByRole("heading", { level: 2, name: t })).toBeInTheDocument();
  }
  expect(await screen.findByText("Your report is ready")).toBeInTheDocument();
});

test("there is no <img> anywhere on the Overview", async () => {
  mockApi();
  const { container } = overview();
  await screen.findByText("Title a");
  expect(container.querySelector("img")).toBeNull();
});

test("each shared endpoint is fetched once, however many cards read it", async () => {
  const spy = mockApi();
  overview();
  await screen.findByText("Title a");
  await screen.findByText("Your report is ready");
  await screen.findByRole("heading", { level: 2, name: "Policy gate" });
  const count = (p: string) => spy.mock.calls.filter((c) => String(c[0]) === p).length;
  for (const p of ["/api/findings", "/api/gates", "/api/gate", "/api/audit", "/api/report", "/api/engagement"]) {
    expect(count(p), p).toBe(1);
  }
});

// ---- hero ----

test("the hero names the engagement and summarises only loaded facts", async () => {
  mockApi({
    "/api/findings": () => json([finding("a", {}, "ABSTAIN", 0.4), finding("b", {}, "ABSTAIN", 0.3), finding("c")]),
    "/api/gate": () =>
      json({ policy: { name: "ci", hash: "ab" }, decision: "FAIL", exit_code: 1, complete: true, counts: { evaluated: 1, failed: 1, warned: 0, demoted_fp: 0 }, failed: [], warned: [] }),
  });
  const { container } = overview();
  await screen.findByText("Watching", { exact: false });
  await waitFor(() =>
    expect(container.querySelector(".hero-sum")).toHaveTextContent("2 need your review · 1 approval pending · policy FAIL"),
  );
  expect(container.querySelector(".hero-eng")).toHaveTextContent("Watching ascent-local-lab");
  expect(container.querySelector(".hero")?.textContent).not.toMatch(/Title|Confirm SSRF/);
});

test("with no engagement the hero says to define a scope", async () => {
  mockApi({ "/api/engagement": () => json(null) });
  overview();
  expect(await screen.findByText("Define a scope to get started.")).toBeInTheDocument();
});

test("a failed engagement fetch drops the line without an error banner", async () => {
  mockApi({ "/api/engagement": () => json({}, 500) });
  const { container } = overview();
  await screen.findByText("Title a");
  expect(container.querySelector(".hero-eng")).toBeNull();
  expect(screen.queryByText("Could not load the engagement")).toBeNull();
});

test("hero CTAs navigate", async () => {
  mockApi();
  const { props } = overview();
  fireEvent.click(await screen.findByRole("button", { name: "Define a new scan" }));
  expect(props.onNavigate).toHaveBeenCalledWith("newscan");
  fireEvent.click(await screen.findByRole("button", { name: "Review approvals" }));
  expect(props.onNavigate).toHaveBeenLastCalledWith("gates");
});

// ---- KPI row ----

const mix = () => [
  finding("a", { tool: "nuclei" }, "TRUE_POSITIVE"),
  finding("b", { tool: "opengrep" }, "TRUE_POSITIVE"),
  finding("c", { tool: "nuclei" }, "ABSTAIN", 0.4),
  finding("d", { tool: "nuclei" }, "LIKELY_FALSE_POSITIVE", 0.7),
];

function tile(label: string): HTMLElement {
  return screen.getByText(label, { selector: ".kpi .l" }).closest(".kpi") as HTMLElement;
}

test("the four tiles show totals, shares and the exact sub-lines", async () => {
  mockApi({ "/api/findings": () => json(mix()) });
  overview();
  await screen.findByText("Title a");
  const t = (label: string) => {
    const el = tile(label);
    return [el.querySelector(".n")?.textContent, el.querySelector(".sub")?.textContent];
  };
  expect(t("Findings")).toEqual(["4", "from 2 scanners"]);
  expect(t("True positive")).toEqual(["2", "50% · confirmed by triage"]);
  expect(t("Needs human")).toEqual(["1", "25% · awaiting your review"]);
  expect(t("Likely noise")).toEqual(["1", "25% · cut by Crux"]);
});

test("without scanner names the first tile falls back to 'triaged by Crux'", async () => {
  mockApi({ "/api/findings": () => json([finding("a", { tool: undefined })]) });
  overview();
  await screen.findByText("Title a");
  expect(tile("Findings").querySelector(".sub")).toHaveTextContent("triaged by Crux");
});

test("tiles are buttons that open Findings with the matching filter", async () => {
  mockApi({ "/api/findings": () => json(mix()) });
  const { props } = overview();
  await screen.findByText("Title a");
  const cases: [string, string][] = [
    ["Findings", "ALL"],
    ["True positive", "TRUE_POSITIVE"],
    ["Needs human", "ABSTAIN"],
    ["Likely noise", "LIKELY_FALSE_POSITIVE"],
  ];
  for (const [label, filter] of cases) {
    fireEvent.click(tile(label));
    expect(props.onOpenFindings).toHaveBeenLastCalledWith(filter);
  }
  expect(tile("Findings").tagName).toBe("BUTTON");
  expect(tile("Findings")).not.toHaveAttribute("aria-pressed");
});

test("an empty findings list gives zero tiles, 0% shares and empty charts", async () => {
  mockApi({ "/api/findings": () => json([]) });
  const { container } = overview();
  await waitFor(() => expect(tile("Findings").querySelector(".n")).toHaveTextContent("0"));
  expect(tile("True positive").querySelector(".sub")).toHaveTextContent("0% · confirmed by triage");
  expect(container.querySelectorAll("circle.donut-seg")).toHaveLength(0);
  expect(screen.getAllByText("No findings yet").length).toBeGreaterThanOrEqual(2);
});

test("while findings load: skeleton tiles under one status, no buttons", () => {
  vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise<Response>(() => {}));
  const { container } = overview();
  expect(container.querySelectorAll(".kpi-row .kpi")).toHaveLength(4);
  expect(container.querySelectorAll(".kpi-row .skeleton").length).toBeGreaterThan(0);
  expect(screen.getAllByRole("status").some((s) => /Loading findings/.test(s.textContent ?? ""))).toBe(true);
  expect(container.querySelector(".kpi-row button.kpi")).toBeNull();
});

test("when findings fail: four error cards but only the KPI row's announces, and Retry recovers all", async () => {
  let fail = true;
  mockApi({ "/api/findings": () => (fail ? json({}, 500) : json([finding("a")])) });
  const { container } = overview();
  await waitFor(() => expect(screen.getAllByText("Could not load findings")).toHaveLength(4));
  // One resource, one announcement: the first card (the KPI row) is the alert, the others are quiet.
  // (The Approval card's always-mounted, empty toast alert region is not a load error.)
  const alerts = screen.getAllByRole("alert").filter((a) => /Could not load/.test(a.textContent ?? ""));
  expect(alerts).toHaveLength(1);
  expect(alerts[0]).toHaveTextContent("Could not load findings");
  expect(container.querySelector(".grid > :nth-child(2)")).toContainElement(alerts[0]);
  expect(screen.getAllByRole("button", { name: "Retry" })).toHaveLength(4);
  expect(screen.queryByRole("heading", { level: 2, name: "Findings by severity" })).toBeNull();
  fail = false;
  fireEvent.click(screen.getAllByRole("button", { name: "Retry" })[0]);
  expect(await screen.findByText("Title a")).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 2, name: "Findings by severity" })).toBeInTheDocument();
  expect(screen.queryByText("Could not load findings")).toBeNull();
});

test("with the backend down there is one alert per resource, not one per card", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json({}, 500));
  overview();
  await waitFor(() => expect(screen.getAllByText("Could not load findings")).toHaveLength(4));
  await screen.findByText("Could not load approval gates");
  await screen.findByText("Could not load the audit log");
  await screen.findByText("Could not load the policy gate");
  // findings (KPI row), approval gates, audit log, policy gate: the engagement and the report fail quietly.
  expect(screen.getAllByRole("alert")).toHaveLength(4);
});

// ---- card entrance (spec 1.9) ----

test("the grid cells enter once, staggered by grid order (the stylesheet caps the stagger at six)", async () => {
  mockApi();
  const { container } = overview();
  await screen.findByText("Title a");
  const cells = Array.from(container.querySelectorAll(".grid > *"));
  expect(cells.length).toBeGreaterThanOrEqual(8);
  for (const cell of cells) expect(cell).toHaveClass("card--enter");
});

// ---- charts ----

test("the bar chart and donut read the same findings", async () => {
  mockApi({ "/api/findings": () => json(mix()) });
  overview();
  await screen.findByText("Title a");
  expect(screen.getByRole("img", { name: "Findings by severity: Critical 0, High 4, Medium 0, Low 0, Info 0" })).toBeInTheDocument();
  expect(screen.getByRole("img", { name: "Verdict mix: True positive 2, Needs human 1, Likely noise 1" })).toBeInTheDocument();
});

// ---- top findings ----

test("top findings: TP first, then needs-human, then noise; at most 5; one line each", async () => {
  const rows = [
    finding("n1", {}, "LIKELY_FALSE_POSITIVE", 0.99),
    finding("h1", {}, "ABSTAIN", 0.4),
    finding("t1", {}, "TRUE_POSITIVE", 0.6),
    finding("t2", {}, "TRUE_POSITIVE", 0.95),
    finding("h2", {}, "ABSTAIN", 0.8),
    finding("n2", {}, "LIKELY_FALSE_POSITIVE", 0.5),
    finding("t3", {}, "TRUE_POSITIVE", 0.7),
  ];
  mockApi({ "/api/findings": () => json(rows) });
  overview();
  await screen.findByText("Title t2");
  const list = card("Top findings");
  const titles = [...list.querySelectorAll(".row-title")].map((n) => n.textContent);
  expect(titles).toEqual(["Title t2", "Title t3", "Title t1", "Title h2", "Title h1"]);
  expect(within(list).getByText("7 triaged")).toBeInTheDocument();
  const first = list.querySelector(".list-row") as HTMLElement;
  expect(first.querySelector(".row-title")).toHaveAttribute("title", "Title t2");
  expect(first.querySelector(".row-meta")).toHaveTextContent("rule-t2");
  expect(first.querySelector(".sev-chip")).toHaveTextContent("HIGH");
  expect(first.querySelector(".vchip")).toHaveTextContent("True positive");
  // Rows are not interactive.
  expect(within(list).queryAllByRole("button").map((b) => b.textContent)).toEqual(["See all findings"]);
});

test("top findings: See all opens Findings", async () => {
  mockApi();
  const { props } = overview();
  await screen.findByText("Title a");
  fireEvent.click(screen.getByRole("button", { name: "See all findings" }));
  expect(props.onNavigate).toHaveBeenCalledWith("findings");
});

test("top findings respects the search query and says how many match", async () => {
  mockApi({
    "/api/findings": () => json([finding("a", { title: "SSRF in fetch" }), finding("b", { title: "SQL injection" }), finding("c", { title: "SSRF again" })]),
  });
  overview({ query: "ssrf" });
  await screen.findByText("SSRF in fetch");
  const list = card("Top findings");
  expect(within(list).getByText("SSRF again")).toBeInTheDocument();
  expect(within(list).queryByText("SQL injection")).toBeNull();
  expect(within(list).getByText("2 of 3 match")).toBeInTheDocument();
});

test("the query filters before the cut to 5", async () => {
  const rows = Array.from({ length: 8 }, (_, i) =>
    finding(`x${i}`, { title: i < 6 ? `Other ${i}` : `Needle ${i}` }, i < 6 ? "TRUE_POSITIVE" : "LIKELY_FALSE_POSITIVE"),
  );
  mockApi({ "/api/findings": () => json(rows) });
  overview({ query: "needle" });
  await screen.findByText("Needle 6");
  expect(screen.getByText("Needle 7")).toBeInTheDocument();
  expect(screen.getByText("2 of 8 match")).toBeInTheDocument();
});

test("a query with no match shows it as text with a Clear search button", async () => {
  mockApi();
  const evil = "<img src=x onerror=alert(1)>";
  const { props, container } = overview({ query: evil });
  expect(await screen.findByText(`No findings match “${evil}”`)).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByText("0 of 1 match")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
  expect(props.onClearQuery).toHaveBeenCalledTimes(1);
});

test("a blank query filters nothing", async () => {
  mockApi();
  overview({ query: "   " });
  await screen.findByText("Title a");
  expect(screen.getByText("1 triaged")).toBeInTheDocument();
});

test("top findings empty state", async () => {
  mockApi({ "/api/findings": () => json([]) });
  overview();
  await waitFor(() => expect(within(card("Top findings")).getByText("No findings yet")).toBeInTheDocument());
});

// ---- pending approvals ----

test("pending approvals is the compact Gates card, and deciding reports upward", async () => {
  mockApi({ "/api/gates/g1/approve": () => json({ ok: true }) });
  const { props } = overview();
  const gates = await screen.findByRole("heading", { level: 2, name: "Approval required" });
  expect(within(gates.closest("section") as HTMLElement).getByText("1 pending")).toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  await waitFor(() => expect(props.onDecided).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("button", { name: "See all approval gates" }));
  expect(props.onNavigate).toHaveBeenCalledWith("gates");
});

// ---- recent audit ----

test("recent audit: the last 5 entries, newest first, with the chain chip", async () => {
  const entries = Array.from({ length: 7 }, (_, i) => ({ type: "gate_decision", gate_id: `g${i}`, decision: "approved", entry_hash: `h${i}` }));
  mockApi({ "/api/audit": () => json({ entries, chain_ok: true }) });
  overview();
  await screen.findByText("Hash chain OK");
  const rows = [...card("Recent audit").querySelectorAll(".audit-row")];
  expect(rows.map((r) => r.querySelector(".audit-line")?.textContent)).toEqual([
    "Human decision · gate g6 → approved",
    "Human decision · gate g5 → approved",
    "Human decision · gate g4 → approved",
    "Human decision · gate g3 → approved",
    "Human decision · gate g2 → approved",
  ]);
  expect(rows[0]).toHaveClass("audit-row--compact");
  expect(screen.getByText("Hash chain OK")).toHaveAttribute("role", "status");
});

test("recent audit: a broken chain is the alarming alert", async () => {
  mockApi({ "/api/audit": () => json({ entries: [], chain_ok: false }) });
  overview();
  const chip = await screen.findByText("Hash chain FAIL: log may have been tampered with");
  expect(chip).toHaveAttribute("role", "alert");
  expect(chip).toHaveClass("chain-fail");
});

test("recent audit: empty text, See all opens the Audit screen", async () => {
  mockApi();
  const { props } = overview();
  expect(await screen.findByText("No audit entries yet")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "See all audit entries" }));
  expect(props.onNavigate).toHaveBeenCalledWith("audit");
});

test("recent audit: a failure is a card alert with Retry", async () => {
  let fail = true;
  mockApi({ "/api/audit": () => (fail ? json({}, 500) : json({ entries: [], chain_ok: true })) });
  overview();
  expect(await screen.findByText("Could not load the audit log")).toBeInTheDocument();
  fail = false;
  fireEvent.click(within(screen.getByText("Could not load the audit log").closest("section") as HTMLElement).getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
});

// ---- report banner ----

test("the banner offers the report when there is one", async () => {
  mockApi();
  const { props } = overview();
  expect(await screen.findByText("Your report is ready")).toBeInTheDocument();
  expect(screen.getByText("Findings, the policy verdict and DAST coverage in one markdown report.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Open report" }));
  expect(props.onNavigate).toHaveBeenCalledWith("report");
});

test("an empty report points to New scan instead", async () => {
  mockApi({ "/api/report": () => json({ markdown: "  \n" }) });
  const { props, container } = overview();
  expect(await screen.findByText("No report yet")).toBeInTheDocument();
  expect(container.querySelector(".banner-sub code")).toHaveTextContent("ascent run");
  expect(container.querySelector(".banner-sub")).toHaveTextContent("Run ascent run on a defined scope and the report lands here.");
  expect(screen.queryByRole("button", { name: "Open report" })).toBeNull();
  const ctas = screen.getAllByRole("button", { name: "Define a new scan" });
  fireEvent.click(ctas[ctas.length - 1]);
  expect(props.onNavigate).toHaveBeenLastCalledWith("newscan");
});

test("the banner is omitted when the report cannot be loaded", async () => {
  mockApi({ "/api/report": () => json({}, 500) });
  const { container } = overview();
  await screen.findByText("Title a");
  await waitFor(() => expect(spyCalled("/api/report")).toBe(true));
  expect(container.querySelector(".banner")).toBeNull();
  expect(screen.queryByText("Could not load the report")).toBeNull();
  // ...and it leaves no empty grid cell behind (an empty cell still adds a row gap).
  const cells = Array.from(container.querySelectorAll(".grid > *"));
  expect(cells.length).toBeGreaterThan(0);
  for (const cell of cells) expect(cell.childElementCount, cell.className).toBeGreaterThan(0);
});

function spyCalled(path: string): boolean {
  return (globalThis.fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls.some((c) => String(c[0]) === path);
}

test("the report text itself never appears on the Overview", async () => {
  mockApi();
  overview();
  await screen.findByText("Your report is ready");
  expect(screen.queryByText("Report body")).toBeNull();
});

// ---- isolation and refresh ----

test("a crash in the approvals card leaves everything else working", async () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  mockApi({ "/api/gates": () => json([{ ...gate, title: { not: "text" } }]) });
  overview();
  expect(await screen.findByText("Title a")).toBeInTheDocument();
  expect(await screen.findAllByText("This view failed to render.")).toHaveLength(1);
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
});

test("a crash in top findings is contained to that card", async () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  mockApi({ "/api/findings": () => json([finding("a", { title: { not: "text" } })]) });
  overview();
  expect(await screen.findAllByText("This view failed to render.")).toHaveLength(1);
  expect(screen.getByRole("heading", { level: 2, name: "Findings by severity" })).toBeInTheDocument();
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
});

test("bumping versions swaps the data in place instead of remounting", async () => {
  let n = 0;
  mockApi({ "/api/findings": () => json([finding(n++ === 0 ? "old" : "new")]) });
  const { rerender, props } = overview();
  await screen.findByText("Title old");
  const heading = screen.getByRole("heading", { level: 2, name: "Findings by severity" });
  rerender(<Overview {...props} versions={{ ...zeroVersions, findings: 1 }} />);
  // The old payload stays until the new one lands, and the cards are not remounted.
  expect(screen.getByText("Title old")).toBeInTheDocument();
  expect(await screen.findByText("Title new")).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 2, name: "Findings by severity" })).toBe(heading);
});

test("a decision empties the hero summary and the Approval card together, even if the refetch is stale", async () => {
  let reads = 0;
  mockApi({
    // stale: every later read still lists the decided gate, next to a genuinely new one
    "/api/gates": () => json(reads++ === 0 ? [gate] : [gate, { ...gate, id: "g2", title: "Confirm XSS" }]),
    "/api/gates/g1/approve": () => json({ ok: true }),
  });
  const { container, props, rerender } = overview();
  await waitFor(() => expect(container.querySelector(".hero-sum")).toHaveTextContent("1 approval pending"));
  expect(screen.getByText("1 pending")).toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  expect(await screen.findByText("0 pending")).toBeInTheDocument();
  await waitFor(() => expect(container.querySelector(".hero-sum")?.textContent ?? "").not.toMatch(/approval/));
  expect(screen.queryByRole("button", { name: "Review approvals" })).toBeNull();
  expect(props.onDecided).toHaveBeenCalledTimes(1);

  // `App` answers onDecided with a refetch; the stale answer must not bring the decided gate back.
  rerender(<Overview {...props} versions={{ ...zeroVersions, gates: 1 }} />);
  expect(await screen.findByRole("heading", { name: "Confirm XSS" })).toBeInTheDocument();
  expect(reads).toBe(2);
  expect(screen.queryByRole("heading", { name: "Confirm SSRF" })).toBeNull();
  expect(screen.getByText("1 pending")).toBeInTheDocument();
  expect(container.querySelector(".hero-sum")).toHaveTextContent("1 approval pending");
});
