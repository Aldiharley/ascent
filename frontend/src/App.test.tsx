import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import App from "./App";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

const finding = {
  finding: { id: "f1", rule_id: "ssrf-1", severity: "HIGH", title: "SSRF in fetch", url: "http://lab/x" },
  verdict: "TRUE_POSITIVE",
  confidence: 0.9,
  fp_likelihood: 0.1,
};

const gate = {
  id: "g1",
  title: "Confirm SSRF",
  why: "w",
  command: "nuclei ...",
  target: "/x",
  in_scope: true,
};

/** Routes fetch by URL path; `overrides` replaces a route (a function result is used as the Response). */
function mockApi(overrides: Record<string, () => Response | Promise<Response>> = {}) {
  const routes: Record<string, () => Response | Promise<Response>> = {
    "/api/findings": () => json([finding]),
    "/api/gates": () => json([gate]),
    "/api/audit": () => json({ entries: [], chain_ok: true }),
    "/api/gate": () => json(null),
    "/api/report": () => json({ markdown: "## Report body" }),
    "/api/engagement": () => json({ name: "ascent-local-lab" }),
    ...overrides,
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input);
    const route = routes[path];
    if (!route) throw new Error(`unmocked fetch: ${path}`);
    return route();
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("overview shows the top findings and the pending approvals", async () => {
  mockApi();
  render(<App />);
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  expect(await screen.findByText("Approval required")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Overview" })).toHaveAttribute("aria-current", "page");
});

test("overview also shows the recent audit card", async () => {
  mockApi();
  render(<App />);
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
});

test("rail switches to gates", async () => {
  mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.click(screen.getByRole("button", { name: "Approval gates" }));
  expect(await screen.findByText("Approval required")).toBeInTheDocument();
  expect(screen.queryByText("SSRF in fetch")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approval gates" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("button", { name: "Overview" })).not.toHaveAttribute("aria-current");
});

test("rail switches to the audit screen and shows the chain badge", async () => {
  mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
  expect(screen.queryByText("SSRF in fetch")).not.toBeInTheDocument();
});

test("rail switches to findings and report screens", async () => {
  mockApi();
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Report" }));
  expect(await screen.findByText("Report body")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  expect(screen.queryByText("Approval required")).not.toBeInTheDocument();
});

test("topbar shows the engagement name", async () => {
  mockApi();
  render(<App />);
  expect(await screen.findByText(/engagement: ascent-local-lab/)).toBeInTheDocument();
});

test("topbar falls back to a neutral status when the engagement is null", async () => {
  mockApi({ "/api/engagement": () => json(null) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  expect(screen.getByText(/no engagement loaded/)).toBeInTheDocument();
});

test("topbar falls back to a neutral status when the engagement fetch fails", async () => {
  mockApi({ "/api/engagement": () => json({ error: "x" }, 500) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  await waitFor(() => expect(screen.getByText(/no engagement loaded/)).toBeInTheDocument());
});

test("a failed engagement refetch keeps the last known name", async () => {
  let calls = 0;
  mockApi({
    "/api/engagement": () => (++calls === 1 ? json({ name: "ascent-local-lab" }) : json({ error: "x" }, 500)),
    "/api/engagements": () =>
      json({
        ok: true,
        name: "Acme",
        path: "engagements/acme.yaml",
        scope: { hosts: ["example.com"], cidrs: [], urls: [] },
        source: "",
        dast: { profile: "standard", auth_header: "" },
        run_command: "ascent run --engagement engagements/acme.yaml --out out",
      }),
  });
  render(<App />);
  expect(await screen.findByText(/engagement: ascent-local-lab/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "New scan" }));
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "example.com" } });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();

  // The creation bumped the engagement key; its refetch failed (second call).
  await waitFor(() => expect(calls).toBeGreaterThanOrEqual(2));
  expect(screen.getByText(/engagement: ascent-local-lab/)).toBeInTheDocument();
  expect(screen.queryByText(/no engagement loaded/)).not.toBeInTheDocument();
});

test("deciding a gate refreshes the audit feed", async () => {
  let decided = false;
  mockApi({
    "/api/gates/g1/approve": () => {
      decided = true;
      return json({ ok: true });
    },
    "/api/audit": () =>
      json({
        entries: decided ? [{ type: "gate_decision", gate_id: "g1", decision: "approved", entry_hash: "abc" }] : [],
        chain_ok: true,
      }),
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  expect(await screen.findByText(/gate g1 → approved/)).toBeInTheDocument();
});

const failGate = {
  policy: { name: "ci", hash: "abcdef0123456789" },
  decision: "FAIL",
  exit_code: 1,
  complete: true,
  counts: { evaluated: 1, failed: 1, warned: 0, demoted_fp: 0 },
  failed: [],
  warned: [],
};

function h1Name() {
  return screen.getByRole("heading", { level: 1 }).textContent;
}

function calls(spy: ReturnType<typeof mockApi>, path: string) {
  return spy.mock.calls.filter((c) => String(c[0]) === path).length;
}

test("the page title follows the screen", async () => {
  mockApi();
  render(<App />);
  expect(h1Name()).toBe("Ascent Console: Overview");
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  expect(h1Name()).toBe("Ascent Console: Audit log");
  await screen.findByText("Hash chain OK");
});

test("search Enter on another screen opens Findings and keeps the query", async () => {
  mockApi();
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  await screen.findByText("Hash chain OK");
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  fireEvent.change(box, { target: { value: "ssrf" } });
  // Typing alone does not leave the Audit screen.
  expect(h1Name()).toBe("Ascent Console: Audit log");
  fireEvent.submit(screen.getByRole("search"));
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  expect(h1Name()).toBe("Ascent Console: Findings");
  expect(screen.getByRole("button", { name: "Findings" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveValue("ssrf");
});

test("the bell shows the pending count and opens Approval gates", async () => {
  mockApi();
  render(<App />);
  const bell = await screen.findByRole("button", { name: "Pending approvals: 1" });
  expect(within(screen.getByRole("button", { name: "Approval gates" })).getByText("1")).toBeInTheDocument();
  fireEvent.click(bell);
  expect(await screen.findByText("Confirm SSRF")).toBeInTheDocument();
  expect(h1Name()).toBe("Ascent Console: Approval gates");
  expect(screen.getByRole("button", { name: "Approval gates" })).toHaveAttribute("aria-current", "page");
  expect(screen.queryByText("SSRF in fetch")).not.toBeInTheDocument();
});

test("deciding a gate on the Approval gates screen updates the bell", async () => {
  let decided = false;
  mockApi({
    "/api/gates": () => json(decided ? [] : [gate]),
    "/api/gates/g1/approve": () => {
      decided = true;
      return json({ ok: true });
    },
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Pending approvals: 1" }));
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  expect(await screen.findByRole("button", { name: "Pending approvals: 0" })).toBeInTheDocument();
});

test("Refresh data refetches what the shell and the visible screen read", async () => {
  const spy = mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  await screen.findByRole("button", { name: "Pending approvals: 1" });
  await waitFor(() => expect(calls(spy, "/api/engagement")).toBe(1));
  const before = {
    engagement: calls(spy, "/api/engagement"),
    gates: calls(spy, "/api/gates"),
    gate: calls(spy, "/api/gate"),
    findings: calls(spy, "/api/findings"),
    audit: calls(spy, "/api/audit"),
  };
  fireEvent.click(screen.getByRole("button", { name: "Refresh data" }));
  await waitFor(() => {
    expect(calls(spy, "/api/engagement")).toBe(before.engagement + 1);
    expect(calls(spy, "/api/gates")).toBeGreaterThan(before.gates);
    expect(calls(spy, "/api/gate")).toBeGreaterThan(before.gate);
    expect(calls(spy, "/api/findings")).toBe(before.findings + 1);
    expect(calls(spy, "/api/audit")).toBe(before.audit + 1);
  });
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  // Busy ends once everything has landed.
  await waitFor(() => expect(screen.getByRole("button", { name: "Refresh data" })).not.toHaveAttribute("aria-busy"));
});

test("the sidebar policy card shows the read-only verdict from /api/gate", async () => {
  mockApi({ "/api/gate": () => json(failGate) });
  render(<App />);
  const nav = screen.getByRole("navigation", { name: "Primary" });
  expect(await within(nav).findByText("exit 1 · ci")).toBeInTheDocument();
  expect(within(nav).getByText("FAIL")).toHaveClass("vpill");
});

test("the sidebar policy card says so when no policy has been evaluated", async () => {
  mockApi({ "/api/gate": () => json(null) });
  render(<App />);
  const nav = screen.getByRole("navigation", { name: "Primary" });
  expect(await within(nav).findByText("No verdict yet")).toBeInTheDocument();
});

test("the sidebar policy card is omitted when /api/gate fails to load", async () => {
  mockApi({ "/api/gate": () => json({ error: "x" }, 500) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  await screen.findByText("Could not load the policy gate");
  const nav = screen.getByRole("navigation", { name: "Primary" });
  expect(within(nav).queryByText("Policy gate")).not.toBeInTheDocument();
});

test("View verdict returns to Overview and focuses the policy card heading", async () => {
  mockApi({ "/api/gate": () => json(failGate) });
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  fireEvent.click(await screen.findByRole("button", { name: "View verdict" }));
  expect(h1Name()).toBe("Ascent Console: Overview");
  await waitFor(() => expect(document.getElementById("policy-gate-title")).toHaveFocus());
});

test("a crash in the approvals card leaves the findings list working", async () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  // An object title is not a valid React child, so the Gates panel throws on render.
  mockApi({ "/api/gates": () => json([{ ...gate, title: { not: "text" } }]) });
  render(<App />);
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  expect(await screen.findByText("This view failed to render.")).toBeInTheDocument();
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
});

test("a crashed screen does not leak its fallback into the next screen", async () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  // An object title is not a valid React child, so the Findings view throws on render.
  mockApi({
    "/api/findings": () => json([{ ...finding, finding: { ...finding.finding, title: { not: "text" } } }]),
  });
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  expect(await screen.findByText("This view failed to render.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Approval gates" }));
  expect(await screen.findByText("Confirm SSRF")).toBeInTheDocument();
  expect(screen.queryByText("This view failed to render.")).not.toBeInTheDocument();
});

// ---- Overview navigation paths (spec 7.1) ----

const noise = {
  finding: { id: "f2", rule_id: "xss-2", severity: "LOW", title: "Reflected XSS", url: "http://lab/y" },
  verdict: "LIKELY_FALSE_POSITIVE",
  confidence: 0.7,
  fp_likelihood: 0.6,
};
const unsure = {
  finding: { id: "f3", rule_id: "redir-3", severity: "MEDIUM", title: "Open redirect", url: "http://lab/z" },
  verdict: "ABSTAIN",
  confidence: 0.4,
  fp_likelihood: 0.3,
};

test("the hero CTA opens New scan and the hero never uses the sidebar chip's phrases", async () => {
  mockApi();
  render(<App />);
  const hero = (await screen.findByRole("region", { name: "Welcome" })) as HTMLElement;
  await within(hero).findByText(/Watching/);
  expect(hero.textContent).not.toMatch(/engagement:|no engagement loaded/);
  fireEvent.click(within(hero).getByRole("button", { name: "Define a new scan" }));
  expect(h1Name()).toBe("Ascent Console: New scan");
  expect(screen.getByRole("button", { name: "New scan" })).toHaveAttribute("aria-current", "page");
});

test("the hero's Review approvals and the Approval required See all both open Approval gates", async () => {
  mockApi();
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Review approvals" }));
  expect(h1Name()).toBe("Ascent Console: Approval gates");
  fireEvent.click(screen.getByRole("button", { name: "Overview" }));
  fireEvent.click(await screen.findByRole("button", { name: "See all approval gates" }));
  expect(h1Name()).toBe("Ascent Console: Approval gates");
});

test("a KPI tile opens Findings narrowed to that verdict, and Clear filters lifts it", async () => {
  mockApi({ "/api/findings": () => json([finding, noise, unsure]) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  const tile = screen.getByText("Needs human", { selector: ".kpi .l" }).closest("button") as HTMLElement;
  fireEvent.click(tile);
  expect(h1Name()).toBe("Ascent Console: Findings");
  const table = await screen.findByRole("table");
  expect(within(table).getByText("Open redirect")).toBeInTheDocument();
  expect(within(table).queryByText("SSRF in fetch")).not.toBeInTheDocument();
  expect(within(table).queryByText("Reflected XSS")).not.toBeInTheDocument();
  // The filter is visible as the pressed tile and a "shown" count, and one button lifts it.
  expect(screen.getByText("Needs human", { selector: ".kpi .l" }).closest("button")).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByText("1 shown")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
  expect(within(screen.getByRole("table")).getByText("SSRF in fetch")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
});

test("the Findings tile opens an unfiltered Findings screen", async () => {
  mockApi({ "/api/findings": () => json([finding, noise]) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.click(screen.getByText("True positive", { selector: ".kpi .l" }).closest("button") as HTMLElement);
  expect(within(await screen.findByRole("table")).queryByText("Reflected XSS")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Overview" }));
  fireEvent.click((await screen.findByText("Findings", { selector: ".kpi .l" })).closest("button") as HTMLElement);
  expect(within(await screen.findByRole("table")).getByText("Reflected XSS")).toBeInTheDocument();
});

test("search Enter on Overview opens Findings", async () => {
  mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.change(screen.getByRole("searchbox", { name: "Search findings" }), { target: { value: "ssrf" } });
  fireEvent.submit(screen.getByRole("search"));
  expect(h1Name()).toBe("Ascent Console: Findings");
  expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveValue("ssrf");
});

test("the Overview top findings follow the search box, and Clear search empties it", async () => {
  mockApi({ "/api/findings": () => json([finding, noise]) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  fireEvent.change(box, { target: { value: "xss" } });
  expect(screen.queryByText("SSRF in fetch")).not.toBeInTheDocument();
  expect(screen.getByText("Reflected XSS")).toBeInTheDocument();
  expect(screen.getByText("1 of 2 match")).toBeInTheDocument();
  fireEvent.change(box, { target: { value: "nothing-like-this" } });
  expect(screen.getByText("No findings match “nothing-like-this”")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
  expect(box).toHaveValue("");
  expect(screen.getByText("SSRF in fetch")).toBeInTheDocument();
});

test("the Overview has one Approve button and fetches each endpoint once", async () => {
  const spy = mockApi();
  render(<App />);
  await screen.findByRole("button", { name: "Approve" });
  expect(screen.getAllByRole("button", { name: /approve/i })).toHaveLength(1);
  expect(screen.getByText(/Approving records consent; it does not run the command/)).toBeInTheDocument();
  await waitFor(() => expect(calls(spy, "/api/engagement")).toBe(1));
  expect(calls(spy, "/api/gates")).toBe(1);
  expect(calls(spy, "/api/gate")).toBe(1);
  expect(calls(spy, "/api/findings")).toBe(1);
  expect(calls(spy, "/api/audit")).toBe(1);
  expect(calls(spy, "/api/report")).toBe(1);
});

test("going Overview -> Findings -> Overview reuses the data instead of refetching", async () => {
  const spy = mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  await screen.findByRole("table");
  fireEvent.click(screen.getByRole("button", { name: "Overview" }));
  await screen.findByText("Approval required");
  expect(calls(spy, "/api/findings")).toBe(1);
  expect(calls(spy, "/api/audit")).toBe(1);
});

test("Refresh data swaps the Overview data in place without a loading flash", async () => {
  let n = 0;
  mockApi({
    "/api/findings": () =>
      json([{ ...finding, finding: { ...finding.finding, title: n++ === 0 ? "First title" : "Second title" } }]),
  });
  render(<App />);
  await screen.findByText("First title");
  const heading = screen.getByRole("heading", { level: 2, name: "Top findings" });
  fireEvent.click(screen.getByRole("button", { name: "Refresh data" }));
  expect(screen.getByText("First title")).toBeInTheDocument();
  expect(await screen.findByText("Second title")).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 2, name: "Top findings" })).toBe(heading);
});

test("deciding a gate on the Overview updates the bell and the hero", async () => {
  let decided = false;
  mockApi({
    "/api/gates": () => json(decided ? [] : [gate]),
    "/api/gates/g1/approve": () => {
      decided = true;
      return json({ ok: true });
    },
  });
  render(<App />);
  await screen.findByRole("button", { name: "Pending approvals: 1" });
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  expect(await screen.findByRole("button", { name: "Pending approvals: 0" })).toBeInTheDocument();
  expect(await screen.findByText("No actions awaiting approval")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review approvals" })).not.toBeInTheDocument();
});

// ---- Findings: filter toggles, search, empty state (spec 3.3) ----

function tileButton(label: string) {
  return screen.getByText(label, { selector: ".kpi .l" }).closest("button") as HTMLElement;
}

function findingRows() {
  return within(screen.getByRole("table"))
    .getAllByRole("row")
    .slice(1)
    .map((r) => r.querySelector(".fname")?.textContent);
}

test("the Findings tiles toggle the filter, and pressing the pressed tile shows everything again", async () => {
  mockApi({ "/api/findings": () => json([finding, noise, unsure]) });
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  await screen.findByRole("table");
  expect(findingRows()).toHaveLength(3);
  fireEvent.click(tileButton("Likely noise"));
  expect(findingRows()).toEqual(["Reflected XSS"]);
  expect(tileButton("Likely noise")).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(tileButton("True positive"));
  expect(findingRows()).toEqual(["SSRF in fetch"]);
  fireEvent.click(tileButton("True positive"));
  expect(findingRows()).toHaveLength(3);
  expect(tileButton("Findings")).toHaveAttribute("aria-pressed", "true");
});

test("the top-bar search filters the Findings rows live, and Clear filters empties it and the verdict filter", async () => {
  mockApi({ "/api/findings": () => json([finding, noise, unsure]) });
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  await screen.findByRole("table");
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  fireEvent.change(box, { target: { value: "xss" } });
  expect(findingRows()).toEqual(["Reflected XSS"]);
  expect(screen.getByText("1 shown")).toBeInTheDocument();
  fireEvent.click(tileButton("True positive")); // narrower than the query allows
  expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  fireEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]);
  expect(box).toHaveValue("");
  expect(findingRows()).toHaveLength(3);
  expect(tileButton("Findings")).toHaveAttribute("aria-pressed", "true");
});

test("the search text and the verdict filter survive a trip to another screen", async () => {
  mockApi({ "/api/findings": () => json([finding, noise, unsure]) });
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  await screen.findByRole("table");
  fireEvent.change(screen.getByRole("searchbox", { name: "Search findings" }), { target: { value: "lab" } });
  fireEvent.click(tileButton("Needs human"));
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  await screen.findByText("Hash chain OK");
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  expect(findingRows()).toEqual(["Open redirect"]);
  expect(screen.getByRole("searchbox", { name: "Search findings" })).toHaveValue("lab");
  expect(tileButton("Needs human")).toHaveAttribute("aria-pressed", "true");
});

test("an unknown verdict is counted by its Overview tile and listed by that tile's filter", async () => {
  const odd = { ...unsure, finding: { ...unsure.finding, id: "f9", title: "Odd verdict" }, verdict: "SOMETHING_NEW" };
  mockApi({ "/api/findings": () => json([finding, unsure, odd]) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  const tile = tileButton("Needs human");
  expect(within(tile).getByText("2", { selector: ".n" })).toBeInTheDocument();
  fireEvent.click(tile);
  await screen.findByRole("table");
  expect(findingRows().sort()).toEqual(["Odd verdict", "Open redirect"]);
});

test("the Findings empty state sends you to New scan", async () => {
  mockApi({ "/api/findings": () => json([]) });
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  await screen.findByText("No findings yet");
  const cta = screen
    .getAllByRole("button", { name: "Define a new scan" })
    .find((b) => b.closest(".empty-state")) as HTMLElement;
  fireEvent.click(cta);
  expect(h1Name()).toBe("Ascent Console: New scan");
});

// ---- approval decisions: one pending count, wherever it is shown ----

test("after a decision the bell, the hero and the Approval card agree, even if the refetch is stale", async () => {
  let posted = false;
  mockApi({
    // A stale server view: it keeps listing the gate after the decision was recorded.
    "/api/gates": () => json([gate]),
    "/api/gates/g1/approve": () => {
      posted = true;
      return json({ ok: true });
    },
  });
  render(<App />);
  await screen.findByRole("button", { name: "Pending approvals: 1" });
  expect(screen.getByText("1 pending")).toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  expect(await screen.findByRole("button", { name: "Pending approvals: 0" })).toBeInTheDocument();
  expect(posted).toBe(true);
  expect(screen.getByText("0 pending")).toBeInTheDocument();
  expect(screen.getByText("No actions awaiting approval")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review approvals" })).not.toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Welcome" }).textContent).not.toMatch(/approval/i);
  expect(within(screen.getByRole("button", { name: "Approval gates" })).queryByText("1")).not.toBeInTheDocument();
});

test("a decision made on the Approval gates screen is still recorded when you leave before the answer arrives", async () => {
  let release!: () => void;
  const answer = new Promise<void>((r) => (release = r));
  let decided = false;
  mockApi({
    "/api/gates/g1/approve": async () => {
      await answer;
      decided = true;
      return json({ ok: true });
    },
    "/api/gates": () => json(decided ? [] : [gate]),
    "/api/audit": () =>
      json({
        entries: decided ? [{ type: "gate_decision", gate_id: "g1", decision: "approved", entry_hash: "abc" }] : [],
        chain_ok: true,
      }),
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Pending approvals: 1" }));
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  // Leave while the POST is still in flight.
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  await screen.findByText("Hash chain OK");
  expect(screen.queryByText(/gate g1 → approved/)).not.toBeInTheDocument();
  release();
  expect(await screen.findByText(/gate g1 → approved/)).toBeInTheDocument();
  expect(await screen.findByRole("button", { name: "Pending approvals: 0" })).toBeInTheDocument();
});
